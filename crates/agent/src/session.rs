//! An authenticated connection, from `Welcome` to its end.
//!
//! The agent sends a heartbeat when the session starts and one per interval after that,
//! answers what the server asks, and checks that the server is still there.
//!
//! **Is the server still there?** The server never pings, and a connection that died
//! without a close looks exactly like a quiet one. So the agent pings, and takes any frame
//! from the server as a sign of life. After `Timing::silence` without one it gives the
//! connection up and connects again. Pings start here and not earlier: before `Welcome`
//! the server ends the connection on anything that is not the answer to its challenge.
//!
//! **The server is not trusted** (invariant 2 in `AGENTS.md`). Nothing it sends runs
//! anything: `RunAction` is answered with `actions_disabled` until the agent verifies
//! manifests (M2). `CollectNow` gets a heartbeat, but not more often than `Timing::min_collect_gap`,
//! so asking fast does not turn into reading the machine fast. A message that does not
//! parse is dropped and the session goes on (ADR-0006). The device key is not here at all:
//! a challenge after the handshake ends the session, and so does any other handshake
//! message.

use futures_util::{Sink, Stream, StreamExt};
use ponte_protocol::{ActionOutcome, ActionResult, AgentToServer, RejectReason, ServerToAgent};
use tokio::sync::watch;
use tokio::time::{Instant, sleep_until};
use tracing::{debug, warn};

use crate::Timing;
use crate::telemetry::Collect;
use crate::wire::{self, Message};

/// How many dropped or refused messages of one session get a log line each. A server
/// that keeps sending what the agent does not take must not fill the machine's disk.
const DROPS_LOGGED: u32 = 8;

/// The answer to every `RunAction` until the agent can verify a manifest.
const REFUSAL: RejectReason = RejectReason::ActionsDisabled;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionEnd {
    /// The server closed, or the connection failed.
    ServerClosed,
    /// No frame from the server for `Timing::silence`.
    ServerSilent,
    /// A frame could not be sent, or not in time.
    SendFailed,
    /// The server sent a handshake message in the middle of a session.
    HandshakeRepeated,
    /// The agent is shutting down.
    Stopped,
}

/// Runs the session until something ends it. The caller closes the connection.
pub(crate) async fn run<St, Si, E, C>(
    stream: &mut St,
    sink: &mut Si,
    collector: &C,
    timing: &Timing,
    stopped: &mut watch::Receiver<bool>,
) -> SessionEnd
where
    St: Stream<Item = Result<Message, E>> + Unpin,
    Si: Sink<Message> + Unpin,
    C: Collect,
{
    let start = Instant::now();
    // The first heartbeat goes out at once, so a device is not "online, no data" for a
    // whole interval.
    let mut heartbeat_at = start;
    let mut collected_at = None;
    let mut ping_at = start + timing.ping;
    let mut silent_at = start + timing.silence;
    let mut drops = Drops::default();

    loop {
        let frame = tokio::select! {
            () = crate::stop_signal(stopped) => return SessionEnd::Stopped,
            frame = stream.next() => frame,
            () = sleep_until(silent_at) => return SessionEnd::ServerSilent,
            () = sleep_until(heartbeat_at) => {
                if let Some(telemetry) = collector.snapshot().await {
                    let heartbeat = AgentToServer::Heartbeat { telemetry };
                    if wire::send(sink, &heartbeat, timing.send).await.is_err() {
                        return SessionEnd::SendFailed;
                    }
                }
                let now = Instant::now();
                collected_at = Some(now);
                heartbeat_at = now + timing.heartbeat;
                continue;
            }
            () = sleep_until(ping_at) => {
                let ping = Message::Ping(Vec::new().into());
                if wire::send_frame(sink, ping, timing.send).await.is_err() {
                    return SessionEnd::SendFailed;
                }
                ping_at = Instant::now() + timing.ping;
                continue;
            }
        };

        let text = match frame {
            Some(Ok(Message::Text(text))) => text,
            Some(Ok(Message::Close(_)) | Err(_)) | None => return SessionEnd::ServerClosed,
            // The library has already answered a ping by the time it shows up here.
            Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_))) => {
                silent_at = Instant::now() + timing.silence;
                continue;
            }
            Some(Ok(Message::Binary(_))) => {
                silent_at = Instant::now() + timing.silence;
                if drops.log_this_one() {
                    warn!("frame dropped: not text");
                }
                continue;
            }
        };
        // Whatever it says, the server is there.
        let now = Instant::now();
        silent_at = now + timing.silence;

        match serde_json::from_str::<ServerToAgent>(text.as_str()) {
            Ok(ServerToAgent::CollectNow {}) => {
                // As soon as allowed, and no sooner. Asking again before then changes
                // nothing: the requests in between are answered by the same heartbeat.
                let earliest = collected_at.map_or(now, |at| at + timing.min_collect_gap);
                heartbeat_at = heartbeat_at.min(earliest.max(now));
            }
            Ok(ServerToAgent::RunAction(request)) => {
                // Only the id: the rest of the request is text the server chose.
                if drops.log_this_one() {
                    warn!(request = %request.request_id, reason = ?REFUSAL, "action refused");
                }
                let refusal = AgentToServer::ActionResult(ActionResult {
                    request_id: request.request_id,
                    outcome: ActionOutcome::Rejected { reason: REFUSAL },
                    output: None,
                    duration_ms: 0,
                });
                if wire::send(sink, &refusal, timing.send).await.is_err() {
                    return SessionEnd::SendFailed;
                }
            }
            Ok(ServerToAgent::CancelAction { request_id }) => {
                // Nothing is ever running, so there is nothing to cancel.
                debug!(request = %request_id, "cancel ignored: no action is running");
            }
            Ok(
                ServerToAgent::Challenge { .. }
                | ServerToAgent::Enrolled { .. }
                | ServerToAgent::Welcome {},
            ) => return SessionEnd::HandshakeRepeated,
            Err(error) => {
                // ADR-0006: logged and dropped. Only the kind of error, never its text.
                if drops.log_this_one() {
                    warn!(category = ?error.classify(), "message dropped: it does not parse");
                }
            }
        }
    }
}

/// Counts what a session dropped or refused, so that only the first few are logged.
#[derive(Default)]
struct Drops(u32);

impl Drops {
    /// Whether this one still gets a line. The first one that does not gets a notice.
    fn log_this_one(&mut self) -> bool {
        self.0 = self.0.saturating_add(1);
        if self.0 == DROPS_LOGGED + 1 {
            warn!("further drops are no longer logged for this session");
        }
        self.0 <= DROPS_LOGGED
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ponte_protocol::{Nonce, RequestId};
    use tokio::task::JoinHandle;
    use tokio::time::{sleep, timeout_at};

    use super::*;
    use crate::testkit::{FakeCollector, Peer, Sent, action_request, device_id, pipe, stuck_sink};

    const fn secs(secs: u64) -> Duration {
        Duration::from_secs(secs)
    }

    /// A session against a peer the test plays, with the default timing.
    struct Running {
        peer: Peer,
        collector: FakeCollector,
        stop: watch::Sender<bool>,
        task: JoinHandle<SessionEnd>,
        start: Instant,
    }

    fn session() -> Running {
        let (peer, mut stream, mut sink) = pipe();
        let collector = FakeCollector::default();
        let (stop, mut stopped) = watch::channel(false);
        let task = tokio::spawn({
            let collector = collector.clone();
            async move {
                run(
                    &mut stream,
                    &mut sink,
                    &collector,
                    &Timing::default(),
                    &mut stopped,
                )
                .await
            }
        });
        Running {
            peer,
            collector,
            stop,
            task,
            start: Instant::now(),
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    enum Event {
        /// A heartbeat, with the number of the reading it carries.
        Heartbeat(u64),
        Ping,
        Rejected(RequestId),
        Other,
    }

    impl Running {
        /// Everything the agent sends until `until` after the start, with the second it
        /// was sent in. Pings are answered if `answer_pings`.
        async fn watch(&mut self, until: Duration, answer_pings: bool) -> Vec<(u64, Event)> {
            let mut events = Vec::new();
            while let Ok(Some(sent)) = timeout_at(self.start + until, self.peer.next()).await {
                let event = match sent {
                    Sent::Frame(Message::Ping(_)) => {
                        if answer_pings {
                            self.peer.send_frame(Message::Pong(Vec::new().into()));
                        }
                        Event::Ping
                    }
                    Sent::Frame(Message::Text(text)) => {
                        match serde_json::from_str(text.as_str()).unwrap() {
                            AgentToServer::Heartbeat { telemetry } => {
                                Event::Heartbeat(telemetry.uptime_secs)
                            }
                            AgentToServer::ActionResult(ActionResult {
                                request_id,
                                outcome: ActionOutcome::Rejected { .. },
                                ..
                            }) => Event::Rejected(request_id),
                            _ => Event::Other,
                        }
                    }
                    _ => Event::Other,
                };
                events.push((self.start.elapsed().as_secs(), event));
            }
            events
        }

        fn elapsed(&self) -> Duration {
            self.start.elapsed()
        }

        async fn end(self) -> SessionEnd {
            self.task.await.unwrap()
        }
    }

    fn heartbeats(events: &[(u64, Event)]) -> Vec<(u64, u64)> {
        events
            .iter()
            .filter_map(|(at, event)| match event {
                Event::Heartbeat(reading) => Some((*at, *reading)),
                _ => None,
            })
            .collect()
    }

    fn pings(events: &[(u64, Event)]) -> Vec<u64> {
        events
            .iter()
            .filter(|(_, event)| *event == Event::Ping)
            .map(|(at, _)| *at)
            .collect()
    }

    #[tokio::test(start_paused = true)]
    async fn heartbeats_go_out_at_the_start_and_then_once_per_interval() {
        let mut running = session();
        let events = running.watch(secs(125), true).await;

        assert_eq!(heartbeats(&events), [(0, 1), (60, 2), (120, 3)]);
        assert_eq!(pings(&events), [30, 60, 90, 120]);
        assert_eq!(running.collector.readings(), 3);
        assert!(!running.task.is_finished());
    }

    /// The server never pings, and a connection that died without a close is silent for
    /// ever. The agent gives it ninety seconds and three pings.
    #[tokio::test(start_paused = true)]
    async fn a_server_that_says_nothing_for_ninety_seconds_is_gone() {
        let mut running = session();
        let events = running.watch(secs(300), false).await;

        assert_eq!(running.elapsed(), secs(90));
        assert_eq!(running.elapsed(), Timing::default().silence);
        assert_eq!(pings(&events)[..2], [30, 60]);
        assert_eq!(heartbeats(&events), [(0, 1), (60, 2)]);
        assert_eq!(running.end().await, SessionEnd::ServerSilent);
    }

    /// The other half of the test above: with an answer to every ping, the same session
    /// is still there long after the deadline. Without this, a deadline that fired for
    /// any reason at all would pass for a working check.
    #[tokio::test(start_paused = true)]
    async fn a_server_that_answers_pings_keeps_the_session() {
        let mut running = session();
        let events = running.watch(secs(599), true).await;

        assert_eq!(running.elapsed(), secs(599));
        assert!(!running.task.is_finished());
        assert_eq!(pings(&events).len(), 19);
        assert_eq!(heartbeats(&events).len(), 10);

        // And it ends when the answers stop: ninety seconds after the last one, which
        // answered the ping of second 570.
        let events = running.watch(secs(1_000), false).await;
        assert_eq!(pings(&events)[..2], [600, 630]);
        assert_eq!(running.elapsed(), secs(660));
        assert_eq!(running.end().await, SessionEnd::ServerSilent);
    }

    /// Any frame shows the server is there, not only a pong: text it cannot use included.
    #[tokio::test(start_paused = true)]
    async fn any_frame_from_the_server_is_a_sign_of_life() {
        for frame in [
            Message::text("not a message"),
            Message::text(serde_json::to_string(&ServerToAgent::CollectNow {}).unwrap()),
            Message::Binary(vec![1, 2, 3].into()),
            Message::Ping(Vec::new().into()),
            Message::Pong(Vec::new().into()),
        ] {
            let mut running = session();
            for _ in 0..3 {
                running.watch(running.elapsed() + secs(80), false).await;
                assert!(!running.task.is_finished(), "{frame:?}");
                running.peer.send_frame(frame.clone());
            }
            running.watch(secs(1_000), false).await;
            assert_eq!(running.elapsed(), secs(240 + 90), "{frame:?}");
            assert_eq!(running.end().await, SessionEnd::ServerSilent, "{frame:?}");
        }
    }

    /// `CollectNow` is the server asking the machine to work. However often it asks, the
    /// machine is read once per gap.
    #[tokio::test(start_paused = true)]
    async fn collect_now_gets_one_heartbeat_per_gap_however_often_it_is_asked() {
        let collect_now = ServerToAgent::CollectNow {};
        let mut running = session();

        running.watch(secs(1), true).await;
        for _ in 0..100 {
            running.peer.send(&collect_now);
        }
        running.watch(secs(6), true).await;
        for _ in 0..100 {
            running.peer.send(&collect_now);
        }
        let events = running.watch(secs(75), true).await;
        // The first hundred were answered at second 5. These are answered at 10, the
        // earliest moment allowed, and the next heartbeat is one interval after that.
        assert_eq!(heartbeats(&events), [(10, 3), (70, 4)]);
        assert_eq!(running.collector.readings(), 4);

        // Long after the last reading, it is answered at once.
        running.watch(secs(100), true).await;
        running.peer.send(&collect_now);
        let events = running.watch(secs(101), true).await;
        assert_eq!(heartbeats(&events), [(100, 5)]);
        assert_eq!(Timing::default().min_collect_gap, secs(5));
    }

    #[tokio::test(start_paused = true)]
    async fn the_heartbeat_after_the_first_collect_now_comes_five_seconds_after_the_last() {
        let mut running = session();
        running.watch(secs(1), true).await;
        running.peer.send(&ServerToAgent::CollectNow {});
        let events = running.watch(secs(9), true).await;
        assert_eq!(heartbeats(&events), [(5, 2)]);
    }

    /// Nothing runs on the server's word. Until the agent verifies manifests (M2) every
    /// request is refused, and the server is told so.
    #[tokio::test(start_paused = true)]
    async fn run_action_is_refused() {
        let mut running = session();
        running.watch(secs(1), true).await;

        let request_id = RequestId::new();
        running
            .peer
            .send(&ServerToAgent::RunAction(Box::new(action_request(
                request_id,
            ))));
        let AgentToServer::ActionResult(result) = running.peer.message().await else {
            panic!("not an action result");
        };
        assert_eq!(
            result,
            ActionResult {
                request_id,
                outcome: ActionOutcome::Rejected {
                    reason: RejectReason::ActionsDisabled,
                },
                output: None,
                duration_ms: 0,
            }
        );

        running
            .peer
            .send(&ServerToAgent::CancelAction { request_id });
        let events = running.watch(secs(20), true).await;
        assert_eq!(events, []);
        assert!(!running.task.is_finished());
    }

    /// ADR-0006: a message the agent cannot read is dropped and the session goes on. A
    /// newer server must not be able to knock an older agent off by talking to it.
    #[tokio::test(start_paused = true)]
    async fn what_the_agent_cannot_read_is_dropped_and_the_session_goes_on() {
        let mut running = session();
        running.watch(secs(1), true).await;

        for _ in 0..20 {
            for frame in [
                Message::text("not a message"),
                Message::text(r#"{"type":"reboot_now"}"#),
                Message::text(r#"{"type":"collect_now","and":"more"}"#),
                Message::text(""),
                Message::Binary(vec![0xff; 64].into()),
            ] {
                running.peer.send_frame(frame);
            }
        }
        let events = running.watch(secs(29), true).await;
        assert_eq!(events, []);
        assert_eq!(running.collector.readings(), 1);
        assert!(!running.task.is_finished());
    }

    /// The key is not in the session, so there is nothing to sign a second challenge
    /// with. A server that sends one, or any other handshake message, is not speaking
    /// the protocol, and the agent leaves without answering.
    #[tokio::test(start_paused = true)]
    async fn a_handshake_message_in_the_middle_of_a_session_ends_it() {
        for message in [
            ServerToAgent::Challenge {
                nonce: Nonce::from_bytes([0x12; 32]),
            },
            ServerToAgent::Enrolled {
                device_id: device_id(),
            },
            ServerToAgent::Welcome {},
        ] {
            let mut running = session();
            running.watch(secs(1), true).await;
            running.peer.send(&message);

            let events = running.watch(secs(300), true).await;
            assert_eq!(events, [], "{message:?}");
            assert_eq!(running.elapsed(), secs(1), "{message:?}");
            assert_eq!(running.end().await, SessionEnd::HandshakeRepeated);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn the_session_ends_when_the_server_closes_or_the_connection_drops() {
        let mut running = session();
        running.watch(secs(1), true).await;
        running.peer.send_frame(Message::Close(None));
        assert_eq!(running.end().await, SessionEnd::ServerClosed);

        let mut running = session();
        running.watch(secs(1), true).await;
        running.peer.hang_up();
        assert_eq!(running.end().await, SessionEnd::ServerClosed);
    }

    /// A reading that fails skips its heartbeat. It does not send an old or an empty one,
    /// and it does not end the session.
    #[tokio::test(start_paused = true)]
    async fn a_failed_reading_skips_a_heartbeat_and_nothing_else() {
        let mut running = session();
        running.collector.fail(true);
        let events = running.watch(secs(65), true).await;
        assert_eq!(heartbeats(&events), []);
        assert_eq!(pings(&events), [30, 60]);
        assert_eq!(running.collector.readings(), 2);

        running.collector.fail(false);
        let events = running.watch(secs(125), true).await;
        assert_eq!(heartbeats(&events), [(120, 3)]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_frame_that_cannot_be_sent_ends_the_session_after_ten_seconds() {
        let (_peer, mut stream, _) = pipe();
        let mut sink = stuck_sink();
        let (_stop, mut stopped) = watch::channel(false);
        let start = Instant::now();

        let end = run(
            &mut stream,
            &mut sink,
            &FakeCollector::default(),
            &Timing::default(),
            &mut stopped,
        )
        .await;
        assert_eq!(end, SessionEnd::SendFailed);
        assert_eq!(start.elapsed(), Timing::default().send);
        assert_eq!(start.elapsed(), secs(10));
    }

    #[tokio::test(start_paused = true)]
    async fn the_session_ends_when_the_agent_stops() {
        let mut running = session();
        running.watch(secs(45), true).await;
        running.stop.send(true).unwrap();
        sleep(Duration::ZERO).await;

        assert_eq!(running.elapsed(), secs(45));
        assert_eq!(running.end().await, SessionEnd::Stopped);
    }

    #[test]
    fn only_the_first_few_drops_are_logged() {
        let mut drops = Drops::default();
        let logged = (0..1_000).filter(|_| drops.log_this_one()).count();
        assert_eq!(logged, 8);
        let mut drops = Drops(u32::MAX - 1);
        assert!(!drops.log_this_one());
        assert!(!drops.log_this_one());
    }
}
