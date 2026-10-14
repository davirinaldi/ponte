//! One agent connection, from the challenge to the last heartbeat (ADR-0008).
//!
//! ```text
//! unauthenticated   Challenge sent. One message is accepted, `Enroll` or `Hello`, within
//!                   the deadline. Anything else ends the connection.
//! enrolled          `Enrolled` sent and the connection closed: the agent connects again.
//! authenticated     `Welcome` sent. Heartbeats are recorded. A message that does not parse
//!                   is logged and dropped, and the session goes on (ADR-0006).
//! ```
//!
//! Every ending looks the same from the other side: the server closes, with no reason.
//!
//! Nothing here logs a frame, a message or a transcript. Before authentication a frame is
//! whatever a stranger chose to send, and an `Enroll` holds a token. A message that fails to
//! parse is logged by the kind of its error only, because the error text of `serde_json` can
//! repeat what was sent.

use std::time::Duration;

use axum::extract::ws::Message;
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use ponte_protocol::{
    AgentToServer, DeviceId, MAX_HANDSHAKE_MESSAGE_BYTES, Nonce, ProtocolVersion, ServerToAgent,
};
use tokio::sync::OwnedSemaphorePermit;
use tokio::time::{sleep, timeout};
use tracing::{error, info, warn};

use super::Gateway;
use super::audit::{self, AuditEvent};
use super::handshake::{self, Accepted, Rejection};
use super::store::{AgentInfo, Device, DeviceStatus, DeviceStore, SessionId};

/// Why an authenticated session ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionEnd {
    /// The peer closed, or the connection failed.
    Disconnected,
    /// The same device authenticated on another connection.
    Replaced,
    /// The session reached its time limit.
    Expired,
    /// The device was revoked, or is gone from the store.
    Revoked,
    /// The peer sent `Enroll` or `Hello` again.
    HandshakeRepeated,
    /// The store failed. The agent connects again and the server starts from what it knows.
    StoreFailed,
}

/// Runs one connection to its end. `permit` is its place among the unauthenticated
/// connections, given back as soon as the peer has proven who it is, or is gone.
pub(crate) async fn run<D, St, Si, E>(
    gateway: &Gateway<D>,
    version: ProtocolVersion,
    mut stream: St,
    mut sink: Si,
    permit: OwnedSemaphorePermit,
) where
    D: DeviceStore,
    St: Stream<Item = Result<Message, E>> + Unpin,
    Si: Sink<Message> + Unpin,
{
    let limits = gateway.limits;
    // One deadline for the whole handshake, the store included: a peer cannot stretch it
    // by sending slowly.
    let outcome = timeout(
        limits.handshake,
        handshake(gateway, version, &mut stream, &mut sink),
    )
    .await
    .unwrap_or(Err(Rejection::TimedOut.into()));

    match outcome {
        Ok(Accepted::Authenticated { device, about }) => {
            drop(permit);
            session(gateway, version, device, &about, &mut stream, &mut sink).await;
        }
        Ok(Accepted::Enrolled {
            device_id,
            customer,
            status,
            repeated,
        }) => {
            if repeated {
                info!(device = %device_id, "enrollment repeated: same token, same key");
            } else {
                audit::record(&AuditEvent::DeviceEnrolled {
                    device: device_id,
                    customer,
                    status,
                });
            }
            // If this is lost on the way the agent enrolls again and gets the same answer.
            let _ = send(&mut sink, &ServerToAgent::Enrolled { device_id }).await;
            close(limits.close, &mut stream, &mut sink).await;
            drop(permit);
        }
        Err(Refused { reason, claimed }) => {
            info!(
                ?reason,
                claimed_device = claimed.map(tracing::field::display),
                version = version.number(),
                "handshake refused"
            );
            close(limits.close, &mut stream, &mut sink).await;
            drop(permit);
        }
    }
}

/// A handshake that failed, with what the log wants to know about it.
struct Refused {
    reason: Rejection,
    /// The id a `Hello` came with. A claim and nothing more: no key was proven.
    claimed: Option<DeviceId>,
}

impl From<Rejection> for Refused {
    fn from(reason: Rejection) -> Self {
        Self {
            reason,
            claimed: None,
        }
    }
}

/// Sends the challenge and judges the one message that may answer it.
async fn handshake<D, St, Si, E>(
    gateway: &Gateway<D>,
    version: ProtocolVersion,
    stream: &mut St,
    sink: &mut Si,
) -> Result<Accepted, Refused>
where
    D: DeviceStore,
    St: Stream<Item = Result<Message, E>> + Unpin,
    Si: Sink<Message> + Unpin,
{
    // Kept here and nowhere else: when the connection goes, so does the nonce.
    let nonce = fresh_nonce()?;
    send(sink, &ServerToAgent::Challenge { nonce })
        .await
        .map_err(|SendFailed| Rejection::Disconnected)?;

    let text = match stream.next().await {
        Some(Ok(Message::Text(text))) => text,
        Some(Ok(Message::Close(_)) | Err(_)) | None => {
            return Err(Rejection::Disconnected.into());
        }
        // Binary, and ping and pong too: before the handshake there is one thing to say.
        Some(Ok(_)) => return Err(Rejection::NotText.into()),
    };
    if text.len() > MAX_HANDSHAKE_MESSAGE_BYTES {
        return Err(Rejection::TooLarge.into());
    }
    let message = serde_json::from_str::<AgentToServer>(text.as_str())
        .map_err(|error| Rejection::Unparseable(error.classify()))?;

    let claimed = match &message {
        AgentToServer::Hello { device_id, .. } => Some(*device_id),
        _ => None,
    };
    handshake::answer(&gateway.store, version, &nonce, message, gateway.now())
        .await
        .map_err(|reason| Refused { reason, claimed })
}

/// 32 bytes from the operating system. If it has none to give, nobody gets a challenge:
/// a nonce that can be guessed is a handshake that can be replayed.
fn fresh_nonce() -> Result<Nonce, Rejection> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).map_err(|error| {
        error!(%error, "the operating system gave no random bytes for a nonce");
        Rejection::ServerFailure
    })?;
    Ok(Nonce::from_bytes(bytes))
}

/// Everything after `Hello` was accepted, until the session ends.
async fn session<D, St, Si, E>(
    gateway: &Gateway<D>,
    version: ProtocolVersion,
    device: Device,
    about: &AgentInfo,
    stream: &mut St,
    sink: &mut Si,
) where
    D: DeviceStore,
    St: Stream<Item = Result<Message, E>> + Unpin,
    Si: Sink<Message> + Unpin,
{
    let id = device.id;
    let session = SessionId::new();
    let (registration, replaced) = gateway.registry.register(id, session);
    if let Some(old) = replaced {
        audit::record(&AuditEvent::SessionReplaced {
            device: id,
            old,
            new: session,
        });
    }

    let end = match gateway
        .store
        .session_started(id, session, about, gateway.now())
        .await
    {
        Ok(()) => {
            audit::record(&AuditEvent::SessionStarted {
                device: id,
                session,
            });
            info!(
                device = %id,
                %session,
                status = ?device.status,
                version = version.number(),
                agent_version = %about.agent_version,
                os = %about.os,
                "agent connected"
            );
            if send(sink, &ServerToAgent::Welcome {}).await.is_ok() {
                let limit = gateway.limits.session;
                tokio::select! {
                    end = serve(gateway, &device, stream) => end,
                    () = registration.replaced() => SessionEnd::Replaced,
                    () = sleep(limit) => SessionEnd::Expired,
                }
            } else {
                SessionEnd::Disconnected
            }
        }
        Err(error) => {
            error!(device = %id, %error, "the device store failed at the start of a session");
            SessionEnd::StoreFailed
        }
    };

    // The place in the registry goes first, so a session that starts now is not mistaken
    // for a takeover of this one.
    drop(registration);
    if let Err(error) = gateway
        .store
        .session_ended(id, session, gateway.now())
        .await
    {
        error!(device = %id, %error, "the device store failed at the end of a session");
    }
    audit::record(&AuditEvent::SessionEnded {
        device: id,
        session,
        reason: end,
    });
    close(gateway.limits.close, stream, sink).await;
}

/// Reads what the agent sends until something ends the session.
async fn serve<D, St, E>(gateway: &Gateway<D>, device: &Device, stream: &mut St) -> SessionEnd
where
    D: DeviceStore,
    St: Stream<Item = Result<Message, E>> + Unpin,
{
    let id = device.id;
    loop {
        let text = match stream.next().await {
            Some(Ok(Message::Text(text))) => text,
            Some(Ok(Message::Close(_)) | Err(_)) | None => return SessionEnd::Disconnected,
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
            Some(Ok(Message::Binary(_))) => {
                warn!(device = %id, "frame dropped: not text");
                continue;
            }
        };
        let message = match serde_json::from_str::<AgentToServer>(text.as_str()) {
            Ok(message) => message,
            Err(error) => {
                // ADR-0006: logged and dropped. Only the kind of error, never its text.
                warn!(device = %id, category = ?error.classify(), "message dropped: it does not parse");
                continue;
            }
        };
        match message {
            AgentToServer::Heartbeat { telemetry } => {
                match gateway.store.heartbeat(id, &telemetry, gateway.now()).await {
                    Ok(Some(DeviceStatus::Active | DeviceStatus::Pending)) => {}
                    Ok(Some(DeviceStatus::Revoked) | None) => return SessionEnd::Revoked,
                    Err(error) => {
                        error!(device = %id, %error, "the device store failed on a heartbeat");
                        return SessionEnd::StoreFailed;
                    }
                }
            }
            AgentToServer::ActionResult(result) => {
                // The server sends no actions yet (M2), so nothing can be answering one.
                warn!(device = %id, request = %result.request_id, "action result dropped: nothing was asked");
            }
            AgentToServer::Enroll { .. } | AgentToServer::Hello { .. } => {
                return SessionEnd::HandshakeRepeated;
            }
        }
    }
}

struct SendFailed;

async fn send<Si>(sink: &mut Si, message: &ServerToAgent) -> Result<(), SendFailed>
where
    Si: Sink<Message> + Unpin,
{
    let text = serde_json::to_string(message).map_err(|_| SendFailed)?;
    sink.send(Message::Text(text.into()))
        .await
        .map_err(|_| SendFailed)
}

/// Closes with no code and no reason, the same for every ending, then gives the peer a
/// moment to finish reading: hanging up on unread data resets the connection, and a reset
/// can cost the peer the `Enrolled` it was just sent.
async fn close<St, Si, E>(limit: Duration, stream: &mut St, sink: &mut Si)
where
    St: Stream<Item = Result<Message, E>> + Unpin,
    Si: Sink<Message> + Unpin,
{
    let _ = timeout(limit, async {
        if sink.close().await.is_err() {
            return;
        }
        while let Some(Ok(frame)) = stream.next().await {
            if matches!(frame, Message::Close(_)) {
                break;
            }
        }
    })
    .await;
}
#[cfg(test)]
mod tests {
    use std::fmt;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use chrono::{DateTime, Utc};
    use ponte_protocol::{
        ActionOutcome, ActionResult, AgentToServer, DeviceId, MAX_HANDSHAKE_MESSAGE_BYTES, Nonce,
        PublicKey, RequestId, ServerToAgent, TelemetrySnapshot, enroll_transcript,
    };
    use tokio::time::Instant;

    use super::*;
    use crate::agents::Limits;
    use crate::agents::store::{
        AgentInfo, Device, DeviceStatus, EnrollOutcome, EnrollRequest, MemoryStore, SessionId,
        TokenHash,
    };
    use crate::agents::testkit::{
        Logs, Peer, Sent, TestDevice, about, gateway, gateway_with, store_with_token, telemetry,
        token, version,
    };

    type TestGateway = Arc<Gateway<MemoryStore>>;

    fn text(message: &AgentToServer) -> Message {
        Message::Text(serde_json::to_string(message).unwrap().into())
    }

    fn heartbeat(uptime_secs: u64) -> AgentToServer {
        AgentToServer::Heartbeat {
            telemetry: telemetry(uptime_secs),
        }
    }

    /// Lets the server's tasks run until `done` holds.
    async fn eventually(what: &str, done: impl Fn() -> bool) {
        for _ in 0..1_000 {
            if done() {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("never happened: {what}");
    }

    /// The server closes, says nothing more, and does it now. The clock of these tests only
    /// moves when everything is waiting, so "now" tells a connection that was closed from
    /// one that was left open until some deadline closed it.
    async fn closed_at_once(peer: &mut Peer) {
        let started = Instant::now();
        assert_eq!(peer.rest().await, [Sent::Closed]);
        assert_eq!(started.elapsed(), Duration::ZERO, "closed, but only later");
    }

    /// Enrolls `device` on a connection of its own.
    async fn enroll(gateway: &TestGateway, device: &TestDevice, token_seed: u8) -> DeviceId {
        let mut peer = Peer::connect(gateway);
        let nonce = peer.challenge().await;
        peer.send(text(&device.enroll(&nonce, &token(token_seed))));
        let Some(Sent::Message(ServerToAgent::Enrolled { device_id })) = peer.receive().await
        else {
            panic!("not enrolled");
        };
        closed_at_once(&mut peer).await;
        device_id
    }

    /// Connects as `device` and returns the connection after `Welcome`.
    async fn authenticate(gateway: &TestGateway, device: &TestDevice, id: DeviceId) -> Peer {
        let mut peer = Peer::connect(gateway);
        let nonce = peer.challenge().await;
        peer.send(text(&device.hello(&nonce, id)));
        assert_eq!(
            peer.receive().await,
            Some(Sent::Message(ServerToAgent::Welcome {}))
        );
        peer
    }

    /// An enrolled, active device and the gateway it enrolled at.
    async fn enrolled() -> (TestGateway, MemoryStore, TestDevice, DeviceId) {
        let store = store_with_token(1, 1);
        let gateway = gateway(store.clone());
        let device = TestDevice::new(10);
        let id = enroll(&gateway, &device, 1).await;
        (gateway, store, device, id)
    }

    /// ADR-0008: the nonce is what makes a recorded answer useless, so it has to be new.
    #[tokio::test(start_paused = true)]
    async fn every_connection_starts_with_a_fresh_challenge() {
        let gateway = gateway(MemoryStore::new());
        let mut nonces = Vec::new();
        for _ in 0..8 {
            let mut peer = Peer::connect(&gateway);
            nonces.push(peer.challenge().await);
        }
        for (index, nonce) in nonces.iter().enumerate() {
            assert!(!nonces[..index].contains(nonce), "a nonce came twice");
            // Random bytes, not a counter or a clock: every nonce differs from every other
            // in many places.
            for other in &nonces[..index] {
                let same = nonce
                    .as_bytes()
                    .iter()
                    .zip(other.as_bytes())
                    .filter(|(a, b)| a == b)
                    .count();
                assert!(same < 8, "{nonce} and {other} are too alike");
            }
        }
    }

    /// Enrolling does not authenticate: there is one way in, and it is `Hello`.
    #[tokio::test(start_paused = true)]
    async fn enrolling_ends_the_connection() {
        let store = store_with_token(1, 1);
        let gateway = gateway(store.clone());
        let device = TestDevice::new(10);

        let mut peer = Peer::connect(&gateway);
        let nonce = peer.challenge().await;
        peer.send(text(&device.enroll(&nonce, &token(1))));
        let Some(Sent::Message(ServerToAgent::Enrolled { device_id })) = peer.receive().await
        else {
            panic!("not enrolled");
        };

        // Whatever comes next on this connection is not read as a session.
        peer.send(text(&device.hello(&nonce, device_id)));
        peer.send(text(&heartbeat(1)));
        closed_at_once(&mut peer).await;
        peer.finished().await;

        let record = store.record(device_id).unwrap();
        assert_eq!(record.status, DeviceStatus::Active);
        assert_eq!(record.online, None);
        assert_eq!(record.telemetry, None);
        assert_eq!(gateway.registry.current(device_id), None);
    }

    #[tokio::test(start_paused = true)]
    async fn a_session_records_heartbeats_until_the_peer_leaves() {
        let (gateway, store, device, id) = enrolled().await;

        let mut peer = authenticate(&gateway, &device, id).await;
        let session = gateway.registry.current(id).unwrap();
        assert_eq!(store.record(id).unwrap().online, Some(session));
        assert_eq!(store.record(id).unwrap().about, about());

        for uptime in [1, 2] {
            peer.send(text(&heartbeat(uptime)));
            eventually("the heartbeat is recorded", || {
                store.record(id).unwrap().telemetry == Some(telemetry(uptime))
            })
            .await;
        }

        peer.finished().await;
        assert_eq!(store.record(id).unwrap().online, None);
        assert_eq!(gateway.registry.current(id), None);
    }

    /// One refusal for every reason. What the peer sees does not tell a device nobody
    /// knows from a revoked one, or a bad token from a bad signature. The log does.
    #[tokio::test(start_paused = true)]
    async fn a_refused_handshake_ends_the_same_way_whatever_the_reason() {
        let store = store_with_token(1, 2);
        let gateway = gateway(store.clone());
        let device = TestDevice::new(10);
        let id = enroll(&gateway, &device, 1).await;
        let revoked = TestDevice::new(11);
        let revoked_id = enroll(&gateway, &revoked, 1).await;
        store.revoke_device(revoked_id);
        let stranger = TestDevice::new(12);

        let padded = |nonce: &Nonce| {
            let hello = serde_json::to_string(&device.hello(nonce, id)).unwrap();
            let padding = " ".repeat(MAX_HANDSHAKE_MESSAGE_BYTES + 1 - hello.len());
            assert!(serde_json::from_str::<AgentToServer>(&format!("{padding}{hello}")).is_ok());
            Message::Text(format!("{padding}{hello}").into())
        };
        let with_unknown_field = |nonce: &Nonce| {
            let mut hello = serde_json::to_value(device.hello(nonce, id)).unwrap();
            hello["skip_signature_check"] = true.into();
            Message::Text(hello.to_string().into())
        };
        let with_weak_key = |nonce: &Nonce| {
            let public_key = PublicKey::from_bytes([0; 32]);
            let transcript = enroll_transcript(version(), nonce, &token(1), &public_key);
            text(&AgentToServer::Enroll {
                token: token(1),
                public_key,
                agent_version: about().agent_version,
                os: about().os,
                signature: stranger.sign(&transcript),
            })
        };
        let elsewhere = Nonce::from_bytes([7; 32]);

        type Case<'a> = (&'a str, Box<dyn Fn(&Nonce) -> Message + 'a>);
        let cases: Vec<Case<'_>> = vec![
            (
                "reason=Unparseable(Syntax)",
                Box::new(|_| Message::Text("hello?".into())),
            ),
            ("reason=Unparseable(Data)", Box::new(with_unknown_field)),
            (
                "reason=NotText",
                Box::new(|nonce| {
                    let hello = serde_json::to_vec(&device.hello(nonce, id)).unwrap();
                    Message::Binary(hello.into())
                }),
            ),
            (
                "reason=NotText",
                Box::new(|_| Message::Ping(Vec::new().into())),
            ),
            ("reason=TooLarge", Box::new(padded)),
            ("reason=NotAHandshake", Box::new(|_| text(&heartbeat(1)))),
            (
                "reason=UnknownDevice",
                Box::new(|nonce| text(&device.hello(nonce, DeviceId::new()))),
            ),
            (
                "reason=BadSignature",
                Box::new(|nonce| text(&stranger.hello(nonce, id))),
            ),
            (
                "reason=BadSignature",
                Box::new(|_| text(&device.hello(&elsewhere, id))),
            ),
            (
                "reason=RevokedDevice",
                Box::new(|nonce| text(&revoked.hello(nonce, revoked_id))),
            ),
            (
                "reason=Enrollment(UnknownToken)",
                Box::new(|nonce| text(&stranger.enroll(nonce, &token(9)))),
            ),
            (
                "reason=Enrollment(ExhaustedToken)",
                Box::new(|nonce| text(&stranger.enroll(nonce, &token(1)))),
            ),
            (
                "reason=BadSignature",
                Box::new(|_| text(&stranger.enroll(&elsewhere, &token(1)))),
            ),
            ("reason=UnusableKey", Box::new(with_weak_key)),
        ];

        for (reason, frame) in cases {
            let (logs, _guard) = Logs::capture();
            let started = Instant::now();
            let mut peer = Peer::connect(&gateway);
            let nonce = peer.challenge().await;
            peer.send(frame(&nonce));

            assert_eq!(peer.rest().await, [Sent::Closed], "{reason}");
            // Refused at once: no reason makes the peer wait longer than another.
            assert_eq!(started.elapsed(), Duration::ZERO, "{reason}");
            peer.finished().await;
            assert!(logs.text().contains(reason), "{reason}: {}", logs.text());
        }

        // None of it touched the two devices or let a third one in.
        assert_eq!(store.uses_left(&TokenHash::of(&token(1))), Some(0));
        assert_eq!(store.record(id).unwrap().online, None);
        assert_eq!(gateway.registry.current(id), None);
    }

    /// A peer gets one message to prove who it is, and a deadline to send it by.
    #[tokio::test(start_paused = true)]
    async fn silence_is_cut_off_at_the_deadline() {
        let (gateway, store, device, id) = enrolled().await;
        let (logs, _guard) = Logs::capture();
        let started = Instant::now();

        let mut peer = Peer::connect(&gateway);
        let nonce = peer.challenge().await;
        assert_eq!(peer.receive().await, Some(Sent::Closed));
        assert_eq!(started.elapsed(), Duration::from_secs(10));

        // A good answer that comes too late is no answer.
        peer.send(text(&device.hello(&nonce, id)));
        assert_eq!(peer.rest().await, []);
        peer.finished().await;
        assert_eq!(store.record(id).unwrap().online, None);
        assert!(logs.text().contains("reason=TimedOut"), "{}", logs.text());
    }

    #[tokio::test(start_paused = true)]
    async fn a_peer_that_leaves_before_answering_is_just_gone() {
        let gateway = gateway(MemoryStore::new());
        let (logs, _guard) = Logs::capture();

        let mut peer = Peer::connect(&gateway);
        peer.challenge().await;
        peer.finished().await;
        assert!(
            logs.text().contains("reason=Disconnected"),
            "{}",
            logs.text()
        );
        assert!(gateway.admit().is_some());
    }

    /// The place among the unauthenticated connections is what bounds them. It is held for
    /// exactly as long as the peer has proven nothing.
    #[tokio::test(start_paused = true)]
    async fn a_connection_holds_a_place_until_it_authenticates_or_ends() {
        let limits = Limits {
            unauthenticated: 2,
            ..Limits::default()
        };
        let gateway = gateway_with(store_with_token(1, 1), limits);
        let device = TestDevice::new(10);
        let id = enroll(&gateway, &device, 1).await;

        let mut silent = Peer::connect(&gateway);
        silent.challenge().await;
        let mut peer = Peer::connect(&gateway);
        let nonce = peer.challenge().await;
        assert!(gateway.admit().is_none(), "a third place");

        // Authenticated: the session goes on and its place is free.
        peer.send(text(&device.hello(&nonce, id)));
        assert_eq!(
            peer.receive().await,
            Some(Sent::Message(ServerToAgent::Welcome {}))
        );
        let place = gateway
            .admit()
            .expect("the place of the authenticated peer");
        assert!(gateway.admit().is_none());
        drop(place);

        // Refused: free once the connection is gone.
        silent.send(Message::Text("no".into()));
        closed_at_once(&mut silent).await;
        silent.finished().await;
        let (_one, _two) = (gateway.admit().unwrap(), gateway.admit().unwrap());
        assert!(gateway.admit().is_none());
    }

    /// Replay, on the wire: the exact frame that opened one session opens no other.
    #[tokio::test(start_paused = true)]
    async fn a_recorded_hello_opens_no_second_session() {
        let (gateway, store, device, id) = enrolled().await;

        let mut peer = Peer::connect(&gateway);
        let nonce = peer.challenge().await;
        let recorded = text(&device.hello(&nonce, id));
        peer.send(recorded.clone());
        assert_eq!(
            peer.receive().await,
            Some(Sent::Message(ServerToAgent::Welcome {}))
        );
        let session = gateway.registry.current(id).unwrap();

        let mut thief = Peer::connect(&gateway);
        thief.challenge().await;
        thief.send(recorded);
        closed_at_once(&mut thief).await;
        thief.finished().await;

        // And the attempt did not disturb the real session.
        assert_eq!(gateway.registry.current(id), Some(session));
        assert_eq!(store.record(id).unwrap().online, Some(session));
        peer.send(text(&heartbeat(5)));
        eventually("the real session still works", || {
            store.record(id).unwrap().telemetry == Some(telemetry(5))
        })
        .await;
    }

    /// ADR-0006: after the handshake, a message the server cannot read is logged and
    /// dropped. The session stays, so that an agent can still be told to update.
    #[tokio::test(start_paused = true)]
    async fn a_message_that_does_not_parse_is_dropped_and_the_session_goes_on() {
        let (gateway, store, device, id) = enrolled().await;
        let (logs, _guard) = Logs::capture();
        let peer = authenticate(&gateway, &device, id).await;

        let mut unknown_field = serde_json::to_value(heartbeat(1)).unwrap();
        unknown_field["telemetry"]["screen_text"] = "anything".into();
        peer.send(Message::Text("not json".into()));
        peer.send(Message::Text(r#"{"type":"from_the_future"}"#.into()));
        peer.send(Message::Text(unknown_field.to_string().into()));
        peer.send(Message::Binary(
            serde_json::to_vec(&heartbeat(2)).unwrap().into(),
        ));
        peer.send(Message::Ping(Vec::new().into()));
        peer.send(Message::Pong(Vec::new().into()));
        peer.send(text(&AgentToServer::ActionResult(ActionResult {
            request_id: RequestId::new(),
            outcome: ActionOutcome::Succeeded {},
            output: Some("nobody asked".to_owned()),
            duration_ms: 1,
        })));
        peer.send(text(&heartbeat(3)));

        eventually("the good heartbeat is recorded", || {
            store.record(id).unwrap().telemetry == Some(telemetry(3))
        })
        .await;
        assert!(store.record(id).unwrap().online.is_some());

        let logs = logs.text();
        assert!(logs.contains("category=Syntax"), "{logs}");
        assert!(logs.contains("category=Data"), "{logs}");
        for written_by_the_peer in ["from_the_future", "screen_text", "nobody asked"] {
            assert!(!logs.contains(written_by_the_peer), "{logs}");
        }
    }

    /// The handshake happens once. A second one would be a way to change identity inside
    /// a session, or to try tokens from behind an authenticated connection.
    #[tokio::test(start_paused = true)]
    async fn a_second_handshake_message_ends_the_session() {
        let store = store_with_token(1, 2);
        let gateway = gateway(store.clone());
        let device = TestDevice::new(10);
        let id = enroll(&gateway, &device, 1).await;
        let nonce = Nonce::from_bytes([7; 32]);

        for again in [
            device.hello(&nonce, id),
            TestDevice::new(11).enroll(&nonce, &token(1)),
        ] {
            let (logs, _guard) = Logs::capture();
            let mut peer = authenticate(&gateway, &device, id).await;
            peer.send(text(&again));
            peer.send(text(&heartbeat(9)));

            closed_at_once(&mut peer).await;
            peer.finished().await;
            let record = store.record(id).unwrap();
            assert_eq!(record.online, None);
            assert_eq!(record.telemetry, None);
            assert!(logs.text().contains("reason=HandshakeRepeated"));
        }
        assert_eq!(store.uses_left(&TokenHash::of(&token(1))), Some(1));
    }

    /// RF-04, as far as M1 takes it: a revoked device is out by its next heartbeat.
    #[tokio::test(start_paused = true)]
    async fn a_revoked_device_is_dropped_at_its_next_heartbeat() {
        let (gateway, store, device, id) = enrolled().await;
        let mut peer = authenticate(&gateway, &device, id).await;
        peer.send(text(&heartbeat(1)));
        eventually("the heartbeat is recorded", || {
            store.record(id).unwrap().telemetry.is_some()
        })
        .await;

        store.revoke_device(id);
        peer.send(text(&heartbeat(2)));
        closed_at_once(&mut peer).await;
        peer.finished().await;

        let record = store.record(id).unwrap();
        assert_eq!(record.telemetry, Some(telemetry(1)));
        assert_eq!(record.online, None);

        // And it does not come back.
        let mut peer = Peer::connect(&gateway);
        let nonce = peer.challenge().await;
        peer.send(text(&device.hello(&nonce, id)));
        closed_at_once(&mut peer).await;
    }

    /// RF-49: a pending device connects like any other, so a technician can see it and
    /// approve it. Until then nothing it reports is kept.
    #[tokio::test(start_paused = true)]
    async fn a_pending_device_is_welcomed_but_its_telemetry_is_not_kept() {
        let store = store_with_token(1, 2);
        let gateway = gateway(store.clone());
        let device = TestDevice::new(10);
        let id = enroll(&gateway, &device, 1).await;
        assert_eq!(store.record(id).unwrap().status, DeviceStatus::Pending);

        let peer = authenticate(&gateway, &device, id).await;
        peer.send(text(&heartbeat(1)));
        eventually("the device is seen", || {
            store.record(id).unwrap().last_seen.is_some()
        })
        .await;
        assert!(store.record(id).unwrap().online.is_some());
        assert_eq!(store.record(id).unwrap().telemetry, None);

        // Approval takes effect on the open session.
        store.approve_device(id);
        peer.send(text(&heartbeat(2)));
        eventually("telemetry is kept once approved", || {
            store.record(id).unwrap().telemetry == Some(telemetry(2))
        })
        .await;
    }

    /// One session per device. The newer one wins, and the takeover is audited: either
    /// the old connection was already dead, or two machines hold the same key.
    #[tokio::test(start_paused = true)]
    async fn a_new_session_of_the_same_device_replaces_the_old_one() {
        let (gateway, store, device, id) = enrolled().await;
        let (logs, _guard) = Logs::capture();

        let mut old = authenticate(&gateway, &device, id).await;
        let old_session = gateway.registry.current(id).unwrap();
        let mut new = authenticate(&gateway, &device, id).await;
        let new_session = gateway.registry.current(id).unwrap();
        assert_ne!(old_session, new_session);

        closed_at_once(&mut old).await;
        old.finished().await;

        // The old session ended after the new one began, and left it alone.
        assert_eq!(gateway.registry.current(id), Some(new_session));
        assert_eq!(store.record(id).unwrap().online, Some(new_session));
        new.send(text(&heartbeat(4)));
        eventually("the new session works", || {
            store.record(id).unwrap().telemetry == Some(telemetry(4))
        })
        .await;

        let logs = logs.text();
        let replaced = logs
            .lines()
            .find(|line| line.contains("session_replaced"))
            .unwrap_or_else(|| panic!("not audited: {logs}"));
        assert!(replaced.contains("ponte::audit"), "{replaced}");
        assert!(replaced.contains(&format!("device={id}")), "{replaced}");
        assert!(
            replaced.contains(&format!("old={old_session}")),
            "{replaced}"
        );
        assert!(
            replaced.contains(&format!("new={new_session}")),
            "{replaced}"
        );
        assert!(logs.contains("reason=Replaced"), "{logs}");

        new.finished().await;
        assert_eq!(store.record(id).unwrap().online, None);
    }

    /// No session lives forever on one check of the key and of the device's status.
    #[tokio::test(start_paused = true)]
    async fn a_session_ends_at_its_time_limit() {
        let (gateway, store, device, id) = enrolled().await;
        let (logs, _guard) = Logs::capture();
        let mut peer = authenticate(&gateway, &device, id).await;
        let started = Instant::now();

        assert_eq!(peer.rest().await, [Sent::Closed]);
        assert_eq!(started.elapsed(), Duration::from_secs(24 * 60 * 60));
        peer.finished().await;
        assert_eq!(store.record(id).unwrap().online, None);
        assert!(logs.text().contains("reason=Expired"), "{}", logs.text());
    }

    /// What reaches a log file reaches backups, a log service and whoever reads either.
    #[tokio::test(start_paused = true)]
    async fn logs_hold_no_secret_and_nothing_a_stranger_wrote() {
        let store = store_with_token(1, 1);
        let gateway = gateway(store.clone());
        let device = TestDevice::new(10);
        let (logs, _guard) = Logs::capture();
        let mut seen = Vec::new();

        // A good enrollment and a good session.
        let mut peer = Peer::connect(&gateway);
        let nonce = peer.challenge().await;
        let enroll_message = device.enroll(&nonce, &token(1));
        seen.push(serde_json::to_string(&enroll_message).unwrap());
        peer.send(text(&enroll_message));
        let Some(Sent::Message(ServerToAgent::Enrolled { device_id })) = peer.receive().await
        else {
            panic!("not enrolled");
        };
        peer.rest().await;
        let mut peer = Peer::connect(&gateway);
        let nonce = peer.challenge().await;
        seen.push(nonce.to_string());
        seen.push(serde_json::to_string(&device.hello(&nonce, device_id)).unwrap());
        peer.send(text(&device.hello(&nonce, device_id)));
        peer.receive().await;
        peer.send(text(&heartbeat(1)));
        peer.finished().await;

        // A bad token, a bad signature, and frames that are not messages at all.
        let stranger = TestDevice::new(11);
        type Frame<'a> = Box<dyn Fn(&Nonce) -> String + 'a>;
        let mut refused: Vec<Frame<'_>> = vec![
            Box::new(|nonce| serde_json::to_string(&stranger.enroll(nonce, &token(2))).unwrap()),
            Box::new(|_| {
                let elsewhere = Nonce::from_bytes([7; 32]);
                serde_json::to_string(&stranger.enroll(&elsewhere, &token(3))).unwrap()
            }),
            Box::new(|_| r#"{"type":"stranger-chose-this-type"}"#.to_owned()),
            Box::new(|_| "stranger-chose-this-text".to_owned()),
        ];
        // One that fails to parse halfway through, with the token already read.
        refused.push(Box::new(|nonce| {
            let mut message = serde_json::to_value(stranger.enroll(nonce, &token(4))).unwrap();
            message["os"] = "stranger-chose\nthis-os".into();
            message.to_string()
        }));
        for frame in refused {
            let mut peer = Peer::connect(&gateway);
            let nonce = peer.challenge().await;
            seen.push(nonce.to_string());
            let frame = frame(&nonce);
            seen.push(frame.clone());
            peer.send(Message::Text(frame.into()));
            closed_at_once(&mut peer).await;
            peer.finished().await;
        }

        let logs = logs.text();
        assert!(logs.contains("device_enrolled"), "{logs}");
        assert!(logs.contains("handshake refused"), "{logs}");
        for seed in 1..=4 {
            let secret = token(seed).expose_hex();
            assert!(!logs.contains(&secret), "a token: {logs}");
            assert!(!logs.contains(&secret[..16]), "part of a token: {logs}");
        }
        for frame in &seen {
            assert!(!logs.contains(frame.as_str()), "a frame or a nonce: {logs}");
        }
        // Part of a frame is still a leak: look for the fields that matter one by one.
        for frame in &seen {
            let Ok(frame) = serde_json::from_str::<serde_json::Value>(frame) else {
                continue;
            };
            for field in ["token", "signature"] {
                if let Some(value) = frame[field].as_str() {
                    assert!(!logs.contains(&value[..16]), "part of a {field}: {logs}");
                }
            }
        }
        for written_by_a_stranger in ["stranger-chose", "this-os"] {
            assert!(!logs.contains(written_by_a_stranger), "{logs}");
        }
    }

    /// A store that works until it is told to break.
    struct Flaky {
        inner: MemoryStore,
        /// Every call fails.
        broken: AtomicBool,
        /// Only recording the start of a session fails.
        no_sessions: AtomicBool,
    }

    #[derive(Debug)]
    struct Broken;

    impl fmt::Display for Broken {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("the store is down")
        }
    }

    impl std::error::Error for Broken {}

    impl Flaky {
        fn check(&self) -> Result<(), Broken> {
            if self.broken.load(Ordering::SeqCst) {
                Err(Broken)
            } else {
                Ok(())
            }
        }
    }

    /// `MemoryStore` cannot fail, and the compiler knows it.
    fn never(never: std::convert::Infallible) -> Broken {
        match never {}
    }

    impl DeviceStore for Flaky {
        type Error = Broken;

        async fn enroll(
            &self,
            request: EnrollRequest,
            now: DateTime<Utc>,
        ) -> Result<EnrollOutcome, Broken> {
            self.check()?;
            self.inner.enroll(request, now).await.map_err(never)
        }

        async fn device(&self, id: DeviceId) -> Result<Option<Device>, Broken> {
            self.check()?;
            self.inner.device(id).await.map_err(never)
        }

        async fn session_started(
            &self,
            id: DeviceId,
            session: SessionId,
            about: &AgentInfo,
            now: DateTime<Utc>,
        ) -> Result<(), Broken> {
            self.check()?;
            if self.no_sessions.load(Ordering::SeqCst) {
                return Err(Broken);
            }
            let started = self.inner.session_started(id, session, about, now).await;
            started.map_err(never)
        }

        async fn heartbeat(
            &self,
            id: DeviceId,
            telemetry: &TelemetrySnapshot,
            now: DateTime<Utc>,
        ) -> Result<Option<DeviceStatus>, Broken> {
            self.check()?;
            let status = self.inner.heartbeat(id, telemetry, now).await;
            status.map_err(never)
        }

        async fn session_ended(
            &self,
            id: DeviceId,
            session: SessionId,
            now: DateTime<Utc>,
        ) -> Result<(), Broken> {
            self.check()?;
            let ended = self.inner.session_ended(id, session, now).await;
            ended.map_err(never)
        }
    }

    /// Invariant 7: when the server cannot check, the answer is no.
    #[tokio::test(start_paused = true)]
    async fn a_store_that_fails_lets_nobody_in_and_keeps_nobody() {
        let inner = store_with_token(1, 2);
        let flaky = Flaky {
            inner: inner.clone(),
            broken: AtomicBool::new(false),
            no_sessions: AtomicBool::new(false),
        };
        let gateway = gateway_with(flaky, Limits::default());
        let device = TestDevice::new(10);
        let id = {
            let mut peer = Peer::connect(&gateway);
            let nonce = peer.challenge().await;
            peer.send(text(&device.enroll(&nonce, &token(1))));
            let Some(Sent::Message(ServerToAgent::Enrolled { device_id })) = peer.receive().await
            else {
                panic!("not enrolled");
            };
            device_id
        };

        // It cannot record that a session began: the session never begins.
        gateway.store.no_sessions.store(true, Ordering::SeqCst);
        let mut peer = Peer::connect(&gateway);
        let nonce = peer.challenge().await;
        peer.send(text(&device.hello(&nonce, id)));
        closed_at_once(&mut peer).await;
        peer.finished().await;
        assert_eq!(gateway.registry.current(id), None);
        gateway.store.no_sessions.store(false, Ordering::SeqCst);

        // It breaks in the middle of a session: the session ends.
        let mut peer = Peer::connect(&gateway);
        let nonce = peer.challenge().await;
        peer.send(text(&device.hello(&nonce, id)));
        assert_eq!(
            peer.receive().await,
            Some(Sent::Message(ServerToAgent::Welcome {}))
        );
        gateway.store.broken.store(true, Ordering::SeqCst);
        peer.send(text(&heartbeat(1)));
        closed_at_once(&mut peer).await;
        peer.finished().await;
        assert_eq!(gateway.registry.current(id), None);

        // And while it is broken, neither a known device nor a good token gets in.
        let (logs, _guard) = Logs::capture();
        for message in [
            |device: &TestDevice, nonce: &Nonce, id: DeviceId| device.hello(nonce, id),
            |_: &TestDevice, nonce: &Nonce, _: DeviceId| {
                TestDevice::new(11).enroll(nonce, &token(1))
            },
        ] {
            let mut peer = Peer::connect(&gateway);
            let nonce = peer.challenge().await;
            peer.send(text(&message(&device, &nonce, id)));
            closed_at_once(&mut peer).await;
            peer.finished().await;
        }
        assert!(
            logs.text().contains("reason=ServerFailure"),
            "{}",
            logs.text()
        );
        assert_eq!(inner.uses_left(&TokenHash::of(&token(1))), Some(1));
    }
}
