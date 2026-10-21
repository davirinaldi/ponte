//! One agent connection, from the challenge to the last heartbeat (ADR-0008).
//!
//! ```text
//! unauthenticated   Challenge sent. One message is accepted, `Enroll` or `Hello`, within
//!                   the deadline. Anything else ends the connection.
//! enrolled          `Enrolled` sent and the connection closed: the agent connects again.
//! authenticated     `Welcome` sent. Requests that got no answer are sent again, then
//!                   heartbeats are recorded, requests the sweep hands over are sent, and
//!                   results are stored. A message that does not parse is logged and
//!                   dropped, and the session goes on (ADR-0006).
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
    ActionResult, AgentToServer, DeviceId, MAX_HANDSHAKE_MESSAGE_BYTES, Nonce, ProtocolVersion,
    ServerToAgent, TelemetrySnapshot,
};
use tokio::sync::OwnedSemaphorePermit;
use tokio::time::{Instant, sleep, sleep_until, timeout};
use tracing::{debug, error, info, warn};

use super::Gateway;
use super::audit::{self, AuditEvent};
use super::handshake::{self, Accepted, Claim, Rejection};
use super::registry::{Outbox, Registration};
use super::store::actions::{ActionStore, Finish, Outgoing};
use super::store::{AgentInfo, DeviceStatus, SessionId};

/// How many dropped messages of one session get a log line each. A device that keeps
/// sending what the server cannot read stays connected (ADR-0006), without filling the log.
const DROPS_LOGGED: u32 = 8;

/// Action results one session may hand to the store in a minute. An agent answers the
/// requests it is sent, one at a time; more is a device spending the store's connections.
pub(crate) const RESULTS_PER_MINUTE: u32 = 32;

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
    D: ActionStore,
    St: Stream<Item = Result<Message, E>> + Unpin,
    Si: Sink<Message> + Unpin,
{
    let limits = gateway.limits;
    // The deadline covers what the peer controls: sending its one message. Judging that
    // message is the server's own work and is never cut short. A store call dropped
    // halfway could leave a device enrolled that nobody was told about, the audit log
    // included, and the peer would get to choose the moment.
    let first = timeout(limits.handshake, first_message(&mut stream, &mut sink))
        .await
        .unwrap_or(Err(Rejection::TimedOut));
    let outcome = match first {
        Ok((nonce, message)) => {
            let claim = Claim::of(&message);
            handshake::answer(&gateway.store, version, &nonce, message, gateway.now())
                .await
                .map_err(|reason| (reason, claim))
        }
        Err(reason) => Err((reason, Claim::default())),
    };

    match outcome {
        Ok(Accepted::Authenticated { device, about }) => {
            drop(permit);
            session(gateway, version, device.id, &about, &mut stream, &mut sink).await;
        }
        Ok(Accepted::Enrolled {
            device_id,
            customer,
            public_key,
            status,
            repeated,
        }) => {
            // A repetition is audited too. A store can keep an enrollment and fail to say
            // so, and then the repetition is the first answer anyone saw.
            audit::record(&AuditEvent::DeviceEnrolled {
                device: device_id,
                customer,
                public_key,
                status,
                repeated,
            });
            // If this is lost on the way the agent enrolls again and gets the same answer.
            let _ = send(&mut sink, &ServerToAgent::Enrolled { device_id }).await;
        }
        Err((reason, claim)) => refused(reason, claim, version),
    }
    close(limits.close, &mut stream, &mut sink).await;
}

/// Records a refused handshake. What `claim` says is proven if the refusal came after the
/// signature was checked, and a claim and nothing more otherwise.
fn refused(reason: Rejection, claim: Claim, version: ProtocolVersion) {
    if reason.follows_a_real_credential() {
        audit::record(&AuditEvent::HandshakeRefused { reason, who: claim });
    } else {
        // Anyone who reaches the port can cause these, as often as they like, so they are
        // not worth a line at the default level.
        debug!(
            ?reason,
            claimed_device = claim.device.map(tracing::field::display),
            version = version.number(),
            "handshake refused"
        );
    }
}

/// Sends the challenge and reads the one message that may answer it.
async fn first_message<St, Si, E>(
    stream: &mut St,
    sink: &mut Si,
) -> Result<(Nonce, AgentToServer), Rejection>
where
    St: Stream<Item = Result<Message, E>> + Unpin,
    Si: Sink<Message> + Unpin,
{
    // Kept by the caller and nowhere else: when the connection goes, so does the nonce.
    let nonce = fresh_nonce()?;
    send(sink, &ServerToAgent::Challenge { nonce })
        .await
        .map_err(|SendFailed| Rejection::Disconnected)?;

    let text = match stream.next().await {
        Some(Ok(Message::Text(text))) => text,
        Some(Ok(Message::Close(_)) | Err(_)) | None => return Err(Rejection::Disconnected),
        // Binary, and ping and pong too: before the handshake there is one thing to say.
        Some(Ok(_)) => return Err(Rejection::NotText),
    };
    if text.len() > MAX_HANDSHAKE_MESSAGE_BYTES {
        return Err(Rejection::TooLarge);
    }
    let message = serde_json::from_str::<AgentToServer>(text.as_str())
        .map_err(|error| Rejection::Unparseable(error.classify()))?;
    Ok((nonce, message))
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

/// Everything after `Hello` was accepted, until the session ends. The caller closes the
/// connection.
async fn session<D, St, Si, E>(
    gateway: &Gateway<D>,
    version: ProtocolVersion,
    id: DeviceId,
    about: &AgentInfo,
    stream: &mut St,
    sink: &mut Si,
) where
    D: ActionStore,
    St: Stream<Item = Result<Message, E>> + Unpin,
    Si: Sink<Message> + Unpin,
{
    let session = SessionId::new();
    let Some((registration, outbox)) = start(gateway, version, id, session, about).await else {
        return;
    };

    let limit = gateway.limits.write;
    let end = if send_within(limit, sink, &ServerToAgent::Welcome {})
        .await
        .is_ok()
    {
        tokio::select! {
            end = async {
                if resend(gateway, id, sink).await.is_err() {
                    return SessionEnd::Disconnected;
                }
                serve(gateway, id, stream, sink, outbox).await
            } => end,
            () = registration.replaced() => SessionEnd::Replaced,
            () = sleep(gateway.limits.session) => SessionEnd::Expired,
        }
    } else {
        SessionEnd::Disconnected
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
}

/// Records the new session in the store, then gives it the device's place in the registry
/// and the requests handed to it. `None` if the store refused it or failed: then nothing
/// was replaced and nobody is welcomed.
async fn start<'a, D: ActionStore>(
    gateway: &'a Gateway<D>,
    version: ProtocolVersion,
    id: DeviceId,
    session: SessionId,
    about: &AgentInfo,
) -> Option<(Registration<'a>, Outbox)> {
    // Held across both steps, so two connections of one device reach the store and the
    // registry in the same order. See `Registry::starting`.
    let Some(_turn) = gateway.registry.starting(id).await else {
        // At `debug`: whoever holds the key can cause this as often as they connect.
        debug!(device = %id, "session not started: too many connections of the device are starting");
        return None;
    };

    let started = gateway
        .store
        .session_started(id, session, about, gateway.now())
        .await;
    let status = match started {
        Ok(Some(status @ (DeviceStatus::Active | DeviceStatus::Pending))) => status,
        Ok(Some(DeviceStatus::Revoked) | None) => {
            // Revoked after the handshake looked. The signature was good, so the id is
            // proven and this is the key of a revoked device in use.
            audit::record(&AuditEvent::HandshakeRefused {
                reason: Rejection::RevokedDevice,
                who: Claim {
                    device: Some(id),
                    ..Claim::default()
                },
            });
            return None;
        }
        Err(error) => {
            error!(device = %id, %error, "the device store failed at the start of a session");
            // The store may have written before it failed. Ending this session is harmless
            // if it did not: the store only ends the session it holds.
            if let Err(error) = gateway
                .store
                .session_ended(id, session, gateway.now())
                .await
            {
                error!(device = %id, %error, "the device store failed at the end of a session");
            }
            return None;
        }
    };

    // Only now, with the store's word for it, does the session that was there have to go.
    let (registration, outbox, replaced) = gateway.registry.register(id, session);
    if let Some(old) = replaced {
        audit::record(&AuditEvent::SessionReplaced {
            device: id,
            old,
            new: session,
        });
    }
    audit::record(&AuditEvent::SessionStarted {
        device: id,
        session,
    });
    info!(
        device = %id,
        %session,
        ?status,
        version = version.number(),
        agent_version = %about.agent_version,
        os = %about.os,
        "agent connected"
    );
    Some((registration, outbox))
}

/// Sends again what the device was sent and never answered (ADR-0012). The agent answers a
/// request it knows from its journal, so a result lost on the way is recovered; one it
/// never got is decided now. Fails only if the connection does: a store that fails is
/// logged, and the requests wait for the next session.
async fn resend<D, Si>(gateway: &Gateway<D>, id: DeviceId, sink: &mut Si) -> Result<(), SendFailed>
where
    D: ActionStore,
    Si: Sink<Message> + Unpin,
{
    let unanswered = match gateway.store.unanswered(id, gateway.now()).await {
        Ok(unanswered) => unanswered,
        Err(error) => {
            error!(device = %id, %error, "the store failed to list the requests to send again");
            return Ok(());
        }
    };
    for Outgoing {
        device,
        id: manifest,
        version,
        request,
    } in unanswered
    {
        let request_id = request.request_id;
        send_within(
            gateway.limits.write,
            sink,
            &ServerToAgent::RunAction(request),
        )
        .await?;
        audit::record(&AuditEvent::ActionSent {
            request: request_id,
            device,
            manifest,
            version,
            resent: true,
        });
    }
    Ok(())
}

/// Reads what the agent sends, and writes the requests handed over, until something ends
/// the session.
async fn serve<D, St, Si, E>(
    gateway: &Gateway<D>,
    id: DeviceId,
    stream: &mut St,
    sink: &mut Si,
    mut outbox: Outbox,
) -> SessionEnd
where
    D: ActionStore,
    St: Stream<Item = Result<Message, E>> + Unpin,
    Si: Sink<Message> + Unpin,
{
    let interval = gateway.limits.status_check;
    // The device's status is read again at least this often: by a heartbeat, or without
    // one. A revoked device is out by then whatever it sends, or does not send (RF-04).
    let mut check_at = Instant::now() + interval;
    let mut drops = Drops::default();
    let mut results = Results::new();

    loop {
        let frame = tokio::select! {
            frame = stream.next() => frame,
            Some(request) = outbox.recv() => {
                // Handed over by the sweep, which already recorded `action_sent`. If the
                // connection fails here the request stays `sent`, and the device's next
                // session sends it again.
                let written =
                    send_within(gateway.limits.write, sink, &ServerToAgent::RunAction(request))
                        .await;
                if written.is_err() {
                    return SessionEnd::Disconnected;
                }
                continue;
            }
            () = sleep_until(check_at) => {
                match gateway.store.device(id).await {
                    Ok(Some(device)) if device.status != DeviceStatus::Revoked => {
                        check_at = Instant::now() + interval;
                        continue;
                    }
                    Ok(_) => return SessionEnd::Revoked,
                    Err(error) => {
                        error!(device = %id, %error, "the device store failed on a status check");
                        return SessionEnd::StoreFailed;
                    }
                }
            }
        };
        let text = match frame {
            Some(Ok(Message::Text(text))) => text,
            Some(Ok(Message::Close(_)) | Err(_)) | None => return SessionEnd::Disconnected,
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
            Some(Ok(Message::Binary(_))) => {
                if drops.log_this_one(id) {
                    warn!(device = %id, "frame dropped: not text");
                }
                continue;
            }
        };
        let message = match serde_json::from_str::<AgentToServer>(text.as_str()) {
            Ok(message) => message,
            Err(error) => {
                // ADR-0006: logged and dropped. Only the kind of error, never its text.
                if drops.log_this_one(id) {
                    warn!(device = %id, category = ?error.classify(), "message dropped: it does not parse");
                }
                continue;
            }
        };
        match message {
            AgentToServer::Heartbeat { telemetry } => {
                if !is_possible(&telemetry) {
                    if drops.log_this_one(id) {
                        warn!(device = %id, "heartbeat dropped: a reading no machine can have");
                    }
                    continue;
                }
                match gateway.store.heartbeat(id, &telemetry, gateway.now()).await {
                    Ok(Some(DeviceStatus::Active | DeviceStatus::Pending)) => {
                        check_at = Instant::now() + interval;
                    }
                    Ok(Some(DeviceStatus::Revoked) | None) => return SessionEnd::Revoked,
                    Err(error) => {
                        error!(device = %id, %error, "the device store failed on a heartbeat");
                        return SessionEnd::StoreFailed;
                    }
                }
            }
            AgentToServer::ActionResult(result) => {
                take_result(gateway, id, &result, &mut drops, &mut results).await;
            }
            AgentToServer::Enroll { .. } | AgentToServer::Hello { .. } => {
                return SessionEnd::HandshakeRepeated;
            }
        }
    }
}

/// Stores what the agent answered, if it may. Whatever happens, the session goes on: a
/// result the store failed to keep is asked for again when the device next connects, and
/// ending the session over it would only bring the same result back in a loop.
///
/// Never logs the `output`: it is text from the machine (invariants 4 and 6).
async fn take_result<D: ActionStore>(
    gateway: &Gateway<D>,
    id: DeviceId,
    result: &ActionResult,
    drops: &mut Drops,
    results: &mut Results,
) {
    let request = result.request_id;
    let mut may_log = || drops.log_this_one(id) && gateway.device_logs.allow(id);
    if !results.take() {
        if may_log() {
            warn!(device = %id, %request, "action result dropped: too many this minute");
        }
        return;
    }
    // No run lasts that long, and the store keeps a signed 64-bit number.
    if i64::try_from(result.duration_ms).is_err() {
        if may_log() {
            warn!(device = %id, %request, "action result dropped: a duration no run can have");
        }
        return;
    }
    match gateway.store.finish(id, result, gateway.now()).await {
        Ok(Finish::Recorded { replaced }) => audit::record(&AuditEvent::ActionFinished {
            request,
            device: id,
            outcome: result.outcome.clone(),
            duration_ms: result.duration_ms,
            replaced,
        }),
        // A copy, or an answer the journal sent again (ADR-0012).
        Ok(Finish::Repeated) => debug!(device = %id, %request, "the same result again"),
        Ok(Finish::Conflicting) => {
            if may_log() {
                warn!(
                    device = %id,
                    %request,
                    "a second, different result for a request; the first is kept, and may not be what happened"
                );
            }
        }
        Ok(Finish::DeviceNotActive) => {
            if may_log() {
                warn!(device = %id, %request, "action result dropped: the device is not active");
            }
        }
        Ok(why @ (Finish::NotSent | Finish::OtherDevice | Finish::Unknown)) => {
            if may_log() {
                warn!(device = %id, %request, ?why, "action result dropped: not a request this device was sent");
            }
        }
        Err(error) => {
            if may_log() {
                error!(device = %id, %request, %error, "the store failed to keep an action result; it is asked for again at the next session");
            }
        }
    }
}

/// How many results a session has handed to the store in the current minute.
struct Results {
    since: Instant,
    taken: u32,
}

impl Results {
    fn new() -> Self {
        Self {
            since: Instant::now(),
            taken: 0,
        }
    }

    /// Whether one more result may reach the store now.
    fn take(&mut self) -> bool {
        let now = Instant::now();
        if now.duration_since(self.since) >= Duration::from_secs(60) {
            self.since = now;
            self.taken = 0;
        }
        if self.taken < RESULTS_PER_MINUTE {
            self.taken += 1;
            true
        } else {
            false
        }
    }
}

/// Whether every reading is one a machine can have. The wire format takes any number, and
/// JSON turns a number past the range of an `f32` into infinity: a store writes that as
/// `null` and cannot read it back.
fn is_possible(telemetry: &TelemetrySnapshot) -> bool {
    (0.0..=100.0).contains(&telemetry.cpu_percent)
}

/// Counts what a session dropped, so that only the first few are logged.
#[derive(Default)]
struct Drops(u32);

impl Drops {
    /// Whether this drop still gets a line. The first one that does not gets a notice.
    fn log_this_one(&mut self, id: DeviceId) -> bool {
        self.0 = self.0.saturating_add(1);
        if self.0 == DROPS_LOGGED + 1 {
            warn!(device = %id, "further drops are no longer logged for this session");
        }
        self.0 <= DROPS_LOGGED
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

/// [`send`] within `limit`: a peer that does not read what it is sent gets no longer.
async fn send_within<Si>(
    limit: Duration,
    sink: &mut Si,
    message: &ServerToAgent,
) -> Result<(), SendFailed>
where
    Si: Sink<Message> + Unpin,
{
    timeout(limit, send(sink, message))
        .await
        .unwrap_or(Err(SendFailed))
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
    use tokio::sync::Semaphore;
    use tokio::time::Instant;

    use super::*;
    use crate::agents::Limits;
    use crate::agents::store::DeviceStore;
    use crate::agents::store::{
        AgentInfo, Device, DeviceAdmin, DeviceStatus, EnrollOutcome, EnrollRequest, MemoryStore,
        SessionId, TokenHash,
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
        // Longer than any deadline the server has, so a connection it never closes fails
        // the test instead of hanging it.
        let rest = tokio::time::timeout(Duration::from_secs(7 * 24 * 60 * 60), peer.rest())
            .await
            .expect("the server never closed");
        assert_eq!(rest, [Sent::Closed]);
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
        store.revoke_device(revoked_id).await.unwrap();
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

    /// A reading no machine can have is not kept. `1e39` parses as an infinite `f32`, which
    /// a store writes as `null` and can never read back: one device would break every
    /// listing that holds it.
    #[tokio::test(start_paused = true)]
    async fn a_heartbeat_with_an_impossible_reading_is_dropped() {
        let (gateway, store, device, id) = enrolled().await;
        let peer = authenticate(&gateway, &device, id).await;
        let (logs, _guard) = Logs::capture();

        let normal = serde_json::to_string(&heartbeat(1)).unwrap();
        let field = format!("\"cpu_percent\":{}", telemetry(1).cpu_percent);
        assert!(normal.contains(&field), "{normal}");
        for cpu in ["1e39", "-1e39", "-5", "100.5"] {
            let impossible = normal.replace(&field, &format!("\"cpu_percent\":{cpu}"));
            peer.send(Message::Text(impossible.into()));
        }
        peer.send(text(&heartbeat(2)));
        eventually("the good heartbeat is kept", || {
            store.record(id).unwrap().telemetry == Some(telemetry(2))
        })
        .await;
        assert!(logs.text().contains("heartbeat dropped"), "{}", logs.text());
        assert!(gateway.registry.current(id).is_some());
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
            output: Some("nobody asked".parse().unwrap()),
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

        store.revoke_device(id).await.unwrap();
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
        store.approve_device(id).await.unwrap();
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

    /// A store that works until it is told to misbehave.
    struct Flaky {
        inner: MemoryStore,
        /// Every call fails.
        broken: AtomicBool,
        /// Storing an action result fails.
        no_results: AtomicBool,
        /// A claim is made, and then the call fails anyway: its answer was lost.
        claim_then_fail: AtomicBool,
        /// The call fails at once and the claim commits later, after the first `unclaim`.
        claim_commits_late: AtomicBool,
        late_claim: std::sync::Mutex<Option<(Vec<DeviceId>, DateTime<Utc>)>>,
        /// Recording the start of a session fails.
        no_sessions: AtomicBool,
        /// The start of a session is recorded, and then the call fails anyway: a database
        /// that committed and lost the answer on the way back.
        start_then_fail: AtomicBool,
        /// The device is revoked just before the start of its session is recorded.
        revoke_at_start: AtomicBool,
        /// An enrollment is stored at once and answered half a minute later.
        slow_enroll: AtomicBool,
        /// The next start of a session waits here for a permit, after saying so in `held`.
        hold_next_start: AtomicBool,
        held: AtomicBool,
        release: Semaphore,
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
        fn over(inner: &MemoryStore) -> Self {
            Self {
                inner: inner.clone(),
                broken: AtomicBool::new(false),
                no_results: AtomicBool::new(false),
                claim_then_fail: AtomicBool::new(false),
                claim_commits_late: AtomicBool::new(false),
                late_claim: std::sync::Mutex::new(None),
                no_sessions: AtomicBool::new(false),
                start_then_fail: AtomicBool::new(false),
                revoke_at_start: AtomicBool::new(false),
                slow_enroll: AtomicBool::new(false),
                hold_next_start: AtomicBool::new(false),
                held: AtomicBool::new(false),
                release: Semaphore::new(0),
            }
        }

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
            let outcome = self.inner.enroll(request, now).await;
            if self.slow_enroll.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
            outcome.map_err(never)
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
        ) -> Result<Option<DeviceStatus>, Broken> {
            self.check()?;
            if self.no_sessions.load(Ordering::SeqCst) {
                return Err(Broken);
            }
            if self.revoke_at_start.load(Ordering::SeqCst) {
                self.inner.revoke_device(id).await.unwrap();
            }
            if self.hold_next_start.swap(false, Ordering::SeqCst) {
                self.held.store(true, Ordering::SeqCst);
                let permit = self.release.acquire().await.map_err(|_| Broken)?;
                permit.forget();
            }
            let started = self.inner.session_started(id, session, about, now).await;
            if self.start_then_fail.load(Ordering::SeqCst) {
                return Err(Broken);
            }
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

    impl ActionStore for Flaky {
        async fn claim_due(
            &self,
            online: &[DeviceId],
            now: DateTime<Utc>,
        ) -> Result<Vec<Outgoing>, Broken> {
            self.check()?;
            if self.claim_commits_late.load(Ordering::SeqCst) {
                *self.late_claim.lock().unwrap() = Some((online.to_vec(), now));
                return Err(Broken);
            }
            let claimed = self.inner.claim_due(online, now).await.map_err(never)?;
            if self.claim_then_fail.load(Ordering::SeqCst) {
                return Err(Broken);
            }
            Ok(claimed)
        }

        async fn unclaim(&self, claimed_at: DateTime<Utc>) -> Result<u64, Broken> {
            self.check()?;
            let unclaimed = self.inner.unclaim(claimed_at).await.map_err(never);
            let late = self.late_claim.lock().unwrap().take();
            if let Some((online, at)) = late {
                self.inner.claim_due(&online, at).await.map_err(never)?;
            }
            unclaimed
        }

        async fn release(&self, id: RequestId) -> Result<bool, Broken> {
            self.check()?;
            self.inner.release(id).await.map_err(never)
        }

        async fn unanswered(
            &self,
            device: DeviceId,
            now: DateTime<Utc>,
        ) -> Result<Vec<Outgoing>, Broken> {
            self.check()?;
            self.inner.unanswered(device, now).await.map_err(never)
        }

        async fn finish(
            &self,
            device: DeviceId,
            result: &ActionResult,
            now: DateTime<Utc>,
        ) -> Result<Finish, Broken> {
            self.check()?;
            if self.no_results.load(Ordering::SeqCst) {
                return Err(Broken);
            }
            self.inner.finish(device, result, now).await.map_err(never)
        }

        async fn expire(&self, now: DateTime<Utc>) -> Result<Vec<(RequestId, DeviceId)>, Broken> {
            self.check()?;
            self.inner.expire(now).await.map_err(never)
        }
    }

    /// Enrolls `device` at a gateway over a [`Flaky`] store.
    async fn enroll_at(gateway: &Arc<Gateway<Flaky>>, device: &TestDevice) -> DeviceId {
        let mut peer = Peer::connect(gateway);
        let nonce = peer.challenge().await;
        peer.send(text(&device.enroll(&nonce, &token(1))));
        let Some(Sent::Message(ServerToAgent::Enrolled { device_id })) = peer.receive().await
        else {
            panic!("not enrolled");
        };
        closed_at_once(&mut peer).await;
        device_id
    }

    /// Says `Hello` as `device` on a new connection, without waiting for the answer.
    async fn hello_at(gateway: &Arc<Gateway<Flaky>>, device: &TestDevice, id: DeviceId) -> Peer {
        let mut peer = Peer::connect(gateway);
        let nonce = peer.challenge().await;
        peer.send(text(&device.hello(&nonce, id)));
        peer
    }

    /// A failed call to a database does not say whether it wrote. A session whose start
    /// may have been recorded is ended in the store too, or the device would show as
    /// online, under a session that never began, until it connects again.
    #[tokio::test(start_paused = true)]
    async fn a_session_whose_start_failed_is_not_left_online() {
        let inner = store_with_token(1, 2);
        let gateway = gateway_with(Flaky::over(&inner), Limits::default());
        let device = TestDevice::new(10);
        let id = enroll_at(&gateway, &device).await;

        gateway.store.start_then_fail.store(true, Ordering::SeqCst);
        let mut peer = hello_at(&gateway, &device, id).await;
        closed_at_once(&mut peer).await;
        peer.finished().await;

        assert_eq!(inner.record(id).unwrap().online, None);
        assert_eq!(gateway.registry.current(id), None);
    }

    /// A result the store failed to keep is asked for again at the next session, when the
    /// agent answers from its journal. Ending this session over it would only bring the
    /// same result back, again and again.
    #[tokio::test(start_paused = true)]
    async fn a_result_the_store_fails_to_keep_does_not_end_the_session() {
        let inner = store_with_token(1, 1);
        let gateway = gateway_with(Flaky::over(&inner), Limits::default());
        let device = TestDevice::new(10);
        let id = enroll_at(&gateway, &device).await;
        let mut peer = hello_at(&gateway, &device, id).await;
        assert_eq!(
            peer.receive().await,
            Some(Sent::Message(ServerToAgent::Welcome {}))
        );

        gateway.store.no_results.store(true, Ordering::SeqCst);
        let (logs, _guard) = Logs::capture();
        peer.send(text(&AgentToServer::ActionResult(ActionResult {
            request_id: RequestId::new(),
            outcome: ActionOutcome::Succeeded {},
            output: None,
            duration_ms: 1,
        })));
        peer.send(text(&heartbeat(1)));
        eventually("the heartbeat after it is recorded", || {
            inner.record(id).unwrap().telemetry == Some(telemetry(1))
        })
        .await;
        assert!(
            logs.text()
                .contains("the store failed to keep an action result"),
            "{}",
            logs.text()
        );
        assert!(gateway.registry.current(id).is_some());
        assert!(inner.record(id).unwrap().online.is_some());
    }

    /// A claim that committed and lost its answer would leave its requests `sent`,
    /// delivered to nobody, until each device connects again. The sweep puts them back.
    #[tokio::test(start_paused = true)]
    async fn a_claim_whose_answer_was_lost_is_put_back_in_the_queue() {
        use crate::agents::store::actions::{ActionAdmin, NewRequest, RequestState};
        use crate::agents::testkit::{at, catalog_entry, manifest_public};

        let inner = store_with_token(1, 1);
        let gateway = gateway_with(Flaky::over(&inner), Limits::default());
        let device = TestDevice::new(10);
        let id = enroll_at(&gateway, &device).await;
        let mut peer = hello_at(&gateway, &device, id).await;
        assert_eq!(
            peer.receive().await,
            Some(Sent::Message(ServerToAgent::Welcome {}))
        );
        inner
            .add_signing_key(manifest_public(1), at(0))
            .await
            .unwrap();
        let entry = catalog_entry(1, "erp.restart-service", 1, 0);
        inner.add_manifest(&entry, at(0)).await.unwrap();
        let request = RequestId::new();
        let new = NewRequest {
            id: request,
            device: id,
            manifest: *entry.hash(),
            expires_at: u64::try_from(at(3600).timestamp()).unwrap(),
            initiator: ponte_protocol::Initiator::Human {
                user_id: "server_cli".parse().unwrap(),
            },
        };
        inner.request_action(&new, at(0)).await.unwrap();

        gateway.store.claim_then_fail.store(true, Ordering::SeqCst);
        assert!(crate::agents::delivery::sweep_once(&gateway).await.is_err());
        assert_eq!(
            inner.request_record(request).unwrap().state,
            RequestState::Queued
        );

        gateway.store.claim_then_fail.store(false, Ordering::SeqCst);
        crate::agents::delivery::sweep_once(&gateway).await.unwrap();
        let Some(Sent::Message(ServerToAgent::RunAction(sent))) = peer.receive().await else {
            panic!("the request was not sent");
        };
        assert_eq!(sent.request_id, request);
    }

    /// A claim given up at the store's limit may commit after the `unclaim` that follows it,
    /// which then finds nothing. The next sweeps put its requests back all the same.
    #[tokio::test(start_paused = true)]
    async fn a_claim_that_commits_after_it_was_given_up_is_put_back_by_a_later_sweep() {
        use crate::agents::store::actions::{ActionAdmin, NewRequest, RequestState};
        use crate::agents::testkit::{at, catalog_entry, manifest_public};

        let inner = store_with_token(1, 1);
        let gateway = gateway_with(Flaky::over(&inner), Limits::default());
        let device = TestDevice::new(10);
        let id = enroll_at(&gateway, &device).await;
        let mut peer = hello_at(&gateway, &device, id).await;
        assert_eq!(
            peer.receive().await,
            Some(Sent::Message(ServerToAgent::Welcome {}))
        );
        inner
            .add_signing_key(manifest_public(1), at(0))
            .await
            .unwrap();
        let entry = catalog_entry(1, "erp.restart-service", 1, 0);
        inner.add_manifest(&entry, at(0)).await.unwrap();
        let request = RequestId::new();
        let new = NewRequest {
            id: request,
            device: id,
            manifest: *entry.hash(),
            expires_at: u64::try_from(at(3600).timestamp()).unwrap(),
            initiator: ponte_protocol::Initiator::Human {
                user_id: "server_cli".parse().unwrap(),
            },
        };
        inner.request_action(&new, at(0)).await.unwrap();

        // The claim fails at once. The sweep puts back what it marked, finds nothing, and
        // only then the claim commits: `sent`, and delivered to nobody.
        gateway
            .store
            .claim_commits_late
            .store(true, Ordering::SeqCst);
        assert!(crate::agents::delivery::sweep_once(&gateway).await.is_err());
        gateway
            .store
            .claim_commits_late
            .store(false, Ordering::SeqCst);
        assert!(matches!(
            inner.request_record(request).unwrap().state,
            RequestState::Sent { .. }
        ));

        // The next sweep puts it back, claims it again and sends it.
        crate::agents::delivery::sweep_once(&gateway).await.unwrap();
        let Some(Sent::Message(ServerToAgent::RunAction(sent))) = peer.receive().await else {
            panic!("the request was not sent");
        };
        assert_eq!(sent.request_id, request);
    }

    /// Invariant 7: when the server cannot check, the answer is no.
    #[tokio::test(start_paused = true)]
    async fn a_store_that_fails_lets_nobody_in_and_keeps_nobody() {
        let inner = store_with_token(1, 2);
        let gateway = gateway_with(Flaky::over(&inner), Limits::default());
        let device = TestDevice::new(10);
        let id = enroll_at(&gateway, &device).await;

        // It cannot record that a session began: the session never begins, and the one
        // the device already has is left alone.
        let mut first = hello_at(&gateway, &device, id).await;
        assert_eq!(
            first.receive().await,
            Some(Sent::Message(ServerToAgent::Welcome {}))
        );
        let session = gateway.registry.current(id);
        {
            let (logs, _guard) = Logs::capture();
            gateway.store.no_sessions.store(true, Ordering::SeqCst);
            let mut peer = hello_at(&gateway, &device, id).await;
            closed_at_once(&mut peer).await;
            peer.finished().await;
            gateway.store.no_sessions.store(false, Ordering::SeqCst);
            assert!(!logs.text().contains("session_replaced"), "{}", logs.text());
        }
        assert!(session.is_some());
        assert_eq!(gateway.registry.current(id), session);
        assert_eq!(inner.record(id).unwrap().online, session);
        first.finished().await;

        // It breaks in the middle of a session: the session ends.
        let mut peer = hello_at(&gateway, &device, id).await;
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

    /// RF-04: revocation does not wait for the device to say something. A stolen key that
    /// authenticates and then keeps quiet, or sends anything but heartbeats, is out at
    /// the next check.
    #[tokio::test(start_paused = true)]
    async fn a_revoked_device_that_sends_no_heartbeat_is_dropped_at_the_next_check() {
        let (gateway, store, device, id) = enrolled().await;
        let (logs, _guard) = Logs::capture();
        let mut peer = authenticate(&gateway, &device, id).await;
        let started = Instant::now();

        store.revoke_device(id).await.unwrap();
        // Something every twenty seconds, none of it a heartbeat: it must not buy time.
        for _ in 0..2 {
            tokio::time::sleep(Duration::from_secs(20)).await;
            peer.send(Message::Ping(Vec::new().into()));
            peer.send(Message::Text("not a heartbeat".into()));
            peer.send(Message::Binary(vec![0].into()));
        }
        assert_eq!(peer.rest().await, [Sent::Closed]);
        assert_eq!(started.elapsed(), Duration::from_secs(60));
        peer.finished().await;

        assert_eq!(store.record(id).unwrap().online, None);
        assert_eq!(gateway.registry.current(id), None);
        assert!(logs.text().contains("reason=Revoked"), "{}", logs.text());
    }

    /// The check does nothing to a device in good standing, and a heartbeat counts as one.
    #[tokio::test(start_paused = true)]
    async fn a_quiet_device_in_good_standing_stays_connected() {
        let (gateway, store, device, id) = enrolled().await;
        let mut peer = authenticate(&gateway, &device, id).await;

        tokio::time::sleep(Duration::from_secs(10 * 60)).await;
        peer.send(text(&heartbeat(7)));
        eventually("the session is still there", || {
            store.record(id).unwrap().telemetry == Some(telemetry(7))
        })
        .await;
        assert!(gateway.registry.current(id).is_some());
        peer.finished().await;
    }

    /// The handshake reads the status, and a moment later the session starts. A device
    /// revoked in between gets no `Welcome` and never shows as connected.
    #[tokio::test(start_paused = true)]
    async fn a_device_revoked_while_its_session_starts_is_not_welcomed() {
        let inner = store_with_token(1, 1);
        let gateway = gateway_with(Flaky::over(&inner), Limits::default());
        let device = TestDevice::new(10);
        let id = enroll_at(&gateway, &device).await;
        let (logs, _guard) = Logs::capture();

        gateway.store.revoke_at_start.store(true, Ordering::SeqCst);
        let mut peer = hello_at(&gateway, &device, id).await;
        closed_at_once(&mut peer).await;
        peer.finished().await;

        assert_eq!(inner.record(id).unwrap().online, None);
        assert_eq!(gateway.registry.current(id), None);
        let logs = logs.text();
        assert!(logs.contains("handshake_refused"), "{logs}");
        assert!(logs.contains("reason=RevokedDevice"), "{logs}");
        assert!(!logs.contains("session_started"), "{logs}");
    }

    /// Two connections of one device at the same moment, and a store that takes its time
    /// with the first. Whatever the order, the store and the registry must end up naming
    /// the same session: otherwise the device shows as offline while it is connected.
    #[tokio::test(start_paused = true)]
    async fn two_sessions_of_one_device_start_one_after_the_other() {
        let inner = store_with_token(1, 1);
        let gateway = gateway_with(Flaky::over(&inner), Limits::default());
        let device = TestDevice::new(10);
        let id = enroll_at(&gateway, &device).await;

        gateway.store.hold_next_start.store(true, Ordering::SeqCst);
        let mut first = hello_at(&gateway, &device, id).await;
        eventually("the first session is being recorded", || {
            gateway.store.held.load(Ordering::SeqCst)
        })
        .await;
        let mut second = hello_at(&gateway, &device, id).await;
        for _ in 0..100 {
            tokio::task::yield_now().await;
        }
        gateway.store.release.add_permits(1);

        assert_eq!(
            second.receive().await,
            Some(Sent::Message(ServerToAgent::Welcome {}))
        );
        // The first one was welcomed and then replaced, there and then.
        let released = Instant::now();
        let rest = first.rest().await;
        assert_eq!(
            rest,
            [Sent::Message(ServerToAgent::Welcome {}), Sent::Closed]
        );
        assert_eq!(released.elapsed(), Duration::ZERO, "closed, but only later");
        first.finished().await;

        let session = gateway.registry.current(id);
        assert!(session.is_some());
        assert_eq!(inner.record(id).unwrap().online, session);
        second.send(text(&heartbeat(3)));
        eventually("the session that stayed works", || {
            inner.record(id).unwrap().telemetry == Some(telemetry(3))
        })
        .await;
        second.finished().await;
        assert_eq!(inner.record(id).unwrap().online, None);
    }

    /// The deadline is for the peer. Once its message is in, judging it is the server's
    /// own work and is not cut short: an enrollment stored and then abandoned would be a
    /// device nobody was told about, the audit log included.
    #[tokio::test(start_paused = true)]
    async fn a_slow_store_does_not_lose_an_enrollment_to_the_deadline() {
        let inner = store_with_token(1, 1);
        let gateway = gateway_with(Flaky::over(&inner), Limits::default());
        gateway.store.slow_enroll.store(true, Ordering::SeqCst);
        let device = TestDevice::new(10);
        let (logs, _guard) = Logs::capture();
        let started = Instant::now();

        let mut peer = Peer::connect(&gateway);
        let nonce = peer.challenge().await;
        peer.send(text(&device.enroll(&nonce, &token(1))));
        let Some(Sent::Message(ServerToAgent::Enrolled { device_id })) = peer.receive().await
        else {
            panic!("not enrolled: {}", logs.text());
        };
        assert_eq!(started.elapsed(), Duration::from_secs(30));
        closed_at_once(&mut peer).await;

        assert!(inner.record(device_id).is_some());
        let logs = logs.text();
        let enrolled = logs
            .lines()
            .find(|line| line.contains("device_enrolled"))
            .unwrap_or_else(|| panic!("not audited: {logs}"));
        assert!(
            enrolled.contains(&format!("device={device_id}")),
            "{enrolled}"
        );
        assert!(
            enrolled.contains(&format!("public_key={}", device.public_key())),
            "{enrolled}"
        );
    }

    /// A store can keep an enrollment and still fail to say so: a database that committed
    /// and then went quiet. The agent asks again and gets the same device, and that answer
    /// is audited too, or the device would be in the store and in no audit event.
    #[tokio::test(start_paused = true)]
    async fn a_repeated_enrollment_is_audited() {
        let store = store_with_token(1, 1);
        let gateway = gateway(store.clone());
        let device = TestDevice::new(10);
        let first = enroll(&gateway, &device, 1).await;

        let (logs, _guard) = Logs::capture_with(Some("warn"));
        let again = enroll(&gateway, &device, 1).await;
        assert_eq!(again, first);
        let logs = logs.text();
        let audited = logs
            .lines()
            .find(|line| line.contains("ponte::audit") && line.contains("device_enrolled"))
            .unwrap_or_else(|| panic!("not audited: {logs}"));
        assert!(audited.contains(&format!("device={first}")), "{audited}");
        assert!(audited.contains("repeated=true"), "{audited}");
    }

    /// A refusal that followed a real token or a real key is what a leak looks like, and
    /// goes to the audit log. A refusal anyone can cause does not: the audit log is not
    /// for strangers to write in.
    #[tokio::test(start_paused = true)]
    async fn refusals_after_a_real_token_or_key_are_audited() {
        let store = store_with_token(1, 1);
        let gateway = gateway(store.clone());
        let device = TestDevice::new(10);
        let id = enroll(&gateway, &device, 1).await;
        let stranger = TestDevice::new(11);
        let elsewhere = Nonce::from_bytes([7; 32]);
        let audited = |logs: &Logs| {
            let logs = logs.text();
            logs.lines()
                .find(|line| line.contains("ponte::audit") && line.contains("handshake_refused"))
                .map(str::to_owned)
        };

        // The token is spent: whoever sends it again has a copy of it.
        let (logs, guard) = Logs::capture();
        let mut peer = Peer::connect(&gateway);
        let nonce = peer.challenge().await;
        peer.send(text(&stranger.enroll(&nonce, &token(1))));
        closed_at_once(&mut peer).await;
        let line = audited(&logs).unwrap_or_else(|| panic!("not audited: {}", logs.text()));
        assert!(line.contains("reason=Enrollment(ExhaustedToken)"), "{line}");
        let key = format!("public_key={}", stranger.public_key());
        assert!(line.contains(&key), "{line}");
        let hash = format!("token_hash={}", TokenHash::of(&token(1)).short());
        assert!(line.contains(&hash), "{line}");
        assert!(!line.contains(&token(1).expose_hex()[..16]), "{line}");
        drop(guard);

        // The device is revoked: whoever says hello with its key has the key.
        store.revoke_device(id).await.unwrap();
        let (logs, guard) = Logs::capture();
        let mut peer = Peer::connect(&gateway);
        let nonce = peer.challenge().await;
        peer.send(text(&device.hello(&nonce, id)));
        closed_at_once(&mut peer).await;
        let line = audited(&logs).unwrap_or_else(|| panic!("not audited: {}", logs.text()));
        assert!(line.contains("reason=RevokedDevice"), "{line}");
        assert!(line.contains(&format!("device={id}")), "{line}");
        drop(guard);

        // Things anyone can send, as often as they like.
        let (logs, _guard) = Logs::capture();
        for frame in [
            Message::Text("hello?".into()),
            text(&stranger.hello(&elsewhere, id)),
            text(&stranger.hello(&elsewhere, DeviceId::new())),
            text(&stranger.enroll(&elsewhere, &token(1))),
        ] {
            let mut peer = Peer::connect(&gateway);
            peer.challenge().await;
            peer.send(frame);
            closed_at_once(&mut peer).await;
            peer.finished().await;
        }
        let mut peer = Peer::connect(&gateway);
        let nonce = peer.challenge().await;
        peer.send(text(&stranger.enroll(&nonce, &token(9))));
        closed_at_once(&mut peer).await;
        peer.finished().await;
        assert_eq!(audited(&logs), None, "{}", logs.text());
        assert!(logs.text().contains("handshake refused"), "{}", logs.text());
    }

    /// ADR-0006 keeps the session open for an agent that sends what the server cannot
    /// read. It does not owe that agent a log line for each message.
    #[tokio::test(start_paused = true)]
    async fn only_the_first_dropped_messages_of_a_session_are_logged() {
        let (gateway, store, device, id) = enrolled().await;
        let (logs, _guard) = Logs::capture();
        let peer = authenticate(&gateway, &device, id).await;

        for _ in 0..50 {
            peer.send(Message::Text("not json".into()));
            peer.send(Message::Binary(vec![0].into()));
        }
        peer.send(text(&heartbeat(1)));
        eventually("the heartbeat after the noise is recorded", || {
            store.record(id).unwrap().telemetry == Some(telemetry(1))
        })
        .await;

        let logs = logs.text();
        let dropped = logs
            .lines()
            .filter(|line| line.contains("dropped:"))
            .count();
        assert_eq!(dropped, 8, "{logs}");
        let notices = logs
            .lines()
            .filter(|line| line.contains("no longer logged"))
            .count();
        assert_eq!(notices, 1, "{logs}");
    }

    /// A machine has one agent. Someone who holds a device key and opens connection after
    /// connection gets a few of them in line for a session, and the rest are dropped
    /// before they cost a store call. No other device waits for any of it.
    #[tokio::test(start_paused = true)]
    async fn a_device_that_floods_with_connections_holds_up_only_itself() {
        let inner = store_with_token(1, 2);
        let gateway = gateway_with(Flaky::over(&inner), Limits::default());
        let device = TestDevice::new(10);
        let id = enroll_at(&gateway, &device).await;
        let other = TestDevice::new(11);
        let other_id = enroll_at(&gateway, &other).await;

        // The first connection is held inside the store. Three more line up behind it.
        gateway.store.hold_next_start.store(true, Ordering::SeqCst);
        let mut held = hello_at(&gateway, &device, id).await;
        eventually("the first session is being recorded", || {
            gateway.store.held.load(Ordering::SeqCst)
        })
        .await;
        let mut waiting = Vec::new();
        for _ in 0..3 {
            waiting.push(hello_at(&gateway, &device, id).await);
        }
        for _ in 0..100 {
            tokio::task::yield_now().await;
        }

        // Every one after that is turned away at once, however many come.
        for _ in 0..20 {
            let mut extra = hello_at(&gateway, &device, id).await;
            closed_at_once(&mut extra).await;
            extra.finished().await;
        }
        // Another device is welcomed as if nothing was going on.
        let started = Instant::now();
        let mut neighbour = hello_at(&gateway, &other, other_id).await;
        assert_eq!(
            neighbour.receive().await,
            Some(Sent::Message(ServerToAgent::Welcome {}))
        );
        assert_eq!(started.elapsed(), Duration::ZERO);

        // Once the store answers, the ones in line each get their turn, and the last one
        // to start is the one that stays.
        gateway.store.release.add_permits(1);
        let mut last = waiting.pop().unwrap();
        assert_eq!(
            last.receive().await,
            Some(Sent::Message(ServerToAgent::Welcome {}))
        );
        for peer in waiting.iter_mut().chain([&mut held]) {
            let rest = peer.rest().await;
            assert_eq!(rest.last(), Some(&Sent::Closed), "{rest:?}");
            peer.finished().await;
        }
        let session = gateway.registry.current(id);
        assert!(session.is_some());
        assert_eq!(inner.record(id).unwrap().online, session);
        assert_eq!(gateway.registry.devices_starting(), 0);

        last.finished().await;
        neighbour.finished().await;
        assert_eq!(inner.record(id).unwrap().online, None);
    }
}
