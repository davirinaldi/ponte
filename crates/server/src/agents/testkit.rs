//! Shared by the tests of this module: a device with a real key, a connection without a
//! socket, captured logs and fixed values.

use std::convert::Infallible;
use std::io;
use std::num::NonZeroU32;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use axum::extract::ws::Message;
use chrono::{DateTime, TimeDelta, Utc};
use ed25519_dalek::{Signer, SigningKey};
use futures_util::{Sink, stream};
use ponte_actions::TrustedKeys;
use ponte_protocol::{
    AgentToServer, DeviceId, EnrollmentToken, MemoryUsage, Nonce, ProtocolVersion, PublicKey,
    ServerToAgent, Signature, SignedManifest, TelemetrySnapshot, Transcript, enroll_transcript,
    hello_transcript, manifest_transcript,
};

use super::store::actions::{ActionStore, CatalogEntry};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{Layer, fmt};

use super::store::{AgentInfo, CustomerId, MemoryStore, TokenGrant};
use super::{Gateway, Limits, session};

/// The version every test connection negotiated.
pub(crate) fn version() -> ProtocolVersion {
    ProtocolVersion::supported().next().unwrap()
}

/// A fixed instant plus `secs` seconds.
pub(crate) fn at(secs: i64) -> DateTime<Utc> {
    "2026-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap() + TimeDelta::seconds(secs)
}

pub(crate) fn token(seed: u8) -> EnrollmentToken {
    EnrollmentToken::from_bytes([seed; 32])
}

pub(crate) fn about() -> AgentInfo {
    AgentInfo {
        agent_version: "0.1.0".parse().unwrap(),
        os: "Windows 11 Pro".parse().unwrap(),
    }
}

/// Snapshots with different `uptime_secs` are different snapshots.
pub(crate) fn telemetry(uptime_secs: u64) -> TelemetrySnapshot {
    TelemetrySnapshot {
        collected_at: at(0),
        uptime_secs,
        cpu_percent: 1.5,
        memory: MemoryUsage {
            total_bytes: 2,
            used_bytes: 1,
        },
        disks: Vec::new(),
        services: Vec::new(),
    }
}

/// The example that restarts the ERP: a manifest every rule of `validate_shape` accepts.
const RESTART: &str = include_str!("../../../../manifests/examples/erp-restart-service.toml");

/// A key that signs manifests, as `ponte-sign` holds one.
pub(crate) fn manifest_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed.wrapping_add(100); 32])
}

pub(crate) fn manifest_public(seed: u8) -> PublicKey {
    PublicKey::from_bytes(manifest_key(seed).verifying_key().to_bytes())
}

/// The example manifest under another id and version.
pub(crate) fn manifest_text(id: &str, version: u32) -> String {
    RESTART
        .replacen("id = \"erp.restart-service\"", &format!("id = \"{id}\""), 1)
        .replacen("version = 1", &format!("version = {version}"), 1)
}

/// An envelope signed by `manifest_key(key_seed)`, issued at `issued_at` and valid for 90
/// days, as `ponte-sign` writes it.
pub(crate) fn envelope(key_seed: u8, text: &str, issued_at: DateTime<Utc>) -> SignedManifest {
    let issued_at = u64::try_from(issued_at.timestamp()).unwrap();
    let mut signed = SignedManifest {
        manifest: text.parse().unwrap(),
        issued_at,
        expires_at: issued_at + 90 * 24 * 60 * 60,
        public_key: manifest_public(key_seed),
        signature: Signature::from_bytes([0; 64]),
    };
    let signature = manifest_key(key_seed).sign(manifest_transcript(&signed).expose_bytes());
    signed.signature = Signature::from_bytes(signature.to_bytes());
    signed
}

/// `id` v`version`, signed by `manifest_key(key_seed)` `issued` seconds after `at(0)`
/// minus an hour, and verified at `at(0)` against that key alone.
pub(crate) fn catalog_entry(key_seed: u8, id: &str, version: u32, issued: i64) -> CatalogEntry {
    let signed = envelope(key_seed, &manifest_text(id, version), at(issued - 3600));
    let keys = TrustedKeys::new([manifest_public(key_seed)]).unwrap();
    let now = u64::try_from(at(0).timestamp()).unwrap();
    CatalogEntry::verify(signed, &keys, now).unwrap()
}

/// The agent's side of the handshake, with a real ed25519 key.
pub(crate) struct TestDevice(SigningKey);

impl TestDevice {
    pub(crate) fn new(seed: u8) -> Self {
        Self::from_secret([seed; 32])
    }

    pub(crate) fn from_secret(secret: [u8; 32]) -> Self {
        Self(SigningKey::from_bytes(&secret))
    }

    pub(crate) fn public_key(&self) -> PublicKey {
        PublicKey::from_bytes(self.0.verifying_key().to_bytes())
    }

    pub(crate) fn sign(&self, transcript: &Transcript) -> Signature {
        Signature::from_bytes(self.0.sign(transcript.expose_bytes()).to_bytes())
    }

    /// A correct answer to `Challenge { nonce }` from a machine that holds `token`.
    pub(crate) fn enroll(&self, nonce: &Nonce, token: &EnrollmentToken) -> AgentToServer {
        let public_key = self.public_key();
        let transcript = enroll_transcript(version(), nonce, token, &public_key);
        AgentToServer::Enroll {
            token: token.clone(),
            public_key,
            agent_version: about().agent_version,
            os: about().os,
            signature: self.sign(&transcript),
        }
    }

    /// What the device enrolled as `device_id` answers to `Challenge { nonce }`. Signed with
    /// this key, whether or not it is the one `device_id` enrolled with.
    pub(crate) fn hello(&self, nonce: &Nonce, device_id: DeviceId) -> AgentToServer {
        AgentToServer::Hello {
            device_id,
            agent_version: about().agent_version,
            os: about().os,
            signature: self.sign(&hello_transcript(version(), nonce, device_id)),
        }
    }
}

pub(crate) fn grant(max_uses: u32) -> TokenGrant {
    TokenGrant {
        customer: CustomerId::new(),
        expires_at: at(100),
        max_uses: NonZeroU32::new(max_uses).unwrap(),
    }
}

/// A store where `token(token_seed)` is good for `max_uses` machines until `at(100)`.
pub(crate) fn store_with_token(token_seed: u8, max_uses: u32) -> MemoryStore {
    let store = MemoryStore::new();
    store.add_token(&token(token_seed), grant(max_uses));
    store
}

/// A gateway whose clock stands still at `at(0)`.
pub(crate) fn gateway_with<D>(store: D, limits: Limits) -> Arc<Gateway<D>> {
    Arc::new(Gateway {
        clock: || at(0),
        ..Gateway::new(store, limits)
    })
}

pub(crate) fn gateway(store: MemoryStore) -> Arc<Gateway<MemoryStore>> {
    gateway_with(store, Limits::default())
}

/// What the server did to its end of a connection.
#[derive(Debug, PartialEq)]
pub(crate) enum Sent {
    Message(ServerToAgent),
    /// The server closed the connection. Nothing comes with it: a close has no reason.
    Closed,
}

/// Records what the server sends. With `stall_after`, it takes that many messages and then
/// never another one, like a peer that stopped reading.
struct RecordingSink {
    sent: mpsc::UnboundedSender<Sent>,
    stall_after: Option<usize>,
}

impl Sink<Message> for RecordingSink {
    type Error = Infallible;

    fn poll_ready(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        if self.stall_after == Some(0) {
            // Never woken: the peer never reads again.
            return Poll::Pending;
        }
        Poll::Ready(Ok(()))
    }

    fn start_send(mut self: Pin<&mut Self>, frame: Message) -> Result<(), Infallible> {
        let Message::Text(text) = frame else {
            panic!("the server sent a frame that is not text: {frame:?}");
        };
        // Parsed with the agent's own strict types: whatever the server sends, an agent
        // must be able to read.
        let message = serde_json::from_str(text.as_str()).unwrap();
        let _ = self.sent.send(Sent::Message(message));
        if let Some(left) = self.stall_after.as_mut() {
            *left = left.saturating_sub(1);
        }
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        let _ = self.sent.send(Sent::Closed);
        Poll::Ready(Ok(()))
    }
}

/// The agent's end of a connection that has no socket under it.
pub(crate) struct Peer {
    to_server: Option<mpsc::UnboundedSender<Message>>,
    from_server: mpsc::UnboundedReceiver<Sent>,
    task: JoinHandle<()>,
}

impl Peer {
    /// Opens a connection that negotiated [`version`] and runs the server's side of it.
    pub(crate) fn connect<D: ActionStore>(gateway: &Arc<Gateway<D>>) -> Self {
        Self::connect_with(gateway, None)
    }

    /// Like [`Peer::connect`], for a peer that reads `messages` messages and then never
    /// another one.
    pub(crate) fn connect_stalling<D: ActionStore>(
        gateway: &Arc<Gateway<D>>,
        messages: usize,
    ) -> Self {
        Self::connect_with(gateway, Some(messages))
    }

    fn connect_with<D: ActionStore>(gateway: &Arc<Gateway<D>>, stall_after: Option<usize>) -> Self {
        let (to_server, mut inbox) = mpsc::unbounded_channel::<Message>();
        let (outbox, from_server) = mpsc::unbounded_channel();
        let stream = stream::poll_fn(move |cx| {
            inbox
                .poll_recv(cx)
                .map(|frame| frame.map(Ok::<_, Infallible>))
        });
        let permit = gateway.admit().expect("no place left for a connection");
        let gateway = Arc::clone(gateway);
        let sink = RecordingSink {
            sent: outbox,
            stall_after,
        };
        let task = tokio::spawn(async move {
            session::run(&gateway, version(), stream, sink, permit).await;
        });
        Self {
            to_server: Some(to_server),
            from_server,
            task,
        }
    }

    pub(crate) fn send(&self, frame: Message) {
        if let Some(to_server) = &self.to_server {
            // The server may have stopped reading already. A real peer cannot tell either.
            let _ = to_server.send(frame);
        }
    }

    /// The next thing the server does, or `None` once it let go of the connection.
    pub(crate) async fn receive(&mut self) -> Option<Sent> {
        self.from_server.recv().await
    }

    /// The first message of every connection.
    pub(crate) async fn challenge(&mut self) -> Nonce {
        match self.receive().await {
            Some(Sent::Message(ServerToAgent::Challenge { nonce })) => nonce,
            other => panic!("expected a challenge, got {other:?}"),
        }
    }

    /// Everything the server still does on this connection. Like an agent, this end
    /// leaves once the server closes.
    pub(crate) async fn rest(&mut self) -> Vec<Sent> {
        let mut rest = Vec::new();
        while let Some(sent) = self.receive().await {
            if sent == Sent::Closed {
                self.to_server = None;
            }
            rest.push(sent);
        }
        rest
    }

    /// Leaves, and waits until the server is done with the connection.
    pub(crate) async fn finished(&mut self) {
        self.to_server = None;
        (&mut self.task).await.unwrap();
    }
}

/// Makes every test's captured log see every event of its own thread.
///
/// Each test captures with a subscriber of its own thread (`set_default`). `tracing` keeps,
/// per log line in the code, whether any subscriber wants it, and recomputes that whenever
/// a subscriber comes or goes; with tests starting and ending on other threads at the same
/// moment, it can settle on "nobody" for a while, and a test that looks for an audit line
/// misses it now and then (seen on Linux). A global subscriber that answers "sometimes"
/// for every line, and keeps nothing, makes "nobody" impossible: every event is then
/// offered to its thread's subscriber.
fn ask_every_subscriber() {
    use tracing::span::{Attributes, Id, Record};
    use tracing::subscriber::Interest;
    use tracing::{Event, Metadata, Subscriber};

    struct Sometimes;

    impl Subscriber for Sometimes {
        fn register_callsite(&self, _: &'static Metadata<'static>) -> Interest {
            Interest::sometimes()
        }

        fn enabled(&self, _: &Metadata<'_>) -> bool {
            false
        }

        fn new_span(&self, _: &Attributes<'_>) -> Id {
            Id::from_u64(1)
        }

        fn record(&self, _: &Id, _: &Record<'_>) {}

        fn record_follows_from(&self, _: &Id, _: &Id) {}

        fn event(&self, _: &Event<'_>) {}

        fn enter(&self, _: &Id) {}

        fn exit(&self, _: &Id) {}
    }

    static ONCE: std::sync::Once = std::sync::Once::new();
    // Another test binary's global subscriber, if any, stays: it is set once per process.
    ONCE.call_once(|| {
        let _ = tracing::subscriber::set_global_default(Sometimes);
    });
}

/// Everything logged on this thread while the guard lives.
#[derive(Clone, Default)]
pub(crate) struct Logs(Arc<Mutex<Vec<u8>>>);

impl Logs {
    /// Everything, down to `trace`.
    pub(crate) fn capture() -> (Self, tracing::subscriber::DefaultGuard) {
        Self::capture_with(Some("trace"))
    }

    /// What the server's own filter lets through when `RUST_LOG` is `directives`.
    pub(crate) fn capture_with(
        directives: Option<&str>,
    ) -> (Self, tracing::subscriber::DefaultGuard) {
        ask_every_subscriber();
        let logs = Self::default();
        let writer = logs.clone();
        let layer = fmt::layer()
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .with_filter(crate::log_filter(directives));
        let subscriber = tracing_subscriber::registry().with(layer);
        (logs, tracing::subscriber::set_default(subscriber))
    }

    pub(crate) fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

impl io::Write for Logs {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
