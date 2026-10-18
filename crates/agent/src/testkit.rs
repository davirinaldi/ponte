//! Shared by the unit tests of this crate: a temporary directory, the server's end of a
//! connection that has no socket under it, and fixed values.

use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::task::{Context, Poll};

use futures_util::{Sink, Stream, stream};
use ponte_protocol::{
    ActionRequest, AgentToServer, DeviceId, Initiator, MemoryUsage, ProtocolVersion, PublicKey,
    RequestId, ServerToAgent, Signature, SignedManifest, TelemetrySnapshot,
};
use tokio::sync::mpsc;

use crate::handshake::About;
use crate::telemetry::Collect;
use crate::wire::Message;

/// A directory of its own under the system's temporary one, removed when dropped.
pub(crate) struct TempDir(PathBuf);

impl TempDir {
    pub(crate) fn new() -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let name = format!(
            "ponte-agent-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let path = std::env::temp_dir().join(name);
        // Left by an earlier run that had the same process id.
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The version every test connection negotiated.
pub(crate) fn version() -> ProtocolVersion {
    ProtocolVersion::supported().next().unwrap()
}

pub(crate) fn device_id() -> DeviceId {
    serde_json::from_str("\"00112233-4455-6677-8899-aabbccddeeff\"").unwrap()
}

/// A request whose envelope has the right shape and a signature that verifies against
/// nothing: enough for tests where the agent refuses before looking at it.
pub(crate) fn action_request(request_id: RequestId) -> ActionRequest {
    ActionRequest {
        request_id,
        manifest: SignedManifest {
            manifest: include_str!("../../../manifests/examples/erp-restart-service.toml")
                .parse()
                .unwrap(),
            issued_at: 1_767_225_600,
            expires_at: 1_774_998_000,
            public_key: PublicKey::from_bytes([0x22; 32]),
            signature: Signature::from_bytes([0x33; 64]),
        },
        expires_at: 1_767_229_200,
        initiator: Initiator::Human {
            user_id: "u1".parse().unwrap(),
        },
    }
}

pub(crate) fn about() -> About {
    About {
        agent_version: "0.1.0".parse().unwrap(),
        os: "Windows 11 Pro".parse().unwrap(),
    }
}

/// What the agent did to its end of a connection.
#[derive(Debug, PartialEq)]
pub(crate) enum Sent {
    Frame(Message),
    Closed,
}

/// The agent's sink: everything it sends reaches the [`Peer`].
pub(crate) struct RecordingSink(mpsc::UnboundedSender<Sent>);

impl Sink<Message> for RecordingSink {
    type Error = Infallible;

    fn poll_ready(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, frame: Message) -> Result<(), Infallible> {
        let _ = self.0.send(Sent::Frame(frame));
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        let _ = self.0.send(Sent::Closed);
        Poll::Ready(Ok(()))
    }
}

/// A sink that never takes a frame, like a connection whose other end stopped reading.
pub(crate) struct StuckSink;

pub(crate) fn stuck_sink() -> StuckSink {
    StuckSink
}

impl Sink<Message> for StuckSink {
    type Error = Infallible;

    fn poll_ready(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Pending
    }

    fn start_send(self: Pin<&mut Self>, _: Message) -> Result<(), Infallible> {
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Pending
    }

    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Pending
    }
}

pub(crate) type AgentStream = Pin<Box<dyn Stream<Item = Result<Message, Infallible>> + Send>>;

/// The server's end of a connection, played by the test.
pub(crate) struct Peer {
    to_agent: Option<mpsc::UnboundedSender<Message>>,
    from_agent: mpsc::UnboundedReceiver<Sent>,
}

/// A connection with no socket: the peer, and the two halves the agent's code runs on.
pub(crate) fn pipe() -> (Peer, AgentStream, RecordingSink) {
    let (to_agent, mut inbox) = mpsc::unbounded_channel::<Message>();
    let (outbox, from_agent) = mpsc::unbounded_channel();
    let stream = stream::poll_fn(move |cx| inbox.poll_recv(cx).map(|frame| frame.map(Ok)));
    let peer = Peer {
        to_agent: Some(to_agent),
        from_agent,
    };
    (peer, Box::pin(stream), RecordingSink(outbox))
}

impl Peer {
    pub(crate) fn send_frame(&self, frame: Message) {
        if let Some(to_agent) = &self.to_agent {
            // The agent may be gone already. A real server cannot tell either.
            let _ = to_agent.send(frame);
        }
    }

    pub(crate) fn send(&self, message: &ServerToAgent) {
        self.send_frame(Message::text(serde_json::to_string(message).unwrap()));
    }

    /// Ends the stream without a close frame, like a connection that dropped.
    pub(crate) fn hang_up(&mut self) {
        self.to_agent = None;
    }

    /// The next thing the agent does, or `None` once it let go of the connection.
    pub(crate) async fn next(&mut self) -> Option<Sent> {
        self.from_agent.recv().await
    }

    /// The next thing the agent does, which must be a message.
    pub(crate) async fn message(&mut self) -> AgentToServer {
        match self.next().await {
            Some(Sent::Frame(Message::Text(text))) => serde_json::from_str(text.as_str()).unwrap(),
            other => panic!("expected a message, got {other:?}"),
        }
    }

    /// Everything the agent sent that was not read yet, without waiting for more.
    pub(crate) fn sent_so_far(&mut self) -> Vec<Sent> {
        std::iter::from_fn(|| self.from_agent.try_recv().ok()).collect()
    }
}

/// A snapshot that says which reading it is: `uptime_secs` counts them from 1.
pub(crate) fn telemetry(reading: u64) -> TelemetrySnapshot {
    TelemetrySnapshot {
        collected_at: "2026-01-01T00:00:00Z".parse().unwrap(),
        uptime_secs: reading,
        cpu_percent: 1.5,
        memory: MemoryUsage {
            total_bytes: 2,
            used_bytes: 1,
        },
        disks: Vec::new(),
        services: Vec::new(),
    }
}

/// A collector that takes no time, counts its readings, and can be made to fail.
#[derive(Clone, Default)]
pub(crate) struct FakeCollector {
    readings: Arc<AtomicU64>,
    failing: Arc<AtomicBool>,
}

impl FakeCollector {
    pub(crate) fn readings(&self) -> u64 {
        self.readings.load(Ordering::Relaxed)
    }

    pub(crate) fn fail(&self, failing: bool) {
        self.failing.store(failing, Ordering::Relaxed);
    }
}

impl Collect for FakeCollector {
    async fn snapshot(&self) -> Option<TelemetrySnapshot> {
        let reading = self.readings.fetch_add(1, Ordering::Relaxed) + 1;
        (!self.failing.load(Ordering::Relaxed)).then(|| telemetry(reading))
    }
}

/// Clocks the test sets by hand: the wall clock, which it may move either way, and the
/// monotonic one, which only [`FakeClock::advance`] moves.
#[derive(Clone)]
pub(crate) struct FakeClock(Arc<std::sync::Mutex<(std::time::Duration, std::time::Duration)>>);

impl FakeClock {
    /// Wall clock at `secs` since the Unix epoch, monotonic clock at zero.
    pub(crate) fn at(secs: u64) -> Self {
        Self(Arc::new(std::sync::Mutex::new((
            std::time::Duration::from_secs(secs),
            std::time::Duration::ZERO,
        ))))
    }

    /// Sets the wall clock, as an administrator or a time sync would.
    pub(crate) fn set_wall(&self, secs: u64) {
        self.0.lock().unwrap().0 = std::time::Duration::from_secs(secs);
    }

    /// Lets time pass on both clocks.
    pub(crate) fn advance(&self, by: std::time::Duration) {
        let mut clocks = self.0.lock().unwrap();
        clocks.0 = clocks.0.saturating_add(by);
        clocks.1 = clocks.1.saturating_add(by);
    }
}

impl crate::actions::clock::Clock for FakeClock {
    fn wall_secs(&self) -> u64 {
        self.0.lock().unwrap().0.as_secs()
    }

    fn monotonic(&self) -> std::time::Duration {
        self.0.lock().unwrap().1
    }
}

/// A clock mark kept in memory.
#[derive(Clone, Default)]
pub(crate) struct MemoryMark(pub(crate) Arc<std::sync::Mutex<Option<String>>>);

impl MemoryMark {
    pub(crate) fn set(&self, text: Option<String>) {
        *self.0.lock().unwrap() = text;
    }
}

impl crate::actions::clock::MarkDisk for MemoryMark {
    fn read_mark(&self) -> std::io::Result<Option<String>> {
        Ok(self.0.lock().unwrap().clone())
    }

    fn write_mark(&self, text: &str) -> std::io::Result<()> {
        self.set(Some(text.to_owned()));
        Ok(())
    }
}

/// Everything logged on this thread, and by the blocking tasks it hands its dispatcher to,
/// while the capture lives.
pub(crate) struct LogCapture {
    text: Arc<std::sync::Mutex<Vec<u8>>>,
    _guard: tracing::subscriber::DefaultGuard,
    _second: tracing::Dispatch,
}

#[derive(Clone)]
struct CaptureWriter(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for CaptureWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl LogCapture {
    pub(crate) fn start() -> Self {
        use tracing_subscriber::layer::SubscriberExt;

        let text = Arc::new(std::sync::Mutex::new(Vec::new()));
        let writer = CaptureWriter(Arc::clone(&text));
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(move || writer.clone()),
        );
        let guard = tracing::subscriber::set_default(subscriber);
        // With a single dispatcher registered, `tracing-core` asks the default of whichever
        // thread first reaches a callsite, and a test running beside this one, with no
        // subscriber, would turn this one's events off. A second one makes it ask all.
        let second = tracing::Dispatch::new(tracing_subscriber::registry());
        Self {
            text,
            _guard: guard,
            _second: second,
        }
    }

    pub(crate) fn text(&self) -> String {
        String::from_utf8_lossy(&self.text.lock().unwrap()).into_owned()
    }
}

/// The public key of the manifest signing key made from `seed`, in hex.
pub(crate) fn manifest_key_hex(seed: u8) -> String {
    let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    PublicKey::from_bytes(key.verifying_key().to_bytes()).to_string()
}
