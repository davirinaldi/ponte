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
    AgentToServer, DeviceId, MemoryUsage, ProtocolVersion, ServerToAgent, TelemetrySnapshot,
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
