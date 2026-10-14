//! What the loopback tests share: a real server on `127.0.0.1`, an agent running against
//! it with short waits, and the agent's files.

// Each test binary uses its own part of this module.
#![allow(dead_code)]

use std::future::Future;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use chrono::{TimeDelta, Utc};
use futures_util::StreamExt;
use ponte_agent::{AgentConfig, Timing};
use ponte_protocol::{
    AgentToServer, DeviceId, EnrollmentToken, Nonce, ProtocolVersion, PublicKey, ServerToAgent,
};
use ponte_server::agents::{CustomerId, DeviceRecord, MemoryStore, TokenGrant};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::{WebSocketStream, accept_hdr_async};

/// Nothing here should take long. A test that waits this much is stuck.
pub async fn soon<T>(what: impl Future<Output = T>) -> T {
    timeout(Duration::from_secs(30), what)
        .await
        .expect("timed out")
}

/// Waits for something that happens in another task.
pub async fn eventually(what: &str, done: impl Fn() -> bool) {
    for _ in 0..3_000 {
        if done() {
            return;
        }
        sleep(Duration::from_millis(10)).await;
    }
    panic!("never happened: {what}");
}

/// A directory of its own under the system's temporary one, removed when dropped.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new() -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let name = format!(
            "ponte-agent-loopback-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let path = std::env::temp_dir().join(name);
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn token(seed: u8) -> EnrollmentToken {
    EnrollmentToken::from_bytes([seed; 32])
}

/// A store where `token` is good for one machine for the next hour.
pub fn store_with(token: &EnrollmentToken) -> MemoryStore {
    let store = MemoryStore::new();
    store.add_token(
        token,
        TokenGrant {
            customer: CustomerId::new(),
            expires_at: Utc::now() + TimeDelta::hours(1),
            max_uses: NonZeroU32::MIN,
        },
    );
    store
}

/// The real server, over `store`, on a port of its own.
pub async fn serve(store: MemoryStore) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, ponte_server::router_with(store))
            .await
            .unwrap();
    });
    addr
}

/// The files of one machine: its data directory and where its token file goes.
pub struct Machine {
    dir: TempDir,
}

impl Machine {
    pub fn new() -> Self {
        Self {
            dir: TempDir::new(),
        }
    }

    pub fn with_token(token: &EnrollmentToken) -> Self {
        let machine = Self::new();
        machine.put_token(token);
        machine
    }

    pub fn data_dir(&self) -> PathBuf {
        self.dir.path().join("data")
    }

    pub fn token_file(&self) -> PathBuf {
        self.dir.path().join("enrollment-token")
    }

    pub fn put_token(&self, token: &EnrollmentToken) {
        std::fs::write(self.token_file(), format!("{}\n", token.expose_hex())).unwrap();
    }

    /// The configuration of an agent on this machine that connects to `server`.
    pub fn config(&self, server: SocketAddr) -> AgentConfig {
        // Literal strings: a Windows path is full of backslashes.
        format!(
            "server_url = 'ws://{server}/agent'\ndata_dir = '{}'\nenrollment_token_file = '{}'\n",
            self.data_dir().display(),
            self.token_file().display(),
        )
        .parse()
        .unwrap()
    }

    /// What `identity.toml` says, if it is there.
    pub fn identity(&self) -> Option<toml::Table> {
        let text = std::fs::read_to_string(self.data_dir().join("identity.toml")).ok()?;
        Some(text.parse().unwrap())
    }

    fn identity_field(&self, name: &str) -> Option<String> {
        Some(self.identity()?.get(name)?.as_str()?.to_owned())
    }

    /// `enrolling` or `enrolled`.
    pub fn state(&self) -> Option<String> {
        self.identity_field("state")
    }

    pub fn device_id(&self) -> Option<DeviceId> {
        let id = self.identity_field("device_id")?;
        Some(serde_json::from_value(serde_json::Value::String(id)).unwrap())
    }

    pub fn public_key(&self) -> Option<PublicKey> {
        Some(self.identity_field("public_key")?.parse().unwrap())
    }

    /// The 32 secret bytes of the device key.
    pub fn key_file(&self) -> Option<Vec<u8>> {
        std::fs::read(self.data_dir().join("device.key")).ok()
    }

    /// Waits until the agent on this machine is enrolled and connected, and returns its id.
    pub async fn online(&self, store: &MemoryStore) -> DeviceId {
        eventually("the device is enrolled and online", || {
            self.device_id()
                .and_then(|id| store.record(id))
                .is_some_and(|record| record.online.is_some())
        })
        .await;
        self.device_id().unwrap()
    }
}

pub fn record(store: &MemoryStore, id: DeviceId) -> DeviceRecord {
    store
        .record(id)
        .expect("the store does not know the device")
}

/// Waits that are right for a test: everything a real agent does in a minute happens in
/// a fraction of a second, and nothing gives up early on a slow machine.
pub fn fast() -> Timing {
    Timing {
        heartbeat: Duration::from_millis(100),
        ping: Duration::from_millis(100),
        close: Duration::from_millis(500),
        ..Timing::default()
    }
}

/// An agent running in a task of this test.
pub struct RunningAgent {
    stop: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl RunningAgent {
    pub fn start(config: AgentConfig, timing: Timing) -> Self {
        let (stop, stopped) = oneshot::channel::<()>();
        let task = tokio::spawn(ponte_agent::run_with(config, timing, async move {
            let _ = stopped.await;
        }));
        Self {
            stop: Some(stop),
            task,
        }
    }

    /// Whether the agent is still running. It should be until it is told to stop.
    pub fn is_running(&self) -> bool {
        !self.task.is_finished()
    }

    /// Tells the agent to stop and waits until it has.
    pub async fn stop(mut self) {
        drop(self.stop.take());
        soon(&mut self.task).await.unwrap();
    }
}

pub fn nonce() -> Nonce {
    Nonce::from_bytes([0x5a; 32])
}

pub fn challenge() -> Message {
    let challenge = ServerToAgent::Challenge { nonce: nonce() };
    Message::text(serde_json::to_string(&challenge).unwrap())
}

pub async fn listen() -> (TcpListener, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    (listener, addr)
}

pub fn newest() -> String {
    ProtocolVersion::supported().next().unwrap().subprotocol()
}

/// A WebSocket server that answers every upgrade by selecting `select`, one header per
/// name, whatever was offered, and then hands the connection to `then`.
pub async fn fake_server<F, Fut>(select: &[&str], then: F) -> SocketAddr
where
    F: Fn(WebSocketStream<TcpStream>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send,
{
    fake_server_on(listen().await, select, then)
}

/// [`fake_server`] on a listener of the caller's.
// The signature of the callback is the library's: it is the one that makes the error large.
#[allow(clippy::result_large_err)]
pub fn fake_server_on<F, Fut>(
    (listener, addr): (TcpListener, SocketAddr),
    select: &[&str],
    then: F,
) -> SocketAddr
where
    F: Fn(WebSocketStream<TcpStream>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send,
{
    let select: Vec<String> = select.iter().map(|name| (*name).to_owned()).collect();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let select = select.clone();
            let callback = move |_: &Request, mut response: Response| {
                for name in &select {
                    response
                        .headers_mut()
                        .append("sec-websocket-protocol", name.parse().unwrap());
                }
                Ok::<_, ErrorResponse>(response)
            };
            if let Ok(socket) = accept_hdr_async(stream, callback).await {
                then(socket).await;
            }
        }
    });
    addr
}

/// The next message the agent sends on `socket`, if it sends one before it leaves.
pub async fn message(socket: &mut WebSocketStream<TcpStream>) -> Option<AgentToServer> {
    loop {
        match timeout(Duration::from_secs(10), socket.next()).await {
            Ok(Some(Ok(Message::Text(text)))) => {
                return Some(serde_json::from_str(text.as_str()).unwrap());
            }
            Ok(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => {}
            _ => return None,
        }
    }
}
