//! The agent endpoint over a real socket on 127.0.0.1: the upgrade, the subprotocol and the
//! frames as they are on the wire. Everything else about a connection is tested without a
//! socket, next to the code in `src/agents`.
//!
//! The client here is written by hand, a few lines of RFC 6455. That keeps the tests free
//! to send what a well-behaved client library would refuse to.

// Integration-test helpers are not `#[test]` functions, so clippy.toml's
// allow-unwrap-in-tests and allow-expect-in-tests do not cover them.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::future::Future;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::time::Duration;

use chrono::{TimeDelta, Utc};
use ed25519_dalek::{Signer, SigningKey};
use ponte_protocol::{
    AgentToServer, DeviceId, EnrollmentToken, MAX_MESSAGE_BYTES, MemoryUsage, Nonce,
    ProtocolVersion, PublicKey, ServerToAgent, Signature, TelemetrySnapshot, enroll_transcript,
    hello_transcript,
};
use ponte_server::agents::{CustomerId, DeviceStatus, MemoryStore, TokenGrant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};

const CONTINUATION: u8 = 0x0;
const TEXT: u8 = 0x1;
const CLOSE: u8 = 0x8;
/// Set on the last frame of a message.
const FIN: u8 = 0x80;

/// One frame as a client writes it: `first` is the FIN bit and the opcode, and the payload
/// is masked.
fn masked(first: u8, payload: &[u8]) -> Vec<u8> {
    const MASK: [u8; 4] = [0x3a, 0x51, 0xc4, 0x0e];
    let mut frame = vec![first];
    match payload.len() {
        len if len < 126 => frame.push(0x80 | u8::try_from(len).unwrap()),
        len if len <= usize::from(u16::MAX) => {
            frame.push(0x80 | 126);
            frame.extend(u16::try_from(len).unwrap().to_be_bytes());
        }
        len => {
            frame.push(0x80 | 127);
            frame.extend(u64::try_from(len).unwrap().to_be_bytes());
        }
    }
    frame.extend(MASK);
    frame.extend(payload.iter().zip(MASK.iter().cycle()).map(|(b, m)| b ^ m));
    frame
}

/// Nothing here should take long. A test that waits this much is stuck.
async fn soon<T>(what: impl Future<Output = T>) -> T {
    timeout(Duration::from_secs(20), what)
        .await
        .expect("timed out")
}

async fn serve(store: MemoryStore) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, ponte_server::router_with(store))
            .await
            .unwrap();
    });
    addr
}

fn newest() -> ProtocolVersion {
    ProtocolVersion::supported().next().unwrap()
}

/// The server's answer to an upgrade request.
struct Answer {
    status: u16,
    /// The value of `Sec-WebSocket-Protocol`, if the header is there.
    protocol: Option<String>,
    socket: Socket,
}

struct Socket {
    stream: TcpStream,
    /// Read from the stream and not consumed yet.
    buffered: Vec<u8>,
}

/// Asks for the upgrade, offering `offer` as the list of subprotocols.
async fn ask(addr: SocketAddr, offer: Option<&str>) -> Answer {
    let mut request = format!(
        "GET /agent HTTP/1.1\r\n\
         Host: {addr}\r\n\
         Connection: Upgrade\r\n\
         Upgrade: websocket\r\n\
         Sec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    );
    if let Some(offer) = offer {
        request.push_str(&format!("Sec-WebSocket-Protocol: {offer}\r\n"));
    }
    request.push_str("\r\n");

    let mut stream = soon(TcpStream::connect(addr)).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut socket = Socket {
        stream,
        buffered: Vec::new(),
    };

    let end = loop {
        if let Some(end) = socket
            .buffered
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
        {
            break end + 4;
        }
        assert!(socket.read_more().await, "closed before answering");
    };
    let head = String::from_utf8(socket.buffered.drain(..end).collect()).unwrap();
    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|line| line.split(' ').nth(1))
        .unwrap()
        .parse()
        .unwrap();
    let protocol = lines.find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("sec-websocket-protocol")
            .then(|| value.trim().to_owned())
    });
    Answer {
        status,
        protocol,
        socket,
    }
}

/// Opens a connection that negotiated the newest version and returns it with the nonce of
/// its challenge.
async fn connect(addr: SocketAddr) -> (Socket, Nonce) {
    let answer = ask(addr, Some(&newest().subprotocol())).await;
    assert_eq!(answer.status, 101);
    let mut socket = answer.socket;
    let ServerToAgent::Challenge { nonce } = socket.message().await else {
        panic!("the first message is not a challenge");
    };
    (socket, nonce)
}

impl Socket {
    /// Returns `false` at the end of the stream.
    async fn read_more(&mut self) -> bool {
        let mut chunk = [0; 4096];
        // A reset counts as the end: the server is entitled to hang up on a rude client.
        let read = soon(self.stream.read(&mut chunk)).await.unwrap_or(0);
        self.buffered.extend(&chunk[..read]);
        read != 0
    }

    async fn buffer(&mut self, len: usize) -> bool {
        while self.buffered.len() < len {
            if !self.read_more().await {
                return false;
            }
        }
        true
    }

    /// The next frame as opcode and payload, or `None` at the end of the stream.
    async fn frame(&mut self) -> Option<(u8, Vec<u8>)> {
        if !self.buffer(2).await {
            assert!(self.buffered.is_empty(), "the stream ended inside a frame");
            return None;
        }
        let (first, second) = (self.buffered[0], self.buffered[1]);
        assert_eq!(first & 0xf0, 0x80, "fragmented, or with reserved bits");
        assert_eq!(second & 0x80, 0, "a server does not mask");
        let (header, len) = match second {
            126 => {
                assert!(self.buffer(4).await);
                let len = u16::from_be_bytes([self.buffered[2], self.buffered[3]]);
                (4, usize::from(len))
            }
            127 => panic!("a frame larger than anything the server sends"),
            len => (2, usize::from(len)),
        };
        assert!(self.buffer(header + len).await);
        let frame: Vec<u8> = self.buffered.drain(..header + len).collect();
        Some((first & 0x0f, frame[header..].to_vec()))
    }

    async fn message(&mut self) -> ServerToAgent {
        let (opcode, payload) = self.frame().await.expect("closed instead of a message");
        assert_eq!(opcode, TEXT);
        serde_json::from_slice(&payload).unwrap()
    }

    /// Sends one whole, masked frame, as a client must.
    async fn send_frame(&mut self, opcode: u8, payload: &[u8]) -> std::io::Result<()> {
        soon(self.stream.write_all(&masked(FIN | opcode, payload))).await
    }

    async fn send_bytes(&mut self, bytes: &[u8]) {
        soon(self.stream.write_all(bytes)).await.unwrap();
    }

    async fn send_text(&mut self, text: &str) {
        self.send_frame(TEXT, text.as_bytes()).await.unwrap();
    }

    async fn send(&mut self, message: &AgentToServer) {
        self.send_text(&serde_json::to_string(message).unwrap())
            .await;
    }

    /// Every byte from here to the end of the stream, answering the server's close the way
    /// a client does.
    async fn rest(&mut self) -> Vec<u8> {
        let mut rest = Vec::new();
        while let Some((opcode, payload)) = self.frame().await {
            rest.push(0x80 | opcode);
            rest.push(u8::try_from(payload.len()).unwrap());
            rest.extend(payload);
            if opcode == CLOSE {
                // The server may be gone already, and then there is nobody to tell.
                let _ = self.send_frame(CLOSE, &[]).await;
            }
        }
        rest
    }
}

struct TestDevice(SigningKey);

impl TestDevice {
    fn new(seed: u8) -> Self {
        Self(SigningKey::from_bytes(&[seed; 32]))
    }

    fn public_key(&self) -> PublicKey {
        PublicKey::from_bytes(self.0.verifying_key().to_bytes())
    }

    fn sign(&self, bytes: &[u8]) -> Signature {
        Signature::from_bytes(self.0.sign(bytes).to_bytes())
    }

    fn enroll(&self, nonce: &Nonce, token: &EnrollmentToken) -> AgentToServer {
        let public_key = self.public_key();
        let transcript = enroll_transcript(newest(), nonce, token, &public_key);
        AgentToServer::Enroll {
            token: token.clone(),
            public_key,
            agent_version: "0.1.0".parse().unwrap(),
            os: "Windows 11 Pro".parse().unwrap(),
            signature: self.sign(transcript.expose_bytes()),
        }
    }

    fn hello(&self, nonce: &Nonce, device_id: DeviceId) -> AgentToServer {
        let transcript = hello_transcript(newest(), nonce, device_id);
        AgentToServer::Hello {
            device_id,
            agent_version: "0.1.0".parse().unwrap(),
            os: "Windows 11 Pro".parse().unwrap(),
            signature: self.sign(transcript.expose_bytes()),
        }
    }
}

fn token(seed: u8) -> EnrollmentToken {
    EnrollmentToken::from_bytes([seed; 32])
}

/// A store where `token(1)` is good for one machine for the next hour.
fn store_with_token() -> MemoryStore {
    let store = MemoryStore::new();
    store.add_token(
        &token(1),
        TokenGrant {
            customer: CustomerId::new(),
            expires_at: Utc::now() + TimeDelta::hours(1),
            max_uses: NonZeroU32::MIN,
        },
    );
    store
}

fn telemetry(uptime_secs: u64) -> TelemetrySnapshot {
    TelemetrySnapshot {
        collected_at: Utc::now(),
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

/// A heartbeat that is valid JSON of exactly `len` bytes.
fn heartbeat_of(uptime_secs: u64, len: usize) -> String {
    let heartbeat = serde_json::to_string(&AgentToServer::Heartbeat {
        telemetry: telemetry(uptime_secs),
    })
    .unwrap();
    format!("{heartbeat}{}", " ".repeat(len - heartbeat.len()))
}

async fn enroll(addr: SocketAddr, device: &TestDevice) -> DeviceId {
    let (mut socket, nonce) = connect(addr).await;
    socket.send(&device.enroll(&nonce, &token(1))).await;
    let ServerToAgent::Enrolled { device_id } = socket.message().await else {
        panic!("not enrolled");
    };
    device_id
}

async fn authenticate(addr: SocketAddr, device: &TestDevice, id: DeviceId) -> Socket {
    let (mut socket, nonce) = connect(addr).await;
    socket.send(&device.hello(&nonce, id)).await;
    assert_eq!(socket.message().await, ServerToAgent::Welcome {});
    socket
}

/// `uptime_secs` of the last heartbeat the store kept for the device.
fn uptime(store: &MemoryStore, id: DeviceId) -> Option<u64> {
    let telemetry = store.record(id).unwrap().telemetry;
    telemetry.map(|telemetry| telemetry.uptime_secs)
}

/// Waits for the server to get to what was sent.
async fn eventually(what: &str, done: impl Fn() -> bool) {
    for _ in 0..1_000 {
        if done() {
            return;
        }
        sleep(Duration::from_millis(10)).await;
    }
    panic!("never happened: {what}");
}

/// ADR-0007: the server picks the newest version both sides speak and says which.
#[tokio::test]
async fn ws_loopback_picks_the_newest_version_in_common() {
    let addr = serve(MemoryStore::new()).await;
    let ours = newest().subprotocol();

    for offer in [
        ours.clone(),
        format!("ponte.v65535, {ours}"),
        format!("mqtt,{ours},ponte.v0"),
        format!("  {ours}  "),
    ] {
        let mut answer = ask(addr, Some(&offer)).await;
        assert_eq!(answer.status, 101, "{offer:?}");
        assert_eq!(answer.protocol.as_deref(), Some(ours.as_str()), "{offer:?}");
        // The server speaks first.
        let first = answer.socket.message().await;
        assert!(
            matches!(first, ServerToAgent::Challenge { .. }),
            "{first:?}"
        );
    }

    // Newest first, whatever the order of the offer.
    let all: Vec<String> = ProtocolVersion::supported()
        .map(ProtocolVersion::subprotocol)
        .collect();
    let oldest_first: Vec<&str> = all.iter().rev().map(String::as_str).collect();
    let answer = ask(addr, Some(&oldest_first.join(", "))).await;
    assert_eq!(answer.protocol, Some(ours));
}

/// ADR-0007: with no version in common there is no connection. An upgrade that went
/// through without a subprotocol would leave both sides guessing the shape of every message.
#[tokio::test]
async fn ws_loopback_refuses_the_upgrade_without_a_version_in_common() {
    let addr = serve(MemoryStore::new()).await;

    for offer in [
        None,
        Some(""),
        Some("mqtt"),
        Some("ponte.v0"),
        Some("ponte.v65535"),
        Some("PONTE.V1"),
        Some("ponte.v1.1"),
        Some("ponte.v01"),
        Some("ponte"),
    ] {
        let mut answer = ask(addr, offer).await;
        assert_eq!(answer.status, 400, "{offer:?}");
        assert_eq!(answer.protocol, None, "{offer:?}");

        // And it stayed HTTP: no challenge follows.
        answer.socket.stream.shutdown().await.unwrap();
        while answer.socket.read_more().await {}
        let body = String::from_utf8_lossy(&answer.socket.buffered);
        assert!(!body.contains("challenge"), "{offer:?}: {body}");
    }
}

/// The whole of M1's server side on a real socket: enroll, come back, send heartbeats.
#[tokio::test]
async fn ws_loopback_enrolls_then_authenticates_and_sends_heartbeats() {
    let store = store_with_token();
    let addr = serve(store.clone()).await;
    let device = TestDevice::new(10);

    // Enrolling ends the connection.
    let (mut socket, nonce) = connect(addr).await;
    socket.send(&device.enroll(&nonce, &token(1))).await;
    let ServerToAgent::Enrolled { device_id } = socket.message().await else {
        panic!("not enrolled");
    };
    assert_eq!(socket.rest().await, [0x80 | CLOSE, 0]);
    let record = store.record(device_id).unwrap();
    assert_eq!(record.status, DeviceStatus::Active);
    assert_eq!(record.public_key, device.public_key());
    assert_eq!(record.online, None);

    let mut socket = authenticate(addr, &device, device_id).await;
    assert!(store.record(device_id).unwrap().online.is_some());
    for uptime in [1, 2] {
        let heartbeat = AgentToServer::Heartbeat {
            telemetry: telemetry(uptime),
        };
        socket.send(&heartbeat).await;
        eventually("the heartbeat is recorded", || {
            let telemetry = store.record(device_id).unwrap().telemetry;
            telemetry.is_some_and(|telemetry| telemetry.uptime_secs == uptime)
        })
        .await;
    }

    socket.send_frame(CLOSE, &[]).await.unwrap();
    eventually("the device goes offline", || {
        store.record(device_id).unwrap().online.is_none()
    })
    .await;
}

/// On the wire, byte for byte: a refused handshake gets a close frame with no code and no
/// text, whatever was wrong with it. An accepted enrollment ends with the same bytes.
#[tokio::test]
async fn ws_loopback_closes_every_refused_handshake_with_the_same_bytes() {
    let store = store_with_token();
    let addr = serve(store.clone()).await;
    let device = TestDevice::new(10);
    let id = enroll(addr, &device).await;
    let stranger = TestDevice::new(11);

    type Frame<'a> = Box<dyn Fn(&Nonce) -> String + 'a>;
    let json = |message: AgentToServer| serde_json::to_string(&message).unwrap();
    let refused: Vec<(&str, Frame<'_>)> = vec![
        ("not json", Box::new(|_| "hello?".to_owned())),
        (
            "unknown device",
            Box::new(|nonce| json(device.hello(nonce, DeviceId::new()))),
        ),
        (
            "wrong key",
            Box::new(|nonce| json(stranger.hello(nonce, id))),
        ),
        (
            "an answer to another challenge",
            Box::new(|_| json(device.hello(&Nonce::from_bytes([7; 32]), id))),
        ),
        (
            "unknown token",
            Box::new(|nonce| json(stranger.enroll(nonce, &token(2)))),
        ),
        (
            "spent token",
            Box::new(|nonce| json(stranger.enroll(nonce, &token(1)))),
        ),
        ("a heartbeat", Box::new(|_| heartbeat_of(1, 200))),
    ];

    for (case, frame) in refused {
        let (mut socket, nonce) = connect(addr).await;
        socket.send_text(&frame(&nonce)).await;
        assert_eq!(socket.rest().await, [0x80 | CLOSE, 0], "{case}");
    }
    assert!(store.record(id).unwrap().online.is_none());
}

/// A message may take all of `MAX_MESSAGE_BYTES`, and a frame that announces more is
/// refused by its header alone. The server never waits for, or buffers, the rest of it:
/// left at its default the socket would take 16 MiB a frame from anyone.
#[tokio::test]
async fn ws_loopback_refuses_a_frame_over_the_size_limit_without_reading_it() {
    let store = store_with_token();
    let addr = serve(store.clone()).await;
    let device = TestDevice::new(10);
    let id = enroll(addr, &device).await;

    // Exactly at the limit is fine.
    let mut socket = authenticate(addr, &device, id).await;
    socket.send_text(&heartbeat_of(1, MAX_MESSAGE_BYTES)).await;
    eventually("the largest heartbeat is recorded", || {
        uptime(&store, id) == Some(1)
    })
    .await;

    // One byte more: the header and the start of the payload are enough to be refused.
    let over = masked(
        FIN | TEXT,
        heartbeat_of(2, MAX_MESSAGE_BYTES + 1).as_bytes(),
    );
    socket.stream.write_all(&over[..64]).await.unwrap();
    let rest = socket.rest().await;
    assert!(rest.len() <= 125, "the server answered with a message");
    eventually("the device goes offline", || {
        store.record(id).unwrap().online.is_none()
    })
    .await;
    assert_eq!(uptime(&store, id), Some(1));
}

/// The limit is on the message, not only on each frame: small frames that add up to more
/// are refused as well. Left at its default the socket would take 64 MiB a message.
#[tokio::test]
async fn ws_loopback_refuses_fragments_that_add_up_over_the_size_limit() {
    let store = store_with_token();
    let addr = serve(store.clone()).await;
    let device = TestDevice::new(10);
    let id = enroll(addr, &device).await;
    let mut socket = authenticate(addr, &device, id).await;

    // A message in two frames is fine in itself.
    let heartbeat = heartbeat_of(1, 400);
    let (start, end) = heartbeat.as_bytes().split_at(200);
    socket.send_bytes(&masked(TEXT, start)).await;
    socket.send_bytes(&masked(FIN | CONTINUATION, end)).await;
    eventually("the heartbeat in two frames is recorded", || {
        uptime(&store, id) == Some(1)
    })
    .await;

    // Each frame within the limit, the two together one byte over it.
    let heartbeat = heartbeat_of(2, MAX_MESSAGE_BYTES + 1);
    let (start, end) = heartbeat.as_bytes().split_at(MAX_MESSAGE_BYTES);
    socket.send_bytes(&masked(TEXT, start)).await;
    // The server may hang up before the second frame is written.
    let _ = socket
        .stream
        .write_all(&masked(FIN | CONTINUATION, end))
        .await;
    let rest = socket.rest().await;
    assert!(rest.len() <= 125, "the server answered with a message");
    eventually("the device goes offline", || {
        store.record(id).unwrap().online.is_none()
    })
    .await;
    assert_eq!(uptime(&store, id), Some(1));
}
