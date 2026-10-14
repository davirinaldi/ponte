//! A WebSocket client written by hand, a few lines of RFC 6455, and what the loopback
//! tests share. Writing the frames here keeps the tests free to send what a well-behaved
//! client library would refuse to.

// Each test binary uses its own part of this module.
#![allow(dead_code)]

use std::future::Future;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::time::Duration;

use chrono::{TimeDelta, Utc};
use ed25519_dalek::{Signer, SigningKey};
use ponte_protocol::{
    AgentToServer, DeviceId, EnrollmentToken, MemoryUsage, Nonce, ProtocolVersion, PublicKey,
    ServerToAgent, Signature, TelemetrySnapshot, enroll_transcript, hello_transcript,
};
use ponte_server::agents::{CustomerId, MemoryStore, TokenGrant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};

pub const CONTINUATION: u8 = 0x0;
pub const TEXT: u8 = 0x1;
pub const CLOSE: u8 = 0x8;
/// Set on the last frame of a message.
pub const FIN: u8 = 0x80;

/// One frame as a client writes it: `first` is the FIN bit and the opcode, and the payload
/// is masked.
pub fn masked(first: u8, payload: &[u8]) -> Vec<u8> {
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
pub async fn soon<T>(what: impl Future<Output = T>) -> T {
    timeout(Duration::from_secs(20), what)
        .await
        .expect("timed out")
}

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

pub fn newest() -> ProtocolVersion {
    ProtocolVersion::supported().next().unwrap()
}

/// The server's answer to an upgrade request.
pub struct Answer {
    pub status: u16,
    /// The value of `Sec-WebSocket-Protocol`, if the header is there.
    pub protocol: Option<String>,
    pub socket: Socket,
}

pub struct Socket {
    pub stream: TcpStream,
    /// Read from the stream and not consumed yet.
    pub buffered: Vec<u8>,
}

/// Asks for the upgrade, offering `offer` as the list of subprotocols.
pub async fn ask(addr: SocketAddr, offer: Option<&str>) -> Answer {
    ask_with(addr, offer, &[]).await
}

/// Asks for the upgrade with more header lines, each written as `Name: value`.
pub async fn ask_with(addr: SocketAddr, offer: Option<&str>, more: &[&str]) -> Answer {
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
    for line in more {
        request.push_str(&format!("{line}\r\n"));
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
pub async fn connect(addr: SocketAddr) -> (Socket, Nonce) {
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
    pub async fn read_more(&mut self) -> bool {
        let mut chunk = [0; 4096];
        // A reset counts as the end: the server is entitled to hang up on a rude client.
        let read = soon(self.stream.read(&mut chunk)).await.unwrap_or(0);
        self.buffered.extend(&chunk[..read]);
        read != 0
    }

    pub async fn buffer(&mut self, len: usize) -> bool {
        while self.buffered.len() < len {
            if !self.read_more().await {
                return false;
            }
        }
        true
    }

    /// The next frame as opcode and payload, or `None` at the end of the stream.
    pub async fn frame(&mut self) -> Option<(u8, Vec<u8>)> {
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

    pub async fn message(&mut self) -> ServerToAgent {
        let (opcode, payload) = self.frame().await.expect("closed instead of a message");
        assert_eq!(opcode, TEXT);
        serde_json::from_slice(&payload).unwrap()
    }

    /// Sends one whole, masked frame, as a client must.
    pub async fn send_frame(&mut self, opcode: u8, payload: &[u8]) -> std::io::Result<()> {
        soon(self.stream.write_all(&masked(FIN | opcode, payload))).await
    }

    pub async fn send_bytes(&mut self, bytes: &[u8]) {
        soon(self.stream.write_all(bytes)).await.unwrap();
    }

    pub async fn send_text(&mut self, text: &str) {
        self.send_frame(TEXT, text.as_bytes()).await.unwrap();
    }

    pub async fn send(&mut self, message: &AgentToServer) {
        self.send_text(&serde_json::to_string(message).unwrap())
            .await;
    }

    /// Every byte from here to the end of the stream, answering the server's close the way
    /// a client does.
    pub async fn rest(&mut self) -> Vec<u8> {
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

pub struct TestDevice(SigningKey);

impl TestDevice {
    pub fn new(seed: u8) -> Self {
        Self(SigningKey::from_bytes(&[seed; 32]))
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey::from_bytes(self.0.verifying_key().to_bytes())
    }

    pub fn sign(&self, bytes: &[u8]) -> Signature {
        Signature::from_bytes(self.0.sign(bytes).to_bytes())
    }

    pub fn enroll(&self, nonce: &Nonce, token: &EnrollmentToken) -> AgentToServer {
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

    pub fn hello(&self, nonce: &Nonce, device_id: DeviceId) -> AgentToServer {
        let transcript = hello_transcript(newest(), nonce, device_id);
        AgentToServer::Hello {
            device_id,
            agent_version: "0.1.0".parse().unwrap(),
            os: "Windows 11 Pro".parse().unwrap(),
            signature: self.sign(transcript.expose_bytes()),
        }
    }
}

pub fn token(seed: u8) -> EnrollmentToken {
    EnrollmentToken::from_bytes([seed; 32])
}

/// A store where `token(1)` is good for one machine for the next hour.
pub fn store_with_token() -> MemoryStore {
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

pub fn telemetry(uptime_secs: u64) -> TelemetrySnapshot {
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
pub fn heartbeat_of(uptime_secs: u64, len: usize) -> String {
    let heartbeat = serde_json::to_string(&AgentToServer::Heartbeat {
        telemetry: telemetry(uptime_secs),
    })
    .unwrap();
    format!("{heartbeat}{}", " ".repeat(len - heartbeat.len()))
}

pub async fn enroll(addr: SocketAddr, device: &TestDevice) -> DeviceId {
    let (mut socket, nonce) = connect(addr).await;
    socket.send(&device.enroll(&nonce, &token(1))).await;
    let ServerToAgent::Enrolled { device_id } = socket.message().await else {
        panic!("not enrolled");
    };
    device_id
}

pub async fn authenticate(addr: SocketAddr, device: &TestDevice, id: DeviceId) -> Socket {
    let (mut socket, nonce) = connect(addr).await;
    socket.send(&device.hello(&nonce, id)).await;
    assert_eq!(socket.message().await, ServerToAgent::Welcome {});
    socket
}

/// `uptime_secs` of the last heartbeat the store kept for the device.
pub fn uptime(store: &MemoryStore, id: DeviceId) -> Option<u64> {
    let telemetry = store.record(id).unwrap().telemetry;
    telemetry.map(|telemetry| telemetry.uptime_secs)
}

/// Waits for the server to get to what was sent.
pub async fn eventually(what: &str, done: impl Fn() -> bool) {
    for _ in 0..1_000 {
        if done() {
            return;
        }
        sleep(Duration::from_millis(10)).await;
    }
    panic!("never happened: {what}");
}
