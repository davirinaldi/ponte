//! What the server process writes to its log while agents connect over a real socket, with
//! the log level turned all the way up.
//!
//! The tests in `src/agents` read the logs of the server's own code. This one is here for
//! the code that is not ours: the WebSocket library logs every frame it reads at `trace`,
//! through the `log` crate, and an `Enroll` frame holds a token. It gets a process of its
//! own, because the logger it installs is the process-wide one, as in `main`.

// Integration-test helpers are not `#[test]` functions, so clippy.toml's
// allow-unwrap-in-tests and allow-expect-in-tests do not cover them.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::io;
use std::sync::{Arc, Mutex};

use ponte_protocol::ServerToAgent;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{Layer, fmt};

use common::{
    CLOSE, TestDevice, authenticate, connect, heartbeat_of, serve, store_with_token, token,
};

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Captured {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

impl io::Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Someone debugging a connection problem sets `RUST_LOG=trace`. That must not turn the
/// log into a copy of every frame: tokens, and whatever a stranger chose to send.
#[tokio::test]
async fn ws_loopback_logs_no_frame_even_at_trace() {
    let captured = Captured::default();
    let writer = captured.clone();
    // The same setup as `main`, with the output kept instead of printed.
    let layer = fmt::layer()
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .with_filter(ponte_server::log_filter(Some("trace")));
    tracing_subscriber::registry()
        .with(layer)
        .try_init()
        .expect("this test is the only one in its process");

    let store = store_with_token();
    let addr = serve(store.clone()).await;
    let device = TestDevice::new(10);

    // An enrollment: the frame with the token.
    let (mut socket, nonce) = connect(addr).await;
    socket.send(&device.enroll(&nonce, &token(1))).await;
    let ServerToAgent::Enrolled { device_id } = socket.message().await else {
        panic!("not enrolled");
    };
    socket.rest().await;

    // A session, a heartbeat, and a close frame with text in it.
    let mut socket = authenticate(addr, &device, device_id).await;
    socket.send_text(&heartbeat_of(1, 300)).await;
    let mut close = 1000_u16.to_be_bytes().to_vec();
    close.extend(b"stranger-wrote-this-reason");
    socket.send_frame(CLOSE, &close).await.unwrap();
    socket.rest().await;

    // A stranger: a frame that is no message, then a close frame with text.
    let (mut socket, _) = connect(addr).await;
    socket.send_text("stranger-wrote-this-frame").await;
    socket.rest().await;
    let (mut socket, _) = connect(addr).await;
    let mut close = 1000_u16.to_be_bytes().to_vec();
    close.extend(b"stranger-wrote-this-reason");
    socket.send_frame(CLOSE, &close).await.unwrap();
    socket.rest().await;

    common::eventually("the session is over", || {
        store.record(device_id).unwrap().online.is_none()
            && captured.text().contains("session_ended")
    })
    .await;

    let logs = captured.text();
    // The capture works and the level is what it claims to be.
    assert!(logs.contains("device_enrolled"), "{logs}");
    assert!(logs.contains("DEBUG") || logs.contains("TRACE"), "{logs}");

    let secret = token(1).expose_hex();
    assert!(!logs.contains(&secret[..16]), "a token: {logs}");
    assert!(
        !logs.contains("stranger-wrote-this"),
        "a stranger's text: {logs}"
    );
    for part_of_a_frame in ["\"type\"", "\"signature\"", "\"telemetry\"", "uptime_secs"] {
        assert!(!logs.contains(part_of_a_frame), "{part_of_a_frame}: {logs}");
    }
}
