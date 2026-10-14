//! What an agent writes to its log, with the level turned all the way up, while it
//! enrolls, holds a session and is refused.
//!
//! The agent runs on somebody else's machine and its log stays there, readable by whoever
//! administers it. It must never hold the enrollment token, the device key, or a frame:
//! `Enroll` carries the token, and what the server sends is text somebody else chose. The
//! WebSocket library logs every frame it reads and writes at `trace`, through the `log`
//! crate; the workspace is built without the bridge that would bring that here, and this
//! test fails if it ever comes back. It gets a process of its own, because the logger it
//! installs is the process-wide one, as in `main`.

// Integration-test helpers are not `#[test]` functions, so clippy.toml's
// allow-unwrap-in-tests and allow-expect-in-tests do not cover them.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ponte_server::agents::DeviceAdmin;
use tokio::time::sleep;
use tracing_subscriber::fmt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use common::{Machine, RunningAgent, eventually, fast, record, serve, store_with, token};

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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[tokio::test]
async fn ws_loopback_the_log_holds_no_token_no_key_and_no_frame_even_at_trace() {
    let captured = Captured::default();
    let writer = captured.clone();
    // No filter at all: every level of every target, ours and our dependencies'.
    tracing_subscriber::registry()
        .with(
            fmt::layer()
                .with_ansi(false)
                .with_writer(move || writer.clone()),
        )
        .try_init()
        .expect("this test is the only one in its process");

    let store = store_with(&token(0xa1));
    let addr = serve(store.clone()).await;

    // An enrollment, a session with heartbeats and pings, a revocation and the refusals
    // that follow it.
    let machine = Machine::with_token(&token(0xa1));
    let agent = RunningAgent::start(machine.config(addr), fast());
    let id = machine.online(&store).await;
    eventually("a heartbeat is stored", || {
        record(&store, id).telemetry.is_some()
    })
    .await;
    let key = machine.key_file().unwrap();
    assert!(store.revoke_device(id).await.unwrap());
    eventually("the agent was refused", || {
        captured.text().contains("did not accept this device")
    })
    .await;
    agent.stop().await;

    // A machine whose token the server does not know: refused while enrolling.
    let stranger = Machine::with_token(&token(0xb2));
    let agent = RunningAgent::start(stranger.config(addr), fast());
    eventually("the enrollment was refused", || {
        captured.text().contains("enrollment was not accepted")
    })
    .await;
    let strangers_key = stranger.key_file().unwrap();
    agent.stop().await;
    sleep(Duration::from_millis(100)).await;

    let logs = captured.text();
    // The capture works, the level is what it claims to be, and the agent did log.
    assert!(logs.contains("TRACE") || logs.contains("DEBUG"), "{logs}");
    assert!(logs.contains("ponte_agent"), "{logs}");
    assert!(
        logs.contains("enrolled: the server gave this device its id"),
        "{logs}"
    );
    assert!(logs.contains("waiting before connecting again"), "{logs}");

    for (what, secret) in [
        ("a token", token(0xa1).expose_hex()),
        ("a token", token(0xb2).expose_hex()),
        ("a device key", hex(&key)),
        ("a device key", hex(&strangers_key)),
    ] {
        assert!(!logs.contains(&secret[..16]), "{what}: {logs}");
        assert!(!logs.contains(&secret[48..]), "{what}: {logs}");
    }
    // A key or a token printed as a list of numbers.
    for bytes in [
        &key[..4],
        &strangers_key[..4],
        &[0xa1; 4][..],
        &[0xb2; 4][..],
    ] {
        let listed = format!("{bytes:?}");
        assert!(!logs.contains(listed.trim_matches(['[', ']'])), "{logs}");
    }
    for part_of_a_frame in [
        "\"type\"",
        "\"signature\"",
        "\"token\"",
        "\"telemetry\"",
        "\"nonce\"",
        "uptime_secs",
        "<FRAME>",
        "payload",
    ] {
        assert!(!logs.contains(part_of_a_frame), "{part_of_a_frame}: {logs}");
    }
    // What the libraries under the agent would say, if anything brought their logs here.
    for library in ["tungstenite", "rustls", "sysinfo", "Sec-WebSocket"] {
        assert!(!logs.contains(library), "{library}: {logs}");
    }
}
