//! The agent endpoint over a real socket on 127.0.0.1: the upgrade, the subprotocol and the
//! frames as they are on the wire. Everything else about a connection is tested without a
//! socket, next to the code in `src/agents`.
//!
//! The client is in `common`.

// Integration-test helpers are not `#[test]` functions, so clippy.toml's
// allow-unwrap-in-tests and allow-expect-in-tests do not cover them.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use ponte_protocol::{
    AgentToServer, DeviceId, MAX_MESSAGE_BYTES, Nonce, ProtocolVersion, ServerToAgent,
};
use ponte_server::agents::{DeviceStatus, MemoryStore};
use tokio::io::AsyncWriteExt;

use common::{
    CLOSE, CONTINUATION, FIN, TEXT, TestDevice, ask, ask_with, authenticate, connect, enroll,
    eventually, heartbeat_of, masked, newest, serve, store_with_token, telemetry, token, uptime,
};

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

/// Agents are not web pages. A request that names an origin comes from a browser, where any
/// site could open sockets to this endpoint from its visitors' machines.
#[tokio::test]
async fn ws_loopback_refuses_a_request_from_a_browser() {
    let addr = serve(MemoryStore::new()).await;
    let ours = newest().subprotocol();

    for origin in ["Origin: https://example.com", "Origin: null", "origin:"] {
        let answer = ask_with(addr, Some(&ours), &[origin]).await;
        assert_eq!(answer.status, 403, "{origin:?}");
        assert_eq!(answer.protocol, None, "{origin:?}");
    }
    assert_eq!(
        ask_with(addr, Some(&ours), &["X-Other: 1"]).await.status,
        101
    );
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
