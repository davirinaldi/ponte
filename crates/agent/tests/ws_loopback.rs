//! The agent against the real server, and against servers that misbehave, over real
//! sockets on `127.0.0.1`.
//!
//! The unit tests of the handshake and the session play the server themselves. These are
//! here for what only the real one can say: whether the signature the agent makes is the
//! one the server verifies, whether the two WebSocket libraries agree on the upgrade, and
//! whether the server answers the pings the agent's liveness check depends on.

// Integration-test helpers are not `#[test]` functions, so clippy.toml's
// allow-unwrap-in-tests and allow-expect-in-tests do not cover them.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use ponte_agent::Timing;
use ponte_protocol::{AgentToServer, ProtocolVersion, PublicKey, ServerToAgent};
use ponte_server::agents::{DeviceStatus, TokenHash};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::sleep;
use tokio_tungstenite::tungstenite::Message;

use common::{
    Machine, RunningAgent, challenge, eventually, fake_server, fast, listen, message, newest,
    record, serve, soon, store_with, token,
};

/// The whole of M1 from the agent's side: a machine with a token and nothing else ends
/// up as a device the server knows, online, with telemetry, and with no token left.
#[tokio::test]
async fn ws_loopback_a_machine_with_a_token_enrolls_connects_and_reports() {
    let store = store_with(&token(1));
    let addr = serve(store.clone()).await;
    let machine = Machine::with_token(&token(1));

    let agent = RunningAgent::start(machine.config(addr), fast());
    let id = machine.online(&store).await;

    // The server verified the signatures: of the enrollment, and of the `Hello` on the
    // second connection, both made with the key that is on this machine's disk.
    let device = record(&store, id);
    assert_eq!(device.status, DeviceStatus::Active);
    assert_eq!(Some(device.public_key), machine.public_key());
    assert_eq!(machine.state().as_deref(), Some("enrolled"));
    assert_eq!(machine.key_file().map(|key| key.len()), Some(32));
    assert_eq!(
        device.about.agent_version.as_str(),
        env!("CARGO_PKG_VERSION")
    );
    assert_ne!(device.about.os.as_str(), "");

    // The token is spent on the server and gone from the machine.
    assert_eq!(store.uses_left(&TokenHash::of(&token(1))), Some(0));
    assert!(!machine.token_file().exists());

    // Telemetry of this very machine arrives, and keeps arriving.
    eventually("a heartbeat is stored", || {
        record(&store, id).telemetry.is_some()
    })
    .await;
    let first = record(&store, id).telemetry.unwrap();
    assert!(first.uptime_secs > 0);
    assert!(first.memory.total_bytes > 0);
    eventually("a later heartbeat is stored", || {
        record(&store, id).telemetry.unwrap().collected_at > first.collected_at
    })
    .await;

    // Stopping closes the connection, and the server sees the device leave.
    assert!(agent.is_running());
    agent.stop().await;
    eventually("the device is offline", || {
        record(&store, id).online.is_none()
    })
    .await;

    // Started again, the same machine is the same device: no token, no new enrollment.
    let agent = RunningAgent::start(machine.config(addr), fast());
    assert_eq!(machine.online(&store).await, id);
    assert_eq!(Some(record(&store, id).public_key), machine.public_key());
    agent.stop().await;
}

/// The answer to `Enroll` never arrives. The server may have stored the key, so the agent
/// must come back with the same key and the same token: the server then gives the same
/// device back and no second use of the token is spent.
#[tokio::test]
async fn ws_loopback_an_enrollment_whose_answer_was_lost_is_repeated_with_the_same_key() {
    let machine = Machine::with_token(&token(1));

    // A server that takes the enrollment and hangs up without a word.
    let (seen, mut keys) = mpsc::unbounded_channel::<PublicKey>();
    let lossy = fake_server(&[&newest()], move |mut socket| {
        let seen = seen.clone();
        async move {
            socket.send(challenge()).await.unwrap();
            if let Some(AgentToServer::Enroll { public_key, .. }) = message(&mut socket).await {
                let _ = seen.send(public_key);
            }
        }
    })
    .await;
    let agent = RunningAgent::start(machine.config(lossy), fast());
    let first = soon(keys.recv()).await.unwrap();
    agent.stop().await;

    // What was sent is on disk, and the token is still there to try again with.
    assert_eq!(machine.state().as_deref(), Some("enrolling"));
    assert_eq!(machine.public_key(), Some(first));
    assert!(machine.token_file().exists());

    // The real server, which has never seen this machine.
    let store = store_with(&token(1));
    let addr = serve(store.clone()).await;
    let agent = RunningAgent::start(machine.config(addr), fast());
    let id = machine.online(&store).await;

    assert_eq!(record(&store, id).public_key, first);
    assert_eq!(machine.public_key(), Some(first));
    assert_eq!(store.uses_left(&TokenHash::of(&token(1))), Some(0));
    agent.stop().await;
}

/// A revoked device is dropped by the server and refused from then on, with no reason
/// given. The agent keeps trying, slower each time, and keeps its identity: it cannot
/// tell a revocation from a server that is having a bad day.
#[tokio::test]
async fn ws_loopback_a_revoked_device_is_dropped_and_the_agent_keeps_its_identity() {
    let store = store_with(&token(1));
    let addr = serve(store.clone()).await;
    let machine = Machine::with_token(&token(1));
    let agent = RunningAgent::start(machine.config(addr), fast());
    let id = machine.online(&store).await;
    let key = machine.key_file();

    assert!(store.revoke_device(id));
    eventually("the device is dropped", || {
        record(&store, id).online.is_none()
    })
    .await;

    sleep(Duration::from_millis(1_500)).await;
    assert!(agent.is_running());
    assert!(record(&store, id).online.is_none());
    assert_eq!(machine.device_id(), Some(id));
    assert_eq!(machine.state().as_deref(), Some("enrolled"));
    assert_eq!(machine.key_file(), key);
    agent.stop().await;
}

/// The agent's check that the server is still there rests on the server answering
/// pings, which the server's code never does itself: its WebSocket library does. With a
/// silence limit far below the time this test runs, the session survives only if those
/// answers really come.
#[tokio::test]
async fn ws_loopback_the_real_server_answers_pings_so_the_session_stays() {
    let store = store_with(&token(1));
    let addr = serve(store.clone()).await;
    let machine = Machine::with_token(&token(1));
    let timing = Timing {
        // One heartbeat when the session starts and no other: after it, pongs are the
        // only thing the server sends.
        heartbeat: Duration::from_secs(3_600),
        ping: Duration::from_millis(50),
        silence: Duration::from_millis(500),
        ..fast()
    };
    let agent = RunningAgent::start(machine.config(addr), timing);
    let id = machine.online(&store).await;
    let session = record(&store, id).online;

    sleep(Duration::from_secs(3)).await;
    assert!(session.is_some());
    assert_eq!(record(&store, id).online, session);
    agent.stop().await;
}

/// The other half: a server that welcomes the device and then stops reading answers no
/// ping. The agent gives the connection up after the silence limit and connects again.
#[tokio::test]
async fn ws_loopback_a_server_that_goes_quiet_is_given_up_and_connected_to_again() {
    // An enrolled machine, so that the fake server only has to welcome it.
    let store = store_with(&token(1));
    let addr = serve(store.clone()).await;
    let machine = Machine::with_token(&token(1));
    let agent = RunningAgent::start(machine.config(addr), fast());
    machine.online(&store).await;
    agent.stop().await;

    let welcomed = Arc::new(Mutex::new(Vec::<Instant>::new()));
    let quiet = fake_server(&[&newest()], {
        let welcomed = Arc::clone(&welcomed);
        move |mut socket| {
            let welcomed = Arc::clone(&welcomed);
            async move {
                socket.send(challenge()).await.unwrap();
                let Some(AgentToServer::Hello { .. }) = message(&mut socket).await else {
                    return;
                };
                let welcome = serde_json::to_string(&ServerToAgent::Welcome {}).unwrap();
                socket.send(Message::text(welcome)).await.unwrap();
                welcomed.lock().unwrap().push(Instant::now());
                // Holds the connection open and never reads from it again.
                tokio::spawn(async move {
                    sleep(Duration::from_secs(60)).await;
                    drop(socket);
                });
            }
        }
    })
    .await;
    let silence = Duration::from_millis(600);
    let timing = Timing {
        ping: Duration::from_millis(100),
        silence,
        ..fast()
    };
    let agent = RunningAgent::start(machine.config(quiet), timing);

    eventually("the agent connected a second time", || {
        welcomed.lock().unwrap().len() >= 2
    })
    .await;
    let welcomed = welcomed.lock().unwrap().clone();
    // Not before the limit: the first connection was held for all of it.
    assert!(welcomed[1] - welcomed[0] >= silence, "{welcomed:?}");
    agent.stop().await;
}

/// Both ends set the same limit on the socket. A server that sends more than that is cut
/// off by the agent's WebSocket layer before the message is buffered, let alone parsed,
/// and the agent connects again. Without the limit the message would be read in whole,
/// dropped as unreadable, and the session would go on.
#[tokio::test]
async fn ws_loopback_a_message_over_the_size_limit_ends_the_connection() {
    let store = store_with(&token(1));
    let addr = serve(store.clone()).await;
    let machine = Machine::with_token(&token(1));
    let agent = RunningAgent::start(machine.config(addr), fast());
    machine.online(&store).await;
    agent.stop().await;

    let connections = Arc::new(AtomicUsize::new(0));
    let loud = fake_server(&[&newest()], {
        let connections = Arc::clone(&connections);
        move |mut socket| {
            let connections = Arc::clone(&connections);
            async move {
                socket.send(challenge()).await.unwrap();
                let Some(AgentToServer::Hello { .. }) = message(&mut socket).await else {
                    return;
                };
                let welcome = serde_json::to_string(&ServerToAgent::Welcome {}).unwrap();
                socket.send(Message::text(welcome)).await.unwrap();
                connections.fetch_add(1, Ordering::SeqCst);
                let too_large = "x".repeat(ponte_protocol::MAX_MESSAGE_BYTES + 1);
                let _ = socket.send(Message::text(too_large)).await;
                // Keeps reading, so pings are answered and nothing else ends the session.
                tokio::spawn(async move { while let Some(Ok(_)) = socket.next().await {} });
            }
        }
    })
    .await;
    let agent = RunningAgent::start(machine.config(loud), fast());

    eventually("the agent left and connected again", || {
        connections.load(Ordering::SeqCst) >= 2
    })
    .await;
    agent.stop().await;
}

/// ADR-0007: without a version the server selected out of the ones offered there is no
/// connection. The agent leaves before it says anything, so the token never reaches a
/// server it has not agreed on a protocol with.
#[tokio::test]
async fn ws_loopback_an_upgrade_that_selects_no_offered_version_gets_no_message() {
    let newest = newest();
    let both_in_one = format!("{newest}, {newest}");
    let selections: [&[&str]; 6] = [
        &[],
        &["mqtt"],
        &["ponte.v0"],
        // The library only looks at the first of these, and lets it through.
        &[&newest, &newest],
        &[&newest, "mqtt"],
        &[&both_in_one],
    ];
    for select in selections {
        let machine = Machine::with_token(&token(1));
        let (seen, mut connections) = mpsc::unbounded_channel::<Option<AgentToServer>>();
        let server = fake_server(select, move |mut socket| {
            let seen = seen.clone();
            async move {
                let _ = socket.send(challenge()).await;
                let _ = seen.send(message(&mut socket).await);
            }
        })
        .await;
        let agent = RunningAgent::start(machine.config(server), fast());

        let said = soon(connections.recv()).await.unwrap();
        assert!(said.is_none(), "{select:?}: the agent sent {said:?}");
        assert!(agent.is_running(), "{select:?}");
        assert!(machine.token_file().exists(), "{select:?}");
        assert_eq!(machine.state().as_deref(), Some("enrolling"), "{select:?}");
        agent.stop().await;
    }
}

/// A listener that answers every request with `answer` and closes. Returns its address,
/// how many connections it got, and the head of each request.
async fn http_server(answer: String) -> (SocketAddr, Arc<AtomicUsize>, Arc<Mutex<Vec<String>>>) {
    let (listener, addr) = listen().await;
    let connections = Arc::new(AtomicUsize::new(0));
    let requests = Arc::new(Mutex::new(Vec::new()));
    tokio::spawn({
        let (connections, requests) = (Arc::clone(&connections), Arc::clone(&requests));
        async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                connections.fetch_add(1, Ordering::SeqCst);
                let mut head = Vec::new();
                while !head.windows(4).any(|window| window == b"\r\n\r\n") {
                    let mut chunk = [0; 1024];
                    match stream.read(&mut chunk).await {
                        Ok(read) if read > 0 => head.extend(&chunk[..read]),
                        _ => break,
                    }
                }
                requests
                    .lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&head).into_owned());
                let _ = stream.write_all(answer.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
        }
    });
    (addr, connections, requests)
}

/// The server refuses upgrades with 503 while too many handshakes are open and with 400
/// when no version matches. Both are failed connections: the agent waits and comes back.
/// A redirect is one too, and is never followed: the token goes to the server the
/// configuration names and to no other.
#[tokio::test]
async fn ws_loopback_a_refused_upgrade_is_a_failed_connection_and_the_agent_comes_back() {
    let (elsewhere, visits, _) = http_server("HTTP/1.1 200 OK\r\n\r\n".to_owned()).await;
    for answer in [
        "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n".to_owned(),
        "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n".to_owned(),
        format!(
            "HTTP/1.1 302 Found\r\nLocation: ws://{elsewhere}/agent\r\nContent-Length: 0\r\n\r\n"
        ),
        format!("HTTP/1.1 301 Moved Permanently\r\nLocation: http://{elsewhere}/\r\n\r\n"),
        "nonsense\r\n\r\n".to_owned(),
        String::new(),
    ] {
        let machine = Machine::with_token(&token(1));
        let (addr, connections, _) = http_server(answer.clone()).await;
        let agent = RunningAgent::start(machine.config(addr), fast());

        eventually("the agent came back", || {
            connections.load(Ordering::SeqCst) >= 2
        })
        .await;
        assert!(agent.is_running(), "{answer:?}");
        assert!(machine.token_file().exists(), "{answer:?}");
        agent.stop().await;
    }
    assert_eq!(visits.load(Ordering::SeqCst), 0);
}

/// What the agent asks for when it connects. The server refuses any request that names
/// an `Origin`, and picks the version out of `Sec-WebSocket-Protocol`.
#[tokio::test]
async fn ws_loopback_the_upgrade_request_offers_the_versions_and_names_no_origin() {
    let machine = Machine::with_token(&token(1));
    let (addr, _, requests) =
        http_server("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n".to_owned()).await;
    let agent = RunningAgent::start(machine.config(addr), fast());
    eventually("a request arrived", || !requests.lock().unwrap().is_empty()).await;
    agent.stop().await;

    let request = requests.lock().unwrap()[0].to_lowercase();
    let offer: Vec<String> = ProtocolVersion::supported()
        .map(ProtocolVersion::subprotocol)
        .collect();
    assert!(request.starts_with("get /agent http/1.1\r\n"), "{request}");
    assert!(
        request.contains(&format!(
            "\r\nsec-websocket-protocol: {}\r\n",
            offer.join(", ")
        )),
        "{request}"
    );
    assert!(!request.contains("origin"), "{request}");
    // Nothing of the machine's secrets or identity is in a request anyone can read.
    assert!(!request.contains(&token(1).expose_hex()), "{request}");
    assert!(!request.contains("authorization"), "{request}");
    assert!(!request.contains("cookie"), "{request}");
}

/// A machine with nothing to connect with does not connect and does not give up. When
/// the installer brings a token, the agent finds it by itself.
#[tokio::test]
async fn ws_loopback_an_agent_without_a_token_waits_for_one() {
    let store = store_with(&token(1));
    let addr = serve(store.clone()).await;
    let machine = Machine::new();
    let agent = RunningAgent::start(machine.config(addr), fast());

    sleep(Duration::from_millis(300)).await;
    assert!(agent.is_running());
    assert_eq!(machine.identity(), None);
    assert_eq!(machine.key_file(), None);

    machine.put_token(&token(1));
    let id = machine.online(&store).await;
    assert_eq!(record(&store, id).status, DeviceStatus::Active);
    agent.stop().await;
}

/// A token the server does not know. The agent is refused like everyone else, with no
/// reason, and keeps the key and the token for the next attempt.
#[tokio::test]
async fn ws_loopback_a_token_the_server_refuses_leaves_the_agent_waiting() {
    let store = store_with(&token(1));
    let addr = serve(store.clone()).await;
    let machine = Machine::with_token(&token(2));
    let agent = RunningAgent::start(machine.config(addr), fast());

    eventually("the enrollment was started", || machine.state().is_some()).await;
    let key = machine.key_file();
    sleep(Duration::from_millis(1_500)).await;

    assert!(agent.is_running());
    assert_eq!(machine.state().as_deref(), Some("enrolling"));
    assert_eq!(machine.key_file(), key);
    assert!(machine.token_file().exists());
    assert_eq!(store.uses_left(&TokenHash::of(&token(1))), Some(1));
    agent.stop().await;
}

/// Nobody listening at all: the plainest failed connection.
#[tokio::test]
async fn ws_loopback_a_server_that_is_not_there_is_tried_again() {
    let (listener, addr) = listen().await;
    drop(listener);
    let machine = Machine::with_token(&token(1));
    let agent = RunningAgent::start(machine.config(addr), fast());

    sleep(Duration::from_millis(1_500)).await;
    assert!(agent.is_running());
    assert_eq!(machine.state().as_deref(), Some("enrolling"));
    agent.stop().await;
}
