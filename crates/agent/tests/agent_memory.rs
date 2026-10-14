//! What a server that stops reading can do to the agent's memory.
//!
//! Each ping the agent reads is a pong it owes, and a pong that cannot be written waits.
//! Without a limit on what waits, the memory of the agent grows as fast as the server can
//! send pings, on a machine with little of it to spare (RNF-12). The test measures the
//! memory of its own process, so it gets a process of its own: other tests running beside
//! it would move the number.

// Integration-test helpers are not `#[test]` functions, so clippy.toml's
// allow-unwrap-in-tests and allow-expect-in-tests do not cover them.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use futures_util::SinkExt;
use ponte_agent::Timing;
use ponte_protocol::{AgentToServer, ServerToAgent};
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};
use tokio::time::sleep;
use tokio_tungstenite::tungstenite::Message;

use common::{
    Machine, RunningAgent, challenge, eventually, fake_server_on, fast, listen_with_a_small_window,
    message, newest, serve, store_with, token,
};

/// The resident memory of this process, in bytes.
fn memory() -> u64 {
    let pid = sysinfo::get_current_pid().unwrap();
    let mut system = System::new();
    system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[pid]),
        true,
        ProcessRefreshKind::nothing().with_memory(),
    );
    system.process(pid).unwrap().memory()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ws_loopback_a_server_that_floods_pings_and_reads_nothing_does_not_fill_the_memory() {
    // An enrolled machine, so that the server below only has to welcome it.
    let store = store_with(&token(1));
    let addr = serve(store.clone()).await;
    let machine = Machine::with_token(&token(1));
    let agent = RunningAgent::start(machine.config(addr), fast());
    machine.online(&store).await;
    agent.stop().await;

    let welcomed = Arc::new(AtomicBool::new(false));
    let pings = Arc::new(AtomicU64::new(0));
    let flood = fake_server_on(listen_with_a_small_window(), &[&newest()], {
        let (welcomed, pings) = (Arc::clone(&welcomed), Arc::clone(&pings));
        move |mut socket| {
            let (welcomed, pings) = (Arc::clone(&welcomed), Arc::clone(&pings));
            async move {
                socket.send(challenge()).await.unwrap();
                let Some(AgentToServer::Hello { .. }) = message(&mut socket).await else {
                    return;
                };
                let welcome = serde_json::to_string(&ServerToAgent::Welcome {}).unwrap();
                socket.send(Message::text(welcome)).await.unwrap();
                welcomed.store(true, Ordering::SeqCst);
                // Pings as fast as they go out, and not one read.
                tokio::spawn(async move {
                    while socket.send(Message::Ping(Vec::new().into())).await.is_ok() {
                        pings.fetch_add(1, Ordering::Relaxed);
                    }
                });
            }
        }
    });
    // Nothing of the agent's own ends the session while the test measures: it only reads.
    let hour = Duration::from_secs(3_600);
    let timing = Timing {
        heartbeat: hour,
        ping: hour,
        silence: hour,
        send: hour,
        ..fast()
    };
    let agent = RunningAgent::start(machine.config(flood), timing);
    eventually("the agent was welcomed", || welcomed.load(Ordering::SeqCst)).await;

    // Past the sizes of the sockets' own buffers, where the pongs start to wait.
    sleep(Duration::from_secs(1)).await;
    let (before, pings_before) = (memory(), pings.load(Ordering::Relaxed));
    sleep(Duration::from_secs(8)).await;
    let (after, pings_after) = (memory(), pings.load(Ordering::Relaxed));
    agent.stop().await;

    let read = pings_after - pings_before;
    let grown = after.saturating_sub(before);
    eprintln!("{read} pings read, memory grew by {} KiB", grown / 1024);
    // Every ping read and not answered would be six bytes waiting. The flood has to be
    // large enough for that to show, or the test says nothing. Measured on Windows in a
    // debug build: some 500 000 pings in those eight seconds, and 2.5 MB more memory
    // without the limit, none with it.
    assert!(read > 150_000, "only {read} pings: the flood is too small");
    assert!(
        grown < 3 * read / 2,
        "memory grew by {grown} bytes while {read} pings were read"
    );
}
