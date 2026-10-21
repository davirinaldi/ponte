//! The sweep and the sessions together, without a socket and with a paused clock: what
//! reaches an agent, what comes back, and what the log says about it.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::Message;
use chrono::{DateTime, Utc};
use ponte_protocol::{
    ActionOutcome, ActionRequest, ActionResult, AgentToServer, DeviceId, Initiator, Output,
    RejectReason, RequestId, ServerToAgent,
};

use super::*;
use crate::agents::Limits;
use crate::agents::session::RESULTS_PER_MINUTE;
use crate::agents::store::actions::{
    ActionAdmin, CatalogEntry, NewRequest, RequestOutcome, RequestState,
};
use crate::agents::store::MemoryStore;
use crate::agents::testkit::{
    Logs, Peer, Sent, TestDevice, at, catalog_entry, gateway_with, grant, manifest_public,
    telemetry, token,
};

type TestGateway = Arc<Gateway<MemoryStore>>;

fn text(message: &AgentToServer) -> Message {
    Message::Text(serde_json::to_string(message).unwrap().into())
}

/// A gateway whose clock stands still at `now`.
fn gateway_at(store: &MemoryStore, now: fn() -> DateTime<Utc>) -> TestGateway {
    Arc::new(Gateway {
        clock: now,
        ..Gateway::new(store.clone(), Limits::default())
    })
}

/// Lets the server's tasks run until `done` holds.
async fn eventually(what: &str, done: impl Fn() -> bool) {
    for _ in 0..1_000 {
        if done() {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("never happened: {what}");
}

/// Enrolls `device` with `token(seed)`, a token for one machine, so the device is active.
async fn enroll(
    gateway: &TestGateway,
    store: &MemoryStore,
    device: &TestDevice,
    seed: u8,
) -> DeviceId {
    store.add_token(&token(seed), grant(1));
    let mut peer = Peer::connect(gateway);
    let nonce = peer.challenge().await;
    peer.send(text(&device.enroll(&nonce, &token(seed))));
    let Some(Sent::Message(ServerToAgent::Enrolled { device_id })) = peer.receive().await else {
        panic!("not enrolled");
    };
    peer.finished().await;
    device_id
}

async fn authenticate(gateway: &TestGateway, device: &TestDevice, id: DeviceId) -> Peer {
    let mut peer = Peer::connect(gateway);
    let nonce = peer.challenge().await;
    peer.send(text(&device.hello(&nonce, id)));
    assert_eq!(
        peer.receive().await,
        Some(Sent::Message(ServerToAgent::Welcome {}))
    );
    peer
}

/// Trusts key 1 and adds `erp.restart-service` v1 signed by it.
async fn catalog(store: &MemoryStore) -> CatalogEntry {
    store
        .add_signing_key(manifest_public(1), at(0))
        .await
        .unwrap();
    let entry = catalog_entry(1, "erp.restart-service", 1, 0);
    store.add_manifest(&entry, at(0)).await.unwrap();
    entry
}

/// Queues `entry` for `device`, expiring an hour after `at(0)`.
async fn ask(store: &MemoryStore, device: DeviceId, entry: &CatalogEntry) -> RequestId {
    let id = RequestId::new();
    let request = NewRequest {
        id,
        device,
        manifest: *entry.hash(),
        expires_at: u64::try_from(at(3600).timestamp()).unwrap(),
        initiator: Initiator::Human {
            user_id: "server_cli".parse().unwrap(),
        },
    };
    let queued = store.request_action(&request, at(0)).await.unwrap();
    assert_eq!(queued, RequestOutcome::Queued);
    id
}

async fn state(store: &MemoryStore, id: RequestId) -> RequestState {
    store.request(id).await.unwrap().unwrap().state
}

/// The next message, which must be a request.
async fn run_action(peer: &mut Peer) -> Box<ActionRequest> {
    match peer.receive().await {
        Some(Sent::Message(ServerToAgent::RunAction(request))) => request,
        other => panic!("expected a request, got {other:?}"),
    }
}

fn result(id: RequestId, outcome: ActionOutcome) -> AgentToServer {
    AgentToServer::ActionResult(ActionResult {
        request_id: id,
        outcome,
        output: None,
        duration_ms: 1500,
    })
}

/// One active device, connected, and the catalog.
struct Connected {
    gateway: TestGateway,
    store: MemoryStore,
    device: TestDevice,
    id: DeviceId,
    peer: Peer,
    entry: CatalogEntry,
}

async fn connected() -> Connected {
    let store = MemoryStore::new();
    let gateway = gateway_with(store.clone(), Limits::default());
    let device = TestDevice::new(10);
    let id = enroll(&gateway, &store, &device, 1).await;
    let peer = authenticate(&gateway, &device, id).await;
    let entry = catalog(&store).await;
    Connected {
        gateway,
        store,
        device,
        id,
        peer,
        entry,
    }
}

/// ADR-0012: the sweep claims a request and its session writes it, signed envelope and
/// all, as the agent will read it.
#[tokio::test(start_paused = true)]
async fn the_sweep_hands_a_due_request_to_its_session() {
    let Connected {
        gateway,
        store,
        id,
        mut peer,
        entry,
        ..
    } = connected().await;
    let (logs, _guard) = Logs::capture();
    let request = ask(&store, id, &entry).await;

    sweep_once(&gateway).await.unwrap();
    let sent = run_action(&mut peer).await;
    assert_eq!(sent.request_id, request);
    assert_eq!(sent.manifest, *entry.envelope());
    assert_eq!(
        sent.expires_at,
        u64::try_from(at(3600).timestamp()).unwrap()
    );
    assert_eq!(
        state(&store, request).await,
        RequestState::Sent { at: at(0) }
    );

    let logs = logs.text();
    assert!(logs.contains("event=\"action_sent\""), "{logs}");
    assert!(logs.contains("resent=false"), "{logs}");
    assert!(logs.contains(&request.to_string()), "{logs}");
    // The id and the version, never the text of the manifest.
    assert!(!logs.contains("FakeErp"), "{logs}");
}

/// Nothing goes to a device that has no session here, and nothing is marked sent.
#[tokio::test(start_paused = true)]
async fn nothing_is_sent_to_a_device_that_is_not_connected() {
    let Connected {
        gateway,
        store,
        id,
        mut peer,
        entry,
        ..
    } = connected().await;
    peer.finished().await;
    let request = ask(&store, id, &entry).await;
    sweep_once(&gateway).await.unwrap();
    assert_eq!(state(&store, request).await, RequestState::Queued);
}

/// A request the sweep claimed but no session took never reached a connection: it goes
/// back to the queue, and nothing says it was sent.
#[tokio::test(start_paused = true)]
async fn a_request_no_session_takes_goes_back_to_the_queue() {
    let store = MemoryStore::new();
    let gateway = gateway_with(store.clone(), Limits::default());
    let device = TestDevice::new(10);
    let id = enroll(&gateway, &store, &device, 1).await;
    let entry = catalog(&store).await;
    let request = ask(&store, id, &entry).await;
    // In the registry, with a session that no longer reads its requests.
    let (_registration, outbox, _) = gateway
        .registry
        .register(id, crate::agents::SessionId::new());
    drop(outbox);

    let (logs, _guard) = Logs::capture();
    sweep_once(&gateway).await.unwrap();
    assert_eq!(state(&store, request).await, RequestState::Queued);
    assert!(!logs.text().contains("action_sent"), "{}", logs.text());
}

/// ADR-0012: a session starts by sending again what its device never answered. The agent
/// answers from its journal, so a result lost on the way comes back.
#[tokio::test(start_paused = true)]
async fn a_new_session_sends_again_what_got_no_answer() {
    let Connected {
        gateway,
        store,
        device,
        id,
        mut peer,
        entry,
    } = connected().await;
    let request = ask(&store, id, &entry).await;
    sweep_once(&gateway).await.unwrap();
    run_action(&mut peer).await;
    peer.finished().await;

    let (logs, _guard) = Logs::capture();
    let mut peer = authenticate(&gateway, &device, id).await;
    assert_eq!(run_action(&mut peer).await.request_id, request);
    assert!(logs.text().contains("resent=true"), "{}", logs.text());

    peer.send(text(&result(request, ActionOutcome::Succeeded {})));
    eventually("the answer is stored", || {
        store.request_record(request).unwrap().state.name() == "succeeded"
    })
    .await;
}

/// The answer is stored and audited by its codes; the output is stored and never logged.
#[tokio::test(start_paused = true)]
async fn a_result_is_stored_and_audited_without_its_output() {
    let Connected {
        gateway,
        store,
        id,
        mut peer,
        entry,
        ..
    } = connected().await;
    let request = ask(&store, id, &entry).await;
    sweep_once(&gateway).await.unwrap();
    run_action(&mut peer).await;

    let (logs, _guard) = Logs::capture();
    let output: Output = "SECRET-CUSTOMER-RECORD".parse().unwrap();
    peer.send(text(&AgentToServer::ActionResult(ActionResult {
        request_id: request,
        outcome: ActionOutcome::Rejected {
            reason: RejectReason::ServiceNotAllowed,
        },
        output: Some(output.clone()),
        duration_ms: 12,
    })));
    eventually("the answer is stored", || {
        store.request_record(request).unwrap().state.name() == "rejected"
    })
    .await;
    let RequestState::Answered {
        output: stored,
        duration_ms,
        ..
    } = state(&store, request).await
    else {
        panic!("not answered");
    };
    assert_eq!((stored, duration_ms), (Some(output), 12));

    let logs = logs.text();
    assert!(logs.contains("event=\"action_finished\""), "{logs}");
    assert!(logs.contains("reason=ServiceNotAllowed"), "{logs}");
    assert!(!logs.contains("SECRET"), "{logs}");
}

/// A device answers only for itself: a result for another device's request changes
/// nothing, and is logged with who sent it.
#[tokio::test(start_paused = true)]
async fn a_result_for_a_request_of_another_device_is_dropped() {
    let Connected {
        gateway,
        store,
        id,
        mut peer,
        entry,
        ..
    } = connected().await;
    let intruder = TestDevice::new(11);
    let intruder_id = enroll(&gateway, &store, &intruder, 2).await;
    let other = authenticate(&gateway, &intruder, intruder_id).await;
    let request = ask(&store, id, &entry).await;
    sweep_once(&gateway).await.unwrap();
    run_action(&mut peer).await;

    let (logs, _guard) = Logs::capture();
    other.send(text(&result(request, ActionOutcome::Succeeded {})));
    other.send(text(&AgentToServer::Heartbeat {
        telemetry: telemetry(1),
    }));
    eventually("the heartbeat after it is stored", || {
        store.record(intruder_id).unwrap().telemetry.is_some()
    })
    .await;
    assert_eq!(
        state(&store, request).await,
        RequestState::Sent { at: at(0) }
    );
    let logs = logs.text();
    assert!(logs.contains("why=OtherDevice"), "{logs}");
    assert!(logs.contains(&intruder_id.to_string()), "{logs}");
}

/// ADR-0012: the same answer again is a copy, at `debug`; a different one is an anomaly,
/// at `warn`, and the first one stays.
#[tokio::test(start_paused = true)]
async fn a_second_result_is_quiet_when_identical_and_an_anomaly_when_not() {
    let Connected {
        gateway,
        store,
        id,
        mut peer,
        entry,
        ..
    } = connected().await;
    let request = ask(&store, id, &entry).await;
    sweep_once(&gateway).await.unwrap();
    run_action(&mut peer).await;
    peer.send(text(&result(request, ActionOutcome::Succeeded {})));
    eventually("the answer is stored", || {
        store.request_record(request).unwrap().state.name() == "succeeded"
    })
    .await;

    let (logs, _guard) = Logs::capture();
    peer.send(text(&result(request, ActionOutcome::Succeeded {})));
    let refused = ActionOutcome::Rejected {
        reason: RejectReason::BadSignature,
    };
    peer.send(text(&result(request, refused)));
    peer.send(text(&AgentToServer::Heartbeat {
        telemetry: telemetry(1),
    }));
    eventually("the heartbeat after them is stored", || {
        store.record(id).unwrap().telemetry.is_some()
    })
    .await;
    let logs = logs.text();
    assert!(
        logs.contains("DEBUG") && logs.contains("the same result again"),
        "{logs}"
    );
    assert!(
        logs.contains("WARN") && logs.contains("a second, different result"),
        "{logs}"
    );
    assert_eq!(state(&store, request).await.name(), "succeeded");
}

/// A duration past what the store keeps is no run that happened: dropped before the store.
#[tokio::test(start_paused = true)]
async fn a_result_with_a_duration_no_run_can_have_is_dropped() {
    let Connected {
        gateway,
        store,
        id,
        mut peer,
        entry,
        ..
    } = connected().await;
    let request = ask(&store, id, &entry).await;
    sweep_once(&gateway).await.unwrap();
    run_action(&mut peer).await;

    let (logs, _guard) = Logs::capture();
    peer.send(text(&AgentToServer::ActionResult(ActionResult {
        request_id: request,
        outcome: ActionOutcome::Succeeded {},
        output: None,
        duration_ms: u64::MAX,
    })));
    peer.send(text(&AgentToServer::Heartbeat {
        telemetry: telemetry(1),
    }));
    eventually("the heartbeat after it is stored", || {
        store.record(id).unwrap().telemetry.is_some()
    })
    .await;
    assert_eq!(
        state(&store, request).await,
        RequestState::Sent { at: at(0) }
    );
    assert!(
        logs.text().contains("a duration no run can have"),
        "{}",
        logs.text()
    );
}

/// A device that sends results by the hundred gets a few to the store each minute: the
/// store's connections are for every device.
#[tokio::test(start_paused = true)]
async fn results_past_the_budget_of_a_minute_never_reach_the_store() {
    let Connected {
        gateway,
        store,
        id,
        mut peer,
        entry,
        ..
    } = connected().await;
    let request = ask(&store, id, &entry).await;
    sweep_once(&gateway).await.unwrap();
    run_action(&mut peer).await;

    for _ in 0..RESULTS_PER_MINUTE {
        peer.send(text(&result(RequestId::new(), ActionOutcome::Succeeded {})));
    }
    peer.send(text(&result(request, ActionOutcome::Succeeded {})));
    peer.send(text(&AgentToServer::Heartbeat {
        telemetry: telemetry(1),
    }));
    eventually("the heartbeat after them is stored", || {
        store.record(id).unwrap().telemetry.is_some()
    })
    .await;
    assert_eq!(
        state(&store, request).await,
        RequestState::Sent { at: at(0) }
    );

    // A minute later there is room again.
    tokio::time::advance(Duration::from_secs(60)).await;
    peer.send(text(&result(request, ActionOutcome::Succeeded {})));
    eventually("the answer is stored", || {
        store.request_record(request).unwrap().state.name() == "succeeded"
    })
    .await;
}

/// What a device can make the server log about its results is bounded per device, across
/// its sessions, and does not use up what another device may log.
#[tokio::test(start_paused = true)]
async fn a_noisy_device_does_not_silence_another() {
    let Connected {
        gateway,
        store,
        device,
        id,
        peer,
        ..
    } = connected().await;
    let quiet = TestDevice::new(11);
    let quiet_id = enroll(&gateway, &store, &quiet, 2).await;
    let quiet_peer = authenticate(&gateway, &quiet, quiet_id).await;

    let (logs, _guard) = Logs::capture();
    let noise = |peer: &Peer| {
        for _ in 0..10 {
            peer.send(text(&result(RequestId::new(), ActionOutcome::Succeeded {})));
        }
        peer.send(text(&AgentToServer::Heartbeat {
            telemetry: telemetry(1),
        }));
    };
    noise(&peer);
    eventually("the noise is read", || {
        store.record(id).unwrap().telemetry.is_some()
    })
    .await;
    // Connecting again does not refill it.
    let mut peer = peer;
    peer.finished().await;
    let again = authenticate(&gateway, &device, id).await;
    noise(&again);
    tokio::time::advance(Duration::from_millis(1)).await;
    eventually("the second session's noise is read", || {
        store.record(id).unwrap().last_seen.is_some()
    })
    .await;
    for _ in 0..100 {
        tokio::task::yield_now().await;
    }
    quiet_peer.send(text(&result(RequestId::new(), ActionOutcome::Succeeded {})));
    quiet_peer.send(text(&AgentToServer::Heartbeat {
        telemetry: telemetry(2),
    }));
    eventually("the quiet device's heartbeat is stored", || {
        store.record(quiet_id).unwrap().telemetry == Some(telemetry(2))
    })
    .await;

    let logs = logs.text();
    let lines_of = |device: DeviceId| {
        logs.lines()
            .filter(|line| {
                line.contains("action result dropped") && line.contains(&device.to_string())
            })
            .count()
    };
    assert_eq!(lines_of(id), 8, "{logs}");
    assert_eq!(lines_of(quiet_id), 1, "{logs}");
}

/// A queued request that expires is marked so by the sweep, and audited.
#[tokio::test(start_paused = true)]
async fn the_sweep_expires_what_waited_too_long() {
    let store = MemoryStore::new();
    let device = TestDevice::new(10);
    let enrolling = gateway_with(store.clone(), Limits::default());
    let id = enroll(&enrolling, &store, &device, 1).await;
    let entry = catalog(&store).await;
    let request = ask(&store, id, &entry).await;

    let later = gateway_at(&store, || at(3600));
    let (logs, _guard) = Logs::capture();
    sweep_once(&later).await.unwrap();
    assert_eq!(
        state(&store, request).await,
        RequestState::Expired { at: at(3600) }
    );
    let logs = logs.text();
    assert!(logs.contains("status=\"expired\""), "{logs}");
}

/// The loop sweeps every half second, so a request reaches a connected agent within the
/// second of RNF-13, and ends with the router that owns the gateway.
#[tokio::test(start_paused = true)]
async fn the_loop_sweeps_every_half_second_and_ends_with_its_gateway() {
    let Connected {
        gateway,
        store,
        id,
        mut peer,
        entry,
        ..
    } = connected().await;
    let sweeping = tokio::spawn(run(Arc::downgrade(&gateway)));
    let request = ask(&store, id, &entry).await;
    let started = tokio::time::Instant::now();
    assert_eq!(run_action(&mut peer).await.request_id, request);
    assert!(started.elapsed() <= SWEEP_EVERY, "{:?}", started.elapsed());

    peer.finished().await;
    drop(gateway);
    tokio::time::timeout(SWEEP_EVERY * 4, sweeping)
        .await
        .expect("the loop outlived its gateway")
        .unwrap();
}

/// A refusal that only described the agent then (here, a full queue) gives way to the
/// answer of a copy that ran after it, and the audit says so.
#[tokio::test(start_paused = true)]
async fn a_later_answer_replaces_a_refusal_that_described_the_agent() {
    let Connected {
        gateway,
        store,
        id,
        mut peer,
        entry,
        ..
    } = connected().await;
    let request = ask(&store, id, &entry).await;
    sweep_once(&gateway).await.unwrap();
    run_action(&mut peer).await;
    let full = ActionOutcome::Rejected {
        reason: RejectReason::QueueFull,
    };
    peer.send(text(&result(request, full)));
    eventually("the refusal is stored", || {
        store.request_record(request).unwrap().state.name() == "rejected"
    })
    .await;

    let (logs, _guard) = Logs::capture();
    peer.send(text(&result(request, ActionOutcome::Succeeded {})));
    eventually("the answer replaced it", || {
        store.request_record(request).unwrap().state.name() == "succeeded"
    })
    .await;
    assert!(logs.text().contains("replaced=true"), "{}", logs.text());
}
