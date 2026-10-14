//! The same scenarios as `MemoryStore`, and what only a real database can get wrong:
//! concurrent calls, slow statements, what its errors carry.
//!
//! Each test gets a new database, migrated, from the server named by `DATABASE_URL`. They
//! are ignored by default; run them with
//! `cargo test -p ponte-server -- --ignored pg_`.

use std::num::NonZeroU32;
use std::time::Duration;

use futures_util::future::join_all;
use ponte_protocol::{DiskUsage, EnrollmentToken};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{Connection, PgConnection};
use tokio::time::{Instant, sleep};

use axum::extract::ws::Message;
use ponte_protocol::{AgentToServer, ServerToAgent};

use super::*;
use crate::agents::Limits;
use crate::agents::store::scenarios::{self, for_each_scenario};
use crate::agents::testkit::{
    Logs, Peer, Sent, TestDevice, about, at, gateway_with, telemetry, token,
};

async fn store(pool: PgPoolOptions, options: PgConnectOptions) -> PgStore {
    PgStore::connect_with(pool, options).await.unwrap()
}

macro_rules! in_postgres {
    ($scenario:ident) => {
        #[sqlx::test]
        #[ignore = "needs PostgreSQL: DATABASE_URL"]
        async fn $scenario(pool: PgPoolOptions, options: PgConnectOptions) {
            scenarios::$scenario(&store(pool, options).await).await;
        }
    };
}
for_each_scenario!(in_postgres);

/// Issues `token(token_seed)` for `max_uses` machines until `at(100)`.
async fn issue(store: &PgStore, token_seed: u8, max_uses: u32) {
    let name = format!("Customer {token_seed}").parse().unwrap();
    let customer = store.add_customer(&name).await.unwrap().unwrap();
    let grant = TokenGrant {
        customer,
        expires_at: at(100),
        max_uses: NonZeroU32::new(max_uses).unwrap(),
    };
    let hash = TokenHash::of(&token(token_seed));
    assert!(store.issue_token(hash, grant).await.unwrap());
}

fn request(token_seed: u8, key: [u8; 32]) -> EnrollRequest {
    EnrollRequest {
        token: TokenHash::of(&token(token_seed)),
        public_key: PublicKey::from_bytes(key),
        about: about(),
    }
}

async fn enrolled(store: &PgStore, token_seed: u8, key: [u8; 32]) -> DeviceId {
    match store.enroll(request(token_seed, key), at(0)).await.unwrap() {
        EnrollOutcome::Enrolled { device_id, .. } => device_id,
        EnrollOutcome::Refused(refusal) => panic!("refused: {refusal:?}"),
    }
}

/// Runs `requests` all at once and returns what each got.
async fn at_once(store: &PgStore, requests: Vec<EnrollRequest>) -> Vec<EnrollOutcome> {
    join_all(requests.into_iter().map(|request| {
        let store = store.clone();
        tokio::spawn(async move { store.enroll(request, at(0)).await.unwrap() })
    }))
    .await
    .into_iter()
    .map(Result::unwrap)
    .collect()
}

async fn uses(store: &PgStore, token_seed: u8) -> u32 {
    let token = store.token(&TokenHash::of(&token(token_seed))).await;
    token.unwrap().unwrap().uses
}

fn count(outcomes: &[EnrollOutcome], wanted: impl Fn(&EnrollOutcome) -> bool) -> usize {
    outcomes.iter().filter(|outcome| wanted(outcome)).count()
}

/// An agent that lost the answer and asks again while its first try is still running
/// gets one device, and spends one use.
#[sqlx::test]
#[ignore = "needs PostgreSQL: DATABASE_URL"]
async fn pg_the_same_enrollment_at_once_makes_one_device(
    pool: PgPoolOptions,
    options: PgConnectOptions,
) {
    let store = store(pool, options).await;
    issue(&store, 1, 5).await;

    let outcomes = at_once(&store, (0..16).map(|_| request(1, [10; 32])).collect()).await;
    let mut ids = Vec::new();
    let mut new = 0;
    for outcome in outcomes {
        let EnrollOutcome::Enrolled {
            device_id,
            repeated,
            ..
        } = outcome
        else {
            panic!("{outcome:?}");
        };
        ids.push(device_id);
        new += usize::from(!repeated);
    }
    assert_eq!(new, 1);
    ids.dedup();
    assert_eq!(ids.len(), 1);
    assert_eq!(uses(&store, 1).await, 1);
    assert_eq!(store.devices(None).await.unwrap().len(), 1);
}

/// A token for three machines enrolls three, however many ask at the same moment.
#[sqlx::test]
#[ignore = "needs PostgreSQL: DATABASE_URL"]
async fn pg_a_token_is_never_spent_past_its_limit(pool: PgPoolOptions, options: PgConnectOptions) {
    let store = store(pool, options).await;
    issue(&store, 1, 3).await;

    let requests = (0..12).map(|seed| request(1, [100 + seed; 32])).collect();
    let outcomes = at_once(&store, requests).await;
    let enrolled = count(&outcomes, |outcome| {
        matches!(outcome, EnrollOutcome::Enrolled { .. })
    });
    let exhausted = count(&outcomes, |outcome| {
        *outcome == EnrollOutcome::Refused(EnrollRefusal::ExhaustedToken)
    });
    assert_eq!((enrolled, exhausted), (3, 9), "{outcomes:?}");
    assert_eq!(uses(&store, 1).await, 3);
    assert_eq!(store.devices(None).await.unwrap().len(), 3);
}

/// One key under two tokens at the same moment: one device, and the other token keeps
/// the use it would have spent.
#[sqlx::test]
#[ignore = "needs PostgreSQL: DATABASE_URL"]
async fn pg_one_key_under_two_tokens_at_once_enrolls_once(
    pool: PgPoolOptions,
    options: PgConnectOptions,
) {
    let store = store(pool, options).await;
    issue(&store, 1, 50).await;
    issue(&store, 2, 50).await;

    for seed in 1..=20_u8 {
        let outcomes = at_once(&store, vec![request(1, [seed; 32]), request(2, [seed; 32])]).await;
        let enrolled = count(&outcomes, |outcome| {
            matches!(outcome, EnrollOutcome::Enrolled { .. })
        });
        let refused = count(&outcomes, |outcome| {
            *outcome == EnrollOutcome::Refused(EnrollRefusal::KeyAlreadyEnrolled)
        });
        assert_eq!((enrolled, refused), (1, 1), "{outcomes:?}");
    }
    assert_eq!(uses(&store, 1).await + uses(&store, 2).await, 20);
    assert_eq!(store.devices(None).await.unwrap().len(), 20);
}

/// The server stopped with sessions open and nobody recorded their end.
#[sqlx::test]
#[ignore = "needs PostgreSQL: DATABASE_URL"]
async fn pg_starting_the_server_marks_every_device_offline(
    pool: PgPoolOptions,
    options: PgConnectOptions,
) {
    let store = store(pool, options).await;
    issue(&store, 1, 3).await;
    let mut ids = Vec::new();
    for seed in [10, 11, 12] {
        ids.push(enrolled(&store, 1, [seed; 32]).await);
    }
    for id in &ids[..2] {
        let session = SessionId::new();
        store
            .session_started(*id, session, &about(), at(1))
            .await
            .unwrap();
    }

    assert_eq!(store.clear_online().await.unwrap(), 2);
    for id in ids {
        let record = store.device_record(id).await.unwrap().unwrap();
        assert_eq!(record.online, None);
    }
    assert_eq!(store.clear_online().await.unwrap(), 0);
}

/// `clear_online` assumes it is the only server: a second one, started by mistake, would
/// mark every connected device offline. Only one may hold the claim.
#[sqlx::test]
#[ignore = "needs PostgreSQL: DATABASE_URL"]
async fn pg_only_one_server_serves_a_database(pool: PgPoolOptions, options: PgConnectOptions) {
    let first = store(pool.clone(), options.clone()).await;
    let second = store(pool, options).await;

    let claim = first.claim_server().await.unwrap();
    let refused = second.claim_server().await.unwrap_err();
    assert_eq!(refused.kind(), ErrorKind::AnotherServer);

    drop(claim);
    eventually("the claim is given back", || async {
        second.claim_server().await.is_ok()
    })
    .await;
}

/// The database can drop the claim's connection (a restart, an administrator, an idle
/// limit). The server takes the claim again if nobody else did, and stops if somebody did.
#[sqlx::test]
#[ignore = "needs PostgreSQL: DATABASE_URL"]
async fn pg_a_lost_claim_is_taken_again_or_the_server_stops(
    pool: PgPoolOptions,
    options: PgConnectOptions,
) {
    let mut admin = PgConnection::connect_with(&options).await.unwrap();
    let first = store(pool.clone(), options.clone()).await;
    let second = store(pool, options).await;
    let end_claims = async |admin: &mut PgConnection| {
        sqlx::query(
            "SELECT pg_terminate_backend(pid) FROM pg_locks \
             WHERE locktype = 'advisory' AND pid <> pg_backend_pid() \
             AND database = (SELECT oid FROM pg_database WHERE datname = current_database())",
        )
        .execute(admin)
        .await
        .unwrap();
    };

    let claim = first.claim_server().await.unwrap();
    let watch = tokio::spawn({
        let first = first.clone();
        async move { first.hold_claim(claim, Duration::from_millis(50)).await }
    });

    // Lost, and nobody else took it: taken again.
    end_claims(&mut admin).await;
    let mut held = false;
    for _ in 0..200 {
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND granted \
             AND database = (SELECT oid FROM pg_database WHERE datname = current_database())",
        )
        .fetch_one(&mut admin)
        .await
        .unwrap();
        // The old session may still be on its way out: wait for one holder, a new one.
        if count == 1 && !watch.is_finished() {
            held = true;
            sleep(Duration::from_millis(200)).await;
            break;
        }
        sleep(Duration::from_millis(20)).await;
    }
    assert!(held, "the claim was not taken again");
    assert_eq!(
        second.claim_server().await.unwrap_err().kind(),
        ErrorKind::AnotherServer
    );
    assert!(!watch.is_finished());

    // Lost, and another server took it first: the watch ends, and says why.
    end_claims(&mut admin).await;
    let taken = second.claim_server().await;
    let lost = tokio::time::timeout(Duration::from_secs(5), watch)
        .await
        .expect("the watch never noticed")
        .unwrap();
    assert!(taken.is_ok());
    assert_eq!(lost.kind(), ErrorKind::AnotherServer);
}

/// A ping can be slow while the claim's session is alive and still holds the lock. That
/// is this server's own claim, not another server's, and must not stop it.
#[sqlx::test]
#[ignore = "needs PostgreSQL: DATABASE_URL"]
async fn pg_a_slow_claim_is_not_mistaken_for_another_server(
    pool: PgPoolOptions,
    options: PgConnectOptions,
) {
    let first = store(pool.clone(), options.clone()).await;
    let second = store(pool, options).await;
    let claim = first.claim_server().await.unwrap();
    // The same key held in another database of the cluster is another lock, and must not
    // be taken for the holder of this one: here, the database the tests are made from.
    let mut elsewhere = PgConnection::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    sqlx::query("SELECT pg_try_advisory_lock($1)")
        .bind(SERVER_LOCK)
        .execute(&mut elsewhere)
        .await
        .unwrap();

    // What `hold_claim` does after a ping that did not answer in time, more than once.
    let mut kept = claim;
    for _ in 0..5 {
        kept = match first.regain(kept).await {
            Regained::Ours(claim) => claim,
            other => panic!("{other:?}"),
        };
    }
    assert_eq!(
        second.claim_server().await.unwrap_err().kind(),
        ErrorKind::AnotherServer
    );

    // And it is still a claim that can be lost to another server.
    drop(kept);
    eventually("the claim is given back", || async {
        second.claim_server().await.is_ok()
    })
    .await;
}

/// What decides whether a claim is still this server's: the session holding the lock,
/// named by its pid and the start of the database server it lives in.
#[test]
fn only_the_session_that_took_the_claim_counts_as_this_server() {
    let ours = Holder {
        pid: 72,
        since: Some(at(0)),
    };
    assert!(matches!(judge(&ours, Some(ours)), Verdict::Ours));
    // Same pid, but the database restarted: a new session that took the pid back.
    let reborn = Holder {
        pid: 72,
        since: Some(at(60)),
    };
    assert!(matches!(judge(&ours, Some(reborn)), Verdict::Another));
    let other = Holder {
        pid: 79,
        since: Some(at(0)),
    };
    assert!(matches!(judge(&ours, Some(other)), Verdict::Another));
    // Our pid without a start: our session ending while the lookup ran (it lets go of the
    // lock before it leaves the activity view). Not proof either way.
    let leaving = Holder {
        pid: 72,
        since: None,
    };
    assert!(matches!(judge(&ours, Some(leaving)), Verdict::Unsure));
    // Another pid without a start: a session of another role. Never ours.
    let hidden = Holder {
        pid: 79,
        since: None,
    };
    assert!(matches!(judge(&ours, Some(hidden)), Verdict::Another));
    // Nobody holds it, as far as the database says: look again.
    assert!(matches!(judge(&ours, None), Verdict::Unsure));
}

/// Not knowing who holds the claim is not a reason to keep serving for ever, and a
/// database that is only slow or down is not a reason to stop.
#[test]
fn doubt_about_the_claim_ends_after_a_few_checks() {
    let mut doubt = Doubt::default();
    for _ in 1..UNSURE_LIMIT {
        assert!(!doubt.weigh(Outcome::Unsure));
    }
    assert!(doubt.weigh(Outcome::Unsure));

    // Proof that the claim is ours starts the count again; no answer does not.
    for proof in [Outcome::Answered, Outcome::Taken, Outcome::Ours] {
        let mut doubt = Doubt::default();
        for _ in 1..UNSURE_LIMIT {
            assert!(!doubt.weigh(Outcome::Unsure));
        }
        assert!(!doubt.weigh(proof));
        assert!(!doubt.weigh(Outcome::Unsure), "{proof:?}");
    }
    let mut doubt = Doubt::default();
    for _ in 1..UNSURE_LIMIT {
        assert!(!doubt.weigh(Outcome::Unsure));
        assert!(!doubt.weigh(Outcome::Waiting));
    }
    assert!(doubt.weigh(Outcome::Unsure));

    // However long the database is in trouble, that alone stops nothing.
    let mut doubt = Doubt::default();
    for _ in 0..100 {
        assert!(!doubt.weigh(Outcome::Waiting));
    }
}

/// Only a database that did not answer is "waiting". One that answered with an error
/// gave no proof of anything, and counts toward the limit like any other non-answer.
#[test]
fn only_a_missing_answer_is_waiting() {
    let error = |kind| PgStoreError {
        operation: "find who holds the claim on the database",
        kind,
    };
    let state = |code| ErrorKind::Database(SqlState::of(code).unwrap());
    for waiting in [
        ErrorKind::TimedOut,
        ErrorKind::PoolTimedOut,
        ErrorKind::Connection,
        // An overloaded or stopping database answers with these: no answer to the question.
        state("57014"),
        state("57P01"),
        state("53300"),
        state("53200"),
        state("08006"),
    ] {
        assert!(no_answer(&error(waiting)), "{waiting:?}");
    }
    for answered in [
        state("42501"),
        state("28P01"),
        state("42P01"),
        ErrorKind::CorruptRow("a column"),
        ErrorKind::Other,
    ] {
        assert!(!no_answer(&error(answered)), "{answered:?}");
    }
}

/// A row the code cannot read is an error, never a guess.
#[sqlx::test]
#[ignore = "needs PostgreSQL: DATABASE_URL"]
async fn pg_a_row_that_does_not_read_is_an_error(pool: PgPoolOptions, options: PgConnectOptions) {
    let mut raw = PgConnection::connect_with(&options).await.unwrap();
    let store = store(pool, options).await;
    issue(&store, 1, 1).await;
    let device_id = enrolled(&store, 1, [10; 32]).await;
    sqlx::query("UPDATE devices SET os = 'line' || chr(10) || 'break' WHERE id = $1")
        .bind(device_id.as_uuid())
        .execute(&mut raw)
        .await
        .unwrap();

    let error = store.device_record(device_id).await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::CorruptRow("label"));
    assert!(!error.to_string().contains("break"), "{error}");
    // What the handshake reads does not include the labels.
    assert!(store.device(device_id).await.unwrap().is_some());
}

/// Telemetry written by an older server, or one that let an impossible reading through,
/// costs that device its last reading, not every listing that holds it.
#[sqlx::test]
#[ignore = "needs PostgreSQL: DATABASE_URL"]
async fn pg_telemetry_that_does_not_read_is_left_out(
    pool: PgPoolOptions,
    options: PgConnectOptions,
) {
    let mut raw = PgConnection::connect_with(&options).await.unwrap();
    let store = store(pool, options).await;
    issue(&store, 1, 2).await;
    let broken = enrolled(&store, 1, [10; 32]).await;
    let fine = enrolled(&store, 1, [11; 32]).await;
    sqlx::query(
        "UPDATE devices SET telemetry = '{\"cpu_percent\": null, \"SECRET\": 1}' WHERE id = $1",
    )
    .bind(broken.as_uuid())
    .execute(&mut raw)
    .await
    .unwrap();
    let (logs, _guard) = Logs::capture();

    let devices = store.devices(None).await.unwrap();
    assert_eq!(devices.len(), 2);
    assert!(devices.iter().all(|device| device.telemetry.is_none()));
    let record = store.device_record(broken).await.unwrap().unwrap();
    assert_eq!(record.telemetry, None);
    assert!(store.device_record(fine).await.unwrap().is_some());

    let logs = logs.text();
    assert!(logs.contains(&broken.to_string()), "{logs}");
    assert!(!logs.contains("SECRET"), "{logs}");
}

/// A database that does not answer frees the call within the limit. The handshake waits
/// on this store while it holds a place among the unauthenticated connections.
#[sqlx::test]
#[ignore = "needs PostgreSQL: DATABASE_URL"]
async fn pg_a_database_that_hangs_frees_the_call_in_time(
    pool: PgPoolOptions,
    options: PgConnectOptions,
) {
    let mut blocker = PgConnection::connect_with(&options).await.unwrap();
    let store = store(pool, options).await;
    let mut held = blocker.begin().await.unwrap();
    sqlx::query("LOCK TABLE devices IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *held)
        .await
        .unwrap();

    let started = Instant::now();
    let error = store.device(DeviceId::new()).await.unwrap_err();
    let waited = started.elapsed();
    assert!(waited >= Duration::from_secs(4), "{waited:?}");
    assert!(waited < CALL_LIMIT, "{waited:?}");
    // The database's own limit on a statement: `query_canceled`.
    let canceled = SqlState::of("57014").unwrap();
    assert_eq!(error.kind(), ErrorKind::Database(canceled));
    held.rollback().await.unwrap();
}

/// Telemetry is free text from the machine. A value the database refuses must not come
/// back in the error, which goes to the log.
#[sqlx::test]
#[ignore = "needs PostgreSQL: DATABASE_URL"]
async fn pg_an_error_carries_no_value_of_the_call(pool: PgPoolOptions, options: PgConnectOptions) {
    let store = store(pool, options).await;
    issue(&store, 1, 1).await;
    let device_id = enrolled(&store, 1, [10; 32]).await;
    let mut poisoned = telemetry(1);
    // PostgreSQL refuses a NUL in JSON text, and the context of its error quotes the JSON
    // around it. `tests::an_error_keeps_the_kind_and_drops_the_text` covers a message that
    // quotes a value itself.
    poisoned.disks.push(DiskUsage {
        mount: "\0SECRET-CUSTOMER-RECORD".to_owned(),
        total_bytes: 1,
        available_bytes: 1,
    });

    let error = store
        .heartbeat(device_id, &poisoned, at(1))
        .await
        .unwrap_err();
    for text in [error.to_string(), format!("{error:?}")] {
        assert!(!text.contains("SECRET"), "{text}");
    }
    assert!(matches!(error.kind(), ErrorKind::Database(_)), "{error:?}");
    let record = store.device_record(device_id).await.unwrap().unwrap();
    assert_eq!(record.telemetry, None);
}

/// Neither the token, nor its whole hash, nor what the machine reported, nor the database
/// password reaches the log, whatever the level.
#[sqlx::test]
#[ignore = "needs PostgreSQL: DATABASE_URL"]
async fn pg_logs_hold_no_secret(pool: PgPoolOptions, options: PgConnectOptions) {
    let (logs, _guard) = Logs::capture();
    let store = store(pool, options).await;
    issue(&store, 1, 1).await;
    let device_id = enrolled(&store, 1, [10; 32]).await;
    let mut reported = telemetry(1);
    reported.disks.push(DiskUsage {
        mount: "MOUNT-CHOSEN-BY-THE-MACHINE".to_owned(),
        total_bytes: 1,
        available_bytes: 1,
    });
    store.heartbeat(device_id, &reported, at(1)).await.unwrap();
    store.device_record(device_id).await.unwrap();
    store.tokens(None).await.unwrap();
    sleep(Duration::from_millis(50)).await;

    let logs = logs.text();
    let secret: EnrollmentToken = token(1);
    let hash = TokenHash::of(&secret);
    let hash_hex: String = hash.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
    for leak in [
        secret.expose_hex(),
        hash_hex,
        "MOUNT-CHOSEN-BY-THE-MACHINE".to_owned(),
        "ponte:ponte".to_owned(),
    ] {
        assert!(!logs.contains(&leak), "{leak} in {logs}");
    }
}

fn text(message: &AgentToServer) -> Message {
    Message::Text(serde_json::to_string(message).unwrap().into())
}

/// Polls `done` until it holds, for a few seconds at most.
async fn eventually<F: Future<Output = bool>>(what: &str, done: impl Fn() -> F) {
    for _ in 0..200 {
        if done().await {
            return;
        }
        sleep(Duration::from_millis(20)).await;
    }
    panic!("never happened: {what}");
}

/// The whole life of a device through the real session code, on the real store: it
/// enrolls, connects, reports, and is dropped once revoked.
#[sqlx::test]
#[ignore = "needs PostgreSQL: DATABASE_URL"]
async fn pg_a_device_enrolls_connects_reports_and_is_dropped_when_revoked(
    pool: PgPoolOptions,
    options: PgConnectOptions,
) {
    let store = store(pool, options).await;
    issue(&store, 1, 1).await;
    let limits = Limits {
        status_check: Duration::from_millis(100),
        ..Limits::default()
    };
    let gateway = gateway_with(store.clone(), limits);
    let device = TestDevice::new(10);

    let mut peer = Peer::connect(&gateway);
    let nonce = peer.challenge().await;
    peer.send(text(&device.enroll(&nonce, &token(1))));
    let Some(Sent::Message(ServerToAgent::Enrolled { device_id })) = peer.receive().await else {
        panic!("not enrolled");
    };
    assert_eq!(peer.rest().await, [Sent::Closed]);

    let mut peer = Peer::connect(&gateway);
    let nonce = peer.challenge().await;
    peer.send(text(&device.hello(&nonce, device_id)));
    assert_eq!(
        peer.receive().await,
        Some(Sent::Message(ServerToAgent::Welcome {}))
    );
    peer.send(text(&AgentToServer::Heartbeat {
        telemetry: telemetry(7),
    }));
    eventually("the heartbeat is stored", || async {
        let record = store.device_record(device_id).await.unwrap().unwrap();
        record.telemetry == Some(telemetry(7)) && record.online.is_some()
    })
    .await;

    assert!(store.revoke_device(device_id).await.unwrap());
    let closed = tokio::time::timeout(Duration::from_secs(5), peer.rest()).await;
    assert_eq!(closed.unwrap(), [Sent::Closed]);
    peer.finished().await;
    let record = store.device_record(device_id).await.unwrap().unwrap();
    assert_eq!(record.online, None);
    assert_eq!(record.status, DeviceStatus::Revoked);
}
