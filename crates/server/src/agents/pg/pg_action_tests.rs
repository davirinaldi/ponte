//! What only a real database can get wrong about action requests: two statements on one
//! row at once, and what its errors carry. The scenarios shared with `MemoryStore` run in
//! `pg_tests.rs`.
//!
//! The races are made to happen, not hoped for: a connection of the test holds the row in
//! an open transaction while the store's statement runs, and lets go only once the store is
//! waiting for it.

use std::num::NonZeroU32;
use std::time::Duration;

use futures_util::future::join_all;
use ponte_protocol::{
    ActionOutcome, ActionResult, DeviceId, Initiator, Output, PublicKey, RejectReason, RequestId,
};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{Connection, PgConnection};
use tokio::time::sleep;

use super::*;
use crate::agents::store::actions::{
    ActionAdmin, ActionStore, CancelOutcome, CatalogEntry, Finish, KeyAdded, MAX_OPEN_PER_DEVICE,
    NewRequest, RequestOutcome, RequestRefusal, RequestState,
};
use crate::agents::testkit::{about, at, catalog_entry, manifest_public, token};

async fn store(pool: PgPoolOptions, options: PgConnectOptions) -> PgStore {
    PgStore::connect_with(pool, options).await.unwrap()
}

/// An active device with its own customer and token.
async fn active(store: &PgStore, seed: u8) -> DeviceId {
    let name = format!("Customer {seed}").parse().unwrap();
    let customer = store.add_customer(&name).await.unwrap().unwrap();
    let grant = TokenGrant {
        customer,
        expires_at: at(100),
        max_uses: NonZeroU32::MIN,
    };
    let hash = TokenHash::of(&token(seed));
    assert!(store.issue_token(hash, grant).await.unwrap());
    let request = EnrollRequest {
        token: hash,
        public_key: PublicKey::from_bytes([seed; 32]),
        about: about(),
    };
    match store.enroll(request, at(0)).await.unwrap() {
        EnrollOutcome::Enrolled { device_id, .. } => device_id,
        EnrollOutcome::Refused(refusal) => panic!("refused: {refusal:?}"),
    }
}

async fn catalog(store: &PgStore) -> CatalogEntry {
    store
        .add_signing_key(manifest_public(1), at(0))
        .await
        .unwrap();
    let entry = catalog_entry(1, "erp.restart-service", 1, 0);
    assert!(store.add_manifest(&entry, at(0)).await.unwrap());
    entry
}

async fn ask(store: &PgStore, device: DeviceId, entry: &CatalogEntry) -> RequestOutcome {
    let request = NewRequest {
        id: RequestId::new(),
        device,
        manifest: *entry.hash(),
        expires_at: u64::try_from(at(3600).timestamp()).unwrap(),
        initiator: Initiator::Human {
            user_id: "server_cli".parse().unwrap(),
        },
    };
    store.request_action(&request, at(0)).await.unwrap()
}

/// A queued request of a new active device, and the device.
async fn queued(store: &PgStore) -> (DeviceId, RequestId) {
    let entry = catalog(store).await;
    let device = active(store, 1).await;
    ask(store, device, &entry).await;
    let records = store.requests(Some(device), 1).await.unwrap();
    (device, records[0].id)
}

async fn state(store: &PgStore, id: RequestId) -> RequestState {
    store.request(id).await.unwrap().unwrap().state
}

/// Holds the request's row in an open transaction on `raw`, after running `change` on it
/// there: the store's statements on that row wait until the transaction ends.
async fn hold<'c>(
    raw: &'c mut PgConnection,
    id: RequestId,
    change: &'static str,
) -> sqlx::Transaction<'c, sqlx::Postgres> {
    let mut held = raw.begin().await.unwrap();
    sqlx::query("SELECT 1 FROM action_requests WHERE id = $1 FOR UPDATE")
        .bind(id.as_uuid())
        .execute(&mut *held)
        .await
        .unwrap();
    sqlx::query(change)
        .bind(id.as_uuid())
        .execute(&mut *held)
        .await
        .unwrap();
    held
}

/// Lets the store's statement start and reach the lock.
async fn waiting<T>(task: &tokio::task::JoinHandle<T>) {
    sleep(Duration::from_millis(300)).await;
    assert!(
        !task.is_finished(),
        "the statement did not wait for the row"
    );
}

/// A cancel that commits while the sweep waits for the row: the sweep must not send what
/// was cancelled. Its `status = 'queued'` is checked again against the cancelled row.
#[sqlx::test]
#[ignore = "needs PostgreSQL: DATABASE_URL"]
async fn pg_a_request_cancelled_while_the_sweep_waits_is_not_sent(
    pool: PgPoolOptions,
    options: PgConnectOptions,
) {
    let mut raw = PgConnection::connect_with(&options).await.unwrap();
    let store = store(pool, options).await;
    let (device, id) = queued(&store).await;

    let held = hold(
        &mut raw,
        id,
        "UPDATE action_requests SET status = 'cancelled', finished_at = now() WHERE id = $1",
    )
    .await;
    let sweeping = {
        let store = store.clone();
        tokio::spawn(async move { store.claim_due(&[device], at(1)).await.unwrap() })
    };
    waiting(&sweeping).await;
    held.commit().await.unwrap();

    assert_eq!(sweeping.await.unwrap(), []);
    assert!(matches!(
        state(&store, id).await,
        RequestState::Cancelled { .. }
    ));
}

/// The other order: the sweep sent it, so a cancel that waited for the row finds it sent.
#[sqlx::test]
#[ignore = "needs PostgreSQL: DATABASE_URL"]
async fn pg_a_request_sent_while_the_cancel_waits_is_not_cancelled(
    pool: PgPoolOptions,
    options: PgConnectOptions,
) {
    let mut raw = PgConnection::connect_with(&options).await.unwrap();
    let store = store(pool, options).await;
    let (_, id) = queued(&store).await;

    let held = hold(
        &mut raw,
        id,
        "UPDATE action_requests SET status = 'sent', sent_at = now() WHERE id = $1",
    )
    .await;
    let cancelling = {
        let store = store.clone();
        tokio::spawn(async move { store.cancel(id, at(1)).await.unwrap() })
    };
    waiting(&cancelling).await;
    held.commit().await.unwrap();

    assert_eq!(cancelling.await.unwrap(), CancelOutcome::NotQueued);
    assert!(matches!(state(&store, id).await, RequestState::Sent { .. }));
}

/// Expiring and cancelling the same request at once: whichever commits first wins.
#[sqlx::test]
#[ignore = "needs PostgreSQL: DATABASE_URL"]
async fn pg_a_request_cancelled_while_it_expires_stays_cancelled(
    pool: PgPoolOptions,
    options: PgConnectOptions,
) {
    let mut raw = PgConnection::connect_with(&options).await.unwrap();
    let store = store(pool, options).await;
    let (_, id) = queued(&store).await;

    let held = hold(
        &mut raw,
        id,
        "UPDATE action_requests SET status = 'cancelled', finished_at = now() WHERE id = $1",
    )
    .await;
    let expiring = {
        let store = store.clone();
        tokio::spawn(async move { store.expire(at(7200)).await.unwrap() })
    };
    waiting(&expiring).await;
    held.commit().await.unwrap();

    assert_eq!(expiring.await.unwrap(), []);
    assert!(matches!(
        state(&store, id).await,
        RequestState::Cancelled { .. }
    ));
}

/// Two answers to one request at once (a session that was replaced, and the new one): the
/// second is judged against what the first stored, never written over it.
#[sqlx::test]
#[ignore = "needs PostgreSQL: DATABASE_URL"]
async fn pg_two_answers_at_once_are_judged_one_after_the_other(
    pool: PgPoolOptions,
    options: PgConnectOptions,
) {
    let mut raw = PgConnection::connect_with(&options).await.unwrap();
    let store = store(pool, options).await;
    let (device, id) = queued(&store).await;
    store.claim_due(&[device], at(1)).await.unwrap();

    let held = hold(
        &mut raw,
        id,
        "UPDATE action_requests SET status = 'succeeded', duration_ms = 1, finished_at = now()
         WHERE id = $1",
    )
    .await;
    let answering = {
        let store = store.clone();
        tokio::spawn(async move {
            let result = ActionResult {
                request_id: id,
                outcome: ActionOutcome::Rejected {
                    reason: RejectReason::BadSignature,
                },
                output: None,
                duration_ms: 2,
            };
            store.finish(device, &result, at(2)).await.unwrap()
        })
    };
    waiting(&answering).await;
    held.commit().await.unwrap();

    assert_eq!(answering.await.unwrap(), Finish::Conflicting);
    let RequestState::Answered { outcome, .. } = state(&store, id).await else {
        panic!("not answered");
    };
    assert_eq!(outcome, ActionOutcome::Succeeded {});
}

/// Requests for one device take turns on its row, so many at once never pass the limit.
#[sqlx::test]
#[ignore = "needs PostgreSQL: DATABASE_URL"]
async fn pg_requests_at_once_never_pass_the_limit(pool: PgPoolOptions, options: PgConnectOptions) {
    let store = store(pool, options).await;
    let entry = catalog(&store).await;
    let device = active(&store, 1).await;
    for _ in 1..MAX_OPEN_PER_DEVICE {
        assert_eq!(ask(&store, device, &entry).await, RequestOutcome::Queued);
    }
    let outcomes = join_all((0..8).map(|_| {
        let (store, entry) = (store.clone(), entry.clone());
        tokio::spawn(async move { ask(&store, device, &entry).await })
    }))
    .await;
    let outcomes: Vec<_> = outcomes.into_iter().map(Result::unwrap).collect();
    let queued = outcomes
        .iter()
        .filter(|o| **o == RequestOutcome::Queued)
        .count();
    assert_eq!(queued, 1, "{outcomes:?}");
    assert!(outcomes.iter().all(|o| *o == RequestOutcome::Queued
        || *o == RequestOutcome::Refused(RequestRefusal::TooManyOpen)));
}

/// Keys added at once take turns on the table, so the list never grows past its limit.
#[sqlx::test]
#[ignore = "needs PostgreSQL: DATABASE_URL"]
async fn pg_keys_added_at_once_never_pass_the_limit(
    pool: PgPoolOptions,
    options: PgConnectOptions,
) {
    let store = store(pool, options).await;
    for seed in 1..=3 {
        store
            .add_signing_key(manifest_public(seed), at(0))
            .await
            .unwrap();
    }
    let added = join_all((4..=9).map(|seed| {
        let store = store.clone();
        tokio::spawn(async move { store.add_signing_key(manifest_public(seed), at(0)).await })
    }))
    .await;
    let added: Vec<_> = added.into_iter().map(|a| a.unwrap().unwrap()).collect();
    assert_eq!(
        added.iter().filter(|a| **a == KeyAdded::Added).count(),
        1,
        "{added:?}"
    );
    assert_eq!(store.signing_keys().await.unwrap().len(), 4);
}

/// `output` is free text from the machine. A value the database refuses must not come back
/// in the error, which goes to the log. PostgreSQL's DETAIL of a failed check quotes the
/// whole row; a check put here by the test makes it fail on purpose.
#[sqlx::test]
#[ignore = "needs PostgreSQL: DATABASE_URL"]
async fn pg_an_error_carries_no_value_of_the_call(pool: PgPoolOptions, options: PgConnectOptions) {
    let mut raw = PgConnection::connect_with(&options).await.unwrap();
    let store = store(pool, options).await;
    let (device, id) = queued(&store).await;
    store.claim_due(&[device], at(1)).await.unwrap();
    sqlx::query(
        "ALTER TABLE action_requests ADD CONSTRAINT poison
         CHECK (output IS NULL OR output NOT LIKE '%SECRET%')",
    )
    .execute(&mut raw)
    .await
    .unwrap();

    let result = ActionResult {
        request_id: id,
        outcome: ActionOutcome::Succeeded {},
        output: Some("SECRET-CUSTOMER-RECORD".parse::<Output>().unwrap()),
        duration_ms: 1,
    };
    let error = store.finish(device, &result, at(2)).await.unwrap_err();
    for text in [error.to_string(), format!("{error:?}")] {
        assert!(!text.contains("SECRET"), "{text}");
    }
    assert_eq!(
        error.kind(),
        ErrorKind::Database(SqlState::of("23514").unwrap())
    );
    assert!(matches!(state(&store, id).await, RequestState::Sent { .. }));
}

/// The claim commits before its rows are read. One that does not read stays `sent` and is
/// not delivered; the others, of other devices, are.
#[sqlx::test]
#[ignore = "needs PostgreSQL: DATABASE_URL"]
async fn pg_a_claimed_row_that_does_not_read_keeps_no_other_from_its_session(
    pool: PgPoolOptions,
    options: PgConnectOptions,
) {
    let mut raw = PgConnection::connect_with(&options).await.unwrap();
    let store = store(pool, options).await;
    let entry = catalog(&store).await;
    let broken = active(&store, 1).await;
    let fine = active(&store, 2).await;
    ask(&store, broken, &entry).await;
    ask(&store, fine, &entry).await;
    let broken_id = store.requests(Some(broken), 1).await.unwrap()[0].id;
    let fine_id = store.requests(Some(fine), 1).await.unwrap()[0].id;
    sqlx::query("UPDATE action_requests SET initiator = '{}' WHERE id = $1")
        .bind(broken_id.as_uuid())
        .execute(&mut raw)
        .await
        .unwrap();

    let claimed = store.claim_due(&[broken, fine], at(1)).await.unwrap();
    let ids: Vec<_> = claimed.iter().map(|o| o.request.request_id).collect();
    assert_eq!(ids, [fine_id]);
    let status: String = sqlx::query_scalar("SELECT status FROM action_requests WHERE id = $1")
        .bind(broken_id.as_uuid())
        .fetch_one(&mut raw)
        .await
        .unwrap();
    assert_eq!(status, "sent");
}

/// The same when a session sends again what got no answer: one row that does not read
/// keeps no other from being sent.
#[sqlx::test]
#[ignore = "needs PostgreSQL: DATABASE_URL"]
async fn pg_a_request_to_send_again_that_does_not_read_keeps_no_other_back(
    pool: PgPoolOptions,
    options: PgConnectOptions,
) {
    let mut raw = PgConnection::connect_with(&options).await.unwrap();
    let store = store(pool, options).await;
    let entry = catalog(&store).await;
    let device = active(&store, 1).await;
    // Two sent and unanswered: the first expires before the second is claimed.
    let short = NewRequest {
        id: RequestId::new(),
        device,
        manifest: *entry.hash(),
        expires_at: u64::try_from(at(10).timestamp()).unwrap(),
        initiator: Initiator::Human {
            user_id: "server_cli".parse().unwrap(),
        },
    };
    store.request_action(&short, at(0)).await.unwrap();
    store.claim_due(&[device], at(1)).await.unwrap();
    ask(&store, device, &entry).await;
    let long = store.requests(Some(device), 1).await.unwrap()[0].id;
    store.claim_due(&[device], at(11)).await.unwrap();
    sqlx::query("UPDATE action_requests SET initiator = '{}' WHERE id = $1")
        .bind(short.id.as_uuid())
        .execute(&mut raw)
        .await
        .unwrap();

    let resent = store.resend(device, at(12)).await.unwrap();
    let ids: Vec<_> = resent.iter().map(|o| o.request.request_id).collect();
    assert_eq!(ids, [long]);
}

/// A row the code cannot read is an error, never a guess, and never quoted.
#[sqlx::test]
#[ignore = "needs PostgreSQL: DATABASE_URL"]
async fn pg_an_action_row_that_does_not_read_is_an_error(
    pool: PgPoolOptions,
    options: PgConnectOptions,
) {
    let mut raw = PgConnection::connect_with(&options).await.unwrap();
    let store = store(pool, options).await;
    let (device, id) = queued(&store).await;
    store.claim_due(&[device], at(1)).await.unwrap();
    let result = ActionResult {
        request_id: id,
        outcome: ActionOutcome::Rejected {
            reason: RejectReason::QueueFull,
        },
        output: None,
        duration_ms: 1,
    };
    store.finish(device, &result, at(2)).await.unwrap();

    sqlx::query("UPDATE action_requests SET reason = 'secret_reason' WHERE id = $1")
        .bind(id.as_uuid())
        .execute(&mut raw)
        .await
        .unwrap();
    let error = store.request(id).await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::CorruptRow("reason"));
    assert!(!error.to_string().contains("secret"), "{error}");
    // Judging a new answer reads the same row, and fails the same way.
    let error = store.finish(device, &result, at(3)).await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::CorruptRow("reason"));

    // An envelope whose text was edited is no longer the envelope its hash names.
    sqlx::query("UPDATE manifests SET manifest = manifest || '# edited' || chr(10)")
        .execute(&mut raw)
        .await
        .unwrap();
    let error = store.manifests(None).await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::CorruptRow("envelope hash"));

    // An id that could move a terminal's cursor never gets in.
    let refused = sqlx::query("UPDATE manifests SET manifest_id = 'erp.' || chr(27) || '[2J'")
        .execute(&mut raw)
        .await;
    assert!(refused.is_err());
}

/// A date of the wire that does not fit a `bigint` is refused, never saturated.
#[sqlx::test]
#[ignore = "needs PostgreSQL: DATABASE_URL"]
async fn pg_a_date_past_the_range_of_the_database_is_refused(
    pool: PgPoolOptions,
    options: PgConnectOptions,
) {
    let store = store(pool, options).await;
    let entry = catalog(&store).await;
    let device = active(&store, 1).await;
    let request = NewRequest {
        id: RequestId::new(),
        device,
        manifest: *entry.hash(),
        expires_at: u64::MAX,
        initiator: Initiator::Human {
            user_id: "server_cli".parse().unwrap(),
        },
    };
    assert_eq!(
        store.request_action(&request, at(0)).await.unwrap(),
        RequestOutcome::Refused(RequestRefusal::ExpiryOutOfRange)
    );

    let (device, id) = (device, {
        assert_eq!(ask(&store, device, &entry).await, RequestOutcome::Queued);
        store.requests(Some(device), 1).await.unwrap()[0].id
    });
    store.claim_due(&[device], at(1)).await.unwrap();
    let result = ActionResult {
        request_id: id,
        outcome: ActionOutcome::Succeeded {},
        output: None,
        duration_ms: u64::MAX,
    };
    let error = store.finish(device, &result, at(2)).await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::OutOfRange("duration"));
    assert!(matches!(state(&store, id).await, RequestState::Sent { .. }));
}

/// `action run` verifies the envelope it picks once more: a row whose id was changed in
/// the database is not the manifest it claims to be, and is not sent under that name.
#[sqlx::test]
#[ignore = "needs PostgreSQL: DATABASE_URL"]
async fn pg_an_envelope_changed_in_the_database_is_not_sent(
    pool: PgPoolOptions,
    options: PgConnectOptions,
) {
    let mut raw = PgConnection::connect_with(&options).await.unwrap();
    let store = store(pool, options).await;
    catalog(&store).await;
    let device = active(&store, 1).await;
    sqlx::query("UPDATE manifests SET manifest_id = 'erp.delete-everything'")
        .execute(&mut raw)
        .await
        .unwrap();

    let command = crate::admin::Command::ActionRun {
        device,
        manifest: "erp.delete-everything".parse().unwrap(),
        version: None,
        minutes: 10,
    };
    let mut out = Vec::new();
    let refused = crate::admin::run(&store, command, &mut out, at(0)).await;
    assert!(
        matches!(refused, Err(crate::admin::AdminError::NoValidManifest)),
        "{refused:?}"
    );
    assert_eq!(store.requests(None, 10).await.unwrap(), []);
}
