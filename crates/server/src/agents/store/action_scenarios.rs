//! The rules of [`ActionStore`] and [`ActionAdmin`], as scenarios any store must pass.
//!
//! Like `scenarios`, each takes a store that starts empty; `store.rs` runs them on
//! [`MemoryStore`](super::MemoryStore) and `pg/pg_tests.rs` on PostgreSQL.

use std::num::NonZeroU32;

use ponte_protocol::{
    ActionOutcome, ActionResult, DeviceId, FailReason, Initiator, Output, PublicKey, RejectReason,
    RequestId,
};

use super::actions::{
    ActionAdmin, ActionStore, CancelOutcome, CatalogEntry, Finish, KeyAdded, MAX_CLAIMED_PER_SWEEP,
    MAX_OPEN_PER_DEVICE, MAX_RESENT, NewRequest, Outgoing, RESEND_WINDOW_SECS, RequestOutcome,
    RequestRefusal, RequestState,
};
use super::{DeviceAdmin, DeviceStatus, EnrollOutcome, EnrollRequest, TokenGrant, TokenHash};
use crate::agents::testkit::{about, at, catalog_entry, manifest_public, token};

/// Calls `$test!(name)` once for every scenario of this module.
macro_rules! for_each_action_scenario {
    ($test:ident) => {
        $test!(signing_keys_are_trusted_up_to_the_limit);
        $test!(an_envelope_enters_the_catalog_once);
        $test!(a_request_needs_an_active_device_and_a_manifest_the_catalog_holds);
        $test!(a_device_has_a_bounded_number_of_open_requests);
        $test!(the_sweep_sends_one_request_at_a_time_to_each_connected_active_device);
        $test!(the_sweep_sends_nothing_expired_and_nothing_signed_by_a_removed_key);
        $test!(the_sweep_serves_the_oldest_requests_first_across_devices);
        $test!(a_result_is_taken_only_from_its_device_and_only_for_a_sent_request);
        $test!(a_second_result_is_judged_against_the_first);
        $test!(a_refusal_that_describes_the_agent_gives_way_to_a_later_result);
        $test!(only_a_queued_request_is_cancelled);
        $test!(only_queued_requests_expire);
        $test!(requests_that_got_no_answer_are_sent_again);
        $test!(a_request_that_never_reached_the_connection_goes_back_to_the_queue);
        $test!(requests_are_listed_newest_first);
    };
}
pub(crate) use for_each_action_scenario;

const ID: &str = "erp.restart-service";

/// An active device enrolled with `token(seed)` and key `[seed; 32]`.
async fn active<S: DeviceAdmin>(store: &S, seed: u8) -> DeviceId {
    let name = format!("Customer {seed}").parse().unwrap();
    let customer = store.add_customer(&name).await.unwrap().unwrap();
    let grant = TokenGrant {
        customer,
        expires_at: at(1_000_000),
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

/// Trusts key 1 and adds `erp.restart-service` v1 signed by it.
async fn catalog<S: ActionAdmin>(store: &S) -> CatalogEntry {
    store
        .add_signing_key(manifest_public(1), at(0))
        .await
        .unwrap();
    let entry = catalog_entry(1, ID, 1, 0);
    assert!(store.add_manifest(&entry, at(0)).await.unwrap());
    entry
}

fn operator() -> Initiator {
    Initiator::Human {
        user_id: "server_cli".parse().unwrap(),
    }
}

/// Seconds since the Unix epoch of `at(secs)`.
fn epoch(secs: i64) -> u64 {
    u64::try_from(at(secs).timestamp()).unwrap()
}

/// Asks at `at(asked)` for `entry` on `device`, expiring at `at(expires)`.
async fn ask_at<S: ActionAdmin>(
    store: &S,
    device: DeviceId,
    entry: &CatalogEntry,
    asked: i64,
    expires: i64,
) -> Result<RequestId, RequestRefusal> {
    let id = RequestId::new();
    let request = NewRequest {
        id,
        device,
        manifest: *entry.hash(),
        expires_at: epoch(expires),
        initiator: operator(),
    };
    match store.request_action(&request, at(asked)).await.unwrap() {
        RequestOutcome::Queued => Ok(id),
        RequestOutcome::Refused(refusal) => Err(refusal),
    }
}

async fn ask<S: ActionAdmin>(store: &S, device: DeviceId, entry: &CatalogEntry) -> RequestId {
    ask_at(store, device, entry, 0, 3600).await.unwrap()
}

async fn claim<S: ActionStore>(store: &S, online: &[DeviceId], now: i64) -> Vec<RequestId> {
    let claimed = store.claim_due(online, at(now)).await.unwrap();
    claimed
        .iter()
        .map(|outgoing| outgoing.request.request_id)
        .collect()
}

fn answer(id: RequestId, outcome: ActionOutcome) -> ActionResult {
    ActionResult {
        request_id: id,
        outcome,
        output: None,
        duration_ms: 1500,
    }
}

fn succeeded() -> ActionOutcome {
    ActionOutcome::Succeeded {}
}

fn rejected(reason: RejectReason) -> ActionOutcome {
    ActionOutcome::Rejected { reason }
}

async fn state<S: ActionAdmin>(store: &S, id: RequestId) -> RequestState {
    store.request(id).await.unwrap().unwrap().state
}

async fn finish<S: ActionStore>(
    store: &S,
    device: DeviceId,
    id: RequestId,
    outcome: ActionOutcome,
) -> Finish {
    store
        .finish(device, &answer(id, outcome), at(2))
        .await
        .unwrap()
}

fn outcome_of(state: &RequestState) -> Option<&ActionOutcome> {
    match state {
        RequestState::Answered { outcome, .. } => Some(outcome),
        _ => None,
    }
}

pub(crate) async fn signing_keys_are_trusted_up_to_the_limit<S: ActionAdmin>(store: &S) {
    assert_eq!(store.signing_keys().await.unwrap(), []);
    for seed in 1..=4 {
        let added = store.add_signing_key(manifest_public(seed), at(i64::from(seed)));
        assert_eq!(added.await.unwrap(), KeyAdded::Added);
    }
    let again = store.add_signing_key(manifest_public(2), at(9)).await;
    assert_eq!(again.unwrap(), KeyAdded::AlreadyTrusted);
    let fifth = store.add_signing_key(manifest_public(5), at(9)).await;
    assert_eq!(fifth.unwrap(), KeyAdded::Full);

    let keys = store.signing_keys().await.unwrap();
    let listed: Vec<_> = keys.iter().map(|key| key.public_key).collect();
    assert_eq!(listed, (1..=4).map(manifest_public).collect::<Vec<_>>());
    assert_eq!(keys[0].added_at, at(1));

    assert!(store.remove_signing_key(&manifest_public(2)).await.unwrap());
    assert!(!store.remove_signing_key(&manifest_public(2)).await.unwrap());
    let added = store.add_signing_key(manifest_public(5), at(10)).await;
    assert_eq!(added.unwrap(), KeyAdded::Added);
}

/// ADR-0010: an envelope is its hash, so the same one twice is one row, and re-signing a
/// version to renew it is a second one.
pub(crate) async fn an_envelope_enters_the_catalog_once<S: ActionAdmin>(store: &S) {
    let first = catalog_entry(1, ID, 1, -100);
    let renewed = catalog_entry(1, ID, 1, -50);
    let other = catalog_entry(2, "erp.clear-stale-lock", 2, -100);
    assert_ne!(first.hash(), renewed.hash());

    assert!(store.add_manifest(&renewed, at(0)).await.unwrap());
    assert!(store.add_manifest(&first, at(0)).await.unwrap());
    assert!(!store.add_manifest(&first, at(1)).await.unwrap());
    assert!(store.add_manifest(&other, at(0)).await.unwrap());

    let all = store.manifests(None).await.unwrap();
    let hashes: Vec<_> = all.iter().map(CatalogEntry::hash).collect();
    assert_eq!(hashes, [other.hash(), first.hash(), renewed.hash()]);
    assert_eq!(all[1], first);

    let id = ID.parse().unwrap();
    let one = store.manifests(Some(&id)).await.unwrap();
    assert_eq!(one, [first, renewed]);
    let none = store.manifests(Some(&"erp.other".parse().unwrap())).await;
    assert_eq!(none.unwrap(), []);
}

/// RF-49 and RF-04: a pending or revoked device is sent no action, so none is queued for
/// it either.
pub(crate) async fn a_request_needs_an_active_device_and_a_manifest_the_catalog_holds<
    S: ActionAdmin,
>(
    store: &S,
) {
    let entry = catalog(store).await;
    let device = active(store, 1).await;

    let pending = {
        let name = "Pending".parse().unwrap();
        let customer = store.add_customer(&name).await.unwrap().unwrap();
        let grant = TokenGrant {
            customer,
            expires_at: at(100),
            max_uses: NonZeroU32::new(2).unwrap(),
        };
        let hash = TokenHash::of(&token(50));
        assert!(store.issue_token(hash, grant).await.unwrap());
        let request = EnrollRequest {
            token: hash,
            public_key: PublicKey::from_bytes([50; 32]),
            about: about(),
        };
        match store.enroll(request, at(0)).await.unwrap() {
            EnrollOutcome::Enrolled { device_id, .. } => device_id,
            EnrollOutcome::Refused(refusal) => panic!("{refusal:?}"),
        }
    };
    let revoked = active(store, 2).await;
    assert!(store.revoke_device(revoked).await.unwrap());

    let refused = |device| ask_at(store, device, &entry, 0, 3600);
    assert_eq!(
        refused(DeviceId::new()).await,
        Err(RequestRefusal::UnknownDevice)
    );
    assert_eq!(
        refused(pending).await,
        Err(RequestRefusal::DeviceNotActive(DeviceStatus::Pending))
    );
    assert_eq!(
        refused(revoked).await,
        Err(RequestRefusal::DeviceNotActive(DeviceStatus::Revoked))
    );
    let unknown = catalog_entry(1, "erp.not-in-the-catalog", 1, 0);
    assert_eq!(
        ask_at(store, device, &unknown, 0, 3600).await,
        Err(RequestRefusal::UnknownManifest)
    );
    assert_eq!(store.requests(None, 100).await.unwrap(), []);

    let id = ask(store, device, &entry).await;
    let record = store.request(id).await.unwrap().unwrap();
    assert_eq!(record.device, device);
    assert_eq!(record.manifest, *entry.hash());
    assert_eq!(record.manifest_id.as_str(), ID);
    assert_eq!(record.version, 1);
    assert_eq!(record.initiator, operator());
    assert_eq!(record.expires_at, epoch(3600));
    assert_eq!(record.created_at, at(0));
    assert_eq!(record.state, RequestState::Queued);
    assert_eq!(store.request(RequestId::new()).await.unwrap(), None);
}

/// Requests that are queued, or sent and not expired, count; a sent one that expired with
/// no answer does not, or a device whose agent never answers would be locked out for good.
pub(crate) async fn a_device_has_a_bounded_number_of_open_requests<S: ActionAdmin>(store: &S) {
    let entry = catalog(store).await;
    let device = active(store, 1).await;
    let other = active(store, 2).await;
    let open = i64::try_from(MAX_OPEN_PER_DEVICE).unwrap();

    // As many sent as the limit, each unanswered and expired before the next is claimed.
    for asked in 0..open {
        let id = ask_at(store, device, &entry, asked, asked + 1)
            .await
            .unwrap();
        assert_eq!(claim(store, &[device], asked).await, [id]);
    }
    // None of them counts any more.
    let now = open;
    for _ in 0..MAX_OPEN_PER_DEVICE {
        ask_at(store, device, &entry, now, 3600).await.unwrap();
    }
    assert_eq!(
        ask_at(store, device, &entry, now, 3600).await,
        Err(RequestRefusal::TooManyOpen)
    );
    // Per device.
    ask_at(store, other, &entry, now, 3600).await.unwrap();

    // A sent one that has not expired still counts.
    assert_eq!(claim(store, &[device], now + 1).await.len(), 1);
    assert_eq!(
        ask_at(store, device, &entry, now + 1, 3600).await,
        Err(RequestRefusal::TooManyOpen)
    );
}

/// ADR-0012: the sweep claims what is due for the devices that are connected, one request
/// in flight per device, and only for an active device.
pub(crate) async fn the_sweep_sends_one_request_at_a_time_to_each_connected_active_device<
    S: ActionAdmin,
>(
    store: &S,
) {
    let entry = catalog(store).await;
    let (one, two, away) = (
        active(store, 1).await,
        active(store, 2).await,
        active(store, 3).await,
    );
    let first = ask_at(store, one, &entry, 0, 3600).await.unwrap();
    let second = ask_at(store, one, &entry, 1, 3600).await.unwrap();
    let theirs = ask_at(store, two, &entry, 2, 3600).await.unwrap();
    let elsewhere = ask_at(store, away, &entry, 3, 3600).await.unwrap();

    let claimed = store.claim_due(&[one, two], at(10)).await.unwrap();
    let ids: Vec<_> = claimed.iter().map(|o| o.request.request_id).collect();
    assert_eq!(ids, [first, theirs]);
    let Outgoing {
        device,
        id,
        version,
        request,
    } = &claimed[0];
    assert_eq!((*device, id.as_str(), *version), (one, ID, 1));
    assert_eq!(request.manifest, *entry.envelope());
    assert_eq!(request.expires_at, epoch(3600));
    assert_eq!(request.initiator, operator());
    assert_eq!(state(store, first).await, RequestState::Sent { at: at(10) });
    assert_eq!(state(store, second).await, RequestState::Queued);
    assert_eq!(state(store, elsewhere).await, RequestState::Queued);

    // Nothing more while the first is unanswered.
    assert_eq!(claim(store, &[one, two], 11).await, []);
    assert_eq!(
        finish(store, one, first, succeeded()).await,
        Finish::Recorded { replaced: false }
    );
    assert_eq!(claim(store, &[one, two], 12).await, [second]);

    // A device revoked after the request was queued is sent nothing.
    let third = ask_at(store, two, &entry, 13, 3600).await.unwrap();
    assert_eq!(
        finish(store, two, theirs, succeeded()).await,
        Finish::Recorded { replaced: false }
    );
    assert!(store.revoke_device(two).await.unwrap());
    assert_eq!(claim(store, &[two], 14).await, []);
    assert_eq!(state(store, third).await, RequestState::Queued);
    assert_eq!(claim(store, &[], 14).await, []);
}

pub(crate) async fn the_sweep_sends_nothing_expired_and_nothing_signed_by_a_removed_key<
    S: ActionAdmin,
>(
    store: &S,
) {
    let entry = catalog(store).await;
    let device = active(store, 1).await;
    let short = ask_at(store, device, &entry, 0, 5).await.unwrap();
    let long = ask_at(store, device, &entry, 1, 3600).await.unwrap();

    // Expired at the instant it expires.
    assert_eq!(claim(store, &[device], 5).await, [long]);
    assert_eq!(state(store, short).await, RequestState::Queued);

    // A sent request that expired with no answer no longer holds the device's turn.
    let next = ask_at(store, device, &entry, 2, 7200).await.unwrap();
    assert_eq!(claim(store, &[device], 3599).await, []);
    assert_eq!(claim(store, &[device], 3600).await, [next]);

    // A key the server no longer trusts sends nothing, also for what was queued before.
    let last = ask_at(store, device, &entry, 3, 7200).await.unwrap();
    assert_eq!(
        finish(store, device, next, succeeded()).await,
        Finish::Recorded { replaced: false }
    );
    assert!(store.remove_signing_key(&manifest_public(1)).await.unwrap());
    assert_eq!(claim(store, &[device], 3601).await, []);
    assert_eq!(state(store, last).await, RequestState::Queued);
}

/// One request per device, and among those the oldest first: devices enrolled late are
/// not left behind.
pub(crate) async fn the_sweep_serves_the_oldest_requests_first_across_devices<S: ActionAdmin>(
    store: &S,
) {
    let entry = catalog(store).await;
    let count = MAX_CLAIMED_PER_SWEEP + 1;
    let mut devices = Vec::new();
    for seed in 0..count {
        devices.push(active(store, u8::try_from(seed + 1).unwrap()).await);
    }
    // The last device enrolled asks first.
    let mut asked = Vec::new();
    for (index, device) in devices.iter().rev().enumerate() {
        let id = ask_at(store, *device, &entry, i64::try_from(index).unwrap(), 3600);
        asked.push(id.await.unwrap());
    }
    let claimed = claim(store, &devices, 100).await;
    assert_eq!(claimed, asked[..MAX_CLAIMED_PER_SWEEP]);
    assert_eq!(
        claim(store, &devices, 101).await,
        asked[MAX_CLAIMED_PER_SWEEP..]
    );
}

/// ADR-0012: a result is stored only if it comes from the device the request was sent to
/// and the request is `sent`. Anything else changes nothing.
pub(crate) async fn a_result_is_taken_only_from_its_device_and_only_for_a_sent_request<
    S: ActionAdmin,
>(
    store: &S,
) {
    let entry = catalog(store).await;
    let (device, other) = (active(store, 1).await, active(store, 2).await);
    let id = ask(store, device, &entry).await;

    // Never sent: a device cannot answer what it was not asked.
    assert_eq!(
        finish(store, device, id, succeeded()).await,
        Finish::NotSent
    );
    assert_eq!(state(store, id).await, RequestState::Queued);

    assert_eq!(claim(store, &[device], 1).await, [id]);
    assert_eq!(
        finish(store, other, id, succeeded()).await,
        Finish::OtherDevice
    );
    assert_eq!(
        finish(store, device, RequestId::new(), succeeded()).await,
        Finish::Unknown
    );
    assert_eq!(state(store, id).await, RequestState::Sent { at: at(1) });

    let failed = ActionOutcome::Failed {
        reason: FailReason::VerifyFailed,
        step: Some(0),
    };
    let result = ActionResult {
        output: Some("SECRET-CUSTOMER-RECORD".parse::<Output>().unwrap()),
        ..answer(id, failed.clone())
    };
    let finished = store.finish(device, &result, at(3)).await.unwrap();
    assert_eq!(finished, Finish::Recorded { replaced: false });
    assert_eq!(
        state(store, id).await,
        RequestState::Answered {
            sent_at: at(1),
            at: at(3),
            outcome: failed,
            duration_ms: 1500,
            output: result.output.clone(),
        }
    );

    // Cancelled or expired before it was sent: never sent either.
    let cancelled = ask(store, device, &entry).await;
    let expired = ask_at(store, device, &entry, 0, 4).await.unwrap();
    assert_eq!(
        store.cancel(cancelled, at(4)).await.unwrap(),
        CancelOutcome::Cancelled
    );
    assert_eq!(store.expire(at(4)).await.unwrap(), [(expired, device)]);
    for never in [cancelled, expired] {
        assert_eq!(
            finish(store, device, never, succeeded()).await,
            Finish::NotSent
        );
    }
}

/// An identical second answer is a copy (ADR-0012); a different one is an anomaly, and the
/// first stays.
pub(crate) async fn a_second_result_is_judged_against_the_first<S: ActionAdmin>(store: &S) {
    let entry = catalog(store).await;
    let device = active(store, 1).await;
    let id = ask(store, device, &entry).await;
    claim(store, &[device], 1).await;
    let refused = rejected(RejectReason::BadSignature);
    assert_eq!(
        finish(store, device, id, refused.clone()).await,
        Finish::Recorded { replaced: false }
    );

    // The same outcome with another duration is still the same answer: the journal sends
    // what it recorded, without the output.
    let copy = ActionResult {
        duration_ms: 7,
        ..answer(id, refused.clone())
    };
    assert_eq!(
        store.finish(device, &copy, at(5)).await.unwrap(),
        Finish::Repeated
    );
    assert_eq!(
        finish(store, device, id, succeeded()).await,
        Finish::Conflicting
    );
    let failed = ActionOutcome::Failed {
        reason: FailReason::StepFailed,
        step: Some(1),
    };
    assert_eq!(finish(store, device, id, failed).await, Finish::Conflicting);
    assert_eq!(outcome_of(&state(store, id).await), Some(&refused));
}

/// A refusal the agent sends without recording it says that copy did not run, not that the
/// request never will. A later result of the same device takes its place, once.
pub(crate) async fn a_refusal_that_describes_the_agent_gives_way_to_a_later_result<
    S: ActionAdmin,
>(
    store: &S,
) {
    let entry = catalog(store).await;
    let (device, other) = (active(store, 1).await, active(store, 2).await);
    for reason in [
        RejectReason::ActionsDisabled,
        RejectReason::QueueFull,
        RejectReason::ShuttingDown,
        RejectReason::JournalFull,
        RejectReason::JournalUnavailable,
        RejectReason::ClockWentBack,
    ] {
        let id = ask(store, device, &entry).await;
        assert_eq!(claim(store, &[device], 1).await, [id]);
        assert_eq!(
            finish(store, device, id, rejected(reason)).await,
            Finish::Recorded { replaced: false }
        );
        assert_eq!(
            finish(store, device, id, rejected(reason)).await,
            Finish::Repeated
        );
        assert_eq!(
            finish(store, other, id, succeeded()).await,
            Finish::OtherDevice
        );
        assert_eq!(
            finish(store, device, id, succeeded()).await,
            Finish::Recorded { replaced: true }
        );
        // The answer that replaced it is not replaced in turn.
        assert_eq!(
            finish(store, device, id, rejected(reason)).await,
            Finish::Conflicting
        );
        assert_eq!(outcome_of(&state(store, id).await), Some(&succeeded()));
    }

    // A refusal about the request itself is final.
    let id = ask(store, device, &entry).await;
    claim(store, &[device], 1).await;
    let refused = rejected(RejectReason::ServiceNotAllowed);
    finish(store, device, id, refused.clone()).await;
    assert_eq!(
        finish(store, device, id, succeeded()).await,
        Finish::Conflicting
    );
    assert_eq!(outcome_of(&state(store, id).await), Some(&refused));
}

/// ADR-0012: what reached the agent is the agent's; only the queue can be cancelled.
pub(crate) async fn only_a_queued_request_is_cancelled<S: ActionAdmin>(store: &S) {
    let entry = catalog(store).await;
    let device = active(store, 1).await;
    let queued = ask_at(store, device, &entry, 0, 3600).await.unwrap();
    let later = ask_at(store, device, &entry, 1, 3600).await.unwrap();

    assert_eq!(
        store.cancel(queued, at(2)).await.unwrap(),
        CancelOutcome::Cancelled
    );
    assert_eq!(
        state(store, queued).await,
        RequestState::Cancelled { at: at(2) }
    );
    assert_eq!(
        store.cancel(queued, at(3)).await.unwrap(),
        CancelOutcome::NotQueued
    );
    assert_eq!(
        store.cancel(RequestId::new(), at(3)).await.unwrap(),
        CancelOutcome::Unknown
    );

    // A cancelled request is not sent; the next one is, and then cannot be cancelled.
    assert_eq!(claim(store, &[device], 4).await, [later]);
    assert_eq!(
        store.cancel(later, at(5)).await.unwrap(),
        CancelOutcome::NotQueued
    );
    assert_eq!(state(store, later).await, RequestState::Sent { at: at(4) });
    finish(store, device, later, succeeded()).await;
    assert_eq!(
        store.cancel(later, at(6)).await.unwrap(),
        CancelOutcome::NotQueued
    );
}

/// A queued request that expires is marked so; a sent one waits for its answer.
pub(crate) async fn only_queued_requests_expire<S: ActionAdmin>(store: &S) {
    let entry = catalog(store).await;
    let (device, other) = (active(store, 1).await, active(store, 2).await);
    let sent = ask_at(store, device, &entry, 0, 10).await.unwrap();
    assert_eq!(claim(store, &[device], 1).await, [sent]);
    let waiting = ask_at(store, device, &entry, 1, 10).await.unwrap();
    let theirs = ask_at(store, other, &entry, 2, 11).await.unwrap();

    assert_eq!(store.expire(at(9)).await.unwrap(), []);
    assert_eq!(store.expire(at(10)).await.unwrap(), [(waiting, device)]);
    assert_eq!(
        state(store, waiting).await,
        RequestState::Expired { at: at(10) }
    );
    assert_eq!(state(store, sent).await, RequestState::Sent { at: at(1) });
    assert_eq!(state(store, theirs).await, RequestState::Queued);
    assert_eq!(store.expire(at(11)).await.unwrap(), [(theirs, other)]);
    assert_eq!(store.expire(at(12)).await.unwrap(), []);

    // An answer that comes late is still taken.
    assert_eq!(
        store
            .finish(device, &answer(sent, succeeded()), at(20))
            .await
            .unwrap(),
        Finish::Recorded { replaced: false }
    );
}

/// ADR-0012: a session starts by sending again what got no answer. The agent answers a
/// request it knows from its journal, so this recovers results lost on the way.
pub(crate) async fn requests_that_got_no_answer_are_sent_again<S: ActionAdmin>(store: &S) {
    let entry = catalog(store).await;
    let (device, other) = (active(store, 1).await, active(store, 2).await);
    let hour = 3600;
    let window = RESEND_WINDOW_SECS;

    // Sent one after the other, each expiring before the next is claimed.
    let mut sent = Vec::new();
    for index in 0..6 {
        let asked = index * hour;
        let id = ask_at(store, device, &entry, asked, asked + hour)
            .await
            .unwrap();
        assert_eq!(claim(store, &[device], asked).await, [id]);
        sent.push(id);
    }
    let answered = sent.remove(5);
    finish(store, device, answered, succeeded()).await;
    let fresh = ask_at(store, device, &entry, 6 * hour, 30 * hour)
        .await
        .unwrap();
    assert_eq!(claim(store, &[device], 6 * hour).await, [fresh]);
    let theirs = ask_at(store, other, &entry, 0, hour).await.unwrap();
    claim(store, &[other], 0).await;

    let again = |now| async move {
        let outgoing = store.unanswered(device, at(now)).await.unwrap();
        assert!(outgoing.iter().all(|o| o.device == device));
        outgoing
            .iter()
            .map(|o| o.request.request_id)
            .collect::<Vec<_>>()
    };
    // The one still valid first, then the oldest, at most four.
    assert_eq!(MAX_RESENT, 4);
    let now = 6 * hour;
    assert_eq!(again(now).await, [fresh, sent[0], sent[1], sent[2]]);
    // Past the window, the agent may have forgotten them: they are left alone.
    let now = hour + window;
    assert_eq!(again(now).await, [fresh, sent[1], sent[2], sent[3]]);
    assert!(!again(now).await.contains(&theirs));

    // Nothing signed by a key no longer trusted, and nothing for a revoked device.
    assert!(store.remove_signing_key(&manifest_public(1)).await.unwrap());
    assert_eq!(again(now).await, []);
    store
        .add_signing_key(manifest_public(1), at(0))
        .await
        .unwrap();
    assert!(store.revoke_device(device).await.unwrap());
    assert_eq!(again(now).await, []);
}

/// The sweep marks a request sent before the session has it. If the session cannot take
/// it, it never reached the wire, and goes back to the queue.
pub(crate) async fn a_request_that_never_reached_the_connection_goes_back_to_the_queue<
    S: ActionAdmin,
>(
    store: &S,
) {
    let entry = catalog(store).await;
    let device = active(store, 1).await;
    let id = ask(store, device, &entry).await;
    assert_eq!(claim(store, &[device], 1).await, [id]);
    assert!(store.release(id).await.unwrap());
    assert!(!store.release(id).await.unwrap());
    assert_eq!(state(store, id).await, RequestState::Queued);
    assert_eq!(claim(store, &[device], 2).await, [id]);
    finish(store, device, id, succeeded()).await;
    assert!(!store.release(id).await.unwrap());
    assert!(!store.release(RequestId::new()).await.unwrap());
}

pub(crate) async fn requests_are_listed_newest_first<S: ActionAdmin>(store: &S) {
    let entry = catalog(store).await;
    let (device, other) = (active(store, 1).await, active(store, 2).await);
    let mut mine = Vec::new();
    for asked in 0..3 {
        mine.push(ask_at(store, device, &entry, asked, 3600).await.unwrap());
    }
    let theirs = ask_at(store, other, &entry, 5, 3600).await.unwrap();
    let ids = |records: Vec<crate::agents::RequestRecord>| -> Vec<RequestId> {
        records.iter().map(|record| record.id).collect()
    };
    let all = store.requests(None, 100).await.unwrap();
    assert_eq!(ids(all), [theirs, mine[2], mine[1], mine[0]]);
    let two = store.requests(Some(device), 2).await.unwrap();
    assert_eq!(ids(two), [mine[2], mine[1]]);
}
