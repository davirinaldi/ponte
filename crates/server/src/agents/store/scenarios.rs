//! The rules of [`DeviceStore`] and [`DeviceAdmin`], as scenarios any store must pass.
//!
//! Each scenario takes a store that starts empty. `store.rs` runs them all on
//! [`MemoryStore`](super::MemoryStore), and the PostgreSQL store runs the same list (see
//! [`for_each_scenario`]), so the two cannot drift apart.

use std::num::NonZeroU32;

use chrono::TimeDelta;
use ponte_protocol::{DeviceId, PublicKey};

use super::{
    AgentInfo, CustomerId, CustomerName, Device, DeviceAdmin, DeviceRecord, DeviceStatus,
    EnrollOutcome, EnrollRefusal, EnrollRequest, SessionId, TokenGrant, TokenHash,
};
use crate::agents::testkit::{about, at, telemetry, token};

/// Calls `$test!(name)` once for every scenario of this module.
macro_rules! for_each_scenario {
    ($test:ident) => {
        $test!(a_single_use_token_enrolls_one_active_device);
        $test!(a_multi_use_token_enrolls_pending_devices_up_to_its_limit);
        $test!(a_token_that_is_unknown_expired_or_revoked_does_nothing);
        $test!(issuing_a_token_twice_does_not_reset_it);
        $test!(a_token_needs_a_customer_that_exists);
        $test!(repeating_an_enrollment_gives_the_same_device_and_spends_nothing);
        $test!(a_repeated_enrollment_after_the_deadline_gives_the_same_device);
        $test!(a_repeated_enrollment_with_a_revoked_token_is_refused);
        $test!(a_key_enrolls_once);
        $test!(a_revoked_device_does_not_enroll_again);
        $test!(revoking_a_device_takes_it_offline);
        $test!(only_a_pending_device_can_be_approved);
        $test!(telemetry_is_kept_for_an_active_device_only);
        $test!(a_replaced_session_does_not_mark_the_device_offline);
        $test!(a_session_of_a_revoked_device_does_not_start);
        $test!(customer_names_are_unique);
        $test!(lists_hold_what_was_added_and_can_be_narrowed_to_a_customer);
    };
}
pub(crate) use for_each_scenario;

fn key(seed: u8) -> PublicKey {
    PublicKey::from_bytes([seed; 32])
}

fn hash(token_seed: u8) -> TokenHash {
    TokenHash::of(&token(token_seed))
}

fn request(token_seed: u8, key_seed: u8) -> EnrollRequest {
    EnrollRequest {
        token: hash(token_seed),
        public_key: key(key_seed),
        about: about(),
    }
}

fn newer() -> AgentInfo {
    AgentInfo {
        agent_version: "0.2.0".parse().unwrap(),
        os: about().os,
    }
}

async fn customer<S: DeviceAdmin>(store: &S, name: &str) -> CustomerId {
    let name: CustomerName = name.parse().unwrap();
    store.add_customer(&name).await.unwrap().unwrap()
}

/// Issues `token(token_seed)` for `max_uses` machines until `at(100)`, to a customer of
/// its own.
async fn issue<S: DeviceAdmin>(store: &S, token_seed: u8, max_uses: u32) -> CustomerId {
    let customer = customer(store, &format!("Customer {token_seed}")).await;
    let grant = TokenGrant {
        customer,
        expires_at: at(100),
        max_uses: NonZeroU32::new(max_uses).unwrap(),
    };
    assert!(store.issue_token(hash(token_seed), grant).await.unwrap());
    customer
}

async fn uses_left<S: DeviceAdmin>(store: &S, token_seed: u8) -> Option<u32> {
    let token = store.token(&hash(token_seed)).await.unwrap();
    token.map(|token| token.uses_left())
}

async fn enroll<S: DeviceAdmin>(store: &S, token_seed: u8, key_seed: u8) -> EnrollOutcome {
    store
        .enroll(request(token_seed, key_seed), at(0))
        .await
        .unwrap()
}

async fn enrolled<S: DeviceAdmin>(store: &S, token_seed: u8, key_seed: u8) -> DeviceId {
    match enroll(store, token_seed, key_seed).await {
        EnrollOutcome::Enrolled { device_id, .. } => device_id,
        EnrollOutcome::Refused(refusal) => panic!("refused: {refusal:?}"),
    }
}

async fn record_of<S: DeviceAdmin>(store: &S, id: DeviceId) -> DeviceRecord {
    store.device_record(id).await.unwrap().unwrap()
}

async fn status<S: DeviceAdmin>(store: &S, id: DeviceId) -> DeviceStatus {
    store.device_record(id).await.unwrap().unwrap().status
}

pub(crate) async fn a_single_use_token_enrolls_one_active_device<S: DeviceAdmin>(store: &S) {
    let customer = issue(store, 1, 1).await;

    let outcome = enroll(store, 1, 10).await;
    let EnrollOutcome::Enrolled {
        device_id,
        customer: enrolled_for,
        status,
        repeated,
    } = outcome
    else {
        panic!("{outcome:?}");
    };
    assert_eq!(enrolled_for, customer);
    assert_eq!(status, DeviceStatus::Active);
    assert!(!repeated);

    let device = store.device(device_id).await.unwrap().unwrap();
    assert_eq!(
        device,
        Device {
            id: device_id,
            customer,
            public_key: key(10),
            status: DeviceStatus::Active,
        }
    );
    let record = store.device_record(device_id).await.unwrap().unwrap();
    assert_eq!(record.id, device_id);
    assert_eq!(record.about, about());
    assert_eq!(record.online, None);
    assert_eq!(record.last_seen, None);
    assert_eq!(record.telemetry, None);
    assert_eq!(record.enrolled_with, hash(1));

    assert_eq!(uses_left(store, 1).await, Some(0));
    assert_eq!(
        enroll(store, 1, 11).await,
        EnrollOutcome::Refused(EnrollRefusal::ExhaustedToken)
    );
    assert_eq!(store.device(DeviceId::new()).await.unwrap(), None);
    assert_eq!(store.device_record(DeviceId::new()).await.unwrap(), None);
}

/// RF-49: a token for several machines can leak to more people, so its devices wait.
pub(crate) async fn a_multi_use_token_enrolls_pending_devices_up_to_its_limit<S: DeviceAdmin>(
    store: &S,
) {
    issue(store, 1, 2).await;

    for key_seed in [10, 11] {
        let id = enrolled(store, 1, key_seed).await;
        assert_eq!(status(store, id).await, DeviceStatus::Pending);
    }
    assert_eq!(
        enroll(store, 1, 12).await,
        EnrollOutcome::Refused(EnrollRefusal::ExhaustedToken)
    );
    assert_eq!(uses_left(store, 1).await, Some(0));
}

pub(crate) async fn a_token_that_is_unknown_expired_or_revoked_does_nothing<S: DeviceAdmin>(
    store: &S,
) {
    issue(store, 1, 5).await;
    issue(store, 2, 5).await;
    assert!(store.revoke_token(&hash(2)).await.unwrap());
    assert!(store.revoke_token(&hash(2)).await.unwrap());
    assert!(!store.revoke_token(&hash(3)).await.unwrap());

    let just_in_time = at(100) - TimeDelta::microseconds(1);
    for (token_seed, now, refusal) in [
        (3, at(0), EnrollRefusal::UnknownToken),
        (1, at(100), EnrollRefusal::ExpiredToken),
        (1, at(1_000_000), EnrollRefusal::ExpiredToken),
        (2, at(0), EnrollRefusal::RevokedToken),
    ] {
        let outcome = store.enroll(request(token_seed, 10), now).await.unwrap();
        assert_eq!(outcome, EnrollOutcome::Refused(refusal));
    }
    assert_eq!(uses_left(store, 1).await, Some(5));
    assert_eq!(uses_left(store, 2).await, Some(5));
    assert_eq!(uses_left(store, 3).await, None);
    assert!(store.devices(None).await.unwrap().is_empty());

    let outcome = store.enroll(request(1, 10), just_in_time).await.unwrap();
    assert!(matches!(outcome, EnrollOutcome::Enrolled { .. }));
}

pub(crate) async fn issuing_a_token_twice_does_not_reset_it<S: DeviceAdmin>(store: &S) {
    let customer = issue(store, 1, 1).await;
    assert!(store.revoke_token(&hash(1)).await.unwrap());
    let again = TokenGrant {
        customer,
        expires_at: at(1_000),
        max_uses: NonZeroU32::new(9).unwrap(),
    };
    assert!(!store.issue_token(hash(1), again).await.unwrap());

    let token = store.token(&hash(1)).await.unwrap().unwrap();
    assert_eq!(token.grant.max_uses.get(), 1);
    assert_eq!(token.grant.expires_at, at(100));
    assert!(token.revoked);
}

pub(crate) async fn a_token_needs_a_customer_that_exists<S: DeviceAdmin>(store: &S) {
    let grant = TokenGrant {
        customer: CustomerId::new(),
        expires_at: at(100),
        max_uses: NonZeroU32::MIN,
    };
    assert!(!store.issue_token(hash(1), grant).await.unwrap());
    assert_eq!(store.token(&hash(1)).await.unwrap(), None);
}

/// The agent stores its key, sends `Enroll`, and may never see the answer. Trying
/// again must neither spend another use nor leave the machine without an identity.
pub(crate) async fn repeating_an_enrollment_gives_the_same_device_and_spends_nothing<
    S: DeviceAdmin,
>(
    store: &S,
) {
    issue(store, 1, 1).await;

    let first = enrolled(store, 1, 10).await;
    let again = enroll(store, 1, 10).await;
    let EnrollOutcome::Enrolled {
        device_id,
        repeated,
        ..
    } = again
    else {
        panic!("{again:?}");
    };
    assert_eq!(device_id, first);
    assert!(repeated);
    assert_eq!(uses_left(store, 1).await, Some(0));

    // With uses to spare, none of them goes to a repetition either.
    issue(store, 2, 3).await;
    let other = enrolled(store, 2, 20).await;
    for _ in 0..3 {
        assert_eq!(enrolled(store, 2, 20).await, other);
    }
    assert_eq!(uses_left(store, 2).await, Some(2));
    assert_eq!(store.devices(None).await.unwrap().len(), 2);
}

/// The machine may come back after the deadline: it stored its key, sent `Enroll`, and
/// lost the answer. Giving it back the device it already has creates nothing and spends
/// nothing, and only the holder of that key can ask.
pub(crate) async fn a_repeated_enrollment_after_the_deadline_gives_the_same_device<
    S: DeviceAdmin,
>(
    store: &S,
) {
    issue(store, 1, 2).await;
    let first = enrolled(store, 1, 10).await;

    for late in [at(100), at(1_000_000)] {
        let again = store.enroll(request(1, 10), late).await.unwrap();
        let EnrollOutcome::Enrolled {
            device_id,
            repeated,
            ..
        } = again
        else {
            panic!("{again:?}");
        };
        assert_eq!(device_id, first);
        assert!(repeated);
    }
    assert_eq!(uses_left(store, 1).await, Some(1));

    // A key the token never enrolled is still too late.
    let new_key = store.enroll(request(1, 11), at(100)).await.unwrap();
    assert_eq!(new_key, EnrollOutcome::Refused(EnrollRefusal::ExpiredToken));
    assert_eq!(uses_left(store, 1).await, Some(1));

    // And a revoked device stays out, late or not.
    assert!(store.revoke_device(first).await.unwrap());
    let revoked = store.enroll(request(1, 10), at(100)).await.unwrap();
    assert_eq!(
        revoked,
        EnrollOutcome::Refused(EnrollRefusal::DeviceRevoked)
    );
}

/// Revoking a token is a person saying no. That holds for the machines that already
/// enrolled with it and ask again, too.
pub(crate) async fn a_repeated_enrollment_with_a_revoked_token_is_refused<S: DeviceAdmin>(
    store: &S,
) {
    issue(store, 1, 1).await;
    let device = enrolled(store, 1, 10).await;

    assert!(store.revoke_token(&hash(1)).await.unwrap());
    for now in [at(0), at(100)] {
        let again = store.enroll(request(1, 10), now).await.unwrap();
        assert_eq!(again, EnrollOutcome::Refused(EnrollRefusal::RevokedToken));
    }
    // The device itself is not revoked by that: it keeps its key and connects.
    assert_eq!(status(store, device).await, DeviceStatus::Active);
}

pub(crate) async fn a_key_enrolls_once<S: DeviceAdmin>(store: &S) {
    let first_customer = issue(store, 1, 1).await;
    issue(store, 2, 5).await;
    let device = enrolled(store, 1, 10).await;

    assert_eq!(
        enroll(store, 2, 10).await,
        EnrollOutcome::Refused(EnrollRefusal::KeyAlreadyEnrolled)
    );
    // Not even after the deadline of the token it did enroll with.
    let late = store.enroll(request(2, 10), at(100)).await.unwrap();
    assert_eq!(
        late,
        EnrollOutcome::Refused(EnrollRefusal::KeyAlreadyEnrolled)
    );
    assert_eq!(uses_left(store, 2).await, Some(5));
    let record = store.device_record(device).await.unwrap().unwrap();
    assert_eq!(record.customer, first_customer);
    assert_eq!(record.enrolled_with, hash(1));
}

pub(crate) async fn a_revoked_device_does_not_enroll_again<S: DeviceAdmin>(store: &S) {
    issue(store, 1, 5).await;
    let device = enrolled(store, 1, 10).await;

    assert!(store.revoke_device(device).await.unwrap());
    assert!(store.revoke_device(device).await.unwrap());
    assert!(!store.revoke_device(DeviceId::new()).await.unwrap());
    assert_eq!(status(store, device).await, DeviceStatus::Revoked);
    assert_eq!(
        enroll(store, 1, 10).await,
        EnrollOutcome::Refused(EnrollRefusal::DeviceRevoked)
    );
    assert_eq!(uses_left(store, 1).await, Some(4));
}

/// A revoked device is never shown as connected, even if the end of its last session is
/// never recorded. The session itself ends at its next status check.
pub(crate) async fn revoking_a_device_takes_it_offline<S: DeviceAdmin>(store: &S) {
    issue(store, 1, 1).await;
    let device = enrolled(store, 1, 10).await;
    let session = SessionId::new();
    store
        .session_started(device, session, &about(), at(1))
        .await
        .unwrap();
    assert_eq!(record_of(store, device).await.online, Some(session));

    assert!(store.revoke_device(device).await.unwrap());
    let record = record_of(store, device).await;
    assert_eq!(record.online, None);
    assert_eq!(record.last_seen, Some(at(1)));
    // The session's own end changes nothing more.
    store.session_ended(device, session, at(2)).await.unwrap();
    assert_eq!(record_of(store, device).await.last_seen, Some(at(1)));
}

pub(crate) async fn only_a_pending_device_can_be_approved<S: DeviceAdmin>(store: &S) {
    issue(store, 1, 1).await;
    issue(store, 2, 3).await;
    let active = enrolled(store, 1, 10).await;
    let pending = enrolled(store, 2, 11).await;
    let revoked = enrolled(store, 2, 12).await;
    assert!(store.revoke_device(revoked).await.unwrap());

    assert!(store.approve_device(pending).await.unwrap());
    assert_eq!(status(store, pending).await, DeviceStatus::Active);
    assert!(!store.approve_device(pending).await.unwrap());
    assert!(!store.approve_device(active).await.unwrap());
    assert!(!store.approve_device(revoked).await.unwrap());
    assert!(!store.approve_device(DeviceId::new()).await.unwrap());
    assert_eq!(status(store, revoked).await, DeviceStatus::Revoked);
}

/// RF-49: until someone approves the device, what it reports goes nowhere.
pub(crate) async fn telemetry_is_kept_for_an_active_device_only<S: DeviceAdmin>(store: &S) {
    issue(store, 1, 2).await;
    let device = enrolled(store, 1, 10).await;

    let status = store.heartbeat(device, &telemetry(1), at(1)).await.unwrap();
    assert_eq!(status, Some(DeviceStatus::Pending));
    let record = store.device_record(device).await.unwrap().unwrap();
    assert_eq!(record.telemetry, None);
    assert_eq!(record.telemetry_at, None);
    assert_eq!(record.last_seen, Some(at(1)));

    assert!(store.approve_device(device).await.unwrap());
    let status = store.heartbeat(device, &telemetry(2), at(2)).await.unwrap();
    assert_eq!(status, Some(DeviceStatus::Active));
    let record = store.device_record(device).await.unwrap().unwrap();
    assert_eq!(record.telemetry, Some(telemetry(2)));
    assert_eq!(record.telemetry_at, Some(at(2)));
    assert_eq!(record.last_seen, Some(at(2)));

    assert!(store.revoke_device(device).await.unwrap());
    let status = store.heartbeat(device, &telemetry(3), at(3)).await.unwrap();
    assert_eq!(status, Some(DeviceStatus::Revoked));
    let record = store.device_record(device).await.unwrap().unwrap();
    assert_eq!(record.telemetry, Some(telemetry(2)));
    assert_eq!(record.telemetry_at, Some(at(2)));
    assert_eq!(record.last_seen, Some(at(2)));

    let unknown = store.heartbeat(DeviceId::new(), &telemetry(4), at(4)).await;
    assert_eq!(unknown.unwrap(), None);
}

/// The session that was replaced ends after the new one began. It must not take the
/// device offline on its way out.
pub(crate) async fn a_replaced_session_does_not_mark_the_device_offline<S: DeviceAdmin>(store: &S) {
    issue(store, 1, 1).await;
    let device = enrolled(store, 1, 10).await;
    let (old, new) = (SessionId::new(), SessionId::new());

    let started = store.session_started(device, old, &about(), at(1)).await;
    assert_eq!(started.unwrap(), Some(DeviceStatus::Active));
    assert_eq!(record_of(store, device).await.online, Some(old));
    assert_eq!(record_of(store, device).await.last_seen, Some(at(1)));

    let started = store.session_started(device, new, &newer(), at(2)).await;
    assert_eq!(started.unwrap(), Some(DeviceStatus::Active));
    store.session_ended(device, old, at(3)).await.unwrap();
    let after = record_of(store, device).await;
    assert_eq!(after.online, Some(new));
    assert_eq!(after.about, newer());
    assert_eq!(after.last_seen, Some(at(2)));

    store.session_ended(device, new, at(4)).await.unwrap();
    let after = record_of(store, device).await;
    assert_eq!(after.online, None);
    assert_eq!(after.last_seen, Some(at(4)));

    // Nothing to do for a device that is not there, and no error either.
    let unknown = DeviceId::new();
    let started = store.session_started(unknown, new, &about(), at(5)).await;
    assert_eq!(started.unwrap(), None);
    store.session_ended(unknown, new, at(5)).await.unwrap();
    assert_eq!(store.device_record(unknown).await.unwrap(), None);
}

/// RF-04: the handshake may have looked a moment before the device was revoked. The
/// store has the last word, and a revoked device is never shown as connected.
pub(crate) async fn a_session_of_a_revoked_device_does_not_start<S: DeviceAdmin>(store: &S) {
    issue(store, 1, 2).await;
    let device = enrolled(store, 1, 10).await;
    let session = SessionId::new();

    let started = store
        .session_started(device, session, &about(), at(1))
        .await;
    assert_eq!(started.unwrap(), Some(DeviceStatus::Pending));
    store.session_ended(device, session, at(2)).await.unwrap();
    let before = store.device_record(device).await.unwrap().unwrap();

    assert!(store.revoke_device(device).await.unwrap());
    let started = store
        .session_started(device, session, &newer(), at(3))
        .await;
    assert_eq!(started.unwrap(), Some(DeviceStatus::Revoked));
    let after = store.device_record(device).await.unwrap().unwrap();
    assert_eq!(after.online, None);
    assert_eq!(after.about, before.about);
    assert_eq!(after.last_seen, before.last_seen);
}

pub(crate) async fn customer_names_are_unique<S: DeviceAdmin>(store: &S) {
    let acme: CustomerName = "Acme Software".parse().unwrap();
    let first = store.add_customer(&acme).await.unwrap().unwrap();
    assert_eq!(store.add_customer(&acme).await.unwrap(), None);

    let other: CustomerName = "Another Shop".parse().unwrap();
    let second = store.add_customer(&other).await.unwrap().unwrap();
    assert_ne!(first, second);

    let customers = store.customers().await.unwrap();
    let names: Vec<_> = customers.iter().map(|c| (c.id, c.name.as_str())).collect();
    assert_eq!(names, [(first, "Acme Software"), (second, "Another Shop")]);
}

pub(crate) async fn lists_hold_what_was_added_and_can_be_narrowed_to_a_customer<S: DeviceAdmin>(
    store: &S,
) {
    let first = issue(store, 1, 2).await;
    let second = issue(store, 2, 1).await;
    let a = enrolled(store, 1, 10).await;
    let b = enrolled(store, 2, 11).await;
    let c = enrolled(store, 1, 12).await;

    let ids = |devices: Vec<DeviceRecord>| -> Vec<DeviceId> {
        devices.into_iter().map(|device| device.id).collect()
    };
    assert_eq!(ids(store.devices(None).await.unwrap()), [a, b, c]);
    assert_eq!(ids(store.devices(Some(first)).await.unwrap()), [a, c]);
    assert_eq!(ids(store.devices(Some(second)).await.unwrap()), [b]);
    assert!(
        store
            .devices(Some(CustomerId::new()))
            .await
            .unwrap()
            .is_empty()
    );

    let tokens = store.tokens(None).await.unwrap();
    let mut hashes: Vec<_> = tokens.iter().map(|token| token.hash).collect();
    hashes.sort_by_key(|hash| *hash.as_bytes());
    let mut expected = vec![hash(1), hash(2)];
    expected.sort_by_key(|hash| *hash.as_bytes());
    assert_eq!(hashes, expected);
    let of_second = store.tokens(Some(second)).await.unwrap();
    assert_eq!(of_second.len(), 1);
    assert_eq!(of_second[0].hash, hash(2));
    assert_eq!(of_second[0].uses, 1);
    assert_eq!(of_second[0].grant.customer, second);
    assert!(!of_second[0].revoked);
}
