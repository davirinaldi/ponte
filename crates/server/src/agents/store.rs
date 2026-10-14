//! Devices and enrollment tokens: what the handshake asks and what a session records.
//!
//! [`DeviceStore`] is what a connection needs and nothing more. [`MemoryStore`] keeps
//! everything in the process, for tests and for running without a database. The PostgreSQL
//! store comes later in M1 and follows the same rules, which are written on the trait.

use std::collections::HashMap;
use std::convert::Infallible;
use std::fmt;
use std::future::Future;
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use chrono::{DateTime, Utc};
use ponte_protocol::{DeviceId, EnrollmentToken, Label, PublicKey, TelemetrySnapshot};
use sha2::{Digest, Sha256};
use uuid::Uuid;

macro_rules! uuid_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name(Uuid);

        impl $name {
            /// Creates a new, time-ordered (UUIDv7) identifier.
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }

            #[must_use]
            pub const fn from_uuid(uuid: Uuid) -> Self {
                Self(uuid)
            }

            #[must_use]
            pub const fn as_uuid(&self) -> &Uuid {
                &self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }
    };
}

uuid_id!(
    /// The customer of the software house that a token, and every device enrolled with it,
    /// belongs to.
    CustomerId
);

uuid_id!(
    /// One authenticated connection of a device. A device has at most one at a time, and a
    /// store uses the id to tell the current one from one that was replaced.
    SessionId
);

/// SHA-256 of an enrollment token. A store keeps this and never the token, so a leaked
/// database hands out no valid token.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TokenHash([u8; 32]);

impl TokenHash {
    #[must_use]
    pub fn of(token: &EnrollmentToken) -> Self {
        Self(Sha256::digest(token.expose_secret()).into())
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for TokenHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TokenHash(..)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceStatus {
    /// Enrolled with a token issued for several machines and not approved yet (RF-49): it
    /// may connect, but its telemetry is dropped and it is sent no actions. What is kept is
    /// what a technician needs to approve it: when it was last seen and the two labels it
    /// gave in the handshake. Those labels are as untrusted as the device, and whatever
    /// shows devices to a model leaves a pending one out entirely.
    Pending,
    Active,
    /// Refused on every connection (RF-04). There is no way back: the machine enrolls again
    /// with a new key.
    Revoked,
}

/// What the handshake needs to know about an enrolled device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    pub id: DeviceId,
    pub customer: CustomerId,
    pub public_key: PublicKey,
    pub status: DeviceStatus,
}

/// What an agent says about itself in the handshake. Bounded, and still untrusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentInfo {
    pub agent_version: Label,
    pub os: Label,
}

/// An enrollment whose signature was already verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollRequest {
    pub token: TokenHash,
    pub public_key: PublicKey,
    pub about: AgentInfo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollOutcome {
    Enrolled {
        device_id: DeviceId,
        customer: CustomerId,
        status: DeviceStatus,
        /// The device already existed: this was the same token and key again, and no use
        /// of the token was spent.
        repeated: bool,
    },
    Refused(EnrollRefusal),
}

/// Why an enrollment was refused. For the server's own log: the peer is never told.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollRefusal {
    UnknownToken,
    RevokedToken,
    ExpiredToken,
    /// Every use of the token is spent.
    ExhaustedToken,
    /// The key belongs to a device enrolled with another token.
    KeyAlreadyEnrolled,
    /// The key belongs to a device that was revoked.
    DeviceRevoked,
}

/// Storage behind agent connections.
///
/// The futures are `Send` so a connection can run on any worker thread. Methods take the
/// current time instead of reading a clock, so a store's rules can be tested.
///
/// A call may be dropped before it returns, when its connection goes away: a store leaves
/// nothing half done behind. A store also sets its own time limits; the caller waits.
pub trait DeviceStore: Send + Sync + 'static {
    /// Logged with `Display` when a call fails. It must name what failed and never carry
    /// the values of the call: telemetry holds free text from the machine (invariants 4
    /// and 6 in `AGENTS.md`).
    type Error: std::error::Error + Send + Sync + 'static;

    /// Spends one use of the token and stores the key as a new device, in one atomic step.
    ///
    /// Rules every store follows:
    /// - A token that is unknown, revoked or expired at `now` does nothing at all.
    /// - The same token with the same key again gives the same device and spends nothing:
    ///   the answer to the first attempt may have been lost on the way. Not for a device
    ///   that was revoked since.
    /// - A key enrolls once. Under any other token it is refused.
    /// - The device starts [`DeviceStatus::Active`] if the token was issued for one machine
    ///   and [`DeviceStatus::Pending`] otherwise (RF-49).
    fn enroll(
        &self,
        request: EnrollRequest,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<EnrollOutcome, Self::Error>> + Send;

    fn device(
        &self,
        id: DeviceId,
    ) -> impl Future<Output = Result<Option<Device>, Self::Error>> + Send;

    /// Marks the device online under `session`, replacing whichever session it had, and
    /// says what the device is, or `None` if it no longer exists. A revoked device is left
    /// as it was: it may have been revoked since the handshake looked. Checking and writing
    /// happen in one atomic step.
    ///
    /// The caller starts the sessions of one device one at a time, in the order in which
    /// they take over from each other, so the last call is the session that stays.
    fn session_started(
        &self,
        id: DeviceId,
        session: SessionId,
        about: &AgentInfo,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<Option<DeviceStatus>, Self::Error>> + Send;

    /// Records a heartbeat and says what the device is now, or `None` if it no longer
    /// exists. Telemetry is kept for an active device only (RF-49), and a revoked device
    /// changes nothing. Checking and writing happen in one atomic step.
    fn heartbeat(
        &self,
        id: DeviceId,
        telemetry: &TelemetrySnapshot,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<Option<DeviceStatus>, Self::Error>> + Send;

    /// Marks the device offline, unless another session took over in the meantime.
    fn session_ended(
        &self,
        id: DeviceId,
        session: SessionId,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

/// What a token allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenGrant {
    pub customer: CustomerId,
    /// The token is refused from this instant on.
    pub expires_at: DateTime<Utc>,
    /// How many machines may enroll with it. One makes the device active at once; more
    /// leave each device pending until someone approves it (RF-49).
    pub max_uses: NonZeroU32,
}

/// Everything [`MemoryStore`] holds about one device.
#[derive(Debug, Clone, PartialEq)]
pub struct DeviceRecord {
    pub customer: CustomerId,
    pub public_key: PublicKey,
    pub status: DeviceStatus,
    pub about: AgentInfo,
    /// The session the device is connected under, if any.
    pub online: Option<SessionId>,
    pub last_seen: Option<DateTime<Utc>>,
    pub telemetry: Option<TelemetrySnapshot>,
    enrolled_with: TokenHash,
}

#[derive(Debug)]
struct TokenRecord {
    grant: TokenGrant,
    uses: u32,
    revoked: bool,
}

#[derive(Debug, Default)]
struct Inner {
    tokens: HashMap<TokenHash, TokenRecord>,
    devices: HashMap<DeviceId, DeviceRecord>,
    /// A key enrolls once: this is the index that says under which device.
    keys: HashMap<PublicKey, DeviceId>,
}

/// A [`DeviceStore`] that lives in the process and forgets everything when it stops.
///
/// Clones share the same data. Besides the trait it has what a technician will do through
/// the console and the server's subcommands later: issue and revoke tokens, approve and
/// revoke devices.
#[derive(Debug, Clone, Default)]
pub struct MemoryStore(Arc<Mutex<Inner>>);

impl MemoryStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        // Nothing here panics while holding the lock. If something ever does, the data is
        // still whole: every method leaves it consistent before returning.
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Makes `token` valid. Returns `false`, and changes nothing, if it already exists.
    pub fn add_token(&self, token: &EnrollmentToken, grant: TokenGrant) -> bool {
        let mut inner = self.lock();
        let hash = TokenHash::of(token);
        if inner.tokens.contains_key(&hash) {
            return false;
        }
        inner.tokens.insert(
            hash,
            TokenRecord {
                grant,
                uses: 0,
                revoked: false,
            },
        );
        true
    }

    /// Returns `false` if there is no such token.
    pub fn revoke_token(&self, token: &TokenHash) -> bool {
        match self.lock().tokens.get_mut(token) {
            Some(record) => {
                record.revoked = true;
                true
            }
            None => false,
        }
    }

    /// How many more machines may enroll with the token, expired or not.
    #[must_use]
    pub fn uses_left(&self, token: &TokenHash) -> Option<u32> {
        let inner = self.lock();
        let record = inner.tokens.get(token)?;
        Some(record.grant.max_uses.get().saturating_sub(record.uses))
    }

    /// Makes a pending device active. Returns `false` for any other device, a revoked one
    /// included.
    pub fn approve_device(&self, id: DeviceId) -> bool {
        match self.lock().devices.get_mut(&id) {
            Some(device) if device.status == DeviceStatus::Pending => {
                device.status = DeviceStatus::Active;
                true
            }
            _ => false,
        }
    }

    /// Returns `false` if there is no such device.
    pub fn revoke_device(&self, id: DeviceId) -> bool {
        match self.lock().devices.get_mut(&id) {
            Some(device) => {
                device.status = DeviceStatus::Revoked;
                true
            }
            None => false,
        }
    }

    #[must_use]
    pub fn record(&self, id: DeviceId) -> Option<DeviceRecord> {
        self.lock().devices.get(&id).cloned()
    }
}

impl DeviceStore for MemoryStore {
    type Error = Infallible;

    async fn enroll(
        &self,
        request: EnrollRequest,
        now: DateTime<Utc>,
    ) -> Result<EnrollOutcome, Self::Error> {
        // One lock from the first check to the last write: that is what makes it atomic.
        let mut guard = self.lock();
        let inner = &mut *guard;
        let refused = |refusal| Ok(EnrollOutcome::Refused(refusal));

        let Some(token) = inner.tokens.get_mut(&request.token) else {
            return refused(EnrollRefusal::UnknownToken);
        };
        if token.revoked {
            return refused(EnrollRefusal::RevokedToken);
        }
        if now >= token.grant.expires_at {
            return refused(EnrollRefusal::ExpiredToken);
        }

        if let Some(device_id) = inner.keys.get(&request.public_key).copied() {
            let Some(device) = inner.devices.get(&device_id) else {
                // The index and the devices went apart. Refuse instead of guessing.
                return refused(EnrollRefusal::KeyAlreadyEnrolled);
            };
            if device.enrolled_with != request.token {
                return refused(EnrollRefusal::KeyAlreadyEnrolled);
            }
            if device.status == DeviceStatus::Revoked {
                return refused(EnrollRefusal::DeviceRevoked);
            }
            return Ok(EnrollOutcome::Enrolled {
                device_id,
                customer: device.customer,
                status: device.status,
                repeated: true,
            });
        }

        if token.uses >= token.grant.max_uses.get() {
            return refused(EnrollRefusal::ExhaustedToken);
        }
        token.uses += 1;

        let device_id = DeviceId::new();
        let customer = token.grant.customer;
        let status = if token.grant.max_uses.get() == 1 {
            DeviceStatus::Active
        } else {
            DeviceStatus::Pending
        };
        inner.keys.insert(request.public_key, device_id);
        inner.devices.insert(
            device_id,
            DeviceRecord {
                customer,
                public_key: request.public_key,
                status,
                about: request.about,
                online: None,
                last_seen: None,
                telemetry: None,
                enrolled_with: request.token,
            },
        );
        Ok(EnrollOutcome::Enrolled {
            device_id,
            customer,
            status,
            repeated: false,
        })
    }

    async fn device(&self, id: DeviceId) -> Result<Option<Device>, Self::Error> {
        Ok(self.lock().devices.get(&id).map(|record| Device {
            id,
            customer: record.customer,
            public_key: record.public_key,
            status: record.status,
        }))
    }

    async fn session_started(
        &self,
        id: DeviceId,
        session: SessionId,
        about: &AgentInfo,
        now: DateTime<Utc>,
    ) -> Result<Option<DeviceStatus>, Self::Error> {
        let mut inner = self.lock();
        let Some(device) = inner.devices.get_mut(&id) else {
            return Ok(None);
        };
        if device.status != DeviceStatus::Revoked {
            device.online = Some(session);
            device.about = about.clone();
            device.last_seen = Some(now);
        }
        Ok(Some(device.status))
    }

    async fn heartbeat(
        &self,
        id: DeviceId,
        telemetry: &TelemetrySnapshot,
        now: DateTime<Utc>,
    ) -> Result<Option<DeviceStatus>, Self::Error> {
        let mut inner = self.lock();
        let Some(device) = inner.devices.get_mut(&id) else {
            return Ok(None);
        };
        match device.status {
            DeviceStatus::Active => {
                device.last_seen = Some(now);
                device.telemetry = Some(telemetry.clone());
            }
            DeviceStatus::Pending => device.last_seen = Some(now),
            DeviceStatus::Revoked => {}
        }
        Ok(Some(device.status))
    }

    async fn session_ended(
        &self,
        id: DeviceId,
        session: SessionId,
        now: DateTime<Utc>,
    ) -> Result<(), Self::Error> {
        if let Some(device) = self.lock().devices.get_mut(&id)
            && device.online == Some(session)
        {
            device.online = None;
            device.last_seen = Some(now);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeDelta;

    use super::*;
    use crate::agents::testkit::{about, at, grant, telemetry, token};

    fn key(seed: u8) -> PublicKey {
        PublicKey::from_bytes([seed; 32])
    }

    fn request(token_seed: u8, key_seed: u8) -> EnrollRequest {
        EnrollRequest {
            token: TokenHash::of(&token(token_seed)),
            public_key: key(key_seed),
            about: about(),
        }
    }

    async fn enroll(store: &MemoryStore, token_seed: u8, key_seed: u8) -> EnrollOutcome {
        store
            .enroll(request(token_seed, key_seed), at(0))
            .await
            .unwrap()
    }

    async fn enrolled(store: &MemoryStore, token_seed: u8, key_seed: u8) -> DeviceId {
        match enroll(store, token_seed, key_seed).await {
            EnrollOutcome::Enrolled { device_id, .. } => device_id,
            EnrollOutcome::Refused(refusal) => panic!("refused: {refusal:?}"),
        }
    }

    /// A store that kept the token itself would hand it out with any leak of its data.
    #[test]
    fn a_token_is_kept_as_its_sha256() {
        let hash = TokenHash::of(&EnrollmentToken::from_bytes([0; 32]));
        let expected = [
            0x66, 0x68, 0x7a, 0xad, 0xf8, 0x62, 0xbd, 0x77, 0x6c, 0x8f, 0xc1, 0x8b, 0x8e, 0x9f,
            0x8e, 0x20, 0x08, 0x97, 0x14, 0x85, 0x6e, 0xe2, 0x33, 0xb3, 0x90, 0x2a, 0x59, 0x1d,
            0x0d, 0x5f, 0x29, 0x25,
        ];
        assert_eq!(hash.as_bytes(), &expected);
        assert_eq!(format!("{hash:?}"), "TokenHash(..)");

        let store = MemoryStore::new();
        store.add_token(&token(1), grant(1));
        let dump = format!("{store:?}");
        assert!(!dump.contains(&token(1).expose_hex()), "{dump}");
    }

    #[tokio::test]
    async fn a_single_use_token_enrolls_one_active_device() {
        let store = MemoryStore::new();
        let grant = grant(1);
        assert!(store.add_token(&token(1), grant));

        let outcome = enroll(&store, 1, 10).await;
        let EnrollOutcome::Enrolled {
            device_id,
            customer,
            status,
            repeated,
        } = outcome
        else {
            panic!("{outcome:?}");
        };
        assert_eq!(customer, grant.customer);
        assert_eq!(status, DeviceStatus::Active);
        assert!(!repeated);

        let device = store.device(device_id).await.unwrap().unwrap();
        assert_eq!(
            device,
            Device {
                id: device_id,
                customer: grant.customer,
                public_key: key(10),
                status: DeviceStatus::Active,
            }
        );
        let record = store.record(device_id).unwrap();
        assert_eq!(record.about, about());
        assert_eq!(record.online, None);
        assert_eq!(record.telemetry, None);

        assert_eq!(store.uses_left(&TokenHash::of(&token(1))), Some(0));
        assert_eq!(
            enroll(&store, 1, 11).await,
            EnrollOutcome::Refused(EnrollRefusal::ExhaustedToken)
        );
        assert_eq!(store.device(DeviceId::new()).await.unwrap(), None);
    }

    /// RF-49: a token for several machines can leak to more people, so its devices wait.
    #[tokio::test]
    async fn a_multi_use_token_enrolls_pending_devices_up_to_its_limit() {
        let store = MemoryStore::new();
        store.add_token(&token(1), grant(2));

        for key_seed in [10, 11] {
            let id = enrolled(&store, 1, key_seed).await;
            assert_eq!(store.record(id).unwrap().status, DeviceStatus::Pending);
        }
        assert_eq!(
            enroll(&store, 1, 12).await,
            EnrollOutcome::Refused(EnrollRefusal::ExhaustedToken)
        );
    }

    #[tokio::test]
    async fn a_token_that_is_unknown_expired_or_revoked_does_nothing() {
        let store = MemoryStore::new();
        store.add_token(&token(1), grant(5));
        store.add_token(&token(2), grant(5));
        assert!(store.revoke_token(&TokenHash::of(&token(2))));
        assert!(!store.revoke_token(&TokenHash::of(&token(3))));

        let just_in_time = at(100) - TimeDelta::nanoseconds(1);
        for (token_seed, now, refusal) in [
            (3, at(0), EnrollRefusal::UnknownToken),
            (1, at(100), EnrollRefusal::ExpiredToken),
            (1, at(1_000_000), EnrollRefusal::ExpiredToken),
            (2, at(0), EnrollRefusal::RevokedToken),
        ] {
            let outcome = store.enroll(request(token_seed, 10), now).await.unwrap();
            assert_eq!(outcome, EnrollOutcome::Refused(refusal));
        }
        assert_eq!(store.uses_left(&TokenHash::of(&token(1))), Some(5));
        assert_eq!(store.uses_left(&TokenHash::of(&token(2))), Some(5));
        assert_eq!(store.uses_left(&TokenHash::of(&token(3))), None);

        let outcome = store.enroll(request(1, 10), just_in_time).await.unwrap();
        assert!(matches!(outcome, EnrollOutcome::Enrolled { .. }));
    }

    #[test]
    fn adding_a_token_twice_does_not_reset_it() {
        let store = MemoryStore::new();
        assert!(store.add_token(&token(1), grant(1)));
        assert!(store.revoke_token(&TokenHash::of(&token(1))));
        assert!(!store.add_token(&token(1), grant(9)));
        assert_eq!(store.uses_left(&TokenHash::of(&token(1))), Some(1));
    }

    /// The agent stores its key, sends `Enroll`, and may never see the answer. Trying
    /// again must neither spend another use nor leave the machine without an identity.
    #[tokio::test]
    async fn repeating_an_enrollment_gives_the_same_device_and_spends_nothing() {
        let store = MemoryStore::new();
        store.add_token(&token(1), grant(1));

        let first = enrolled(&store, 1, 10).await;
        let again = enroll(&store, 1, 10).await;
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
        assert_eq!(store.uses_left(&TokenHash::of(&token(1))), Some(0));

        // With uses to spare, none of them goes to a repetition either.
        store.add_token(&token(2), grant(3));
        let other = enrolled(&store, 2, 20).await;
        for _ in 0..3 {
            assert_eq!(enrolled(&store, 2, 20).await, other);
        }
        assert_eq!(store.uses_left(&TokenHash::of(&token(2))), Some(2));

        // Only while the token is good.
        let late = store.enroll(request(1, 10), at(100)).await.unwrap();
        assert_eq!(late, EnrollOutcome::Refused(EnrollRefusal::ExpiredToken));
        store.revoke_token(&TokenHash::of(&token(1)));
        assert_eq!(
            enroll(&store, 1, 10).await,
            EnrollOutcome::Refused(EnrollRefusal::RevokedToken)
        );
    }

    #[tokio::test]
    async fn a_key_enrolls_once() {
        let store = MemoryStore::new();
        store.add_token(&token(1), grant(1));
        store.add_token(&token(2), grant(5));
        let device = enrolled(&store, 1, 10).await;

        assert_eq!(
            enroll(&store, 2, 10).await,
            EnrollOutcome::Refused(EnrollRefusal::KeyAlreadyEnrolled)
        );
        assert_eq!(store.uses_left(&TokenHash::of(&token(2))), Some(5));
        assert_eq!(store.record(device).unwrap().customer, {
            let EnrollOutcome::Enrolled { customer, .. } = enroll(&store, 1, 10).await else {
                panic!("the first enrollment no longer repeats");
            };
            customer
        });
    }

    #[tokio::test]
    async fn a_revoked_device_does_not_enroll_again() {
        let store = MemoryStore::new();
        store.add_token(&token(1), grant(5));
        let device = enrolled(&store, 1, 10).await;

        assert!(store.revoke_device(device));
        assert!(!store.revoke_device(DeviceId::new()));
        assert_eq!(store.record(device).unwrap().status, DeviceStatus::Revoked);
        assert_eq!(
            enroll(&store, 1, 10).await,
            EnrollOutcome::Refused(EnrollRefusal::DeviceRevoked)
        );
        assert_eq!(store.uses_left(&TokenHash::of(&token(1))), Some(4));
    }

    #[tokio::test]
    async fn only_a_pending_device_can_be_approved() {
        let store = MemoryStore::new();
        store.add_token(&token(1), grant(1));
        store.add_token(&token(2), grant(2));
        let active = enrolled(&store, 1, 10).await;
        let pending = enrolled(&store, 2, 11).await;
        let revoked = enrolled(&store, 2, 12).await;
        store.revoke_device(revoked);

        assert!(store.approve_device(pending));
        assert_eq!(store.record(pending).unwrap().status, DeviceStatus::Active);
        assert!(!store.approve_device(active));
        assert!(!store.approve_device(revoked));
        assert!(!store.approve_device(DeviceId::new()));
        assert_eq!(store.record(revoked).unwrap().status, DeviceStatus::Revoked);
    }

    /// RF-49: until someone approves the device, what it reports goes nowhere.
    #[tokio::test]
    async fn telemetry_is_kept_for_an_active_device_only() {
        let store = MemoryStore::new();
        store.add_token(&token(1), grant(2));
        let device = enrolled(&store, 1, 10).await;

        let status = store.heartbeat(device, &telemetry(1), at(1)).await.unwrap();
        assert_eq!(status, Some(DeviceStatus::Pending));
        let record = store.record(device).unwrap();
        assert_eq!(record.telemetry, None);
        assert_eq!(record.last_seen, Some(at(1)));

        store.approve_device(device);
        let status = store.heartbeat(device, &telemetry(2), at(2)).await.unwrap();
        assert_eq!(status, Some(DeviceStatus::Active));
        let record = store.record(device).unwrap();
        assert_eq!(record.telemetry, Some(telemetry(2)));
        assert_eq!(record.last_seen, Some(at(2)));

        store.revoke_device(device);
        let status = store.heartbeat(device, &telemetry(3), at(3)).await.unwrap();
        assert_eq!(status, Some(DeviceStatus::Revoked));
        let record = store.record(device).unwrap();
        assert_eq!(record.telemetry, Some(telemetry(2)));
        assert_eq!(record.last_seen, Some(at(2)));

        let unknown = store.heartbeat(DeviceId::new(), &telemetry(4), at(4)).await;
        assert_eq!(unknown.unwrap(), None);
    }

    /// The session that was replaced ends after the new one began. It must not take the
    /// device offline on its way out.
    #[tokio::test]
    async fn a_replaced_session_does_not_mark_the_device_offline() {
        let store = MemoryStore::new();
        store.add_token(&token(1), grant(1));
        let device = enrolled(&store, 1, 10).await;
        let (old, new) = (SessionId::new(), SessionId::new());
        let newer = AgentInfo {
            agent_version: "0.2.0".parse().unwrap(),
            os: about().os,
        };

        let started = store.session_started(device, old, &about(), at(1)).await;
        assert_eq!(started.unwrap(), Some(DeviceStatus::Active));
        assert_eq!(store.record(device).unwrap().online, Some(old));
        assert_eq!(store.record(device).unwrap().last_seen, Some(at(1)));

        let started = store.session_started(device, new, &newer, at(2)).await;
        assert_eq!(started.unwrap(), Some(DeviceStatus::Active));
        store.session_ended(device, old, at(3)).await.unwrap();
        let record = store.record(device).unwrap();
        assert_eq!(record.online, Some(new));
        assert_eq!(record.about, newer);

        store.session_ended(device, new, at(4)).await.unwrap();
        assert_eq!(store.record(device).unwrap().online, None);

        // Nothing to do for a device that is not there, and no error either.
        let unknown = DeviceId::new();
        let started = store.session_started(unknown, new, &about(), at(5)).await;
        assert_eq!(started.unwrap(), None);
        store.session_ended(unknown, new, at(5)).await.unwrap();
        assert_eq!(store.record(unknown), None);
    }

    /// RF-04: the handshake may have looked a moment before the device was revoked. The
    /// store has the last word, and a revoked device is never shown as connected.
    #[tokio::test]
    async fn a_session_of_a_revoked_device_does_not_start() {
        let store = MemoryStore::new();
        store.add_token(&token(1), grant(2));
        let device = enrolled(&store, 1, 10).await;
        let session = SessionId::new();
        let newer = AgentInfo {
            agent_version: "0.2.0".parse().unwrap(),
            os: about().os,
        };

        let started = store
            .session_started(device, session, &about(), at(1))
            .await;
        assert_eq!(started.unwrap(), Some(DeviceStatus::Pending));
        store.session_ended(device, session, at(2)).await.unwrap();
        let before = store.record(device).unwrap();

        store.revoke_device(device);
        let started = store.session_started(device, session, &newer, at(3)).await;
        assert_eq!(started.unwrap(), Some(DeviceStatus::Revoked));
        let after = store.record(device).unwrap();
        assert_eq!(after.online, None);
        assert_eq!(after.about, before.about);
        assert_eq!(after.last_seen, before.last_seen);
    }
}
