//! Devices and enrollment tokens: what the handshake asks and what a session records.
//!
//! [`DeviceStore`] is what a connection needs and nothing more. [`DeviceAdmin`] adds what an
//! operator does: customers, tokens, approving and revoking. [`MemoryStore`] keeps
//! everything in the process, for tests. Every store follows the rules written on the
//! traits, and `scenarios` checks them on each one.

use std::collections::HashMap;
use std::convert::Infallible;
use std::fmt;
use std::future::Future;
use std::num::NonZeroU32;
use std::str::FromStr;
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

    /// A hash a store kept.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The first eight bytes in hex, for a log line: enough to find the token in a store,
    /// and of no use to anyone who wants the token itself.
    #[must_use]
    pub fn short(&self) -> String {
        self.0[..8]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
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
    /// Rules every store follows, checked in this order:
    /// - A token that is unknown or revoked does nothing at all. Revoking is a person
    ///   saying no, to the machines that already enrolled with it too.
    /// - A key enrolls once. Under any other token it is refused, and so is the key of a
    ///   device that was revoked.
    /// - The same token with the same key again gives the same device and spends nothing,
    ///   even after the deadline: the answer to the first attempt may have been lost on the
    ///   way, and only the holder of the key can ask.
    /// - Otherwise a token that expired at `now`, or has no use left, does nothing at all.
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
    /// they take over from each other, so the last call is the session that stays. That
    /// holds within one server process, which is all there is for now.
    ///
    /// After an error the caller treats the session as never begun. A store may not know
    /// whether it wrote (a database can commit and lose the answer), so the caller also
    /// calls [`DeviceStore::session_ended`] for that session, which changes nothing if the
    /// device is under another session or none.
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

/// What an operator does to customers, tokens and devices: through the server's
/// subcommands now, through the console later.
///
/// Agent connections never use it. They are generic over [`DeviceStore`] only, so nothing a
/// device sends can reach a method that approves or revokes. The same rules as the trait
/// it extends: methods take what they need and nothing more, a store keeps the hash of a
/// token and never the token, and errors never carry the values of a call.
pub trait DeviceAdmin: DeviceStore {
    /// `None`, and nothing changes, if a customer already has that name.
    fn add_customer(
        &self,
        name: &CustomerName,
    ) -> impl Future<Output = Result<Option<CustomerId>, Self::Error>> + Send;

    /// Every customer, ordered by name.
    fn customers(&self) -> impl Future<Output = Result<Vec<Customer>, Self::Error>> + Send;

    /// Makes the token whose hash is `token` valid. `false`, and nothing changes, if it
    /// already exists or its customer does not.
    fn issue_token(
        &self,
        token: TokenHash,
        grant: TokenGrant,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send;

    /// `false` if there is no such token. Revoking twice is the same as once.
    fn revoke_token(
        &self,
        token: &TokenHash,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send;

    fn token(
        &self,
        token: &TokenHash,
    ) -> impl Future<Output = Result<Option<TokenInfo>, Self::Error>> + Send;

    /// The tokens of one customer, or of all, ordered by deadline.
    fn tokens(
        &self,
        customer: Option<CustomerId>,
    ) -> impl Future<Output = Result<Vec<TokenInfo>, Self::Error>> + Send;

    /// Makes a pending device active (RF-49). `false` for any other device, a revoked one
    /// included.
    fn approve_device(
        &self,
        id: DeviceId,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send;

    /// `false` if there is no such device. There is no way back (RF-04). The device is
    /// shown offline at once; a session it has ends at its next status check.
    fn revoke_device(&self, id: DeviceId)
    -> impl Future<Output = Result<bool, Self::Error>> + Send;

    fn device_record(
        &self,
        id: DeviceId,
    ) -> impl Future<Output = Result<Option<DeviceRecord>, Self::Error>> + Send;

    /// The devices of one customer, or of all, oldest first.
    fn devices(
        &self,
        customer: Option<CustomerId>,
    ) -> impl Future<Output = Result<Vec<DeviceRecord>, Self::Error>> + Send;
}

/// The name of a customer, as an operator typed it: 1 to 100 characters, none of them a
/// control character or one that changes how the text around it is shown.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CustomerName(String);

impl CustomerName {
    pub const MAX_CHARS: usize = 100;

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("a customer name has 1 to 100 characters, with no control or formatting characters")]
pub struct InvalidCustomerName;

impl FromStr for CustomerName {
    type Err = InvalidCustomerName;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        let chars = name.chars().count();
        let shown_as_is = |c: char| {
            !c.is_control()
                && !matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}'
                    | '\u{2060}'..='\u{2069}' | '\u{feff}')
        };
        if (1..=Self::MAX_CHARS).contains(&chars)
            && name.trim() == name
            && name.chars().all(shown_as_is)
        {
            Ok(Self(name.to_owned()))
        } else {
            Err(InvalidCustomerName)
        }
    }
}

impl fmt::Display for CustomerName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Customer {
    pub id: CustomerId,
    pub name: CustomerName,
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

/// What a store holds about a token. Never the token itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenInfo {
    pub hash: TokenHash,
    pub grant: TokenGrant,
    /// Machines enrolled with it so far.
    pub uses: u32,
    pub revoked: bool,
}

impl TokenInfo {
    /// How many more machines may enroll with it, expired or not.
    #[must_use]
    pub fn uses_left(&self) -> u32 {
        self.grant.max_uses.get().saturating_sub(self.uses)
    }
}

/// Everything a store holds about one device.
#[derive(Debug, Clone, PartialEq)]
pub struct DeviceRecord {
    pub id: DeviceId,
    pub customer: CustomerId,
    pub public_key: PublicKey,
    pub status: DeviceStatus,
    /// What the agent said about itself when it last connected. Untrusted.
    pub about: AgentInfo,
    /// The session the device is connected under, if any.
    pub online: Option<SessionId>,
    pub last_seen: Option<DateTime<Utc>>,
    pub telemetry: Option<TelemetrySnapshot>,
    pub enrolled_with: TokenHash,
}

#[derive(Debug)]
struct TokenRecord {
    grant: TokenGrant,
    uses: u32,
    revoked: bool,
}

impl TokenRecord {
    fn info(&self, hash: TokenHash) -> TokenInfo {
        TokenInfo {
            hash,
            grant: self.grant,
            uses: self.uses,
            revoked: self.revoked,
        }
    }
}

#[derive(Debug, Default)]
struct Inner {
    customers: HashMap<CustomerId, CustomerName>,
    tokens: HashMap<TokenHash, TokenRecord>,
    devices: HashMap<DeviceId, DeviceRecord>,
    /// A key enrolls once: this is the index that says under which device.
    keys: HashMap<PublicKey, DeviceId>,
}

/// A [`DeviceStore`] that lives in the process and forgets everything when it stops.
///
/// Clones share the same data. Besides the traits it has a few shortcuts for tests, which
/// do not wait: [`MemoryStore::add_token`], [`MemoryStore::uses_left`] and
/// [`MemoryStore::record`].
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

    /// Makes `token` valid, adding its customer first if the store does not know it.
    /// Returns `false`, and changes nothing, if the token already exists. For tests.
    pub fn add_token(&self, token: &EnrollmentToken, grant: TokenGrant) -> bool {
        let mut inner = self.lock();
        inner
            .customers
            .entry(grant.customer)
            .or_insert_with(|| CustomerName(format!("customer {}", grant.customer)));
        inner.issue_token(TokenHash::of(token), grant)
    }

    /// How many more machines may enroll with the token, expired or not.
    #[must_use]
    pub fn uses_left(&self, token: &TokenHash) -> Option<u32> {
        let inner = self.lock();
        let record = inner.tokens.get(token)?;
        Some(record.info(*token).uses_left())
    }

    #[must_use]
    pub fn record(&self, id: DeviceId) -> Option<DeviceRecord> {
        self.lock().devices.get(&id).cloned()
    }
}

impl Inner {
    fn issue_token(&mut self, hash: TokenHash, grant: TokenGrant) -> bool {
        if self.tokens.contains_key(&hash) || !self.customers.contains_key(&grant.customer) {
            return false;
        }
        self.tokens.insert(
            hash,
            TokenRecord {
                grant,
                uses: 0,
                revoked: false,
            },
        );
        true
    }
}

impl DeviceAdmin for MemoryStore {
    async fn add_customer(&self, name: &CustomerName) -> Result<Option<CustomerId>, Self::Error> {
        let mut inner = self.lock();
        if inner.customers.values().any(|taken| taken == name) {
            return Ok(None);
        }
        let id = CustomerId::new();
        inner.customers.insert(id, name.clone());
        Ok(Some(id))
    }

    async fn customers(&self) -> Result<Vec<Customer>, Self::Error> {
        let mut customers: Vec<_> = self
            .lock()
            .customers
            .iter()
            .map(|(id, name)| Customer {
                id: *id,
                name: name.clone(),
            })
            .collect();
        customers.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(customers)
    }

    async fn issue_token(&self, token: TokenHash, grant: TokenGrant) -> Result<bool, Self::Error> {
        Ok(self.lock().issue_token(token, grant))
    }

    async fn revoke_token(&self, token: &TokenHash) -> Result<bool, Self::Error> {
        Ok(match self.lock().tokens.get_mut(token) {
            Some(record) => {
                record.revoked = true;
                true
            }
            None => false,
        })
    }

    async fn token(&self, token: &TokenHash) -> Result<Option<TokenInfo>, Self::Error> {
        Ok(self
            .lock()
            .tokens
            .get(token)
            .map(|record| record.info(*token)))
    }

    async fn tokens(&self, customer: Option<CustomerId>) -> Result<Vec<TokenInfo>, Self::Error> {
        let mut tokens: Vec<_> = self
            .lock()
            .tokens
            .iter()
            .map(|(hash, record)| record.info(*hash))
            .filter(|token| customer.is_none_or(|customer| token.grant.customer == customer))
            .collect();
        tokens.sort_by_key(|token| (token.grant.expires_at, *token.hash.as_bytes()));
        Ok(tokens)
    }

    async fn approve_device(&self, id: DeviceId) -> Result<bool, Self::Error> {
        Ok(match self.lock().devices.get_mut(&id) {
            Some(device) if device.status == DeviceStatus::Pending => {
                device.status = DeviceStatus::Active;
                true
            }
            _ => false,
        })
    }

    async fn revoke_device(&self, id: DeviceId) -> Result<bool, Self::Error> {
        Ok(match self.lock().devices.get_mut(&id) {
            Some(device) => {
                device.status = DeviceStatus::Revoked;
                device.online = None;
                true
            }
            None => false,
        })
    }

    async fn device_record(&self, id: DeviceId) -> Result<Option<DeviceRecord>, Self::Error> {
        Ok(self.record(id))
    }

    async fn devices(
        &self,
        customer: Option<CustomerId>,
    ) -> Result<Vec<DeviceRecord>, Self::Error> {
        let mut devices: Vec<_> = self
            .lock()
            .devices
            .values()
            .filter(|device| customer.is_none_or(|customer| device.customer == customer))
            .cloned()
            .collect();
        // Ids are UUIDv7: in the order they were made.
        devices.sort_by_key(|device| *device.id.as_uuid());
        Ok(devices)
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

        // Before the deadline: a repetition creates nothing and spends nothing.
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

        if now >= token.grant.expires_at {
            return refused(EnrollRefusal::ExpiredToken);
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
                id: device_id,
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
pub(crate) mod scenarios;

#[cfg(test)]
mod tests {
    use super::scenarios::{self, for_each_scenario};
    use super::*;
    use crate::agents::testkit::{grant, token};

    macro_rules! in_memory {
        ($scenario:ident) => {
            #[tokio::test]
            async fn $scenario() {
                scenarios::$scenario(&MemoryStore::new()).await;
            }
        };
    }
    for_each_scenario!(in_memory);

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
        assert_eq!(hash.short(), "66687aadf862bd77");

        let store = MemoryStore::new();
        store.add_token(&token(1), grant(1));
        let dump = format!("{store:?}");
        assert!(!dump.contains(&token(1).expose_hex()), "{dump}");
    }

    /// Names are shown in a terminal and, later, in the console. What an operator typed
    /// must read the same there.
    #[test]
    fn a_customer_name_is_plain_text_of_bounded_length() {
        for good in ["A", "Acme Software", "Padaria São João", &"x".repeat(100)] {
            assert_eq!(good.parse::<CustomerName>().unwrap().as_str(), good);
        }
        for bad in [
            "",
            " Acme",
            "Acme ",
            "Ac\nme",
            "Ac\u{1b}[2Jme",
            "Acme\u{202e}exe",
            "Ac\u{200b}me",
            "\u{feff}Acme",
            &"x".repeat(101),
        ] {
            assert_eq!(
                bad.parse::<CustomerName>(),
                Err(InvalidCustomerName),
                "{bad:?}"
            );
        }
    }
}
