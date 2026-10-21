//! Signing keys, the catalog of signed manifests and action requests (ADR-0010, ADR-0012).
//!
//! [`ActionStore`] is what delivering requests needs: claiming what is due for connected
//! devices, sending again what got no answer, storing results and expiring what waited too
//! long. [`ActionAdmin`] adds what an operator does: trusting keys, adding manifests,
//! asking for and cancelling actions. Connections are generic over [`ActionStore`] only,
//! so nothing a device sends can reach a method that trusts a key or creates a request.
//! `action_scenarios` checks the rules on every store.

use std::fmt;
use std::future::Future;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use ponte_actions::{RiskLevel, TrustedKeys, VerifyError};
use ponte_protocol::{
    ActionOutcome, ActionRequest, ActionResult, DeviceId, Initiator, Output, PublicKey,
    RejectReason, RequestId, SignedManifest, manifest_transcript,
};
use sha2::{Digest, Sha256};

use super::{DeviceAdmin, DeviceStatus, DeviceStore, Inner, MemoryStore};

/// At most this many requests of one device are open at once: queued, or sent with no
/// answer and not expired yet. More is refused when it is asked for.
pub const MAX_OPEN_PER_DEVICE: usize = 16;

/// The most requests one sweep claims, over all devices.
pub const MAX_CLAIMED_PER_SWEEP: usize = 64;

/// The most queued requests one sweep marks expired.
pub const MAX_EXPIRED_PER_SWEEP: usize = 256;

/// The most requests sent again when a session starts. The agent's queue holds 4.
pub const MAX_RESENT: usize = 4;

/// How long after its expiry a request that got no answer is still sent again. The agent
/// remembers a request for a day past its expiry (ADR-0012); an hour less leaves room for a
/// clock that runs ahead. Older ones stay `sent` with no answer: an agent that forgot them
/// would answer `request_expired`, which may not be what happened.
pub const RESEND_WINDOW_SECS: i64 = 23 * 60 * 60;

/// SHA-256 of an envelope's public key followed by its transcript (ADR-0010): the same
/// envelope has one id whatever JSON spelling carried it.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EnvelopeHash([u8; 32]);

impl EnvelopeHash {
    #[must_use]
    pub fn of(envelope: &SignedManifest) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(envelope.public_key.as_bytes());
        hasher.update(manifest_transcript(envelope).expose_bytes());
        Self(hasher.finalize().into())
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

    /// The first eight bytes in hex: how listings and audit events name an envelope.
    #[must_use]
    pub fn short(&self) -> String {
        hex(&self.0[..8])
    }
}

impl fmt::Debug for EnvelopeHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EnvelopeHash({})", self.short())
    }
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The id of a manifest, by the rule of `ponte_actions`: lowercase dotted segments, each
/// `[a-z][a-z0-9-]*`, at least two, at most 64 bytes. Printed in a terminal and logged, so
/// it is read back with the same rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ManifestId(String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("a manifest id is lowercase dotted segments of at most 64 bytes, e.g. erp.restart-service")]
pub struct InvalidManifestId;

impl ManifestId {
    pub const MAX_LEN: usize = 64;

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for ManifestId {
    type Err = InvalidManifestId;

    fn from_str(id: &str) -> Result<Self, Self::Err> {
        if id.len() > Self::MAX_LEN {
            return Err(InvalidManifestId);
        }
        let mut segments = 0;
        for segment in id.split('.') {
            let mut chars = segment.chars();
            let starts = chars.next().is_some_and(|c| c.is_ascii_lowercase());
            let rest = chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
            if !starts || !rest {
                return Err(InvalidManifestId);
            }
            segments += 1;
        }
        if segments < 2 {
            return Err(InvalidManifestId);
        }
        Ok(Self(id.to_owned()))
    }
}

impl fmt::Display for ManifestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An envelope the catalog holds: verified against the server's trusted keys when it was
/// added (ADR-0010), with what listings show about it.
#[derive(Clone, PartialEq, Eq)]
pub struct CatalogEntry {
    hash: EnvelopeHash,
    id: ManifestId,
    version: u32,
    risk: RiskLevel,
    envelope: SignedManifest,
}

/// Why an envelope did not enter the catalog.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CatalogError {
    #[error(transparent)]
    Verify(#[from] VerifyError),
    #[error(transparent)]
    Id(#[from] InvalidManifestId),
}

impl CatalogEntry {
    /// The only way in from outside: `envelope` verified against `keys`, the server's own,
    /// never the key the envelope names. `now` is the server's clock, in seconds since the
    /// Unix epoch, and the server keeps no high-water mark: it is passed as both.
    ///
    /// # Errors
    /// What `ponte_actions::verify` refuses: an unknown key, a bad signature, a validity
    /// that has ended or not begun, a text that is not a valid manifest.
    pub fn verify(
        envelope: SignedManifest,
        keys: &TrustedKeys,
        now: u64,
    ) -> Result<Self, CatalogError> {
        let verified = ponte_actions::verify(&envelope, keys, now, now)?;
        let manifest = verified.manifest();
        Ok(Self {
            hash: EnvelopeHash::of(&envelope),
            id: manifest.id.parse()?,
            version: manifest.version,
            risk: manifest.risk,
            envelope,
        })
    }

    /// An entry a store read back. The store checks what it can: the id's rule, and that
    /// the hash is the envelope's.
    pub(crate) fn stored(
        id: ManifestId,
        version: u32,
        risk: RiskLevel,
        envelope: SignedManifest,
    ) -> Self {
        Self {
            hash: EnvelopeHash::of(&envelope),
            id,
            version,
            risk,
            envelope,
        }
    }

    #[must_use]
    pub const fn hash(&self) -> &EnvelopeHash {
        &self.hash
    }

    #[must_use]
    pub const fn id(&self) -> &ManifestId {
        &self.id
    }

    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    #[must_use]
    pub const fn risk(&self) -> RiskLevel {
        self.risk
    }

    #[must_use]
    pub const fn envelope(&self) -> &SignedManifest {
        &self.envelope
    }
}

/// The id, the version and the hash: the text names paths and services, which logs do not.
impl fmt::Debug for CatalogEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CatalogEntry({} v{} {})",
            self.id,
            self.version,
            self.hash.short()
        )
    }
}

/// A key the server trusts to sign manifests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigningKey {
    pub public_key: PublicKey,
    pub added_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAdded {
    Added,
    AlreadyTrusted,
    /// `ponte_actions::MAX_TRUSTED_KEYS` are trusted already.
    Full,
}

/// A request an operator asks for.
#[derive(Debug, Clone, PartialEq)]
pub struct NewRequest {
    pub id: RequestId,
    pub device: DeviceId,
    pub manifest: EnvelopeHash,
    /// Seconds since the Unix epoch, at most 24 hours after `now` (ADR-0012).
    pub expires_at: u64,
    pub initiator: Initiator,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestOutcome {
    Queued,
    Refused(RequestRefusal),
}

/// Why a request was not queued.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestRefusal {
    UnknownDevice,
    /// Only an active device is sent actions (RF-49, RF-04).
    DeviceNotActive(DeviceStatus),
    /// [`MAX_OPEN_PER_DEVICE`] requests of the device are open.
    TooManyOpen,
    UnknownManifest,
    /// The request's expiry does not fit a store's `bigint`.
    ExpiryOutOfRange,
}

/// A request on its way to the agent: what the sweep claimed or a session sends again.
#[derive(Debug, Clone, PartialEq)]
pub struct Outgoing {
    pub device: DeviceId,
    pub id: ManifestId,
    pub version: u32,
    pub request: Box<ActionRequest>,
}

/// What became of a result a device sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Finish {
    /// Stored. `replaced` when it took the place of a refusal that only described the
    /// agent's state at the time (see [`describes_the_agent`]).
    Recorded { replaced: bool },
    /// The request already had this outcome: a copy, or an answer sent again.
    Repeated,
    /// The request already had another outcome. An anomaly (ADR-0012): the stored outcome
    /// may not be what happened.
    Conflicting,
    /// The request was never sent: queued, cancelled by an operator, or expired.
    NotSent,
    /// The request belongs to another device.
    OtherDevice,
    /// The device is no longer active: a revoked key writes no outcome (RF-04, RF-49).
    DeviceNotActive,
    /// No such request.
    Unknown,
}

/// What a store holds about one request.
#[derive(Debug, Clone, PartialEq)]
pub struct RequestRecord {
    pub id: RequestId,
    pub device: DeviceId,
    pub manifest: EnvelopeHash,
    pub manifest_id: ManifestId,
    pub version: u32,
    pub initiator: Initiator,
    pub expires_at: u64,
    pub created_at: DateTime<Utc>,
    pub state: RequestState,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RequestState {
    Queued,
    Sent {
        at: DateTime<Utc>,
    },
    /// The agent answered.
    Answered {
        sent_at: DateTime<Utc>,
        at: DateTime<Utc>,
        outcome: ActionOutcome,
        duration_ms: u64,
        /// Untrusted text from the machine: never logged, and marked as data wherever it
        /// is shown (invariant 4).
        output: Option<Output>,
    },
    /// An operator cancelled it before it was sent.
    Cancelled {
        at: DateTime<Utc>,
    },
    /// It expired before it was sent.
    Expired {
        at: DateTime<Utc>,
    },
}

impl RequestState {
    /// The word listings and the database use.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Sent { .. } => "sent",
            Self::Answered { outcome, .. } => outcome_name(outcome),
            Self::Cancelled { .. } => "cancelled",
            Self::Expired { .. } => "expired",
        }
    }
}

pub(crate) fn outcome_name(outcome: &ActionOutcome) -> &'static str {
    match outcome {
        ActionOutcome::Succeeded {} => "succeeded",
        ActionOutcome::Failed { .. } => "failed",
        ActionOutcome::Rejected { .. } => "rejected",
        ActionOutcome::Cancelled {} => "cancelled",
        ActionOutcome::TimedOut {} => "timed_out",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelOutcome {
    Cancelled,
    /// Only a queued request can be cancelled: a sent one is the agent's (ADR-0012).
    NotQueued,
    Unknown,
}

/// Whether a refusal says something about the agent at the moment it answered, rather than
/// about the request. The agent sends these without recording them (ADR-0012), so another
/// copy of the same request may still run: a later result of the same device replaces one.
#[must_use]
pub const fn describes_the_agent(reason: RejectReason) -> bool {
    matches!(
        reason,
        RejectReason::ActionsDisabled
            | RejectReason::QueueFull
            | RejectReason::ShuttingDown
            | RejectReason::JournalFull
            | RejectReason::JournalUnavailable
            | RejectReason::ClockWentBack
    )
}

/// What a store knows of a request when a result for it comes in.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Stored<'a> {
    Sent,
    Answered(&'a ActionOutcome),
    /// Queued, cancelled by an operator or expired.
    NeverSent,
}

/// What a store does with a result: the rule of ADR-0012, written once for every store.
pub(crate) fn judge(stored: Stored<'_>, outcome: &ActionOutcome) -> Finish {
    match stored {
        Stored::Sent => Finish::Recorded { replaced: false },
        Stored::NeverSent => Finish::NotSent,
        Stored::Answered(before) if before == outcome => Finish::Repeated,
        // Replaced only by an answer about the request itself, so it happens once.
        Stored::Answered(ActionOutcome::Rejected { reason })
            if describes_the_agent(*reason) && !is_about_the_agent(outcome) =>
        {
            Finish::Recorded { replaced: true }
        }
        Stored::Answered(_) => Finish::Conflicting,
    }
}

fn is_about_the_agent(outcome: &ActionOutcome) -> bool {
    matches!(outcome, ActionOutcome::Rejected { reason } if describes_the_agent(*reason))
}

/// The code of an outcome's reason as the wire and the database spell it (`queue_full`),
/// and the index of its step.
pub(crate) fn reason_of(outcome: &ActionOutcome) -> (Option<String>, Option<u8>) {
    let code = |value: serde_json::Result<serde_json::Value>| match value {
        Ok(serde_json::Value::String(code)) => Some(code),
        _ => None,
    };
    match outcome {
        ActionOutcome::Failed { reason, step } => (code(serde_json::to_value(reason)), *step),
        ActionOutcome::Rejected { reason } => (code(serde_json::to_value(reason)), None),
        ActionOutcome::Succeeded {} | ActionOutcome::Cancelled {} | ActionOutcome::TimedOut {} => {
            (None, None)
        }
    }
}

/// Seconds since the Unix epoch, as a store keeps them.
pub(crate) fn secs(now: DateTime<Utc>) -> i64 {
    now.timestamp()
}

/// What delivering requests needs. The rules every store follows are written on each
/// method; `action_scenarios` checks them. Like [`DeviceStore`], a call leaves nothing
/// half done, sets its own time limits, and its error never carries a value of the call.
pub trait ActionStore: DeviceStore {
    /// Marks due requests `sent` and returns them, in one atomic step. A request is due
    /// when it is queued, its device is in `online` and active, it has not expired at
    /// `now`, its envelope's key is still trusted, and its device has no other request
    /// sent, unanswered and not expired: one at a time per device. At most one per device
    /// and [`MAX_CLAIMED_PER_SWEEP`] in all, the oldest first across all devices.
    fn claim_due(
        &self,
        online: &[DeviceId],
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<Vec<Outgoing>, Self::Error>> + Send;

    /// Puts a request that the claim at `claimed_at` marked, and that never reached the
    /// connection, back in the queue. `false` if it is no longer `sent` at that instant:
    /// answered, or sent again by a session since ([`ActionStore::resend`]).
    fn release(
        &self,
        id: RequestId,
        claimed_at: DateTime<Utc>,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send;

    /// Puts back in the queue every request still `sent` at one of the instants in
    /// `claimed_at`, and says how many: for claims whose answer was lost, which may have
    /// committed. Each sweep claims at its own instant, and a session that sends a request
    /// again stamps it with its own ([`ActionStore::resend`]), so nothing else is touched.
    fn unclaim(
        &self,
        claimed_at: &[DateTime<Utc>],
    ) -> impl Future<Output = Result<u64, Self::Error>> + Send;

    /// The requests of `device` that were sent and got no answer, to send again when a
    /// session starts: an active device, a key still trusted, not expired for longer than
    /// [`RESEND_WINDOW_SECS`]; the unexpired ones first, then the oldest; at most
    /// [`MAX_RESENT`]. In one atomic step, each is marked sent again at `now`: it is on its
    /// way through this session, and the `unclaim` of an older claim must not take it back.
    fn resend(
        &self,
        device: DeviceId,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<Vec<Outgoing>, Self::Error>> + Send;

    /// Stores what `device` answered, in one atomic step. Only the device the request was
    /// for, while it is active, only a request that was sent. An answer to a request that already has one is
    /// [`Finish::Repeated`] or [`Finish::Conflicting`] and changes nothing, unless the
    /// stored one is a refusal that [`describes_the_agent`]: then it is replaced.
    fn finish(
        &self,
        device: DeviceId,
        result: &ActionResult,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<Finish, Self::Error>> + Send;

    /// Marks `expired` the queued requests whose expiry is not after `now`, at most
    /// [`MAX_EXPIRED_PER_SWEEP`], and returns them. Sent ones are left as they are: the
    /// agent may still answer.
    fn expire(
        &self,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<Vec<(RequestId, DeviceId)>, Self::Error>> + Send;
}

/// What an operator does with keys, the catalog and requests.
pub trait ActionAdmin: ActionStore + DeviceAdmin {
    /// Trusts `key`. At most `ponte_actions::MAX_TRUSTED_KEYS`; the caller checks the key
    /// with `TrustedKeys` first.
    fn add_signing_key(
        &self,
        key: PublicKey,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<KeyAdded, Self::Error>> + Send;

    /// `false` if the key was not trusted. Manifests it signed stay in the catalog, but no
    /// request with one of them is sent from then on.
    fn remove_signing_key(
        &self,
        key: &PublicKey,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send;

    /// The trusted keys, oldest first.
    fn signing_keys(&self) -> impl Future<Output = Result<Vec<SigningKey>, Self::Error>> + Send;

    /// `false`, and nothing changes, if the envelope is already there.
    fn add_manifest(
        &self,
        entry: &CatalogEntry,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send;

    /// The envelopes of one manifest id, or all, by id, version and `issued_at`.
    fn manifests(
        &self,
        id: Option<&ManifestId>,
    ) -> impl Future<Output = Result<Vec<CatalogEntry>, Self::Error>> + Send;

    /// Queues a request, in one atomic step: refused for a device that is unknown or not
    /// active, an envelope the catalog does not hold, or a device with
    /// [`MAX_OPEN_PER_DEVICE`] requests open.
    fn request_action(
        &self,
        request: &NewRequest,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<RequestOutcome, Self::Error>> + Send;

    fn request(
        &self,
        id: RequestId,
    ) -> impl Future<Output = Result<Option<RequestRecord>, Self::Error>> + Send;

    /// The newest `limit` requests, of one device or all.
    fn requests(
        &self,
        device: Option<DeviceId>,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<RequestRecord>, Self::Error>> + Send;

    /// Cancels a queued request, in one atomic step. A sent one is not cancelled.
    fn cancel(
        &self,
        id: RequestId,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<CancelOutcome, Self::Error>> + Send;
}

impl Inner {
    fn trusted(&self, key: &PublicKey) -> bool {
        self.signing_keys
            .iter()
            .any(|known| known.public_key == *key)
    }

    fn outgoing(&self, request: &RequestRecord) -> Option<Outgoing> {
        let entry = self.manifests.get(&request.manifest)?;
        Some(Outgoing {
            device: request.device,
            id: entry.id.clone(),
            version: entry.version,
            request: Box::new(ActionRequest {
                request_id: request.id,
                manifest: entry.envelope.clone(),
                expires_at: request.expires_at,
                initiator: request.initiator.clone(),
            }),
        })
    }

    fn device_is_active(&self, device: DeviceId) -> bool {
        self.devices
            .get(&device)
            .is_some_and(|record| record.status == DeviceStatus::Active)
    }

    fn key_of(&self, request: &RequestRecord) -> Option<PublicKey> {
        Some(self.manifests.get(&request.manifest)?.envelope.public_key)
    }

    fn sendable(&self, request: &RequestRecord) -> bool {
        self.device_is_active(request.device)
            && self.key_of(request).is_some_and(|key| self.trusted(&key))
    }

    fn open(&self, device: DeviceId, now: i64) -> usize {
        self.requests
            .values()
            .filter(|record| record.device == device)
            .filter(|record| match record.state {
                RequestState::Queued => true,
                RequestState::Sent { .. } => not_expired(record.expires_at, now),
                _ => false,
            })
            .count()
    }

    /// Requests in the order they were made: ids are UUIDv7, so the id breaks a tie.
    fn by_age(&self) -> Vec<&RequestRecord> {
        let mut requests: Vec<_> = self.requests.values().collect();
        requests.sort_by_key(|record| (record.created_at, *record.id.as_uuid()));
        requests
    }
}

fn not_expired(expires_at: u64, now: i64) -> bool {
    i128::from(expires_at) > i128::from(now)
}

impl MemoryStore {
    /// What the store holds about a request, without waiting. For tests, like
    /// [`MemoryStore::record`].
    #[must_use]
    pub fn request_record(&self, id: RequestId) -> Option<RequestRecord> {
        self.lock().requests.get(&id).cloned()
    }
}

impl ActionStore for MemoryStore {
    async fn claim_due(
        &self,
        online: &[DeviceId],
        now: DateTime<Utc>,
    ) -> Result<Vec<Outgoing>, Self::Error> {
        let mut inner = self.lock();
        let now_secs = secs(now);
        let busy: Vec<DeviceId> = inner
            .requests
            .values()
            .filter(|record| {
                matches!(record.state, RequestState::Sent { .. })
                    && not_expired(record.expires_at, now_secs)
            })
            .map(|record| record.device)
            .collect();
        let mut chosen: Vec<RequestId> = Vec::new();
        let mut devices: Vec<DeviceId> = Vec::new();
        for record in inner.by_age() {
            if chosen.len() == MAX_CLAIMED_PER_SWEEP {
                break;
            }
            if record.state == RequestState::Queued
                && online.contains(&record.device)
                && !busy.contains(&record.device)
                && !devices.contains(&record.device)
                && not_expired(record.expires_at, now_secs)
                && inner.sendable(record)
            {
                chosen.push(record.id);
                devices.push(record.device);
            }
        }
        let mut claimed = Vec::new();
        for id in chosen {
            let Some(record) = inner.requests.get_mut(&id) else {
                continue;
            };
            record.state = RequestState::Sent { at: now };
            let record = record.clone();
            claimed.extend(inner.outgoing(&record));
        }
        Ok(claimed)
    }

    async fn release(&self, id: RequestId, claimed_at: DateTime<Utc>) -> Result<bool, Self::Error> {
        let mut inner = self.lock();
        Ok(match inner.requests.get_mut(&id) {
            Some(record) if record.state == (RequestState::Sent { at: claimed_at }) => {
                record.state = RequestState::Queued;
                true
            }
            _ => false,
        })
    }

    async fn unclaim(&self, claimed_at: &[DateTime<Utc>]) -> Result<u64, Self::Error> {
        let mut inner = self.lock();
        let mut count = 0;
        for record in inner.requests.values_mut() {
            if matches!(record.state, RequestState::Sent { at } if claimed_at.contains(&at)) {
                record.state = RequestState::Queued;
                count += 1;
            }
        }
        Ok(count)
    }

    async fn resend(
        &self,
        device: DeviceId,
        now: DateTime<Utc>,
    ) -> Result<Vec<Outgoing>, Self::Error> {
        let mut inner = self.lock();
        let now_secs = secs(now);
        let mut waiting: Vec<&RequestRecord> = inner
            .by_age()
            .into_iter()
            .filter(|record| {
                record.device == device
                    && matches!(record.state, RequestState::Sent { .. })
                    && not_expired(record.expires_at, now_secs - RESEND_WINDOW_SECS)
                    && inner.sendable(record)
            })
            .collect();
        // Stable: within each group, still the oldest first.
        waiting.sort_by_key(|record| !not_expired(record.expires_at, now_secs));
        let chosen: Vec<RequestId> = waiting
            .into_iter()
            .take(MAX_RESENT)
            .map(|record| record.id)
            .collect();
        let mut resent = Vec::new();
        for id in chosen {
            let Some(record) = inner.requests.get_mut(&id) else {
                continue;
            };
            record.state = RequestState::Sent { at: now };
            let record = record.clone();
            resent.extend(inner.outgoing(&record));
        }
        Ok(resent)
    }

    async fn finish(
        &self,
        device: DeviceId,
        result: &ActionResult,
        now: DateTime<Utc>,
    ) -> Result<Finish, Self::Error> {
        let mut inner = self.lock();
        let active = inner.device_is_active(device);
        let Some(record) = inner.requests.get_mut(&result.request_id) else {
            return Ok(Finish::Unknown);
        };
        if record.device != device {
            return Ok(Finish::OtherDevice);
        }
        if !active {
            return Ok(Finish::DeviceNotActive);
        }
        let (judged, sent_at) = match &record.state {
            RequestState::Sent { at } => (judge(Stored::Sent, &result.outcome), *at),
            RequestState::Answered {
                outcome, sent_at, ..
            } => (judge(Stored::Answered(outcome), &result.outcome), *sent_at),
            RequestState::Queued
            | RequestState::Cancelled { .. }
            | RequestState::Expired { .. } => {
                return Ok(judge(Stored::NeverSent, &result.outcome));
            }
        };
        if let Finish::Recorded { .. } = judged {
            record.state = RequestState::Answered {
                sent_at,
                at: now,
                outcome: result.outcome.clone(),
                duration_ms: result.duration_ms,
                output: result.output.clone(),
            };
        }
        Ok(judged)
    }

    async fn expire(&self, now: DateTime<Utc>) -> Result<Vec<(RequestId, DeviceId)>, Self::Error> {
        let mut inner = self.lock();
        let now_secs = secs(now);
        let due: Vec<RequestId> = inner
            .by_age()
            .into_iter()
            .filter(|record| {
                record.state == RequestState::Queued && !not_expired(record.expires_at, now_secs)
            })
            .take(MAX_EXPIRED_PER_SWEEP)
            .map(|record| record.id)
            .collect();
        let mut expired = Vec::new();
        for id in due {
            if let Some(record) = inner.requests.get_mut(&id) {
                record.state = RequestState::Expired { at: now };
                expired.push((id, record.device));
            }
        }
        Ok(expired)
    }
}

impl ActionAdmin for MemoryStore {
    async fn add_signing_key(
        &self,
        key: PublicKey,
        now: DateTime<Utc>,
    ) -> Result<KeyAdded, Self::Error> {
        let mut inner = self.lock();
        if inner.trusted(&key) {
            return Ok(KeyAdded::AlreadyTrusted);
        }
        if inner.signing_keys.len() >= ponte_actions::MAX_TRUSTED_KEYS {
            return Ok(KeyAdded::Full);
        }
        inner.signing_keys.push(SigningKey {
            public_key: key,
            added_at: now,
        });
        Ok(KeyAdded::Added)
    }

    async fn remove_signing_key(&self, key: &PublicKey) -> Result<bool, Self::Error> {
        let mut inner = self.lock();
        let before = inner.signing_keys.len();
        inner.signing_keys.retain(|known| known.public_key != *key);
        Ok(inner.signing_keys.len() != before)
    }

    async fn signing_keys(&self) -> Result<Vec<SigningKey>, Self::Error> {
        Ok(self.lock().signing_keys.clone())
    }

    async fn add_manifest(
        &self,
        entry: &CatalogEntry,
        _now: DateTime<Utc>,
    ) -> Result<bool, Self::Error> {
        let mut inner = self.lock();
        if inner.manifests.contains_key(&entry.hash) {
            return Ok(false);
        }
        inner.manifests.insert(entry.hash, entry.clone());
        Ok(true)
    }

    async fn manifests(&self, id: Option<&ManifestId>) -> Result<Vec<CatalogEntry>, Self::Error> {
        let mut entries: Vec<CatalogEntry> = self
            .lock()
            .manifests
            .values()
            .filter(|entry| id.is_none_or(|id| entry.id == *id))
            .cloned()
            .collect();
        entries.sort_by_key(|entry| {
            (
                entry.id.clone(),
                entry.version,
                entry.envelope.issued_at,
                entry.hash,
            )
        });
        Ok(entries)
    }

    async fn request_action(
        &self,
        request: &NewRequest,
        now: DateTime<Utc>,
    ) -> Result<RequestOutcome, Self::Error> {
        let mut inner = self.lock();
        let refused = |refusal| Ok(RequestOutcome::Refused(refusal));
        let Some(device) = inner.devices.get(&request.device) else {
            return refused(RequestRefusal::UnknownDevice);
        };
        if device.status != DeviceStatus::Active {
            return refused(RequestRefusal::DeviceNotActive(device.status));
        }
        if i64::try_from(request.expires_at).is_err() {
            return refused(RequestRefusal::ExpiryOutOfRange);
        }
        let Some(entry) = inner.manifests.get(&request.manifest) else {
            return refused(RequestRefusal::UnknownManifest);
        };
        let (manifest_id, version) = (entry.id.clone(), entry.version);
        if inner.open(request.device, secs(now)) >= MAX_OPEN_PER_DEVICE {
            return refused(RequestRefusal::TooManyOpen);
        }
        inner.requests.insert(
            request.id,
            RequestRecord {
                id: request.id,
                device: request.device,
                manifest: request.manifest,
                manifest_id,
                version,
                initiator: request.initiator.clone(),
                expires_at: request.expires_at,
                created_at: now,
                state: RequestState::Queued,
            },
        );
        Ok(RequestOutcome::Queued)
    }

    async fn request(&self, id: RequestId) -> Result<Option<RequestRecord>, Self::Error> {
        Ok(self.lock().requests.get(&id).cloned())
    }

    async fn requests(
        &self,
        device: Option<DeviceId>,
        limit: usize,
    ) -> Result<Vec<RequestRecord>, Self::Error> {
        let inner = self.lock();
        let mut records: Vec<RequestRecord> = inner
            .by_age()
            .into_iter()
            .filter(|record| device.is_none_or(|device| record.device == device))
            .cloned()
            .collect();
        records.reverse();
        records.truncate(limit);
        Ok(records)
    }

    async fn cancel(
        &self,
        id: RequestId,
        now: DateTime<Utc>,
    ) -> Result<CancelOutcome, Self::Error> {
        let mut inner = self.lock();
        Ok(match inner.requests.get_mut(&id) {
            None => CancelOutcome::Unknown,
            Some(record) if record.state == RequestState::Queued => {
                record.state = RequestState::Cancelled { at: now };
                CancelOutcome::Cancelled
            }
            Some(_) => CancelOutcome::NotQueued,
        })
    }
}
