//! [`ActionStore`] and [`ActionAdmin`] over the tables of `0002_actions.sql`.
//!
//! The same rules as the rest of the store: one atomic step per rule (a statement, or a
//! transaction that locks the row it decides on first), every query checked by the `query!`
//! macros, and errors that name the operation and never a value. Dates of the wire are
//! `bigint` seconds, converted with a check both ways.

use std::str::FromStr;

use chrono::{DateTime, Utc};
use ponte_actions::RiskLevel;
use ponte_protocol::{
    ActionOutcome, ActionRequest, ActionResult, DeviceId, FailReason, Initiator, ManifestText,
    Output, PublicKey, RejectReason, RequestId, Signature, SignedManifest,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use sqlx::types::Json;
use tracing::warn;
use uuid::Uuid;

use super::{ErrorKind, PgStore, PgStoreError, bounded, corrupt, failed, public_key, status_of};
use crate::agents::store::DeviceStatus;
use crate::agents::store::actions::{
    ActionAdmin, ActionStore, CancelOutcome, CatalogEntry, EnvelopeHash, Finish, KeyAdded,
    MAX_CLAIMED_PER_SWEEP, MAX_EXPIRED_PER_SWEEP, MAX_OPEN_PER_DEVICE, MAX_RESENT, ManifestId,
    NewRequest, Outgoing, RESEND_WINDOW_SECS, RequestOutcome, RequestRecord, RequestRefusal,
    RequestState, SigningKey, Stored, judge, outcome_name, secs,
};

fn out_of_range(operation: &'static str, what: &'static str) -> PgStoreError {
    PgStoreError {
        operation,
        kind: ErrorKind::OutOfRange(what),
    }
}

/// A count or a limit as the database takes it.
fn limit(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// A date of the wire as a stored `bigint`, refused rather than saturated.
fn stored_secs(operation: &'static str, value: u64) -> Result<i64, PgStoreError> {
    i64::try_from(value).map_err(|_| out_of_range(operation, "date"))
}

/// A stored `bigint` date as the wire has it.
fn wire_secs(operation: &'static str, value: i64) -> Result<u64, PgStoreError> {
    u64::try_from(value).map_err(|_| corrupt(operation, "date"))
}

fn version_of(operation: &'static str, value: i64) -> Result<u32, PgStoreError> {
    u32::try_from(value)
        .ok()
        .filter(|version| *version >= 1)
        .ok_or_else(|| corrupt(operation, "version"))
}

fn manifest_id(operation: &'static str, text: &str) -> Result<ManifestId, PgStoreError> {
    text.parse().map_err(|_| corrupt(operation, "manifest id"))
}

fn risk_text(risk: RiskLevel) -> &'static str {
    match risk {
        RiskLevel::Read => "read",
        RiskLevel::Low => "low",
        RiskLevel::Medium => "medium",
        RiskLevel::High => "high",
    }
}

fn risk_of(operation: &'static str, text: &str) -> Result<RiskLevel, PgStoreError> {
    match text {
        "read" => Ok(RiskLevel::Read),
        "low" => Ok(RiskLevel::Low),
        "medium" => Ok(RiskLevel::Medium),
        "high" => Ok(RiskLevel::High),
        _ => Err(corrupt(operation, "risk")),
    }
}

fn hash_of(operation: &'static str, bytes: &[u8]) -> Result<EnvelopeHash, PgStoreError> {
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| corrupt(operation, "envelope hash"))?;
    Ok(EnvelopeHash::from_bytes(bytes))
}

/// The code of a reason, as the wire spells it (`queue_full`).
fn code<T: Serialize>(operation: &'static str, reason: &T) -> Result<String, PgStoreError> {
    match serde_json::to_value(reason) {
        Ok(serde_json::Value::String(code)) => Ok(code),
        _ => Err(PgStoreError {
            operation,
            kind: ErrorKind::Other,
        }),
    }
}

fn decode<T: DeserializeOwned>(operation: &'static str, code: &str) -> Result<T, PgStoreError> {
    serde_json::from_value(serde_json::Value::String(code.to_owned()))
        .map_err(|_| corrupt(operation, "reason"))
}

/// An outcome as the columns `status`, `reason` and `step` hold it.
struct OutcomeColumns {
    status: &'static str,
    reason: Option<String>,
    step: Option<i16>,
}

fn columns(
    operation: &'static str,
    outcome: &ActionOutcome,
) -> Result<OutcomeColumns, PgStoreError> {
    let (reason, step) = match outcome {
        ActionOutcome::Failed { reason, step } => {
            (Some(code(operation, reason)?), step.map(i16::from))
        }
        ActionOutcome::Rejected { reason } => (Some(code(operation, reason)?), None),
        ActionOutcome::Succeeded {} | ActionOutcome::Cancelled {} | ActionOutcome::TimedOut {} => {
            (None, None)
        }
    };
    Ok(OutcomeColumns {
        status: outcome_name(outcome),
        reason,
        step,
    })
}

/// The agent's answer the columns hold, or `None` for a status that is not one.
fn outcome_of(
    operation: &'static str,
    status: &str,
    sent: bool,
    reason: Option<&str>,
    step: Option<i16>,
) -> Result<Option<ActionOutcome>, PgStoreError> {
    let step = step
        .map(|step| u8::try_from(step).map_err(|_| corrupt(operation, "step")))
        .transpose()?;
    let reason = || reason.ok_or_else(|| corrupt(operation, "reason"));
    Ok(Some(match status {
        "succeeded" => ActionOutcome::Succeeded {},
        "failed" => ActionOutcome::Failed {
            reason: decode::<FailReason>(operation, reason()?)?,
            step,
        },
        "rejected" => ActionOutcome::Rejected {
            reason: decode::<RejectReason>(operation, reason()?)?,
        },
        "timed_out" => ActionOutcome::TimedOut {},
        "cancelled" if sent => ActionOutcome::Cancelled {},
        "queued" | "sent" | "expired" | "cancelled" => return Ok(None),
        _ => return Err(corrupt(operation, "status")),
    }))
}

fn initiator_of(
    operation: &'static str,
    stored: serde_json::Value,
) -> Result<Initiator, PgStoreError> {
    serde_json::from_value(stored).map_err(|_| corrupt(operation, "initiator"))
}

/// The columns of a manifest a request is sent with.
struct EnvelopeColumns {
    manifest: String,
    issued_at: i64,
    expires_at: i64,
    public_key: Vec<u8>,
    signature: Vec<u8>,
}

impl EnvelopeColumns {
    fn envelope(self, operation: &'static str) -> Result<SignedManifest, PgStoreError> {
        let signature: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| corrupt(operation, "signature"))?;
        Ok(SignedManifest {
            manifest: ManifestText::from_str(&self.manifest)
                .map_err(|_| corrupt(operation, "manifest"))?,
            issued_at: wire_secs(operation, self.issued_at)?,
            expires_at: wire_secs(operation, self.expires_at)?,
            public_key: public_key(operation, &self.public_key)?,
            signature: Signature::from_bytes(signature),
        })
    }
}

/// One row of a request on its way to the agent.
struct OutgoingRow {
    id: Uuid,
    device_id: Uuid,
    expires_at: i64,
    initiator: serde_json::Value,
    manifest_id: String,
    version: i64,
    envelope: EnvelopeColumns,
}

impl OutgoingRow {
    fn outgoing(self, operation: &'static str) -> Result<Outgoing, PgStoreError> {
        Ok(Outgoing {
            device: DeviceId::from_uuid(self.device_id),
            id: manifest_id(operation, &self.manifest_id)?,
            version: version_of(operation, self.version)?,
            request: Box::new(ActionRequest {
                request_id: RequestId::from_uuid(self.id),
                manifest: self.envelope.envelope(operation)?,
                expires_at: wire_secs(operation, self.expires_at)?,
                initiator: initiator_of(operation, self.initiator)?,
            }),
        })
    }
}

/// One row of a catalog listing.
struct ManifestRow {
    hash: Vec<u8>,
    manifest_id: String,
    version: i64,
    risk: String,
    envelope: EnvelopeColumns,
}

impl ManifestRow {
    fn entry(self, operation: &'static str) -> Result<CatalogEntry, PgStoreError> {
        let entry = CatalogEntry::stored(
            manifest_id(operation, &self.manifest_id)?,
            version_of(operation, self.version)?,
            risk_of(operation, &self.risk)?,
            self.envelope.envelope(operation)?,
        );
        // The key of the row must be the envelope's own: a row edited by hand is no
        // envelope the catalog accepted.
        if *entry.hash() != hash_of(operation, &self.hash)? {
            return Err(corrupt(operation, "envelope hash"));
        }
        Ok(entry)
    }
}

/// One row of `action_requests` with the manifest's id and version.
struct RequestRow {
    id: Uuid,
    device_id: Uuid,
    manifest_hash: Vec<u8>,
    manifest_id: String,
    version: i64,
    initiator: serde_json::Value,
    expires_at: i64,
    status: String,
    created_at: DateTime<Utc>,
    sent_at: Option<DateTime<Utc>>,
    finished_at: Option<DateTime<Utc>>,
    reason: Option<String>,
    step: Option<i16>,
    duration_ms: Option<i64>,
    output: Option<String>,
}

impl RequestRow {
    fn record(self, operation: &'static str) -> Result<RequestRecord, PgStoreError> {
        let missing = |what| corrupt(operation, what);
        let outcome = outcome_of(
            operation,
            &self.status,
            self.sent_at.is_some(),
            self.reason.as_deref(),
            self.step,
        )?;
        let state = match (self.status.as_str(), outcome) {
            ("queued", None) => RequestState::Queued,
            ("sent", None) => RequestState::Sent {
                at: self.sent_at.ok_or_else(|| missing("sent at"))?,
            },
            ("expired", None) => RequestState::Expired {
                at: self.finished_at.ok_or_else(|| missing("finished at"))?,
            },
            ("cancelled", None) => RequestState::Cancelled {
                at: self.finished_at.ok_or_else(|| missing("finished at"))?,
            },
            (_, Some(outcome)) => RequestState::Answered {
                sent_at: self.sent_at.ok_or_else(|| missing("sent at"))?,
                at: self.finished_at.ok_or_else(|| missing("finished at"))?,
                outcome,
                duration_ms: self
                    .duration_ms
                    .and_then(|duration| u64::try_from(duration).ok())
                    .ok_or_else(|| missing("duration"))?,
                output: self
                    .output
                    .map(|output| Output::from_str(&output).map_err(|_| missing("output")))
                    .transpose()?,
            },
            _ => return Err(missing("status")),
        };
        Ok(RequestRecord {
            id: RequestId::from_uuid(self.id),
            device: DeviceId::from_uuid(self.device_id),
            manifest: hash_of(operation, &self.manifest_hash)?,
            manifest_id: manifest_id(operation, &self.manifest_id)?,
            version: version_of(operation, self.version)?,
            initiator: initiator_of(operation, self.initiator)?,
            expires_at: wire_secs(operation, self.expires_at)?,
            created_at: self.created_at,
            state,
        })
    }
}

/// The columns `OutgoingRow` reads, from a query that names them so.
macro_rules! outgoing_row {
    ($row:expr) => {
        OutgoingRow {
            id: $row.id,
            device_id: $row.device_id,
            expires_at: $row.expires_at,
            initiator: $row.initiator,
            manifest_id: $row.manifest_id,
            version: $row.version,
            envelope: EnvelopeColumns {
                manifest: $row.manifest,
                issued_at: $row.issued_at,
                expires_at: $row.manifest_expires_at,
                public_key: $row.public_key,
                signature: $row.signature,
            },
        }
    };
}

impl ActionStore for PgStore {
    async fn claim_due(
        &self,
        online: &[DeviceId],
        now: DateTime<Utc>,
    ) -> Result<Vec<Outgoing>, Self::Error> {
        const OPERATION: &str = "claim the requests that are due";
        if online.is_empty() {
            return Ok(Vec::new());
        }
        let online: Vec<Uuid> = online.iter().map(|device| *device.as_uuid()).collect();
        bounded(OPERATION, async {
            // The first queued request of each device, then the oldest of those across
            // devices. The `status = 'queued'` of the outer statement is checked again
            // against a row a concurrent `cancel` or `expire` changed: whichever commits
            // first wins, never both.
            let rows = sqlx::query!(
                r#"WITH due AS (
                       SELECT id FROM (
                           SELECT DISTINCT ON (q.device_id) q.id, q.created_at
                           FROM action_requests q
                           JOIN devices d ON d.id = q.device_id AND d.status = 'active'
                           JOIN manifests m ON m.hash = q.manifest_hash
                           JOIN signing_keys k ON k.public_key = m.public_key
                           WHERE q.status = 'queued'
                             AND q.device_id = ANY($1::uuid[])
                             AND q.expires_at > $2
                             AND NOT EXISTS (
                                 SELECT 1 FROM action_requests s
                                 WHERE s.device_id = q.device_id AND s.status = 'sent'
                                   AND s.expires_at > $2)
                           ORDER BY q.device_id, q.created_at, q.id
                       ) firsts
                       ORDER BY created_at, id
                       LIMIT $3
                   )
                   UPDATE action_requests r SET status = 'sent', sent_at = $4
                   FROM due, manifests m
                   WHERE r.id = due.id AND r.status = 'queued' AND m.hash = r.manifest_hash
                   RETURNING r.id AS "id!", r.device_id AS "device_id!",
                             r.expires_at AS "expires_at!", r.initiator AS "initiator!",
                             m.manifest_id AS "manifest_id!", m.version AS "version!",
                             m.manifest AS "manifest!", m.issued_at AS "issued_at!",
                             m.expires_at AS "manifest_expires_at!",
                             m.public_key AS "public_key!", m.signature AS "signature!""#,
                &online,
                secs(now),
                limit(MAX_CLAIMED_PER_SWEEP),
                now,
            )
            .fetch_all(&self.pool)
            .await
            .map_err(failed(OPERATION))?;
            // Each row on its own: the statement committed, and a row that does not read
            // must not keep the others from their sessions. It stays `sent`, undelivered,
            // like any request whose answer is lost; the agent never sees what it holds.
            Ok(rows
                .into_iter()
                .filter_map(|row| {
                    let id = row.id;
                    outgoing_row!(row)
                        .outgoing(OPERATION)
                        .inspect_err(|error| {
                            warn!(request = %id, %error, "a claimed request does not read; it is not sent");
                        })
                        .ok()
                })
                .collect())
        })
        .await
    }

    async fn unclaim(&self, claimed_at: DateTime<Utc>) -> Result<u64, Self::Error> {
        const OPERATION: &str = "put back the requests of a claim";
        bounded(OPERATION, async {
            let released = sqlx::query!(
                "UPDATE action_requests SET status = 'queued', sent_at = NULL
                 WHERE status = 'sent' AND sent_at = $1",
                claimed_at,
            )
            .execute(&self.pool)
            .await
            .map_err(failed(OPERATION))?;
            Ok(released.rows_affected())
        })
        .await
    }

    async fn release(&self, id: RequestId) -> Result<bool, Self::Error> {
        const OPERATION: &str = "put a request back in the queue";
        bounded(OPERATION, async {
            let released = sqlx::query!(
                "UPDATE action_requests SET status = 'queued', sent_at = NULL
                 WHERE id = $1 AND status = 'sent'",
                id.as_uuid(),
            )
            .execute(&self.pool)
            .await
            .map_err(failed(OPERATION))?;
            Ok(released.rows_affected() == 1)
        })
        .await
    }

    async fn unanswered(
        &self,
        device: DeviceId,
        now: DateTime<Utc>,
    ) -> Result<Vec<Outgoing>, Self::Error> {
        const OPERATION: &str = "read the requests that got no answer";
        bounded(OPERATION, async {
            let now = secs(now);
            let rows = sqlx::query!(
                r#"SELECT r.id, r.device_id, r.expires_at, r.initiator,
                          m.manifest_id, m.version, m.manifest, m.issued_at,
                          m.expires_at AS manifest_expires_at, m.public_key, m.signature
                   FROM action_requests r
                   JOIN devices d ON d.id = r.device_id AND d.status = 'active'
                   JOIN manifests m ON m.hash = r.manifest_hash
                   JOIN signing_keys k ON k.public_key = m.public_key
                   WHERE r.device_id = $1 AND r.status = 'sent' AND r.expires_at > $3
                   ORDER BY r.expires_at > $2 DESC, r.created_at, r.id
                   LIMIT $4"#,
                device.as_uuid(),
                now,
                now.saturating_sub(RESEND_WINDOW_SECS),
                limit(MAX_RESENT),
            )
            .fetch_all(&self.pool)
            .await
            .map_err(failed(OPERATION))?;
            rows.into_iter()
                .map(|row| outgoing_row!(row).outgoing(OPERATION))
                .collect()
        })
        .await
    }

    async fn finish(
        &self,
        device: DeviceId,
        result: &ActionResult,
        now: DateTime<Utc>,
    ) -> Result<Finish, Self::Error> {
        const OPERATION: &str = "store the result of a request";
        let columns = columns(OPERATION, &result.outcome)?;
        let duration =
            i64::try_from(result.duration_ms).map_err(|_| out_of_range(OPERATION, "duration"))?;
        bounded(OPERATION, async {
            let mut tx = self.pool.begin().await.map_err(failed(OPERATION))?;
            // Locked until the end: two answers to one request take turns, and the second
            // is judged against what the first stored.
            let row = sqlx::query!(
                r#"SELECT r.device_id, r.status, r.sent_at, r.reason, r.step,
                          d.status AS "device_status"
                   FROM action_requests r JOIN devices d ON d.id = r.device_id
                   WHERE r.id = $1 FOR UPDATE OF r"#,
                result.request_id.as_uuid(),
            )
            .fetch_optional(&mut *tx)
            .await
            .map_err(failed(OPERATION))?;
            let Some(row) = row else {
                return Ok(Finish::Unknown);
            };
            if row.device_id != *device.as_uuid() {
                return Ok(Finish::OtherDevice);
            }
            if status_of(OPERATION, &row.device_status)? != DeviceStatus::Active {
                return Ok(Finish::DeviceNotActive);
            }
            let before = outcome_of(
                OPERATION,
                &row.status,
                row.sent_at.is_some(),
                row.reason.as_deref(),
                row.step,
            )?;
            let stored = match (&before, row.status.as_str()) {
                (Some(outcome), _) => Stored::Answered(outcome),
                (None, "sent") => Stored::Sent,
                (None, _) => Stored::NeverSent,
            };
            let judged = judge(stored, &result.outcome);
            if let Finish::Recorded { .. } = judged {
                sqlx::query!(
                    "UPDATE action_requests SET status = $2, reason = $3, step = $4,
                         duration_ms = $5, output = $6, finished_at = $7
                     WHERE id = $1",
                    result.request_id.as_uuid(),
                    columns.status,
                    columns.reason,
                    columns.step,
                    duration,
                    result.output.as_ref().map(Output::as_str),
                    now,
                )
                .execute(&mut *tx)
                .await
                .map_err(failed(OPERATION))?;
                tx.commit().await.map_err(failed(OPERATION))?;
            }
            Ok(judged)
        })
        .await
    }

    async fn expire(&self, now: DateTime<Utc>) -> Result<Vec<(RequestId, DeviceId)>, Self::Error> {
        const OPERATION: &str = "expire the requests that waited too long";
        bounded(OPERATION, async {
            let rows = sqlx::query!(
                r#"UPDATE action_requests r SET status = 'expired', finished_at = $3
                   FROM (SELECT id FROM action_requests
                         WHERE status = 'queued' AND expires_at <= $1
                         ORDER BY created_at, id LIMIT $2) due
                   WHERE r.id = due.id AND r.status = 'queued'
                   RETURNING r.id, r.device_id"#,
                secs(now),
                limit(MAX_EXPIRED_PER_SWEEP),
                now,
            )
            .fetch_all(&self.pool)
            .await
            .map_err(failed(OPERATION))?;
            Ok(rows
                .into_iter()
                .map(|row| {
                    (
                        RequestId::from_uuid(row.id),
                        DeviceId::from_uuid(row.device_id),
                    )
                })
                .collect())
        })
        .await
    }
}

impl ActionAdmin for PgStore {
    async fn add_signing_key(
        &self,
        key: PublicKey,
        now: DateTime<Utc>,
    ) -> Result<KeyAdded, Self::Error> {
        const OPERATION: &str = "trust a signing key";
        bounded(OPERATION, async {
            let mut tx = self.pool.begin().await.map_err(failed(OPERATION))?;
            // Additions take turns, so two at once cannot both find room for one.
            sqlx::query!("LOCK TABLE signing_keys IN EXCLUSIVE MODE")
                .execute(&mut *tx)
                .await
                .map_err(failed(OPERATION))?;
            let known = sqlx::query!(
                r#"SELECT count(*) AS "count!",
                          bool_or(public_key = $1) AS trusted
                   FROM signing_keys"#,
                &key.as_bytes()[..],
            )
            .fetch_one(&mut *tx)
            .await
            .map_err(failed(OPERATION))?;
            let added = if known.trusted == Some(true) {
                KeyAdded::AlreadyTrusted
            } else if known.count >= limit(ponte_actions::MAX_TRUSTED_KEYS) {
                KeyAdded::Full
            } else {
                sqlx::query!(
                    "INSERT INTO signing_keys (public_key, added_at) VALUES ($1, $2)",
                    &key.as_bytes()[..],
                    now,
                )
                .execute(&mut *tx)
                .await
                .map_err(failed(OPERATION))?;
                KeyAdded::Added
            };
            tx.commit().await.map_err(failed(OPERATION))?;
            Ok(added)
        })
        .await
    }

    async fn remove_signing_key(&self, key: &PublicKey) -> Result<bool, Self::Error> {
        const OPERATION: &str = "stop trusting a signing key";
        bounded(OPERATION, async {
            let removed = sqlx::query!(
                "DELETE FROM signing_keys WHERE public_key = $1",
                &key.as_bytes()[..],
            )
            .execute(&self.pool)
            .await
            .map_err(failed(OPERATION))?;
            Ok(removed.rows_affected() == 1)
        })
        .await
    }

    async fn signing_keys(&self) -> Result<Vec<SigningKey>, Self::Error> {
        const OPERATION: &str = "list the signing keys";
        bounded(OPERATION, async {
            let rows = sqlx::query!(
                "SELECT public_key, added_at FROM signing_keys ORDER BY added_at, public_key"
            )
            .fetch_all(&self.pool)
            .await
            .map_err(failed(OPERATION))?;
            rows.into_iter()
                .map(|row| {
                    Ok(SigningKey {
                        public_key: public_key(OPERATION, &row.public_key)?,
                        added_at: row.added_at,
                    })
                })
                .collect()
        })
        .await
    }

    async fn add_manifest(
        &self,
        entry: &CatalogEntry,
        now: DateTime<Utc>,
    ) -> Result<bool, Self::Error> {
        const OPERATION: &str = "add a manifest to the catalog";
        let envelope = entry.envelope();
        let issued_at = stored_secs(OPERATION, envelope.issued_at)?;
        let expires_at = stored_secs(OPERATION, envelope.expires_at)?;
        bounded(OPERATION, async {
            let added = sqlx::query!(
                "INSERT INTO manifests (hash, manifest_id, version, risk, manifest, issued_at,
                                        expires_at, public_key, signature, added_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                 ON CONFLICT (hash) DO NOTHING",
                &entry.hash().as_bytes()[..],
                entry.id().as_str(),
                i64::from(entry.version()),
                risk_text(entry.risk()),
                envelope.manifest.as_str(),
                issued_at,
                expires_at,
                &envelope.public_key.as_bytes()[..],
                &envelope.signature.as_bytes()[..],
                now,
            )
            .execute(&self.pool)
            .await
            .map_err(failed(OPERATION))?;
            Ok(added.rows_affected() == 1)
        })
        .await
    }

    async fn manifests(&self, id: Option<&ManifestId>) -> Result<Vec<CatalogEntry>, Self::Error> {
        const OPERATION: &str = "list the catalog";
        bounded(OPERATION, async {
            // Byte order for the id, the same as everywhere else, whatever the locale.
            let rows = sqlx::query!(
                r#"SELECT hash, manifest_id, version, risk, manifest, issued_at, expires_at,
                          public_key, signature
                   FROM manifests
                   WHERE $1::text IS NULL OR manifest_id = $1
                   ORDER BY manifest_id COLLATE "C", version, issued_at, hash"#,
                id.map(ManifestId::as_str),
            )
            .fetch_all(&self.pool)
            .await
            .map_err(failed(OPERATION))?;
            rows.into_iter()
                .map(|row| {
                    ManifestRow {
                        hash: row.hash,
                        manifest_id: row.manifest_id,
                        version: row.version,
                        risk: row.risk,
                        envelope: EnvelopeColumns {
                            manifest: row.manifest,
                            issued_at: row.issued_at,
                            expires_at: row.expires_at,
                            public_key: row.public_key,
                            signature: row.signature,
                        },
                    }
                    .entry(OPERATION)
                })
                .collect()
        })
        .await
    }

    async fn request_action(
        &self,
        request: &NewRequest,
        now: DateTime<Utc>,
    ) -> Result<RequestOutcome, Self::Error> {
        const OPERATION: &str = "queue a request";
        let refused = |refusal| Ok(RequestOutcome::Refused(refusal));
        let Ok(expires_at) = i64::try_from(request.expires_at) else {
            return refused(RequestRefusal::ExpiryOutOfRange);
        };
        bounded(OPERATION, async {
            let mut tx = self.pool.begin().await.map_err(failed(OPERATION))?;
            // The device's row stays locked until the end: requests for one device take
            // turns, so two at once cannot both find room under the limit.
            let device = sqlx::query!(
                "SELECT status FROM devices WHERE id = $1 FOR NO KEY UPDATE",
                request.device.as_uuid(),
            )
            .fetch_optional(&mut *tx)
            .await
            .map_err(failed(OPERATION))?;
            let Some(device) = device else {
                return refused(RequestRefusal::UnknownDevice);
            };
            let status = status_of(OPERATION, &device.status)?;
            if status != DeviceStatus::Active {
                return refused(RequestRefusal::DeviceNotActive(status));
            }
            let known = sqlx::query!(
                r#"SELECT EXISTS (SELECT 1 FROM manifests WHERE hash = $1) AS "known!""#,
                &request.manifest.as_bytes()[..],
            )
            .fetch_one(&mut *tx)
            .await
            .map_err(failed(OPERATION))?;
            if !known.known {
                return refused(RequestRefusal::UnknownManifest);
            }
            let open = sqlx::query!(
                r#"SELECT count(*) AS "open!" FROM action_requests
                   WHERE device_id = $1
                     AND (status = 'queued' OR (status = 'sent' AND expires_at > $2))"#,
                request.device.as_uuid(),
                secs(now),
            )
            .fetch_one(&mut *tx)
            .await
            .map_err(failed(OPERATION))?;
            if open.open >= limit(MAX_OPEN_PER_DEVICE) {
                return refused(RequestRefusal::TooManyOpen);
            }
            sqlx::query!(
                "INSERT INTO action_requests
                     (id, device_id, manifest_hash, initiator, expires_at, status, created_at)
                 VALUES ($1, $2, $3, $4, $5, 'queued', $6)",
                request.id.as_uuid(),
                request.device.as_uuid(),
                &request.manifest.as_bytes()[..],
                Json(&request.initiator) as _,
                expires_at,
                now,
            )
            .execute(&mut *tx)
            .await
            .map_err(failed(OPERATION))?;
            tx.commit().await.map_err(failed(OPERATION))?;
            Ok(RequestOutcome::Queued)
        })
        .await
    }

    async fn request(&self, id: RequestId) -> Result<Option<RequestRecord>, Self::Error> {
        const OPERATION: &str = "read a request";
        bounded(OPERATION, async {
            let row = sqlx::query_as!(
                RequestRow,
                r#"SELECT r.id, r.device_id, r.manifest_hash, m.manifest_id, m.version,
                          r.initiator, r.expires_at, r.status, r.created_at, r.sent_at,
                          r.finished_at, r.reason, r.step, r.duration_ms, r.output
                   FROM action_requests r JOIN manifests m ON m.hash = r.manifest_hash
                   WHERE r.id = $1"#,
                id.as_uuid(),
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(failed(OPERATION))?;
            row.map(|row| row.record(OPERATION)).transpose()
        })
        .await
    }

    async fn requests(
        &self,
        device: Option<DeviceId>,
        count: usize,
    ) -> Result<Vec<RequestRecord>, Self::Error> {
        const OPERATION: &str = "list the requests";
        bounded(OPERATION, async {
            let rows = sqlx::query_as!(
                RequestRow,
                r#"SELECT r.id, r.device_id, r.manifest_hash, m.manifest_id, m.version,
                          r.initiator, r.expires_at, r.status, r.created_at, r.sent_at,
                          r.finished_at, r.reason, r.step, r.duration_ms, r.output
                   FROM action_requests r JOIN manifests m ON m.hash = r.manifest_hash
                   WHERE $1::uuid IS NULL OR r.device_id = $1
                   ORDER BY r.created_at DESC, r.id DESC
                   LIMIT $2"#,
                device.as_ref().map(DeviceId::as_uuid),
                limit(count),
            )
            .fetch_all(&self.pool)
            .await
            .map_err(failed(OPERATION))?;
            rows.into_iter().map(|row| row.record(OPERATION)).collect()
        })
        .await
    }

    async fn cancel(
        &self,
        id: RequestId,
        now: DateTime<Utc>,
    ) -> Result<CancelOutcome, Self::Error> {
        const OPERATION: &str = "cancel a request";
        bounded(OPERATION, async {
            let cancelled = sqlx::query!(
                "UPDATE action_requests SET status = 'cancelled', finished_at = $2
                 WHERE id = $1 AND status = 'queued'",
                id.as_uuid(),
                now,
            )
            .execute(&self.pool)
            .await
            .map_err(failed(OPERATION))?;
            if cancelled.rows_affected() == 1 {
                return Ok(CancelOutcome::Cancelled);
            }
            // Only to say why: the statement above already decided.
            let known = sqlx::query!(
                r#"SELECT EXISTS (SELECT 1 FROM action_requests WHERE id = $1) AS "known!""#,
                id.as_uuid(),
            )
            .fetch_one(&self.pool)
            .await
            .map_err(failed(OPERATION))?;
            Ok(if known.known {
                CancelOutcome::NotQueued
            } else {
                CancelOutcome::Unknown
            })
        })
        .await
    }
}
