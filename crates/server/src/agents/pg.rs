//! The PostgreSQL store: [`DeviceStore`] and [`DeviceAdmin`] over the tables of
//! `migrations/`.
//!
//! - **Every rule is one atomic step in the database.** `enroll` is one transaction that
//!   locks the token's row first, so enrollments with one token take turns. The other calls
//!   check and write in a single statement. The constraints of the schema are the second
//!   line: a rule the code gets wrong is refused there.
//! - **All SQL is in the `query!` macros**, checked against the schema when the crate
//!   builds (`.sqlx/` holds what they checked, for builds without a database). Nothing here
//!   puts a value into SQL text.
//! - **The store sets its own time limits** (see [`CALL_LIMIT`]). `device` and `enroll` run
//!   for connections that have not authenticated yet, outside the handshake deadline: a
//!   database that hangs must not keep their places taken.
//! - **An error names what failed and how, never a value** ([`PgStoreError`]). The text of
//!   a database error can repeat what was sent, telemetry is free text from the machine, and
//!   the database URL holds a password.

use std::fmt;
use std::future::Future;
use std::num::NonZeroU32;
use std::str::FromStr;
use std::time::Duration;

use chrono::{DateTime, Utc};
use ponte_protocol::{DeviceId, Label, PublicKey, TelemetrySnapshot};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use sqlx::types::Json;
use sqlx::{Connection, PgPool, Postgres, Transaction};
use tracing::warn;
use uuid::Uuid;

use super::store::{
    AgentInfo, Customer, CustomerId, CustomerName, Device, DeviceAdmin, DeviceRecord, DeviceStatus,
    DeviceStore, EnrollOutcome, EnrollRefusal, EnrollRequest, SessionId, TokenGrant, TokenHash,
    TokenInfo,
};

/// Connections to the database. Sessions hold none between calls: each call borrows one
/// for one statement or one transaction.
pub const POOL_SIZE: u32 = 16;

/// How long a call waits for a free connection.
const ACQUIRE_LIMIT: Duration = Duration::from_secs(3);

/// How long a connection given back to the pool may take to answer a ping. Past it the
/// connection is closed and its place freed.
const RELEASE_CHECK_LIMIT: Duration = Duration::from_secs(2);

/// Connections are replaced after this long, or after this long unused, so none outlives a
/// change of the database's address by much.
const MAX_LIFETIME: Duration = Duration::from_secs(30 * 60);
const IDLE_LIMIT: Duration = Duration::from_secs(10 * 60);

/// What the database itself allows one statement, and a transaction left idle. Set on every
/// connection, so a lock is never held for longer whatever happens to the server.
const STATEMENT_LIMIT: &str = "5s";
const IDLE_IN_TRANSACTION_LIMIT: &str = "10s";

/// The most any call of this store takes, connection and every statement included. The
/// limits of the database do not fire when the database cannot be reached at all.
pub const CALL_LIMIT: Duration = Duration::from_secs(8);

/// The name of the constraint that says a key enrolls once (see the migration).
const UNIQUE_PUBLIC_KEY: &str = "devices_public_key_key";

/// The key of the advisory lock a serving process holds ([`PgStore::claim_server`]): the
/// bytes of `ponte-sv` as a big-endian number.
const SERVER_LOCK: i64 = 0x706f_6e74_652d_7376;

/// This process serves the database. Dropping it gives the claim back.
#[derive(Debug)]
pub struct ServerClaim {
    connection: sqlx::PgConnection,
}

/// How often a serving process checks that it still holds its claim ([`PgStore::hold_claim`]).
pub const CLAIM_CHECK: Duration = Duration::from_secs(30);

/// A store on a pool of connections to PostgreSQL. Clones share the pool.
#[derive(Debug, Clone)]
pub struct PgStore {
    pool: PgPool,
}

/// What went wrong, without any value of the call: see the module documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the device store could not {operation}: {kind}")]
pub struct PgStoreError {
    operation: &'static str,
    kind: ErrorKind,
}

impl PgStoreError {
    #[must_use]
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ErrorKind {
    #[error("the database URL is not valid")]
    InvalidUrl,
    #[error("a database on another host needs sslmode=verify-full in its URL")]
    InsecureTls,
    #[error("another server is already serving this database")]
    AnotherServer,
    #[error("no answer within {} seconds", CALL_LIMIT.as_secs())]
    TimedOut,
    #[error("no connection to the database was free in time")]
    PoolTimedOut,
    #[error("the connection to the database failed")]
    Connection,
    #[error("the database refused the statement (SQLSTATE {0})")]
    Database(SqlState),
    #[error("the migrations did not apply")]
    Migration,
    #[error("a row holds a value the server cannot read ({0})")]
    CorruptRow(&'static str),
    #[error("the database library failed")]
    Other,
}

/// A five-character SQLSTATE code: it says what kind of error the database had, and
/// nothing of the statement or its values.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SqlState([u8; 5]);

impl SqlState {
    fn of(code: &str) -> Option<Self> {
        let bytes: [u8; 5] = code.as_bytes().try_into().ok()?;
        bytes
            .iter()
            .all(u8::is_ascii_alphanumeric)
            .then_some(Self(bytes))
    }
}

impl fmt::Display for SqlState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Five ASCII letters and digits, checked in `of`.
        self.0
            .iter()
            .try_for_each(|byte| write!(f, "{}", char::from(*byte)))
    }
}

impl fmt::Debug for SqlState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Maps an error of the library to what may be logged: the kind, never the text.
fn failed(operation: &'static str) -> impl Fn(sqlx::Error) -> PgStoreError {
    move |error| {
        let kind = match &error {
            sqlx::Error::Database(error) => error
                .code()
                .and_then(|code| SqlState::of(&code))
                .map_or(ErrorKind::Other, ErrorKind::Database),
            sqlx::Error::PoolTimedOut => ErrorKind::PoolTimedOut,
            sqlx::Error::Io(_)
            | sqlx::Error::Tls(_)
            | sqlx::Error::Protocol(_)
            | sqlx::Error::PoolClosed
            | sqlx::Error::WorkerCrashed => ErrorKind::Connection,
            sqlx::Error::ColumnDecode { .. } | sqlx::Error::Decode(_) => {
                ErrorKind::CorruptRow("a column")
            }
            sqlx::Error::Migrate(_) => ErrorKind::Migration,
            _ => ErrorKind::Other,
        };
        PgStoreError { operation, kind }
    }
}

fn corrupt(operation: &'static str, what: &'static str) -> PgStoreError {
    PgStoreError {
        operation,
        kind: ErrorKind::CorruptRow(what),
    }
}

/// The parameters a database URL may carry. sqlx logs the name and the value of any other,
/// and a mistyped `password` is still a password; `options` could set anything at all.
const URL_PARAMETERS: [&str; 11] = [
    "host",
    "hostaddr",
    "port",
    "dbname",
    "user",
    "password",
    "sslmode",
    "sslrootcert",
    "sslcert",
    "sslkey",
    "application_name",
];

/// Whether every parameter in the query of `url` is one of [`URL_PARAMETERS`], spelled
/// exactly so.
fn known_parameters_only(url: &str) -> bool {
    let Some((_, query)) = url.split_once('?') else {
        return true;
    };
    let query = query.split_once('#').map_or(query, |(query, _)| query);
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .all(|pair| {
            let key = pair.split_once('=').map_or(pair, |(key, _)| key);
            URL_PARAMETERS.contains(&key)
        })
}

/// A database on this machine may be reached any way. One elsewhere only over TLS with its
/// certificate and name checked: the default, `prefer`, checks neither and falls back to
/// plain text without a word (invariant 7).
fn secure_enough(options: &PgConnectOptions) -> Result<(), PgStoreError> {
    let host = options.get_host();
    let local = options.get_socket().is_some()
        || host.starts_with('/')
        || matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]");
    if local || matches!(options.get_ssl_mode(), PgSslMode::VerifyFull) {
        Ok(())
    } else {
        Err(PgStoreError {
            operation: "connect",
            kind: ErrorKind::InsecureTls,
        })
    }
}

/// Runs `work` within [`CALL_LIMIT`]. A transaction cut short is rolled back.
async fn bounded<T>(
    operation: &'static str,
    work: impl Future<Output = Result<T, PgStoreError>>,
) -> Result<T, PgStoreError> {
    tokio::time::timeout(CALL_LIMIT, work)
        .await
        .unwrap_or(Err(PgStoreError {
            operation,
            kind: ErrorKind::TimedOut,
        }))
}

fn status_of(operation: &'static str, text: &str) -> Result<DeviceStatus, PgStoreError> {
    match text {
        "pending" => Ok(DeviceStatus::Pending),
        "active" => Ok(DeviceStatus::Active),
        "revoked" => Ok(DeviceStatus::Revoked),
        _ => Err(corrupt(operation, "status")),
    }
}

fn status_text(status: DeviceStatus) -> &'static str {
    match status {
        DeviceStatus::Pending => "pending",
        DeviceStatus::Active => "active",
        DeviceStatus::Revoked => "revoked",
    }
}

fn token_hash(operation: &'static str, bytes: &[u8]) -> Result<TokenHash, PgStoreError> {
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| corrupt(operation, "token hash"))?;
    Ok(TokenHash::from_bytes(bytes))
}

fn public_key(operation: &'static str, bytes: &[u8]) -> Result<PublicKey, PgStoreError> {
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| corrupt(operation, "public key"))?;
    Ok(PublicKey::from_bytes(bytes))
}

fn label(operation: &'static str, text: &str) -> Result<Label, PgStoreError> {
    text.parse().map_err(|_| corrupt(operation, "label"))
}

fn count(operation: &'static str, value: i64) -> Result<u32, PgStoreError> {
    u32::try_from(value).map_err(|_| corrupt(operation, "count"))
}

impl PgStore {
    /// Connects to the database at `url`, with the limits of this module on every
    /// connection. Fails at once if the database cannot be reached.
    pub async fn connect(url: &str) -> Result<Self, PgStoreError> {
        let invalid = PgStoreError {
            operation: "connect",
            kind: ErrorKind::InvalidUrl,
        };
        if !known_parameters_only(url) {
            return Err(invalid);
        }
        let options = PgConnectOptions::from_str(url).map_err(|_| invalid)?;
        Self::connect_with(PgPoolOptions::new(), options).await
    }

    /// Like [`PgStore::connect`], from options already parsed.
    pub async fn connect_with(
        pool: PgPoolOptions,
        options: PgConnectOptions,
    ) -> Result<Self, PgStoreError> {
        secure_enough(&options)?;
        let options = options.application_name("ponte-server").options([
            ("statement_timeout", STATEMENT_LIMIT),
            // A connection that waits is not ended for it: the claim's only answers pings.
            // (PostgreSQL 14 or newer: older ones refuse the parameter.)
            ("idle_session_timeout", "0"),
            (
                "idle_in_transaction_session_timeout",
                IDLE_IN_TRANSACTION_LIMIT,
            ),
        ]);
        let pool = bounded("connect", async {
            pool.max_connections(POOL_SIZE)
                .min_connections(0)
                .acquire_timeout(ACQUIRE_LIMIT)
                // A connection given back by a call that was cut short is checked before it
                // is reused. sqlx's own check has no time limit: on a network path that
                // drops packets, every place in the pool would wait for TCP to give up.
                .after_release(|connection, _| {
                    Box::pin(async move {
                        match tokio::time::timeout(RELEASE_CHECK_LIMIT, connection.ping()).await {
                            Ok(Ok(())) => Ok(true),
                            // Fixed text: sqlx logs it, and the database's could quote values.
                            Ok(Err(_)) | Err(_) => Err(sqlx::Error::Protocol(
                                "the connection failed its check on release".to_owned(),
                            )),
                        }
                    })
                })
                .max_lifetime(MAX_LIFETIME)
                .idle_timeout(IDLE_LIMIT)
                .connect_with(options)
                .await
                .map_err(failed("connect"))
        })
        .await?;
        Ok(Self { pool })
    }

    /// Claims the database for this server process, for as long as the claim lives.
    ///
    /// `clear_online` assumes one server per database: a second one started by mistake
    /// would mark every connected device offline. The claim is a session-level advisory
    /// lock held on a connection of its own, taken out of the pool; the database lets it go
    /// when that connection closes, the process's end included.
    pub async fn claim_server(&self) -> Result<ServerClaim, PgStoreError> {
        const OPERATION: &str = "claim the database for this server";
        bounded(OPERATION, async {
            let mut connection = self
                .pool
                .acquire()
                .await
                .map_err(failed(OPERATION))?
                .detach();
            let claimed = sqlx::query_scalar!(
                r#"SELECT pg_try_advisory_lock($1) AS "claimed!""#,
                SERVER_LOCK
            )
            .fetch_one(&mut connection)
            .await
            .map_err(failed(OPERATION))?;
            if !claimed {
                return Err(PgStoreError {
                    operation: OPERATION,
                    kind: ErrorKind::AnotherServer,
                });
            }
            Ok(ServerClaim { connection })
        })
        .await
    }

    /// Keeps the claim for as long as this process serves, and returns only if it is lost
    /// for good: another server holds it now.
    ///
    /// The database ends the claim's session without a word when it restarts, when an
    /// administrator ends it, or when something on the network drops an idle connection;
    /// the lock goes with it. Every `every`, the claim's connection is checked, which also
    /// keeps it from looking idle. A lost claim is taken again. While the database cannot
    /// be reached the check goes on: nobody else can take the claim then either.
    pub async fn hold_claim(&self, claim: ServerClaim, every: Duration) -> PgStoreError {
        let mut claim = claim;
        loop {
            tokio::time::sleep(every).await;
            let ping = tokio::time::timeout(RELEASE_CHECK_LIMIT, claim.connection.ping()).await;
            if matches!(ping, Ok(Ok(()))) {
                continue;
            }
            warn!("the connection holding this server's claim on the database was lost");
            match self.claim_server().await {
                Ok(again) => {
                    claim = again;
                    warn!("this server's claim on the database was taken again");
                }
                Err(error) if error.kind() == ErrorKind::AnotherServer => return error,
                Err(error) => warn!(%error, "claiming the database again failed; retrying"),
            }
        }
    }

    /// Brings the schema up to date. Safe to run while another process does the same.
    pub async fn migrate(&self) -> Result<(), PgStoreError> {
        // Not bounded by `CALL_LIMIT`: a migration may take longer than a call, and the
        // server does not listen until it is done.
        sqlx::migrate!("./migrations")
            .run(&self.pool)
            .await
            .map_err(|_| PgStoreError {
                operation: "apply the migrations",
                kind: ErrorKind::Migration,
            })
    }

    /// Marks every device offline, and returns how many were online. For the start of the
    /// server: whatever was open before is gone, and nobody recorded its end. Assumes one
    /// server process per database.
    pub async fn clear_online(&self) -> Result<u64, PgStoreError> {
        const OPERATION: &str = "mark every device offline";
        bounded(OPERATION, async {
            let done = sqlx::query!(
                "UPDATE devices SET online_session = NULL WHERE online_session IS NOT NULL"
            )
            .execute(&self.pool)
            .await
            .map_err(failed(OPERATION))?;
            Ok(done.rows_affected())
        })
        .await
    }

    async fn enroll_in(
        tx: &mut Transaction<'static, Postgres>,
        request: &EnrollRequest,
        now: DateTime<Utc>,
    ) -> Result<EnrollOutcome, PgStoreError> {
        const OPERATION: &str = "enroll a device";
        let refused = |refusal| Ok(EnrollOutcome::Refused(refusal));
        let hash = &request.token.as_bytes()[..];

        // The row stays locked until the transaction ends: enrollments with one token take
        // turns, so the same token and key twice at once give one device and a repetition.
        let token = sqlx::query!(
            r#"SELECT customer_id, max_uses, uses, expires_at, revoked_at IS NOT NULL AS "revoked!"
               FROM enrollment_tokens WHERE hash = $1 FOR UPDATE"#,
            hash
        )
        .fetch_optional(&mut **tx)
        .await
        .map_err(failed(OPERATION))?;
        let Some(token) = token else {
            return refused(EnrollRefusal::UnknownToken);
        };
        if token.revoked {
            return refused(EnrollRefusal::RevokedToken);
        }

        // Before the deadline: a repetition creates nothing and spends nothing.
        let known = sqlx::query!(
            "SELECT id, customer_id, status, enrolled_with FROM devices WHERE public_key = $1",
            &request.public_key.as_bytes()[..]
        )
        .fetch_optional(&mut **tx)
        .await
        .map_err(failed(OPERATION))?;
        if let Some(device) = known {
            if device.enrolled_with != hash {
                return refused(EnrollRefusal::KeyAlreadyEnrolled);
            }
            let status = status_of(OPERATION, &device.status)?;
            if status == DeviceStatus::Revoked {
                return refused(EnrollRefusal::DeviceRevoked);
            }
            return Ok(EnrollOutcome::Enrolled {
                device_id: DeviceId::from_uuid(device.id),
                customer: CustomerId::from_uuid(device.customer_id),
                status,
                repeated: true,
            });
        }

        if now >= token.expires_at {
            return refused(EnrollRefusal::ExpiredToken);
        }
        // Spends a use only if one is left, in the same statement that checks.
        let spent = sqlx::query!(
            "UPDATE enrollment_tokens SET uses = uses + 1
             WHERE hash = $1 AND uses < max_uses RETURNING max_uses",
            hash
        )
        .fetch_optional(&mut **tx)
        .await
        .map_err(failed(OPERATION))?;
        let Some(spent) = spent else {
            return refused(EnrollRefusal::ExhaustedToken);
        };

        let device_id = DeviceId::new();
        let customer = CustomerId::from_uuid(token.customer_id);
        let status = if spent.max_uses == 1 {
            DeviceStatus::Active
        } else {
            DeviceStatus::Pending
        };
        let inserted = sqlx::query!(
            "INSERT INTO devices
                 (id, customer_id, public_key, enrolled_with, status, agent_version, os, enrolled_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            device_id.as_uuid(),
            customer.as_uuid(),
            &request.public_key.as_bytes()[..],
            hash,
            status_text(status),
            request.about.agent_version.as_str(),
            request.about.os.as_str(),
            now,
        )
        .execute(&mut **tx)
        .await;
        match inserted {
            Ok(_) => Ok(EnrollOutcome::Enrolled {
                device_id,
                customer,
                status,
                repeated: false,
            }),
            // The same key under another token, at the same moment: that token's turn
            // came first. The caller rolls back, and the use spent above with it.
            Err(sqlx::Error::Database(error)) if error.constraint() == Some(UNIQUE_PUBLIC_KEY) => {
                refused(EnrollRefusal::KeyAlreadyEnrolled)
            }
            Err(error) => Err(failed(OPERATION)(error)),
        }
    }
}

impl DeviceStore for PgStore {
    type Error = PgStoreError;

    async fn enroll(
        &self,
        request: EnrollRequest,
        now: DateTime<Utc>,
    ) -> Result<EnrollOutcome, Self::Error> {
        const OPERATION: &str = "enroll a device";
        bounded(OPERATION, async {
            let mut tx = self.pool.begin().await.map_err(failed(OPERATION))?;
            let outcome = Self::enroll_in(&mut tx, &request, now).await?;
            match outcome {
                EnrollOutcome::Enrolled {
                    repeated: false, ..
                } => tx.commit().await.map_err(failed(OPERATION))?,
                // Nothing was written, or what was must not stay.
                EnrollOutcome::Enrolled { .. } | EnrollOutcome::Refused(_) => {
                    tx.rollback().await.map_err(failed(OPERATION))?;
                }
            }
            Ok(outcome)
        })
        .await
    }

    async fn device(&self, id: DeviceId) -> Result<Option<Device>, Self::Error> {
        const OPERATION: &str = "read a device";
        bounded(OPERATION, async {
            let row = sqlx::query!(
                "SELECT customer_id, public_key, status FROM devices WHERE id = $1",
                id.as_uuid()
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(failed(OPERATION))?;
            row.map(|row| {
                Ok(Device {
                    id,
                    customer: CustomerId::from_uuid(row.customer_id),
                    public_key: public_key(OPERATION, &row.public_key)?,
                    status: status_of(OPERATION, &row.status)?,
                })
            })
            .transpose()
        })
        .await
    }

    async fn session_started(
        &self,
        id: DeviceId,
        session: SessionId,
        about: &AgentInfo,
        now: DateTime<Utc>,
    ) -> Result<Option<DeviceStatus>, Self::Error> {
        const OPERATION: &str = "start a session";
        bounded(OPERATION, async {
            // One statement: the status it checks is the status of the row it writes.
            let row = sqlx::query!(
                "UPDATE devices SET
                     online_session = CASE WHEN status = 'revoked' THEN online_session ELSE $2 END,
                     agent_version = CASE WHEN status = 'revoked' THEN agent_version ELSE $3 END,
                     os = CASE WHEN status = 'revoked' THEN os ELSE $4 END,
                     last_seen = CASE WHEN status = 'revoked' THEN last_seen ELSE $5 END
                 WHERE id = $1
                 RETURNING status",
                id.as_uuid(),
                session.as_uuid(),
                about.agent_version.as_str(),
                about.os.as_str(),
                now,
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(failed(OPERATION))?;
            row.map(|row| status_of(OPERATION, &row.status)).transpose()
        })
        .await
    }

    async fn heartbeat(
        &self,
        id: DeviceId,
        telemetry: &TelemetrySnapshot,
        now: DateTime<Utc>,
    ) -> Result<Option<DeviceStatus>, Self::Error> {
        const OPERATION: &str = "record a heartbeat";
        bounded(OPERATION, async {
            // RF-49 in the statement itself: telemetry only for an active device.
            let row = sqlx::query!(
                "UPDATE devices SET
                     last_seen = CASE WHEN status = 'revoked' THEN last_seen ELSE $2 END,
                     telemetry = CASE WHEN status = 'active' THEN $3 ELSE telemetry END
                 WHERE id = $1
                 RETURNING status",
                id.as_uuid(),
                now,
                Json(telemetry) as _,
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(failed(OPERATION))?;
            row.map(|row| status_of(OPERATION, &row.status)).transpose()
        })
        .await
    }

    async fn session_ended(
        &self,
        id: DeviceId,
        session: SessionId,
        now: DateTime<Utc>,
    ) -> Result<(), Self::Error> {
        const OPERATION: &str = "end a session";
        bounded(OPERATION, async {
            sqlx::query!(
                "UPDATE devices SET online_session = NULL, last_seen = $3
                 WHERE id = $1 AND online_session = $2",
                id.as_uuid(),
                session.as_uuid(),
                now,
            )
            .execute(&self.pool)
            .await
            .map_err(failed(OPERATION))?;
            Ok(())
        })
        .await
    }
}

/// One row of `devices`, as the queries below read it.
struct DeviceRow {
    id: Uuid,
    customer_id: Uuid,
    public_key: Vec<u8>,
    enrolled_with: Vec<u8>,
    status: String,
    agent_version: String,
    os: String,
    online_session: Option<Uuid>,
    last_seen: Option<DateTime<Utc>>,
    telemetry: Option<serde_json::Value>,
}

impl DeviceRow {
    fn record(self, operation: &'static str) -> Result<DeviceRecord, PgStoreError> {
        Ok(DeviceRecord {
            id: DeviceId::from_uuid(self.id),
            customer: CustomerId::from_uuid(self.customer_id),
            public_key: public_key(operation, &self.public_key)?,
            status: status_of(operation, &self.status)?,
            about: AgentInfo {
                agent_version: label(operation, &self.agent_version)?,
                os: label(operation, &self.os)?,
            },
            online: self.online_session.map(SessionId::from_uuid),
            last_seen: self.last_seen,
            telemetry: self.telemetry.and_then(|stored| readable(self.id, stored)),
            enrolled_with: token_hash(operation, &self.enrolled_with)?,
        })
    }
}

/// Stored telemetry as the wire type, or `None` when it does not read: a reading this
/// server would now refuse, or one written in an older format. It costs that device its
/// last reading, never a listing of every device. Logged by id only: the stored text came
/// from the machine.
fn readable(id: Uuid, stored: serde_json::Value) -> Option<TelemetrySnapshot> {
    serde_json::from_value(stored)
        .inspect_err(|_| {
            warn!(device = %id, "the stored telemetry of a device does not read; left out");
        })
        .ok()
}

/// One row of `enrollment_tokens`, as the queries below read it.
struct TokenRow {
    hash: Vec<u8>,
    customer_id: Uuid,
    max_uses: i64,
    uses: i64,
    expires_at: DateTime<Utc>,
    revoked: bool,
}

impl TokenRow {
    fn info(self, operation: &'static str) -> Result<TokenInfo, PgStoreError> {
        let max_uses = NonZeroU32::new(count(operation, self.max_uses)?)
            .ok_or_else(|| corrupt(operation, "max uses"))?;
        Ok(TokenInfo {
            hash: token_hash(operation, &self.hash)?,
            grant: TokenGrant {
                customer: CustomerId::from_uuid(self.customer_id),
                expires_at: self.expires_at,
                max_uses,
            },
            uses: count(operation, self.uses)?,
            revoked: self.revoked,
        })
    }
}

impl DeviceAdmin for PgStore {
    async fn add_customer(&self, name: &CustomerName) -> Result<Option<CustomerId>, Self::Error> {
        const OPERATION: &str = "add a customer";
        bounded(OPERATION, async {
            let id = CustomerId::new();
            let added = sqlx::query!(
                "INSERT INTO customers (id, name) VALUES ($1, $2) ON CONFLICT (name) DO NOTHING",
                id.as_uuid(),
                name.as_str(),
            )
            .execute(&self.pool)
            .await
            .map_err(failed(OPERATION))?;
            Ok((added.rows_affected() == 1).then_some(id))
        })
        .await
    }

    async fn customers(&self) -> Result<Vec<Customer>, Self::Error> {
        const OPERATION: &str = "list the customers";
        bounded(OPERATION, async {
            // Byte order, the same as everywhere else, whatever the database's locale.
            let rows = sqlx::query!(r#"SELECT id, name FROM customers ORDER BY name COLLATE "C""#)
                .fetch_all(&self.pool)
                .await
                .map_err(failed(OPERATION))?;
            rows.into_iter()
                .map(|row| {
                    Ok(Customer {
                        id: CustomerId::from_uuid(row.id),
                        name: row.name.parse().map_err(|_| corrupt(OPERATION, "name"))?,
                    })
                })
                .collect()
        })
        .await
    }

    async fn issue_token(&self, token: TokenHash, grant: TokenGrant) -> Result<bool, Self::Error> {
        const OPERATION: &str = "issue a token";
        bounded(OPERATION, async {
            let issued = sqlx::query!(
                "INSERT INTO enrollment_tokens (hash, customer_id, max_uses, expires_at)
                 SELECT $1, $2, $3, $4 WHERE EXISTS (SELECT 1 FROM customers WHERE id = $2)
                 ON CONFLICT (hash) DO NOTHING",
                &token.as_bytes()[..],
                grant.customer.as_uuid(),
                i64::from(grant.max_uses.get()),
                grant.expires_at,
            )
            .execute(&self.pool)
            .await
            .map_err(failed(OPERATION))?;
            Ok(issued.rows_affected() == 1)
        })
        .await
    }

    async fn revoke_token(&self, token: &TokenHash) -> Result<bool, Self::Error> {
        const OPERATION: &str = "revoke a token";
        bounded(OPERATION, async {
            let revoked = sqlx::query!(
                "UPDATE enrollment_tokens SET revoked_at = COALESCE(revoked_at, now())
                 WHERE hash = $1",
                &token.as_bytes()[..],
            )
            .execute(&self.pool)
            .await
            .map_err(failed(OPERATION))?;
            Ok(revoked.rows_affected() == 1)
        })
        .await
    }

    async fn token(&self, token: &TokenHash) -> Result<Option<TokenInfo>, Self::Error> {
        const OPERATION: &str = "read a token";
        bounded(OPERATION, async {
            let row = sqlx::query_as!(
                TokenRow,
                r#"SELECT hash, customer_id, max_uses, uses, expires_at,
                          revoked_at IS NOT NULL AS "revoked!"
                   FROM enrollment_tokens WHERE hash = $1"#,
                &token.as_bytes()[..],
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(failed(OPERATION))?;
            row.map(|row| row.info(OPERATION)).transpose()
        })
        .await
    }

    async fn tokens(&self, customer: Option<CustomerId>) -> Result<Vec<TokenInfo>, Self::Error> {
        const OPERATION: &str = "list the tokens";
        bounded(OPERATION, async {
            let rows = sqlx::query_as!(
                TokenRow,
                r#"SELECT hash, customer_id, max_uses, uses, expires_at,
                          revoked_at IS NOT NULL AS "revoked!"
                   FROM enrollment_tokens
                   WHERE $1::uuid IS NULL OR customer_id = $1
                   ORDER BY expires_at, hash"#,
                customer.as_ref().map(CustomerId::as_uuid),
            )
            .fetch_all(&self.pool)
            .await
            .map_err(failed(OPERATION))?;
            rows.into_iter().map(|row| row.info(OPERATION)).collect()
        })
        .await
    }

    async fn approve_device(&self, id: DeviceId) -> Result<bool, Self::Error> {
        const OPERATION: &str = "approve a device";
        bounded(OPERATION, async {
            let approved = sqlx::query!(
                "UPDATE devices SET status = 'active' WHERE id = $1 AND status = 'pending'",
                id.as_uuid(),
            )
            .execute(&self.pool)
            .await
            .map_err(failed(OPERATION))?;
            Ok(approved.rows_affected() == 1)
        })
        .await
    }

    async fn revoke_device(&self, id: DeviceId) -> Result<bool, Self::Error> {
        const OPERATION: &str = "revoke a device";
        bounded(OPERATION, async {
            let revoked = sqlx::query!(
                "UPDATE devices SET status = 'revoked', online_session = NULL WHERE id = $1",
                id.as_uuid(),
            )
            .execute(&self.pool)
            .await
            .map_err(failed(OPERATION))?;
            Ok(revoked.rows_affected() == 1)
        })
        .await
    }

    async fn device_record(&self, id: DeviceId) -> Result<Option<DeviceRecord>, Self::Error> {
        const OPERATION: &str = "read a device";
        bounded(OPERATION, async {
            let row = sqlx::query_as!(
                DeviceRow,
                r#"SELECT id, customer_id, public_key, enrolled_with, status, agent_version, os,
                          online_session, last_seen,
                          telemetry
                   FROM devices WHERE id = $1"#,
                id.as_uuid(),
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(failed(OPERATION))?;
            row.map(|row| row.record(OPERATION)).transpose()
        })
        .await
    }

    async fn devices(
        &self,
        customer: Option<CustomerId>,
    ) -> Result<Vec<DeviceRecord>, Self::Error> {
        const OPERATION: &str = "list the devices";
        bounded(OPERATION, async {
            // Ids are UUIDv7: in the order they were made.
            let rows = sqlx::query_as!(
                DeviceRow,
                r#"SELECT id, customer_id, public_key, enrolled_with, status, agent_version, os,
                          online_session, last_seen,
                          telemetry
                   FROM devices
                   WHERE $1::uuid IS NULL OR customer_id = $1
                   ORDER BY id"#,
                customer.as_ref().map(CustomerId::as_uuid),
            )
            .fetch_all(&self.pool)
            .await
            .map_err(failed(OPERATION))?;
            rows.into_iter().map(|row| row.record(OPERATION)).collect()
        })
        .await
    }
}

/// Needs a database: see the module.
#[cfg(test)]
mod pg_tests;

#[cfg(test)]
mod tests {
    use std::future;

    use super::*;

    /// A call that never ends is cut at the limit, and says so without anything else.
    #[tokio::test(start_paused = true)]
    async fn a_call_that_hangs_ends_at_the_limit() {
        let started = tokio::time::Instant::now();
        let outcome: Result<(), _> = bounded("read a device", future::pending()).await;
        assert_eq!(started.elapsed(), CALL_LIMIT);
        let error = outcome.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::TimedOut);
        assert_eq!(
            error.to_string(),
            "the device store could not read a device: no answer within 8 seconds"
        );
    }

    /// A database error whose text quotes the values of the statement, as PostgreSQL's
    /// do (`invalid input syntax for type uuid: "..."`, `Key (...)=(...) already exists`).
    #[derive(Debug)]
    struct Quoting;

    impl fmt::Display for Quoting {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("invalid input: \"SECRET-CUSTOMER-RECORD\"")
        }
    }

    impl std::error::Error for Quoting {}

    impl sqlx::error::DatabaseError for Quoting {
        fn message(&self) -> &str {
            "invalid input: \"SECRET-CUSTOMER-RECORD\""
        }

        fn code(&self) -> Option<std::borrow::Cow<'_, str>> {
            Some("22P02".into())
        }

        fn as_error(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
            self
        }

        fn as_error_mut(&mut self) -> &mut (dyn std::error::Error + Send + Sync + 'static) {
            self
        }

        fn into_error(self: Box<Self>) -> Box<dyn std::error::Error + Send + Sync + 'static> {
            self
        }

        fn kind(&self) -> sqlx::error::ErrorKind {
            sqlx::error::ErrorKind::Other
        }
    }

    /// What goes to the log is the operation and the SQLSTATE, never the database's text.
    #[test]
    fn an_error_keeps_the_kind_and_drops_the_text() {
        let error = failed("record a heartbeat")(sqlx::Error::Database(Box::new(Quoting)));
        assert_eq!(
            error.kind(),
            ErrorKind::Database(SqlState::of("22P02").unwrap())
        );
        for text in [error.to_string(), format!("{error:?}")] {
            assert!(!text.contains("SECRET"), "{text}");
        }
        assert_eq!(
            error.to_string(),
            "the device store could not record a heartbeat: \
             the database refused the statement (SQLSTATE 22P02)"
        );

        let error = failed("connect")(sqlx::Error::Configuration("postgres://u:pw@h".into()));
        assert_eq!(error.kind(), ErrorKind::Other);
        assert!(!error.to_string().contains("pw"), "{error}");
    }

    /// A database on another host is reached over TLS with its certificate checked, or not
    /// at all: whoever sits on the path could otherwise read token hashes and answer that a
    /// revoked device is active.
    #[test]
    fn a_remote_database_needs_a_verified_certificate() {
        let check = |url: &str| -> Result<(), ErrorKind> {
            let options = PgConnectOptions::from_str(url).unwrap();
            secure_enough(&options).map_err(|error| error.kind())
        };
        for fine in [
            "postgres://u:p@localhost/ponte",
            "postgres://u:p@127.0.0.1:5432/ponte",
            "postgres://u:p@[::1]/ponte",
            "postgres://u:p@localhost/ponte?sslmode=disable",
            "postgres:///ponte?host=/var/run/postgresql",
            "postgres://u:p@db.example.com/ponte?sslmode=verify-full",
        ] {
            assert_eq!(check(fine), Ok(()), "{fine}");
        }
        for refused in [
            "postgres://u:p@db.example.com/ponte",
            "postgres://u:p@db.example.com/ponte?sslmode=prefer",
            "postgres://u:p@db.example.com/ponte?sslmode=require",
            "postgres://u:p@db.example.com/ponte?sslmode=verify-ca",
            "postgres://u:p@10.0.0.5/ponte?sslmode=disable",
            "postgres://u:p@localhost.example.com/ponte",
        ] {
            assert_eq!(check(refused), Err(ErrorKind::InsecureTls), "{refused}");
        }
    }

    /// sqlx logs the value of a parameter it does not know, and a mistyped `password` is
    /// still a password. Only the parameters the server needs are taken.
    #[tokio::test]
    async fn a_url_with_a_parameter_the_server_does_not_take_is_refused() {
        for refused in [
            "postgres://u@localhost/ponte?passwrd=SECRET",
            "postgres://u@localhost/ponte?sslmode=disable&sslpassword=SECRET",
            "postgres://u@localhost/ponte?options=-c%20statement_timeout%3D0",
            "postgres://u@localhost/ponte?ssl-mode=disable",
            "postgres://u@localhost/ponte?SSLMODE=disable",
            "postgres://u@localhost/ponte?=SECRET",
        ] {
            let error = PgStore::connect(refused).await.unwrap_err();
            assert_eq!(error.kind(), ErrorKind::InvalidUrl, "{refused}");
            assert!(!error.to_string().contains("SECRET"), "{error}");
        }
        for taken in [
            "postgres://u:p@localhost/ponte",
            "postgres://u:p@localhost/ponte?",
            "postgres://u:p@localhost/ponte?sslmode=disable&application_name=x",
            "postgres:///ponte?host=/var/run/postgresql&user=u&dbname=ponte&port=5433",
            "postgres://u@db.example.com/ponte?sslmode=verify-full&sslrootcert=ca.pem\
             &sslcert=c.pem&sslkey=k.pem&hostaddr=192.0.2.1&password=p",
        ] {
            assert!(known_parameters_only(taken), "{taken}");
        }
    }

    /// Refused before anything is sent.
    #[tokio::test]
    async fn connecting_to_a_remote_database_without_verification_is_refused() {
        let refused = PgStore::connect("postgres://u:p@db.example.invalid/ponte").await;
        assert_eq!(refused.unwrap_err().kind(), ErrorKind::InsecureTls);
    }

    #[test]
    fn only_a_well_formed_sqlstate_is_kept() {
        assert_eq!(SqlState::of("23505").unwrap().to_string(), "23505");
        assert_eq!(SqlState::of("57P01").unwrap().to_string(), "57P01");
        for bad in ["", "2350", "235050", "23 05", "2350\n", "\u{fc}2350"] {
            assert_eq!(SqlState::of(bad), None, "{bad:?}");
        }
    }
}
