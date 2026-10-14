//! Agent connections: enrollment, the handshake on every connection, heartbeats (M1).
//!
//! | Module | What it does |
//! |---|---|
//! | `ws` | `GET /agent`: picks the protocol version and upgrades, or refuses |
//! | `session` | One connection from the challenge to the last heartbeat |
//! | `handshake` | Judges the first message. No socket |
//! | `registry` | One session per device: a new one replaces the old one |
//! | `store` | Tokens and devices: the [`DeviceStore`] and [`DeviceAdmin`] traits, [`MemoryStore`] |
//! | `pg` | The same over PostgreSQL: [`PgStore`] |
//! | `audit` | The events that change what the server holds about a device |
//!
//! Read `crates/server/AGENTS.md` before changing what is accepted, refused or logged here.

pub(crate) mod audit;
mod handshake;
mod pg;
mod registry;
mod session;
mod store;
mod ws;

#[cfg(test)]
pub(crate) mod testkit;

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::routing::get;
use chrono::{DateTime, Utc};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use registry::Registry;

pub use audit::TARGET as AUDIT_TARGET;

pub use pg::{ErrorKind as PgErrorKind, PgStore, PgStoreError, ServerClaim, SqlState};

pub use store::{
    AgentInfo, Customer, CustomerId, CustomerName, Device, DeviceAdmin, DeviceRecord, DeviceStatus,
    DeviceStore, EnrollOutcome, EnrollRefusal, EnrollRequest, InvalidCustomerName, MemoryStore,
    SessionId, TokenGrant, TokenHash, TokenInfo,
};

/// How much a peer gets before and after it proves who it is.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Limits {
    /// From the upgrade to a valid answer to the challenge.
    pub(crate) handshake: Duration,
    /// How long the server waits for the peer to acknowledge that it is closing.
    pub(crate) close: Duration,
    /// A session ends after this long and the agent proves its key again, so no connection
    /// lives forever on one check.
    pub(crate) session: Duration,
    /// The status of a connected device is read again at least this often, so a revoked
    /// device is out by then even if it never sends a heartbeat (RF-04).
    pub(crate) status_check: Duration,
    /// Connections that have not authenticated yet. Past this, upgrades are refused.
    pub(crate) unauthenticated: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            handshake: Duration::from_secs(10),
            close: Duration::from_secs(2),
            session: Duration::from_secs(24 * 60 * 60),
            status_check: Duration::from_secs(60),
            unauthenticated: 256,
        }
    }
}

/// Everything the connections of one server share.
pub(crate) struct Gateway<D> {
    store: D,
    registry: Registry,
    limits: Limits,
    unauthenticated: Arc<Semaphore>,
    clock: fn() -> DateTime<Utc>,
}

impl<D> Gateway<D> {
    pub(crate) fn new(store: D, limits: Limits) -> Self {
        Self {
            store,
            registry: Registry::default(),
            limits,
            unauthenticated: Arc::new(Semaphore::new(limits.unauthenticated)),
            clock: Utc::now,
        }
    }

    /// A place among the connections that have not authenticated yet, or `None` when all
    /// are taken. The place is free again when the permit is dropped.
    pub(crate) fn admit(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.unauthenticated).try_acquire_owned().ok()
    }

    fn now(&self) -> DateTime<Utc> {
        (self.clock)()
    }
}

pub(crate) fn routes<D: DeviceStore>(store: D) -> Router {
    routes_with(store, Limits::default())
}

fn routes_with<D: DeviceStore>(store: D, limits: Limits) -> Router {
    Router::new()
        .route("/agent", get(ws::upgrade::<D>))
        .with_state(Arc::new(Gateway::new(store, limits)))
}
