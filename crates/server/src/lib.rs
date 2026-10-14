//! Ponte control plane.
//!
//! Current state: health and version endpoints, and the agent endpoint (`GET /agent`) with
//! enrollment, the device-key handshake and heartbeats, over a store that lives in memory.
//! PostgreSQL, approvals, the audit log, MCP and helpdesk connectors arrive milestone by
//! milestone (see `docs/roadmap.md`). Keep handlers thin: HTTP in, domain call, HTTP out.

pub mod agents;

use axum::{Json, Router, routing::get};
use serde::Serialize;

use agents::{DeviceStore, MemoryStore};

/// Builds the HTTP router over a store that starts empty and lives in memory. Kept separate
/// from `main` so tests can drive it in-process.
///
/// No token exists in that store and there is no way to add one from outside, so agents can
/// connect but none can enroll.
pub fn router() -> Router {
    router_with(MemoryStore::new())
}

/// Builds the HTTP router over the given device store.
pub fn router_with<D: DeviceStore>(store: D) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/api/v1/version", get(version))
        .merge(agents::routes(store))
}

async fn healthz() -> &'static str {
    "ok"
}

#[derive(Debug, Serialize)]
struct VersionInfo {
    server_version: &'static str,
    protocol_version: u16,
}

async fn version() -> Json<VersionInfo> {
    Json(VersionInfo {
        server_version: env!("CARGO_PKG_VERSION"),
        protocol_version: ponte_protocol::PROTOCOL_VERSION,
    })
}
