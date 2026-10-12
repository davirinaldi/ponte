//! Ponte control plane.
//!
//! Current state: health and version endpoints. Agent WebSocket, persistence,
//! approvals, audit log, MCP and helpdesk connectors arrive milestone by milestone
//! (see `docs/roadmap.md`). Keep handlers thin: HTTP in, domain call, HTTP out.

use axum::{Json, Router, routing::get};
use serde::Serialize;

/// Builds the HTTP router. Kept separate from `main` so tests can drive it in-process.
pub fn router() -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/api/v1/version", get(version))
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
