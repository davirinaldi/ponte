//! Ponte control plane.
//!
//! Current state: health and version endpoints, and the agent endpoint (`GET /agent`) with
//! enrollment, the device-key handshake and heartbeats, over PostgreSQL; subcommands for
//! the operator (`admin`). Approvals, the audit log, MCP and helpdesk connectors arrive
//! milestone by milestone (see `docs/roadmap.md`). Keep handlers thin: HTTP in, domain
//! call, HTTP out.

pub mod admin;
pub mod agents;

use axum::{Json, Router, routing::get};
use serde::Serialize;
use tracing::{Level, Metadata, Subscriber};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::filter::{FilterExt, filter_fn};
use tracing_subscriber::layer::Filter;
use tracing_subscriber::registry::LookupSpan;

use agents::{DeviceStore, MemoryStore};

/// Builds the HTTP router over a store that starts empty and lives in memory, for tests that
/// drive it in-process without a database. The server itself uses [`router_with`] and a
/// `PgStore`.
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

/// What the log keeps when `RUST_LOG` says nothing useful. The database library tells at
/// `info` what the database noticed, on every start; its warnings stay.
const DEFAULT_DIRECTIVES: &str = "info,sqlx=warn";

/// Builds the log filter of the server process from the value of `RUST_LOG`, or
/// [`DEFAULT_DIRECTIVES`] when it is unset, empty or not valid. Put it on the layer that
/// writes the log.
///
/// Whatever the value says, audit events stay on. Until the audit log exists (M3) the lines
/// under the `ponte::audit` target are the only record of who enrolled and who was refused,
/// and asking for a quieter log must not be a way to lose it.
pub fn log_filter<S>(directives: Option<&str>) -> impl Filter<S> + Send + Sync + 'static
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    let directives = directives
        .filter(|directives| !directives.trim().is_empty())
        .unwrap_or(DEFAULT_DIRECTIVES);
    let chosen =
        EnvFilter::try_new(directives).unwrap_or_else(|_| EnvFilter::new(DEFAULT_DIRECTIVES));
    // A filter beside the one from the variable, not one more directive in it: a directive
    // can always be outranked by a more specific one.
    chosen.or(filter_fn(is_audit_event))
}

fn is_audit_event(metadata: &Metadata<'_>) -> bool {
    metadata.target() == agents::AUDIT_TARGET && *metadata.level() <= Level::INFO
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

#[cfg(test)]
mod tests {
    use tracing::{debug, info, warn};

    use super::*;
    use crate::agents::testkit::Logs;

    /// What reaches the log under `directives`, out of one line per level and one audit
    /// event.
    fn logged(directives: Option<&str>) -> String {
        let (logs, _guard) = Logs::capture_with(directives);
        debug!("a debug line");
        info!("an info line");
        warn!("a warn line");
        info!(target: agents::AUDIT_TARGET, event = "an audit event");
        logs.text()
    }

    #[test]
    fn the_level_is_what_rust_log_says_and_info_without_it() {
        for unset_or_useless in [None, Some(""), Some("  "), Some("ponte=nonsense")] {
            let logs = logged(unset_or_useless);
            assert!(
                logs.contains("an info line"),
                "{unset_or_useless:?}: {logs}"
            );
            assert!(
                !logs.contains("a debug line"),
                "{unset_or_useless:?}: {logs}"
            );
        }

        let logs = logged(Some("debug"));
        assert!(logs.contains("a debug line"), "{logs}");

        let logs = logged(Some("warn"));
        assert!(logs.contains("a warn line"), "{logs}");
        assert!(!logs.contains("an info line"), "{logs}");
    }

    /// The database library tells at `info` what the database noticed, on every start.
    /// By default only its warnings and errors are kept; `RUST_LOG` can ask for more.
    #[test]
    fn the_database_library_is_quieter_by_default() {
        let lines = |directives| {
            let (logs, _guard) = Logs::capture_with(directives);
            info!(target: "sqlx::postgres::notice", "a notice");
            warn!(target: "sqlx::query", "a slow statement");
            logs.text()
        };
        let logs = lines(None);
        assert!(!logs.contains("a notice"), "{logs}");
        assert!(logs.contains("a slow statement"), "{logs}");
        assert!(lines(Some("info")).contains("a notice"));
    }

    /// Until M3 these lines are the audit log. Asking for a quieter log must not lose them.
    #[test]
    fn audit_events_are_logged_whatever_rust_log_says() {
        for directives in [
            None,
            Some("warn"),
            Some("error"),
            Some("off"),
            Some("ponte=off"),
            Some("ponte::audit=off"),
            Some("ponte::audit=error,info"),
            Some("ponte_server=trace,off"),
            Some("not a filter!"),
            // Directives that name a field outrank the ones that do not.
            Some("ponte::audit[{event}]=off"),
            Some("warn,ponte::audit[{event}]=off"),
            Some("off,ponte::audit[{event}]=error"),
            Some("[{event}]=off"),
        ] {
            let logs = logged(directives);
            assert!(logs.contains("an audit event"), "{directives:?}: {logs}");
        }
        assert!(!logged(Some("off")).contains("a warn line"));
    }
}
