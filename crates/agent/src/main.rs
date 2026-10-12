//! Ponte agent.
//!
//! Runs on the supported machine (a pharmacy PC, for example) as a privileged
//! Windows service. It only ever opens *outbound* connections, reports telemetry,
//! and runs actions from the signed catalog after checking its own local policy.
//!
//! Current state: loads its configuration and waits for Ctrl+C. The connection
//! loop is milestone M1 in `docs/roadmap.md`.

mod config;
mod platform;

use anyhow::Context;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "agent.toml".to_owned());
    let config = config::AgentConfig::load(&config_path)
        .with_context(|| format!("loading agent config from {config_path}"))?;

    info!(
        server = %config.server_url,
        allowed_roots = config.allowed_roots.len(),
        protocol = ponte_protocol::PROTOCOL_VERSION,
        platform = platform::NAME,
        "agent starting"
    );

    tokio::signal::ctrl_c()
        .await
        .context("waiting for the shutdown signal")?;
    info!("agent stopped");
    Ok(())
}
