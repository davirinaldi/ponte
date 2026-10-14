use anyhow::Context;
use ponte_agent::AgentConfig;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "agent.toml".to_owned());
    let config = AgentConfig::load(&config_path)
        .with_context(|| format!("loading agent config from {config_path}"))?;

    info!(
        server = %config.server_url,
        allowed_roots = config.allowed_roots.len(),
        protocol = ponte_protocol::PROTOCOL_VERSION,
        platform = ponte_agent::PLATFORM,
        "agent starting"
    );

    let runtime = ponte_agent::runtime().context("starting the async runtime")?;
    runtime.block_on(ponte_agent::run(config, shutdown_signal()));
    info!("agent stopped");
    Ok(())
}

async fn shutdown_signal() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        // Without the handler there is no signal to wait for, and an agent that takes
        // that for one would stop the moment it started.
        warn!(%error, "no shutdown signal can be received: the agent runs until it is killed");
        std::future::pending::<()>().await;
    }
}
