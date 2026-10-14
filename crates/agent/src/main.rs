use anyhow::Context;
use ponte_agent::AgentConfig;
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
    let config = AgentConfig::load(&config_path)
        .with_context(|| format!("loading agent config from {config_path}"))?;

    info!(
        server = %config.server_url,
        allowed_roots = config.allowed_roots.len(),
        protocol = ponte_protocol::PROTOCOL_VERSION,
        platform = ponte_agent::PLATFORM,
        "agent starting"
    );

    tokio::signal::ctrl_c()
        .await
        .context("waiting for the shutdown signal")?;
    info!("agent stopped");
    Ok(())
}
