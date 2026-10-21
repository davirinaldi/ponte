use std::path::PathBuf;

use anyhow::{Context, bail};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

const USAGE: &str = "usage: ponte-agent run <config>\n       ponte-agent service --config <config>   (for the Windows service manager)";

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["run", config] => run(PathBuf::from(config)),
        ["service", "--config", config] => service(PathBuf::from(config)),
        _ => bail!("{USAGE}"),
    }
}

/// The agent in a console, for development and diagnosis: logs to stderr, stops on Ctrl+C.
fn run(config_path: PathBuf) -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let prepared = ponte_agent::prepare(&config_path, None)
        .with_context(|| format!("starting with the configuration {}", config_path.display()))?;
    let config = prepared.config();
    info!(
        server = %config.server_url,
        allowed_roots = config.allowed_roots.len(),
        protocol = ponte_protocol::PROTOCOL_VERSION,
        platform = ponte_agent::PLATFORM,
        elevation = ?prepared.elevation(),
        "agent starting"
    );

    let runtime = ponte_agent::runtime().context("starting the async runtime")?;
    runtime.block_on(ponte_agent::run(prepared, shutdown_signal()));
    // Not the runtime's `Drop`, which would wait for an action that did not end within
    // `shutdown_timeout_secs`: the journal reports that one as interrupted at the next start.
    runtime.shutdown_background();
    info!("agent stopped");
    Ok(())
}

/// The agent as the Windows service, started by the service manager (ADR-0013). It logs to
/// `<data_dir>\logs`, and to the Event Log what fails before that.
#[cfg(windows)]
fn service(config_path: PathBuf) -> anyhow::Result<()> {
    ponte_agent::run_as_service(config_path)?;
    Ok(())
}

#[cfg(not(windows))]
fn service(_config_path: PathBuf) -> anyhow::Result<()> {
    bail!("the service exists on Windows only: use `ponte-agent run <config>`")
}

async fn shutdown_signal() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        // Without the handler there is no signal to wait for, and an agent that takes
        // that for one would stop the moment it started.
        warn!(%error, "no shutdown signal can be received: the agent runs until it is killed");
        std::future::pending::<()>().await;
    }
}
