use anyhow::Context;
use tracing::{info, warn};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{Layer, fmt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let directives = std::env::var("RUST_LOG").ok();
    tracing_subscriber::registry()
        .with(fmt::layer().with_filter(ponte_server::log_filter(directives.as_deref())))
        .init();

    let bind = std::env::var("PONTE_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_owned());
    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .with_context(|| format!("binding {bind}"))?;
    info!(%bind, "server listening");
    warn!(
        "devices are kept in memory and no enrollment token exists: agents can connect, \
         none can enroll"
    );

    axum::serve(listener, ponte_server::router())
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("serving HTTP")?;
    Ok(())
}

async fn shutdown_signal() {
    // If installing the handler fails we simply never shut down gracefully.
    let _ = tokio::signal::ctrl_c().await;
}
