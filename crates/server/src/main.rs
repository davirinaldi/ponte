use std::io::Write;
use std::process::ExitCode;

use anyhow::Context;
use chrono::Utc;
use ponte_server::admin::{self, Command};
use ponte_server::agents::PgStore;
use tracing::info;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{Layer, fmt};

#[tokio::main]
async fn main() -> anyhow::Result<ExitCode> {
    let command = match admin::parse(std::env::args_os().skip(1)) {
        Ok(command) => command,
        Err(error) => {
            let _ = writeln!(std::io::stderr(), "{error}\n\n{}", admin::USAGE);
            return Ok(ExitCode::from(2));
        }
    };
    if command == Command::Help {
        let _ = writeln!(std::io::stdout(), "{}", admin::USAGE);
        return Ok(ExitCode::SUCCESS);
    }

    // A subcommand prints its answer on stdout, so its log goes to stderr.
    let directives = std::env::var("RUST_LOG").ok();
    let filter = ponte_server::log_filter(directives.as_deref());
    if command == Command::Serve {
        tracing_subscriber::registry()
            .with(fmt::layer().with_filter(filter))
            .init();
    } else {
        tracing_subscriber::registry()
            .with(
                fmt::layer()
                    .with_writer(std::io::stderr)
                    .with_filter(filter),
            )
            .init();
    }

    // No database, no server: there is nothing to check a device against (invariant 7).
    // The value is never shown: it holds a password, and so may the reason it is unusable.
    let Ok(url) = std::env::var("DATABASE_URL") else {
        anyhow::bail!("DATABASE_URL must name the PostgreSQL database, as valid text");
    };
    let store = PgStore::connect(&url).await?;
    drop(url);

    match command {
        Command::Serve => serve(store).await?,
        Command::Migrate => store.migrate().await?,
        command => {
            let mut out = std::io::stdout().lock();
            admin::run(&store, command, &mut out, Utc::now()).await?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

async fn serve(store: PgStore) -> anyhow::Result<()> {
    // The port first: a second server started by mistake stops here, before it touches
    // anything. The claim covers a second one on another port or host.
    let bind = std::env::var("PONTE_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_owned());
    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .with_context(|| format!("binding {bind}"))?;
    let _claim = store.claim_server().await?;
    store.migrate().await?;

    // Sessions open when the server last stopped ended without a record.
    let cleared = store.clear_online().await?;
    info!(
        devices = cleared,
        "devices left online by the last run marked offline"
    );
    info!(%bind, "server listening");

    axum::serve(listener, ponte_server::router_with(store))
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("serving HTTP")?;
    Ok(())
}

async fn shutdown_signal() {
    // If installing the handler fails we simply never shut down gracefully.
    let _ = tokio::signal::ctrl_c().await;
}
