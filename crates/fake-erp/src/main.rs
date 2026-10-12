//! A fake ERP that fails in the same boring ways real ones do, so demos and
//! end-to-end tests can break it on purpose and watch Ponte fix it.
//!
//! Failure modes to implement (milestone M3): stale lock file after a crash,
//! service stopped, disk almost full, database unreachable.

use std::path::Path;
use std::process::ExitCode;

use tracing::{error, info};

fn main() -> ExitCode {
    tracing_subscriber::fmt().init();

    let lock = std::env::var("FAKE_ERP_LOCK").unwrap_or_else(|_| "erp.lock".to_owned());
    if Path::new(&lock).exists() {
        error!(%lock, "stale lock file found; refusing to start (the demo fixes this)");
        return ExitCode::FAILURE;
    }

    info!("fake ERP started; create the lock file and restart to simulate a crash");
    ExitCode::SUCCESS
}
