//! A fake ERP that fails in the same boring ways real ones do, so demos and
//! end-to-end tests can break it on purpose and watch Ponte fix it.
//!
//! - `fake-erp service [--lock <path>]` is what the Windows service manager starts. Like
//!   many ERPs it keeps a lock file while it runs (`C:\FakeErp\run\erp.lock` by default):
//!   it makes the lock before it reports itself running, removes it on a clean stop, and
//!   refuses to start while one is there.
//! - `fake-erp crash [--name FakeErp]` makes the running service fall over, leaving its
//!   lock behind: the next start fails until the lock is removed, which is what the
//!   `erp.clear-stale-lock` manifest does.
//!
//! Failure modes still to come: disk almost full, database unreachable.

use std::process::ExitCode;

#[cfg(windows)]
#[allow(unsafe_code)]
mod service;

const USAGE: &str =
    "usage: fake-erp service [--lock <path>]\n       fake-erp crash [--name <service>]";

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let outcome = match args.as_slice() {
        ["service"] => run_service(None),
        ["service", "--lock", lock] => run_service(Some(lock)),
        ["crash"] => crash("FakeErp"),
        ["crash", "--name", name] => crash(name),
        _ => Err(USAGE.to_owned()),
    };
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            tracing::error!("{message}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(windows)]
fn run_service(lock: Option<&str>) -> Result<(), String> {
    service::run(lock.map_or_else(|| service::DEFAULT_LOCK.into(), Into::into))
}

#[cfg(windows)]
fn crash(name: &str) -> Result<(), String> {
    service::crash(name)
}

#[cfg(not(windows))]
fn run_service(_lock: Option<&str>) -> Result<(), String> {
    Err("the fake ERP runs as a Windows service only".to_owned())
}

#[cfg(not(windows))]
fn crash(_name: &str) -> Result<(), String> {
    Err("the fake ERP runs as a Windows service only".to_owned())
}
