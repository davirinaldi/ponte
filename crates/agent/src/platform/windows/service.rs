//! The agent as a Windows service (ADR-0013): `ponte-agent service --config <path>`, which
//! only the service manager starts.
//!
//! - **Starting**: `START_PENDING`, with a checkpoint every second, while the agent checks
//!   its ground ([`crate::prepare`], under the name the service manager gave it) and waits
//!   for the journal, which an agent still stopping may hold for up to ten seconds. Then
//!   `RUNNING`, accepting stop and shutdown.
//! - **A failure before the log** (a configuration refused, a folder that fails the ACL
//!   rule) goes to the Event Log as a code and the setting at fault, and the service stops
//!   with that code as its service-specific exit code.
//! - **The log** goes to `<data_dir>\logs`, two files of 5 MB, once the data directory
//!   passed its checks.
//! - **Stopping**: `STOP_PENDING`, with a wait hint of `shutdown_timeout_secs` and the time
//!   to close the session, while the agent stops (ADR-0013); then `STOPPED`.

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;

use tokio::sync::watch;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{
    self, ServiceControlHandlerResult, ServiceStatusHandle,
};
use windows_service::{define_windows_service, service_dispatcher};

use super::eventlog;
use super::log::FileLog;
use crate::{Prepared, ServiceName, StartError};

/// The name the dispatcher is given. A service of its own process gets whatever name it
/// was installed under; that one comes in the arguments of `service_main`.
const DISPATCHER_NAME: &str = "PonteAgent";
/// What the service manager waits for between two checkpoints while the agent starts.
const START_HINT: Duration = Duration::from_secs(15);
/// What closing the session and the last writes take, on top of `shutdown_timeout_secs`.
const CLOSE_HINT: Duration = Duration::from_secs(10);
/// The event id of a log that could not be opened; the others are `StartError::code`.
const LOG_FAILED: u32 = 100;
/// The event id of a runtime that could not be made.
const RUNTIME_FAILED: u32 = 101;

/// The configuration's path, from the command line the service manager ran.
static CONFIG: OnceLock<PathBuf> = OnceLock::new();

// SAFETY: the macro defines the `extern "system"` entry point the service manager calls,
// which reads the arguments it is handed as the service manager documents them and passes
// them on to `service_main` as owned strings.
define_windows_service!(ffi_service_main, service_main);

/// Hands this thread to the service manager until the service stops.
///
/// # Errors
/// The process was not started by the service manager.
pub(crate) fn run_dispatcher(config: PathBuf) -> windows_service::Result<()> {
    let _ = CONFIG.set(config);
    service_dispatcher::start(DISPATCHER_NAME, ffi_service_main)
}

/// Where the service stands, kept so a checkpoint never follows `RUNNING`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Starting(u32),
    Running,
    Done,
}

struct Status {
    handle: ServiceStatusHandle,
    phase: Mutex<Phase>,
}

impl Status {
    fn set(
        &self,
        state: ServiceState,
        accept: ServiceControlAccept,
        checkpoint: u32,
        hint: Duration,
        exit: ServiceExitCode,
    ) {
        let _ = self.handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accept,
            exit_code: exit,
            checkpoint,
            wait_hint: hint,
            process_id: None,
        });
    }

    /// One more checkpoint, while the agent starts.
    fn tick(&self) -> bool {
        let mut phase = self.phase.lock().unwrap_or_else(PoisonError::into_inner);
        let Phase::Starting(checkpoint) = *phase else {
            return false;
        };
        let next = checkpoint.saturating_add(1);
        *phase = Phase::Starting(next);
        self.set(
            ServiceState::StartPending,
            ServiceControlAccept::empty(),
            next,
            START_HINT,
            ServiceExitCode::Win32(0),
        );
        true
    }

    fn running(&self) {
        let mut phase = self.phase.lock().unwrap_or_else(PoisonError::into_inner);
        *phase = Phase::Running;
        self.set(
            ServiceState::Running,
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            0,
            Duration::ZERO,
            ServiceExitCode::Win32(0),
        );
    }

    fn stopping(&self, hint: Duration) {
        *self.phase.lock().unwrap_or_else(PoisonError::into_inner) = Phase::Done;
        self.set(
            ServiceState::StopPending,
            ServiceControlAccept::empty(),
            1,
            hint,
            ServiceExitCode::Win32(0),
        );
    }

    fn stopped(&self, exit: ServiceExitCode) {
        *self.phase.lock().unwrap_or_else(PoisonError::into_inner) = Phase::Done;
        self.set(
            ServiceState::Stopped,
            ServiceControlAccept::empty(),
            0,
            Duration::ZERO,
            exit,
        );
    }
}

fn service_main(arguments: Vec<OsString>) {
    // The service manager passes the name the service is registered under first.
    let registered = arguments
        .first()
        .cloned()
        .unwrap_or_else(|| DISPATCHER_NAME.into());
    let (stop, stopped) = watch::channel(false);
    let handler = move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = stop.send(true);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let Ok(handle) = service_control_handler::register(&registered, handler) else {
        eventlog::report(
            RUNTIME_FAILED,
            &eventlog::text(RUNTIME_FAILED, "the service manager", None),
        );
        return;
    };
    let status = Arc::new(Status {
        handle,
        phase: Mutex::new(Phase::Starting(0)),
    });
    status.tick();
    // A checkpoint every second while the agent starts, so the service manager waits.
    let ticker = {
        let status = Arc::clone(&status);
        std::thread::spawn(move || {
            while status.tick() {
                std::thread::sleep(Duration::from_secs(1));
            }
        })
    };
    let exit = run(&registered, &status, stopped);
    status.stopped(exit);
    let _ = ticker.join();
}

/// Everything between `START_PENDING` and `STOPPED`; the exit code the service ends with.
fn run(
    registered: &OsString,
    status: &Arc<Status>,
    mut stopped: watch::Receiver<bool>,
) -> ServiceExitCode {
    let Some(config) = CONFIG.get() else {
        return ServiceExitCode::ServiceSpecific(RUNTIME_FAILED);
    };
    let name: Option<ServiceName> = registered.to_str().and_then(|name| name.parse().ok());
    let prepared = match crate::prepare(config, name.as_ref()) {
        Ok(prepared) => prepared,
        Err(error) => return refused(&error),
    };
    if let Err(code) = log_to_files(&prepared) {
        return ServiceExitCode::ServiceSpecific(code);
    }
    let shutdown_timeout = prepared.config().actions.shutdown_timeout;
    info!(
        protocol = ponte_protocol::PROTOCOL_VERSION,
        elevation = ?prepared.elevation(),
        "agent starting as a service"
    );
    let runtime = match crate::runtime() {
        Ok(runtime) => runtime,
        Err(error) => {
            error!(%error, "the async runtime could not be started");
            return ServiceExitCode::ServiceSpecific(RUNTIME_FAILED);
        }
    };
    let stopping = {
        let status = Arc::clone(status);
        async move {
            let _ = stopped.wait_for(|stop| *stop).await;
            status.stopping(shutdown_timeout + CLOSE_HINT);
        }
    };
    let ready = {
        let status = Arc::clone(status);
        move || status.running()
    };
    runtime.block_on(crate::run_until(prepared, stopping, ready));
    // Not the runtime's `Drop`, which would wait for an action that overran its time: the
    // journal reports that one as interrupted at the next start.
    runtime.shutdown_background();
    info!("agent stopped");
    ServiceExitCode::Win32(0)
}

/// A start refused before the log: to the Event Log, as a code and a setting.
fn refused(error: &StartError) -> ServiceExitCode {
    let code = error.code();
    eventlog::report(code, &eventlog::text(code, error.setting(), error.line()));
    ServiceExitCode::ServiceSpecific(code)
}

/// Sends the log to `<data_dir>\logs`, once the data directory passed its checks.
fn log_to_files(prepared: &Prepared) -> Result<(), u32> {
    let folder = prepared.config().data_dir.join("logs");
    let log = crate::platform::create_private_dir(&folder)
        .and_then(|()| FileLog::in_folder(&folder))
        .map_err(|_| {
            eventlog::report(
                LOG_FAILED,
                &eventlog::text(LOG_FAILED, "data_dir (its logs folder)", None),
            );
            LOG_FAILED
        })?;
    let installed = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new("info"))
        .with_ansi(false)
        .with_writer(log)
        .try_init();
    if installed.is_err() {
        eventlog::report(LOG_FAILED, &eventlog::text(LOG_FAILED, "the log", None));
        return Err(LOG_FAILED);
    }
    Ok(())
}
