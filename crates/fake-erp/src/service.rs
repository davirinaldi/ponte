//! The fake ERP as a Windows service.

use std::ffi::OsString;
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::mpsc;
use std::time::Duration;

use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState,
    ServiceStatus, ServiceType, UserEventCode,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

/// Where the lock lives unless `--lock` says otherwise.
pub(crate) const DEFAULT_LOCK: &str = r"C:\FakeErp\run\erp.lock";
/// The control that makes the service fall over, one of those a service defines itself.
const CRASH: u32 = 128;
/// Exit codes the service stops with when it does not start.
const LOCK_LEFT: u32 = 1;
const LOCK_NOT_MADE: u32 = 2;

static LOCK: OnceLock<PathBuf> = OnceLock::new();

// SAFETY: the macro defines the `extern "system"` entry point the service manager calls,
// which reads the arguments it is handed as the service manager documents them and passes
// them on to `service_main` as owned strings.
define_windows_service!(ffi_service_main, service_main);

pub(crate) fn run(lock: PathBuf) -> Result<(), String> {
    let _ = LOCK.set(lock);
    service_dispatcher::start("FakeErp", ffi_service_main)
        .map_err(|_| "`service` is for the service manager to start".to_owned())
}

/// Makes the service called `name` fall over, its lock left behind.
pub(crate) fn crash(name: &str) -> Result<(), String> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|error| format!("the service manager: {error}"))?;
    let service = manager
        .open_service(name, ServiceAccess::USER_DEFINED_CONTROL)
        .map_err(|error| format!("the service: {error}"))?;
    let code = UserEventCode::from_raw(CRASH).map_err(|error| error.to_string())?;
    // The service exits while it handles the control, so the answer may be an error.
    let _ = service.notify(code);
    Ok(())
}

enum Event {
    Stop,
    Crash,
}

fn status(
    state: ServiceState,
    accept: ServiceControlAccept,
    exit: ServiceExitCode,
) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accept,
        exit_code: exit,
        checkpoint: 0,
        wait_hint: Duration::from_secs(if state == ServiceState::StartPending {
            10
        } else {
            0
        }),
        process_id: None,
    }
}

fn service_main(arguments: Vec<OsString>) {
    let name = arguments
        .first()
        .cloned()
        .unwrap_or_else(|| "FakeErp".into());
    let (send, events) = mpsc::channel();
    let handler = move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = send.send(Event::Stop);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::UserEvent(code) if code.to_raw() == CRASH => {
            let _ = send.send(Event::Crash);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let Ok(handle) = service_control_handler::register(&name, handler) else {
        return;
    };
    let set = |state, accept, exit| {
        let _ = handle.set_service_status(status(state, accept, exit));
    };
    let none = ServiceControlAccept::empty();
    set(ServiceState::StartPending, none, ServiceExitCode::Win32(0));

    let lock = LOCK.get().cloned().unwrap_or_else(|| DEFAULT_LOCK.into());
    if let Err(code) = take_lock(&lock) {
        set(
            ServiceState::Stopped,
            none,
            ServiceExitCode::ServiceSpecific(code),
        );
        return;
    }
    // The lock is there before anyone is told the ERP runs.
    set(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        ServiceExitCode::Win32(0),
    );
    match events.recv() {
        Ok(Event::Stop) | Err(_) => {
            let _ = std::fs::remove_file(&lock);
            set(ServiceState::Stopped, none, ServiceExitCode::Win32(0));
        }
        // A crash: the process is gone, and the lock stays.
        Ok(Event::Crash) => std::process::exit(3),
    }
}

/// Makes the lock, or says why the ERP does not start.
fn take_lock(lock: &Path) -> Result<(), u32> {
    if lock.exists() {
        return Err(LOCK_LEFT);
    }
    if let Some(folder) = lock.parent() {
        std::fs::create_dir_all(folder).map_err(|_| LOCK_NOT_MADE)?;
    }
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(lock)
        .map(drop)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                LOCK_LEFT
            } else {
                LOCK_NOT_MADE
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_lock_is_taken_once_and_refuses_a_second_start() {
        let dir = std::env::temp_dir().join(format!("fake-erp-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let lock = dir.join("run").join("erp.lock");
        assert_eq!(take_lock(&lock), Ok(()));
        assert!(lock.exists());
        assert_eq!(take_lock(&lock), Err(LOCK_LEFT));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
