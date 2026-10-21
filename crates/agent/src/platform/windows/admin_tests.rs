//! Tests that install services: the fake ERP, and the agent itself. They need an elevated
//! token, so they are `#[ignore]` and named `win_admin_*`: the Windows job of CI runs them
//! after building `fake-erp`, and on a workstation they run only when someone elevated asks
//! (`cargo test -p ponte-agent -- --ignored win_admin_ --test-threads=1`).
//!
//! Each test makes a folder of its own under `C:\ProgramData`, with the protected ACL of
//! `acl.rs`, copies the binary there (a service whose binary a user can change is refused
//! by its structure), installs a service with a name of its own, and removes both when it
//! ends, a failed assertion included.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use ponte_actions::{Check, ExpectedServiceState, Primitive};
use windows_service::service::{
    ServiceAccess, ServiceErrorControl, ServiceExitCode, ServiceInfo, ServiceStartType,
    ServiceState, ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use super::machine::WindowsMachine;
use super::roots::resolve_roots;
use super::services::windows_folder;
use crate::actions::machine::{Machine, ServiceRefusal, StepError};

const MINUTE: Duration = Duration::from_secs(60);

/// A binary built next to this test's executable (`target/<profile>/`).
fn built(name: &str) -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let folder = exe.parent().and_then(Path::parent).unwrap();
    let path = folder.join(format!("{name}.exe"));
    assert!(
        path.is_file(),
        "{} is missing: build it first (cargo build -p {name})",
        path.display()
    );
    path
}

/// A folder under `C:\ProgramData` and a service, removed when dropped.
struct Lab {
    folder: PathBuf,
    service: String,
}

impl Lab {
    /// Made before anything is installed, so a failure halfway still cleans up.
    fn new(label: &str) -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let id = format!(
            "{}{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let folder = PathBuf::from(format!(r"C:\ProgramData\PonteTest-{label}-{id}"));
        let lab = Self {
            folder,
            service: format!("PonteTest{label}{id}"),
        };
        lab.remove_service();
        let _ = std::fs::remove_dir_all(&lab.folder);
        super::acl::create_private_dir(&lab.folder.join("bin")).unwrap();
        lab
    }

    /// Copies `binary` into the lab and installs it as this lab's service.
    fn install(&self, binary: &Path, arguments: &[&str]) -> PathBuf {
        let copy = self.folder.join("bin").join(binary.file_name().unwrap());
        std::fs::copy(binary, &copy).unwrap();
        self.install_at(&copy, arguments);
        copy
    }

    fn install_at(&self, executable: &Path, arguments: &[&str]) {
        let manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
        )
        .unwrap();
        let info = ServiceInfo {
            name: OsString::from(&self.service),
            display_name: OsString::from(&self.service),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::OnDemand,
            error_control: ServiceErrorControl::Normal,
            executable_path: executable.to_owned(),
            launch_arguments: arguments.iter().map(OsString::from).collect(),
            dependencies: Vec::new(),
            account_name: None,
            account_password: None,
        };
        manager
            .create_service(&info, ServiceAccess::QUERY_STATUS)
            .unwrap();
    }

    fn remove_service(&self) {
        let Ok(manager) =
            ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        else {
            return;
        };
        let Ok(service) = manager.open_service(
            &self.service,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        ) else {
            return;
        };
        let _ = service.stop();
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline
            && service
                .query_status()
                .is_ok_and(|status| status.current_state != ServiceState::Stopped)
        {
            std::thread::sleep(Duration::from_millis(200));
        }
        let _ = service.delete();
    }

    /// The state and exit code the service manager reports, once it stops changing.
    fn settled(&self) -> (ServiceState, ServiceExitCode) {
        let manager =
            ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).unwrap();
        let service = manager
            .open_service(&self.service, ServiceAccess::QUERY_STATUS)
            .unwrap();
        let deadline = Instant::now() + MINUTE;
        loop {
            let status = service.query_status().unwrap();
            let pending = matches!(
                status.current_state,
                ServiceState::StartPending | ServiceState::StopPending
            );
            if !pending || Instant::now() > deadline {
                return (status.current_state, status.exit_code);
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    fn start(&self) {
        let manager =
            ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).unwrap();
        let service = manager
            .open_service(&self.service, ServiceAccess::START)
            .unwrap();
        service.start::<&str>(&[]).unwrap();
    }

    fn stop(&self) {
        let manager =
            ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).unwrap();
        let service = manager
            .open_service(&self.service, ServiceAccess::STOP)
            .unwrap();
        let _ = service.stop();
    }

    /// A machine whose roots are this lab's `erp` folder, deleting in `erp\run`.
    fn machine(&self) -> WindowsMachine {
        let erp = self.folder.join("erp");
        std::fs::create_dir_all(erp.join("run")).unwrap();
        let roots = resolve_roots(
            &[erp.to_str().unwrap().to_owned()],
            &[erp.join("run").to_str().unwrap().to_owned()],
            &[],
            &windows_folder().unwrap(),
        )
        .unwrap();
        WindowsMachine::new(roots, windows_folder().unwrap())
    }

    fn lock(&self) -> PathBuf {
        self.folder.join("erp").join("run").join("erp.lock")
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        self.remove_service();
        // A process the service manager reports stopped may hold its binary a moment more.
        let deadline = Instant::now() + Duration::from_secs(10);
        while std::fs::remove_dir_all(&self.folder).is_err()
            && self.folder.exists()
            && Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(250));
        }
    }
}

fn state(service: &str, expected: ExpectedServiceState) -> Check {
    Check::ServiceState {
        service: service.to_owned(),
        state: expected,
    }
}

/// The fake ERP, installed as the walkthrough installs it, passes the structural rules;
/// the machine starts it (and reads it again five seconds later), stops it and restarts it.
#[test]
#[ignore = "installs a service: needs an elevated token"]
fn win_admin_the_machine_starts_stops_and_restarts_the_fake_erp() {
    let lab = Lab::new("Erp");
    let machine = lab.machine();
    let lock = lab.lock();
    lab.install(
        &built("fake-erp"),
        &["service", "--lock", lock.to_str().unwrap()],
    );
    let name = lab.service.as_str();
    let lock_text = lock.to_str().unwrap().to_owned();

    assert_eq!(machine.service_allowed(name, MINUTE), Ok(()));
    assert_eq!(
        machine.check(&state(name, ExpectedServiceState::Stopped), MINUTE),
        Ok(true)
    );
    let started = Instant::now();
    assert_eq!(
        machine.step(
            &Primitive::ServiceStart {
                service: name.to_owned()
            },
            MINUTE
        ),
        Ok(())
    );
    assert!(
        started.elapsed() >= Duration::from_secs(5),
        "the second look"
    );
    assert_eq!(
        machine.check(&state(name, ExpectedServiceState::Running), MINUTE),
        Ok(true)
    );
    // The lock was there before the service manager said "running".
    let exists = Check::PathExists {
        path: lock_text.clone(),
    };
    assert_eq!(machine.check(&exists, MINUTE), Ok(true));

    assert_eq!(
        machine.step(
            &Primitive::ServiceRestart {
                service: name.to_owned()
            },
            MINUTE
        ),
        Ok(())
    );
    assert_eq!(
        machine.step(
            &Primitive::ServiceStop {
                service: name.to_owned()
            },
            MINUTE
        ),
        Ok(())
    );
    assert_eq!(machine.check(&exists, MINUTE), Ok(false));
    // Stopping what is stopped is done already.
    assert_eq!(
        machine.step(
            &Primitive::ServiceStop {
                service: name.to_owned()
            },
            MINUTE
        ),
        Ok(())
    );
}

/// The demo: the ERP falls over and leaves its lock; it no longer starts; deleting the
/// lock through the machine lets it start again.
#[test]
#[ignore = "installs a service: needs an elevated token"]
fn win_admin_a_crash_leaves_the_lock_and_deleting_it_brings_the_erp_back() {
    let lab = Lab::new("Crash");
    let machine = lab.machine();
    let lock = lab.lock();
    let erp = lab.install(
        &built("fake-erp"),
        &["service", "--lock", lock.to_str().unwrap()],
    );
    let name = lab.service.as_str();
    let start = Primitive::ServiceStart {
        service: name.to_owned(),
    };
    assert_eq!(machine.step(&start, MINUTE), Ok(()));

    let crashed = Command::new(&erp)
        .args(["crash", "--name", name])
        .status()
        .unwrap();
    assert!(crashed.success());
    assert_eq!(lab.settled().0, ServiceState::Stopped);
    assert!(lock.exists(), "a crash leaves the lock");

    assert_eq!(machine.step(&start, MINUTE), Err(StepError::Failed));
    let delete = Primitive::DeleteFile {
        path: lock.to_str().unwrap().to_owned(),
    };
    assert_eq!(machine.step(&delete, MINUTE), Ok(()));
    assert_eq!(machine.step(&start, MINUTE), Ok(()));
    assert!(lock.exists(), "the ERP makes its lock again");
}

/// A service whose binary sits where every user may write is refused by its structure:
/// starting it would run that user's code as the service's account.
#[test]
#[ignore = "installs a service: needs an elevated token"]
fn win_admin_a_service_whose_binary_users_can_change_is_refused() {
    let lab = Lab::new("Open");
    let machine = lab.machine();
    // A folder made the ordinary way inherits the ACL of ProgramData: users may add files.
    let open = lab.folder.join("open");
    std::fs::create_dir(&open).unwrap();
    let mut command = Command::new("icacls");
    command
        .arg(&open)
        .args(["/grant", "*S-1-5-32-545:(OI)(CI)M"]);
    assert!(command.output().unwrap().status.success());
    let copy = open.join("fake-erp.exe");
    std::fs::copy(built("fake-erp"), &copy).unwrap();
    lab.install_at(&copy, &["service"]);
    assert_eq!(
        machine.service_allowed(&lab.service, MINUTE),
        Err(ServiceRefusal::Structure)
    );
}

/// The structure is read again in the call that starts the service: a binary that users
/// could change only after the action was decided is still not started.
#[test]
#[ignore = "installs a service: needs an elevated token"]
fn win_admin_a_binary_opened_to_users_after_the_check_is_not_started() {
    let lab = Lab::new("Late");
    let machine = lab.machine();
    let lock = lab.lock();
    lab.install(
        &built("fake-erp"),
        &["service", "--lock", lock.to_str().unwrap()],
    );
    assert_eq!(machine.service_allowed(&lab.service, MINUTE), Ok(()));
    let mut command = Command::new("icacls");
    command
        .arg(lab.folder.join("bin"))
        .args(["/grant", "*S-1-5-32-545:(OI)(CI)M"]);
    assert!(command.output().unwrap().status.success());
    let start = Primitive::ServiceStart {
        service: lab.service.clone(),
    };
    assert_eq!(machine.step(&start, MINUTE), Err(StepError::Failed));
    assert!(!lock.exists(), "the ERP never ran");
}

/// The agent itself, as a service: it reaches `RUNNING`, logs to `<data_dir>\logs`, and
/// stops cleanly. A configuration it refuses stops it with the code of the refusal.
#[test]
#[ignore = "installs a service: needs an elevated token"]
fn win_admin_the_agent_runs_as_a_service_and_refuses_what_it_should() {
    let lab = Lab::new("Agent");
    let agent = lab.folder.join("bin").join("ponte-agent.exe");
    std::fs::copy(built("ponte-agent"), &agent).unwrap();
    let data = lab.folder.join("data");
    let config = lab.folder.join("agent.toml");
    let write_config = |url: &str| {
        std::fs::write(
            &config,
            format!(
                "server_url = '{url}'\ndata_dir = '{}'\nallowed_roots = ['{}']\n",
                data.display(),
                lab.folder.join("erp").display()
            ),
        )
        .unwrap();
    };
    write_config("wss://ponte.invalid/agent");
    lab.install_at(&agent, &["service", "--config", config.to_str().unwrap()]);

    lab.start();
    assert_eq!(lab.settled().0, ServiceState::Running);
    let log = std::fs::read_to_string(data.join("logs").join("agent.log")).unwrap();
    assert!(log.contains("agent starting as a service"), "{log}");
    lab.stop();
    assert_eq!(
        lab.settled(),
        (ServiceState::Stopped, ServiceExitCode::Win32(0))
    );

    // Elevated, plain ws:// is refused, and said with its code.
    write_config("ws://127.0.0.1:8080/agent");
    lab.start();
    assert_eq!(
        lab.settled(),
        (ServiceState::Stopped, ServiceExitCode::ServiceSpecific(3))
    );
}
