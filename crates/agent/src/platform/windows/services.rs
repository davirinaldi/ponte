//! The service manager: what a service is, its state, starting and stopping it.
//!
//! Every call here may wait on the service manager, so the machine of Windows makes them
//! from a thread of their own and bounds each by the time the manifest has left (see
//! `machine.rs`). Nothing here returns text from Windows: only codes.
//!
//! A service is refused by its structure (ADR-0011) whatever `allowed_services` says, when:
//!
//! - it does not exist, or its name is not ASCII;
//! - its type is anything but `SERVICE_WIN32_OWN_PROCESS`: drivers and services that share
//!   an `svchost` are out;
//! - it is a protected service;
//! - its binary path cannot be read: only an absolute path on a drive letter, ending in
//!   `.exe`, quoted or without spaces, with nothing of the environment left in it;
//! - its binary lies inside the Windows folder, as written or where it resolves;
//! - its binary, or a folder above it, can be changed by anyone but SYSTEM,
//!   Administrators or TrustedInstaller: starting it would run that someone's code as the
//!   service's account.

use std::fs::OpenOptions;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use ponte_protocol::{ServiceName, ServiceState, ServiceStatus};
use std::os::windows::fs::OpenOptionsExt;
use std::path::Path;

use windows_sys::Win32::Foundation::{
    ERROR_INSUFFICIENT_BUFFER, ERROR_SERVICE_ALREADY_RUNNING, ERROR_SERVICE_DOES_NOT_EXIST,
    ERROR_SERVICE_NOT_ACTIVE,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_BACKUP_SEMANTICS, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, SECURITY_IDENTIFICATION, SYNCHRONIZE,
};
use windows_sys::Win32::System::Environment::ExpandEnvironmentStringsW;
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, ControlService, OpenSCManagerW, OpenServiceW, QUERY_SERVICE_CONFIGW,
    QueryServiceConfig2W, QueryServiceConfigW, QueryServiceStatusEx, SC_HANDLE, SC_MANAGER_CONNECT,
    SC_STATUS_PROCESS_INFO, SERVICE_CONFIG_LAUNCH_PROTECTED, SERVICE_CONTROL_STOP,
    SERVICE_LAUNCH_PROTECTED_INFO, SERVICE_LAUNCH_PROTECTED_NONE, SERVICE_QUERY_CONFIG,
    SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START, SERVICE_START_PENDING, SERVICE_STATUS,
    SERVICE_STATUS_PROCESS, SERVICE_STOP, SERVICE_STOP_PENDING, SERVICE_STOPPED,
    SERVICE_WIN32_OWN_PROCESS, StartServiceW,
};
use windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;

use super::files::{self, Facts, Segments};
use crate::platform::Leaf;

/// Why a service is refused, one reason per rule, so each can be tested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refused {
    Missing,
    Name,
    Type,
    Protected,
    BinaryPath,
    InWindows,
    BinaryUnreadable,
    BinaryChangeable,
    /// The service manager could not be asked: not about the service.
    Unreadable,
}

/// A handle of the service manager, closed when dropped.
struct Handle(SC_HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: the handle came from OpenSCManagerW or OpenServiceW and is closed once.
        unsafe { CloseServiceHandle(self.0) };
    }
}

/// The service manager and one service in it, open for `access`.
struct Opened {
    service: Handle,
    // Kept open as long as the service's handle, closed after it.
    _manager: Handle,
}

fn last_error() -> u32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .and_then(|code| u32::try_from(code).ok())
        .unwrap_or(0)
}

fn open(name: &str, access: u32) -> Result<Opened, Refused> {
    // SAFETY: null machine and database name mean this machine's active database.
    let manager = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        return Err(Refused::Unreadable);
    }
    let manager = Handle(manager);
    let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    // SAFETY: `manager` is open; `wide` is NUL-terminated and lives through the call.
    let service = unsafe { OpenServiceW(manager.0, wide.as_ptr(), access) };
    if service.is_null() {
        return Err(if last_error() == ERROR_SERVICE_DOES_NOT_EXIST {
            Refused::Missing
        } else {
            Refused::Unreadable
        });
    }
    Ok(Opened {
        service: Handle(service),
        _manager: manager,
    })
}

/// The most the service manager may answer for a configuration (its limit is 8 KiB).
const MAX_CONFIG_BYTES: u32 = 64 * 1024;

/// The type of the service and its binary path, as configured.
fn configuration(service: &Handle) -> Result<(u32, Vec<u16>), Refused> {
    let mut needed = 0_u32;
    // SAFETY: a null buffer of size 0 only asks for the size needed.
    let sized = unsafe { QueryServiceConfigW(service.0, std::ptr::null_mut(), 0, &mut needed) };
    if sized != 0 || last_error() != ERROR_INSUFFICIENT_BUFFER || needed > MAX_CONFIG_BYTES {
        return Err(Refused::Unreadable);
    }
    // u64s, so the structure at the start is aligned.
    let mut buffer = vec![0_u64; usize::try_from(needed).unwrap_or(0).div_ceil(8)];
    let size = u32::try_from(buffer.len() * 8).unwrap_or(u32::MAX);
    // SAFETY: `buffer` is aligned and writable for `size` bytes.
    let read =
        unsafe { QueryServiceConfigW(service.0, buffer.as_mut_ptr().cast(), size, &mut needed) };
    if read == 0 {
        return Err(Refused::Unreadable);
    }
    // SAFETY: the call wrote a QUERY_SERVICE_CONFIGW at the start of the buffer.
    let config = unsafe { buffer.as_ptr().cast::<QUERY_SERVICE_CONFIGW>().read() };
    let binary = wide_in(&buffer, config.lpBinaryPathName).ok_or(Refused::BinaryPath)?;
    Ok((config.dwServiceType, binary))
}

/// The NUL-terminated string at `text`, which must point into `buffer`.
fn wide_in(buffer: &[u64], text: *mut u16) -> Option<Vec<u16>> {
    if text.is_null() {
        return None;
    }
    // Where it points is only compared; what is read comes from `buffer` itself.
    let offset = (text as usize).checked_sub(buffer.as_ptr() as usize)?;
    if !offset.is_multiple_of(2) || offset >= buffer.len() * 8 {
        return None;
    }
    // SAFETY: every bit pattern is a valid u16, and a u64 slice holds four u16s per item,
    // aligned, for as long as `buffer` is borrowed.
    let units =
        unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u16>(), buffer.len() * 4) };
    let units = &units[offset / 2..];
    let length = units.iter().position(|unit| *unit == 0)?;
    Some(units[..length].to_vec())
}

fn launch_protected(service: &Handle) -> Result<bool, Refused> {
    let mut info = SERVICE_LAUNCH_PROTECTED_INFO::default();
    let mut needed = 0_u32;
    // SAFETY: `info` is writable for the size given.
    let read = unsafe {
        QueryServiceConfig2W(
            service.0,
            SERVICE_CONFIG_LAUNCH_PROTECTED,
            (&raw mut info).cast(),
            u32::try_from(size_of::<SERVICE_LAUNCH_PROTECTED_INFO>()).unwrap_or(u32::MAX),
            &mut needed,
        )
    };
    if read == 0 {
        return Err(Refused::Unreadable);
    }
    Ok(info.dwLaunchProtected != SERVICE_LAUNCH_PROTECTED_NONE)
}

/// `text` with the environment variables of this process expanded, as the service manager
/// expands them when it starts the service.
fn expand(text: &[u16]) -> Option<Vec<u16>> {
    let source: Vec<u16> = text.iter().copied().chain(Some(0)).collect();
    // SAFETY: a null destination of size 0 only asks for the size needed.
    let needed = unsafe { ExpandEnvironmentStringsW(source.as_ptr(), std::ptr::null_mut(), 0) };
    if needed == 0 || needed > MAX_CONFIG_BYTES {
        return None;
    }
    let mut expanded = vec![0_u16; usize::try_from(needed).ok()?];
    // SAFETY: `expanded` has room for `needed` units.
    let written =
        unsafe { ExpandEnvironmentStringsW(source.as_ptr(), expanded.as_mut_ptr(), needed) };
    if written == 0 || written > needed {
        return None;
    }
    expanded.truncate(usize::try_from(written).ok()?.saturating_sub(1));
    Some(expanded)
}

/// The executable of a binary path, as the rules allow it to be written: an absolute path
/// on a drive letter ending in `.exe`, either quoted and followed by nothing or by
/// arguments, or unquoted and without spaces. `None` for anything else.
pub(crate) fn binary_path(command: &str) -> Option<String> {
    let path = if let Some(rest) = command.strip_prefix('"') {
        let (path, after) = rest.split_once('"')?;
        if !(after.is_empty() || after.starts_with(' ')) {
            return None;
        }
        path
    } else {
        // Unquoted, the path ends at the first space: one with a space in it is ambiguous,
        // and the first part is then not an executable.
        command.split(' ').next()?
    };
    let plain = !path.contains(['%', '"', '/'])
        && Segments::of_written(path).is_some_and(|segments| segments.len() > 1)
        && path
            .split('\\')
            .skip(1)
            .all(|name| !name.is_empty() && name != "." && name != "..")
        && path.to_ascii_lowercase().ends_with(".exe");
    plain.then(|| path.to_owned())
}

/// The Windows folder, as Windows names it and as it resolves.
pub(crate) fn windows_folder() -> Option<Vec<Segments>> {
    let mut buffer = vec![0_u16; 512];
    // SAFETY: `buffer` has room for the number of units given.
    let written = unsafe {
        GetSystemWindowsDirectoryW(
            buffer.as_mut_ptr(),
            u32::try_from(buffer.len()).unwrap_or(0),
        )
    };
    let written = usize::try_from(written).ok()?;
    if written == 0 || written >= buffer.len() {
        return None;
    }
    buffer.truncate(written);
    let text = String::from_utf16(&buffer).ok()?;
    let named = Segments::of_written(&text)?;
    let file = OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES | SYNCHRONIZE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(&text)
        .ok()?;
    let resolved = Segments::of_final(&files::final_path(&file).ok()?)?;
    Some(vec![named, resolved])
}

/// Where the binary at `path` resolves, if it is a file on a disk outside `windows`, that
/// only SYSTEM, Administrators and TrustedInstaller can change.
fn check_binary(path: &str, windows: &[Segments]) -> Result<(), Refused> {
    let written = Segments::of_written(path).ok_or(Refused::BinaryPath)?;
    if windows.iter().any(|folder| written.inside(folder)) {
        return Err(Refused::InWindows);
    }
    let file = OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES | SYNCHRONIZE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .security_qos_flags(SECURITY_IDENTIFICATION)
        .open(path)
        .map_err(|_| Refused::BinaryUnreadable)?;
    let facts = Facts::of(&file).map_err(|_| Refused::BinaryUnreadable)?;
    if !facts.is_disk() || facts.is_directory() {
        return Err(Refused::BinaryUnreadable);
    }
    let resolved = files::final_path(&file)
        .ok()
        .and_then(|path| Segments::of_final(&path))
        .ok_or(Refused::BinaryUnreadable)?;
    if windows.iter().any(|folder| resolved.inside(folder)) {
        return Err(Refused::InWindows);
    }
    // The path as written is what the service manager launches: it is walked, and may
    // hold no junction or link a user could swap between this check and the start, and it
    // must resolve to itself.
    super::acl::check_chain(Path::new(path), Leaf::Executable)
        .map_err(|_| Refused::BinaryChangeable)
}

/// Whether the service `name` may be touched by its structure (ADR-0011). `windows` is
/// [`windows_folder`].
pub(crate) fn structure(name: &str, windows: &[Segments]) -> Result<(), Refused> {
    if name.is_empty() || !name.is_ascii() {
        return Err(Refused::Name);
    }
    let opened = open(name, SERVICE_QUERY_CONFIG)?;
    let (kind, binary) = configuration(&opened.service)?;
    if kind != SERVICE_WIN32_OWN_PROCESS {
        return Err(Refused::Type);
    }
    if launch_protected(&opened.service)? {
        return Err(Refused::Protected);
    }
    let command = expand(&binary)
        .and_then(|units| String::from_utf16(&units).ok())
        .ok_or(Refused::BinaryPath)?;
    let path = binary_path(&command).ok_or(Refused::BinaryPath)?;
    check_binary(&path, windows)
}

/// What the service manager says of a service now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum State {
    Running,
    Stopped,
    StartPending,
    StopPending,
    /// Paused, or on its way to or from it.
    Other,
}

/// The state of the service `name`.
pub(crate) fn state(name: &str) -> Result<State, Refused> {
    let opened = open(name, SERVICE_QUERY_STATUS)?;
    let mut status = SERVICE_STATUS_PROCESS::default();
    let mut needed = 0_u32;
    // SAFETY: `status` is writable for the size given.
    let read = unsafe {
        QueryServiceStatusEx(
            opened.service.0,
            SC_STATUS_PROCESS_INFO,
            (&raw mut status).cast(),
            u32::try_from(size_of::<SERVICE_STATUS_PROCESS>()).unwrap_or(u32::MAX),
            &mut needed,
        )
    };
    if read == 0 {
        return Err(Refused::Unreadable);
    }
    Ok(match status.dwCurrentState {
        SERVICE_RUNNING => State::Running,
        SERVICE_STOPPED => State::Stopped,
        SERVICE_START_PENDING => State::StartPending,
        SERVICE_STOP_PENDING => State::StopPending,
        _ => State::Other,
    })
}

/// Asks the service manager to start `name`. One that runs already counts as started. The
/// call may wait as long as the service takes to reach the service manager.
pub(crate) fn start(name: &str) -> Result<(), Refused> {
    let opened = open(name, SERVICE_START)?;
    // SAFETY: the service is open for SERVICE_START; no arguments.
    let started = unsafe { StartServiceW(opened.service.0, 0, std::ptr::null()) };
    if started == 0 && last_error() != ERROR_SERVICE_ALREADY_RUNNING {
        return Err(Refused::Unreadable);
    }
    Ok(())
}

/// Asks the service manager to stop `name`. One that is not running counts as stopped.
pub(crate) fn stop(name: &str) -> Result<(), Refused> {
    let opened = open(name, SERVICE_STOP)?;
    let mut status = SERVICE_STATUS::default();
    // SAFETY: the service is open for SERVICE_STOP; `status` receives its state.
    let asked = unsafe { ControlService(opened.service.0, SERVICE_CONTROL_STOP, &mut status) };
    if asked == 0 && last_error() != ERROR_SERVICE_NOT_ACTIVE {
        return Err(Refused::Unreadable);
    }
    Ok(())
}

/// The state of each service in `names`, for the telemetry (RF-06), read within about two
/// seconds in all: what does not answer by then is `Unknown`.
pub(crate) fn report(names: &[ServiceName], reading: &Arc<AtomicBool>) -> Vec<ServiceStatus> {
    let unknown = |names: &[ServiceName]| {
        names
            .iter()
            .map(|name| ServiceStatus {
                name: name.clone(),
                state: ServiceState::Unknown,
            })
            .collect()
    };
    // One reading at a time: if the last one still waits on the service manager, this
    // snapshot says "unknown" rather than leave another thread waiting beside it.
    if reading.swap(true, Ordering::AcqRel) {
        return unknown(names);
    }
    let owned = names.to_vec();
    let done = Arc::clone(reading);
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    let spawned = std::thread::Builder::new()
        .name("ponte-services".to_owned())
        .spawn(move || {
            let states: Vec<ServiceStatus> = owned
                .into_iter()
                .map(|name| {
                    let state = match state(name.as_str()) {
                        Ok(State::Running) => ServiceState::Running,
                        Ok(State::Stopped) => ServiceState::Stopped,
                        Ok(State::StartPending) => ServiceState::StartPending,
                        Ok(State::StopPending) => ServiceState::StopPending,
                        Ok(State::Other) | Err(_) => ServiceState::Unknown,
                    };
                    ServiceStatus { name, state }
                })
                .collect();
            done.store(false, Ordering::Release);
            let _ = send.send(states);
        });
    if spawned.is_err() {
        reading.store(false, Ordering::Release);
        return unknown(names);
    }
    receive
        .recv_timeout(Duration::from_secs(2))
        .unwrap_or_else(|_| unknown(names))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_binary_path_is_one_executable_written_plainly() {
        for (command, path) in [
            (r"C:\FakeErp\fake-erp.exe", r"C:\FakeErp\fake-erp.exe"),
            (
                r"C:\FakeErp\fake-erp.exe service",
                r"C:\FakeErp\fake-erp.exe",
            ),
            (
                r#""C:\Program Files\FakeErp\fake-erp.exe""#,
                r"C:\Program Files\FakeErp\fake-erp.exe",
            ),
            (
                r#""C:\Program Files\FakeErp\fake-erp.exe" service --lock C:\x"#,
                r"C:\Program Files\FakeErp\fake-erp.exe",
            ),
            (r"D:\ERP\ERP.EXE", r"D:\ERP\ERP.EXE"),
        ] {
            assert_eq!(binary_path(command).as_deref(), Some(path), "{command}");
        }
        for refused in [
            // A space without quotes: Windows would try `C:\Program.exe` first.
            r"C:\Program Files\FakeErp\fake-erp.exe",
            r"\??\C:\FakeErp\fake-erp.exe",
            r"\SystemRoot\System32\drivers\x.sys",
            r"System32\svchost.exe",
            r"\\server\share\erp.exe",
            r"\\?\C:\FakeErp\fake-erp.exe",
            r"%ProgramFiles%\FakeErp\fake-erp.exe",
            r"C:\FakeErp\%UNSET%\fake-erp.exe",
            r"C:\FakeErp\fake-erp.bat",
            r"C:\FakeErp\fake-erp",
            r"C:\fake-erp.exe\..\x.exe",
            r"C:\FakeErp\.\fake-erp.exe",
            r"C:/FakeErp/fake-erp.exe",
            r#""C:\FakeErp\fake-erp.exe"x"#,
            r#""C:\FakeErp\fake-erp.exe"#,
            r"C:\FakeErp\erp.exe:stream.exe",
            r"C:\",
            "",
        ] {
            assert_eq!(binary_path(refused), None, "{refused}");
        }
    }

    #[test]
    fn services_of_windows_are_refused_by_their_structure() {
        let windows = windows_folder().unwrap();
        // Shares an svchost.
        assert_eq!(structure("Schedule", &windows), Err(Refused::Type));
        // Its own process, in the Windows folder.
        assert_eq!(
            structure("TrustedInstaller", &windows),
            Err(Refused::InWindows)
        );
        assert_eq!(
            structure("ponte-surely-not-a-service", &windows),
            Err(Refused::Missing)
        );
        assert_eq!(structure("Fak\u{e9}Erp", &windows), Err(Refused::Name));
        assert_eq!(structure("", &windows), Err(Refused::Name));
    }

    /// The antivirus runs its own process, outside the Windows folder, and is protected:
    /// only the protection refuses it. The first of these that exists here is asked.
    #[test]
    fn a_protected_service_is_refused() {
        let windows = windows_folder().unwrap();
        let answers: Vec<_> = ["WdNisSvc", "WinDefend", "Sense"]
            .iter()
            .map(|name| structure(name, &windows))
            .collect();
        let first = answers
            .iter()
            .find(|answer| **answer != Err(Refused::Missing))
            .expect("no protected service on this machine");
        assert_eq!(*first, Err(Refused::Protected));
    }

    /// A binary path that leads into the Windows folder through a junction is in the
    /// Windows folder: where it resolves decides, not how it is written.
    #[test]
    fn a_binary_reached_through_a_junction_into_windows_is_refused() {
        let windows = windows_folder().unwrap();
        let dir = crate::testkit::TempDir::new();
        let link = dir.path().join("erp");
        let system32 = format!(r"{}\System32", windows[1].to_text().unwrap());
        crate::platform::windows::files::tests::junction(&link, Path::new(&system32));
        let binary = link.join("cmd.exe");
        assert_eq!(
            check_binary(binary.to_str().unwrap(), &windows),
            Err(Refused::InWindows)
        );
        assert_eq!(
            check_binary(&format!(r"{system32}\cmd.exe"), &windows),
            Err(Refused::InWindows)
        );
    }

    /// The service manager launches the path as written. A trusted binary reached through
    /// a junction in a folder a user controls is the user's to swap between the check and
    /// the start: the path as written is what must be trusted, and it may hold no junction.
    #[test]
    fn a_trusted_binary_behind_a_users_junction_is_refused() {
        let windows = windows_folder().unwrap();
        let trusted = Path::new(r"C:\Program Files\Windows Defender");
        if !trusted.join("MpCmdRun.exe").is_file() {
            return;
        }
        let direct = trusted.join("MpCmdRun.exe");
        assert_eq!(check_binary(direct.to_str().unwrap(), &windows), Ok(()));
        let dir = crate::testkit::TempDir::new();
        let link = dir.path().join("erp");
        crate::platform::windows::files::tests::junction(&link, trusted);
        let through = link.join("MpCmdRun.exe");
        assert_eq!(
            check_binary(through.to_str().unwrap(), &windows),
            Err(Refused::BinaryChangeable)
        );
    }

    #[test]
    fn the_windows_folder_is_named_and_resolved() {
        let windows = windows_folder().unwrap();
        assert_eq!(windows.len(), 2);
        let system32 = Segments::of_written(r"C:\Windows\System32").unwrap();
        if windows[0].to_text().as_deref() == Some(r"C:\Windows") {
            assert!(system32.inside(&windows[0]));
        }
    }

    #[test]
    fn the_state_of_a_service_is_read() {
        // The task scheduler always runs.
        assert_eq!(state("Schedule"), Ok(State::Running));
        assert_eq!(state("ponte-surely-not-a-service"), Err(Refused::Missing));
    }

    #[test]
    fn the_telemetry_reports_each_listed_service() {
        let names: Vec<ServiceName> = ["Schedule", "ponte-surely-not-a-service"]
            .iter()
            .map(|name| name.parse().unwrap())
            .collect();
        let reading = Arc::new(AtomicBool::new(false));
        let report = report(&names, &reading);
        assert_eq!(report.len(), 2);
        assert_eq!(report[0].name.as_str(), "Schedule");
        assert_eq!(report[0].state, ServiceState::Running);
        assert_eq!(report[1].state, ServiceState::Unknown);
        assert!(super::report(&[], &reading).is_empty());
        // While a reading is still out, the next one does not wait beside it.
        reading.store(true, Ordering::Release);
        assert!(
            super::report(&names, &reading)
                .iter()
                .all(|status| status.state == ServiceState::Unknown)
        );
    }

    #[test]
    fn a_wide_string_is_read_only_inside_its_buffer() {
        let mut buffer = vec![0_u64; 4];
        let units: Vec<u16> = "abc".encode_utf16().chain(Some(0)).collect();
        // SAFETY: the buffer has room for the four units.
        unsafe {
            std::ptr::copy_nonoverlapping(units.as_ptr(), buffer.as_mut_ptr().cast::<u16>(), 4);
        }
        let start = buffer.as_mut_ptr().cast::<u16>();
        assert_eq!(wide_in(&buffer, start), Some(units[..3].to_vec()));
        assert_eq!(wide_in(&buffer, std::ptr::null_mut()), None);
        let mut elsewhere = [0_u16; 4];
        assert_eq!(wide_in(&buffer, elsewhere.as_mut_ptr()), None);
        // No NUL before the end of the buffer.
        buffer.fill(u64::MAX);
        assert_eq!(wide_in(&buffer, start), None);
    }
}
