//! OS-specific code. This is the only module in the workspace where `unsafe` is allowed,
//! and every `unsafe` block must carry a `// SAFETY:` comment.

pub(crate) mod keystore;

#[cfg(windows)]
#[allow(unsafe_code)]
mod windows;
#[cfg(windows)]
pub use windows::NAME;

#[cfg(not(windows))]
mod unsupported;
#[cfg(not(windows))]
pub use unsupported::NAME;

use std::fs::File;
use std::io;
use std::path::Path;
use std::sync::Arc;
#[cfg(not(windows))]
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
};

use ponte_protocol::{ServiceName, ServiceStatus};

use crate::actions::machine::Machine;
#[cfg(not(windows))]
use crate::actions::machine::Unsupported;

/// What runs the steps and checks of actions here, with the roots as they resolve now.
/// `own` names the agent's files (the setting, and the path), which may lie in no root as
/// they resolve. On Windows the machine checks the final path of every file it opens
/// against these roots (ADR-0011); elsewhere every platform refuses everything.
///
/// # Errors
/// A root resolves where no root may be, or the folders Windows keeps for itself could
/// not be read.
pub(crate) fn machine(
    allowed: &[String],
    delete: &[String],
    own: &[(&'static str, &Path)],
) -> Result<Arc<dyn Machine>, RootProblem> {
    #[cfg(windows)]
    {
        let folders = windows::services::windows_folder().ok_or(RootProblem::KnownFolders)?;
        let roots = windows::roots::resolve_roots(allowed, delete, own, &folders)?;
        Ok(Arc::new(windows::machine::WindowsMachine::new(
            roots, folders,
        )))
    }
    #[cfg(not(windows))]
    {
        let _ = (allowed, delete, own);
        Ok(Arc::new(Unsupported))
    }
}

/// The state of each service the configuration allows, for the telemetry (RF-06). None
/// outside Windows.
/// `reading` is set while a reading is out: the caller's own, so a reading that still waits
/// on the service manager is not joined by another.
pub(crate) fn service_states(
    names: &[ServiceName],
    reading: &Arc<std::sync::atomic::AtomicBool>,
) -> Vec<ServiceStatus> {
    #[cfg(windows)]
    return windows::services::report(names, reading);
    #[cfg(not(windows))]
    {
        let _ = (names, reading);
        Vec::new()
    }
}

/// Whether the agent's token is elevated (ADR-0013). Outside Windows it never is: those
/// builds are for development.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Elevation {
    Elevated,
    NotElevated,
    /// The token could not be read.
    Unknown,
}

impl Elevation {
    /// Whether the rules for an elevated agent apply: the owner and ACL rules, and no
    /// `ws://`. A token that could not be read gets them too.
    #[must_use]
    pub fn strict(self) -> bool {
        self != Self::NotElevated
    }
}

/// What the last part of a path is, for [`check_trusted`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Leaf {
    /// The configuration or the token: the file and its folder are the agent's own.
    File,
    /// The data directory, or the folder of a token not there yet: the folder is its own.
    Directory,
    /// An executable: the file and its folder may also belong to TrustedInstaller.
    Executable,
    /// A folder above what the agent is about to make: held to the rule for folders above,
    /// itself included.
    Above,
}

/// Why a path is not one an elevated agent may trust (ADR-0011). Says which rule, never
/// the path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Untrusted {
    #[error("is not an absolute path on a drive with a letter, in plain names")]
    NotAbsolute,
    #[error("does not exist")]
    Missing,
    #[error("or a folder above it is a junction, a link or a mount point")]
    ReparsePoint,
    #[error("or a folder above it is not on a local disk")]
    NotDisk,
    #[error("lies on a volume that keeps no access lists")]
    NoAcls,
    #[error("resolves to another path than the one written (a short 8.3 name?)")]
    Moved,
    #[error("or a folder above it has an owner other than SYSTEM or Administrators")]
    Owner,
    #[error("or a folder above it lets another account change, delete or replace it")]
    Grants,
    #[error("or a folder above it has no access list, or an entry the agent cannot read")]
    Unreadable,
}

/// Why the roots, as they resolve when the agent starts, refuse the start (ADR-0011). A
/// root that fails on its own is left out instead. Names the setting, never the path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RootProblem {
    #[error("{what} lies inside a root, or holds one, as the roots resolve")]
    Overlaps { what: &'static str },
    #[error("the folders Windows keeps for itself could not be read")]
    KnownFolders,
}

impl RootProblem {
    /// The setting at fault.
    #[must_use]
    pub fn setting(&self) -> &'static str {
        match self {
            Self::Overlaps { what } => what,
            Self::KnownFolders => "allowed_roots",
        }
    }
}

/// Holds `path` and every folder above it to the owner and ACL rules of ADR-0011. Only
/// Windows has them; elsewhere nothing is checked, and nothing runs elevated.
pub(crate) fn check_trusted(path: &Path, leaf: Leaf) -> Result<(), Untrusted> {
    #[cfg(windows)]
    return windows::acl::check_chain(path, leaf);
    #[cfg(not(windows))]
    {
        let _ = (path, leaf);
        Ok(())
    }
}

/// The configuration is a few lines; anything this large is not one.
const MAX_CONFIG_BYTES: usize = 256 * 1024;

/// Reads the configuration file as text, opened as the agent's own files are.
pub(crate) fn read_config(path: &Path) -> io::Result<String> {
    let bytes = read_bounded(path, MAX_CONFIG_BYTES)?.ok_or(io::ErrorKind::NotFound)?;
    String::from_utf8(bytes).map_err(|_| io::ErrorKind::InvalidData.into())
}

/// A monotonic clock: time since some fixed moment, never set by anyone. On Windows it
/// also counts the time the machine slept.
pub(crate) fn monotonic() -> std::time::Duration {
    #[cfg(windows)]
    return windows::clock::interrupt_time();
    #[cfg(not(windows))]
    {
        static BASE: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
        BASE.get_or_init(std::time::Instant::now).elapsed()
    }
}

/// Hands this thread to the service manager (ADR-0013).
#[cfg(windows)]
pub(crate) fn run_service(config: std::path::PathBuf) -> windows_service::Result<()> {
    windows::service::run_dispatcher(config)
}

/// Reads the agent's token.
pub(crate) fn elevation() -> Elevation {
    #[cfg(windows)]
    return windows::elevation::probe();
    #[cfg(not(windows))]
    Elevation::NotElevated
}

/// Creates `dir` and whatever is missing above it, private to the agent: on Windows with
/// a protected ACL for SYSTEM, Administrators and the folder's owner; where files have
/// modes, for the owner only.
pub(crate) fn create_private_dir(dir: &Path) -> io::Result<()> {
    #[cfg(windows)]
    return windows::acl::create_private_dir(dir);
    #[cfg(not(windows))]
    create_private_dir_here(dir)
}

/// [`create_private_dir`] for an elevated agent: makes every folder below `checked`, which
/// exists and passed its rule, down to `dir`, and on Windows refuses any that already
/// exists, rather than going through it.
pub(crate) fn create_private_dir_below(checked: &Path, dir: &Path) -> io::Result<()> {
    #[cfg(windows)]
    return windows::acl::create_private_dir_below(checked, dir);
    #[cfg(not(windows))]
    {
        let _ = checked;
        create_private_dir_here(dir)
    }
}

#[cfg(not(windows))]
fn create_private_dir_here(dir: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)
}

/// Writes `bytes` to `path` so that whoever reads it later, after a crash or a power cut
/// included, finds the old content or the new one and never a part of either. Where files
/// have modes, only the owner can read the result. On Windows the folder must exist, the
/// rename is written through and a link is never followed (`windows::files`).
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    #[cfg(windows)]
    return windows::files::write_private(path, bytes);
    #[cfg(not(windows))]
    write_private_here(path, bytes)
}

#[cfg(not(windows))]
fn write_private_here(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    create_private_dir(dir)?;

    let temporary = path.with_extension("tmp");
    // One may be left from a write that was cut short. It is never the file anyone reads.
    match fs::remove_file(&temporary) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
        _ => {}
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, path)?;
    // The rename itself is only on disk once the directory is.
    #[cfg(unix)]
    File::open(dir)?.sync_all()?;
    Ok(())
}

/// Reads the file at `path` if it has at most `max` bytes. `None` if there is no such
/// file, and `InvalidData` if it is larger: what the agent reads has a known size, and a
/// path that points somewhere else must not be pulled into memory. On Windows it must be a
/// regular file of one link on a disk, and a link at the path is refused, not followed.
pub(crate) fn read_bounded(path: &Path, max: usize) -> io::Result<Option<Vec<u8>>> {
    #[cfg(windows)]
    return windows::files::read_bounded(path, max);
    #[cfg(not(windows))]
    read_bounded_here(path, max)
}

#[cfg(not(windows))]
fn read_bounded_here(path: &Path, max: usize) -> io::Result<Option<Vec<u8>>> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let limit = u64::try_from(max).unwrap_or(u64::MAX).saturating_add(1);
    let mut bytes = Vec::new();
    file.take(limit).read_to_end(&mut bytes)?;
    if bytes.len() > max {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(Some(bytes))
}

/// Removes the file at `path`, if there is one. On Windows only a regular file of one link
/// is removed, through the handle that was checked.
pub(crate) fn remove_file(path: &Path) -> io::Result<()> {
    #[cfg(windows)]
    return windows::files::remove(path);
    #[cfg(not(windows))]
    match fs::remove_file(path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

/// Opens, creating it if needed, a file held for the life of the process to lock it.
pub(crate) fn open_lock(path: &Path) -> io::Result<File> {
    #[cfg(windows)]
    return windows::files::open_lock(path);
    #[cfg(not(windows))]
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::testkit::TempDir;

    #[test]
    fn an_unknown_elevation_gets_the_strict_rules() {
        assert!(Elevation::Elevated.strict());
        assert!(Elevation::Unknown.strict());
        assert!(!Elevation::NotElevated.strict());
    }

    #[test]
    fn a_write_replaces_the_file_and_leaves_nothing_else_behind() {
        let dir = TempDir::new();
        let path = dir.path().join("nested").join("identity.toml");
        create_private_dir(path.parent().unwrap()).unwrap();

        write_private(&path, b"first").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"first");
        write_private(&path, b"second, and longer").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"second, and longer");

        let names: Vec<_> = fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, ["identity.toml"]);
    }

    /// A write that was cut short leaves its temporary file. The next one must not trip
    /// over it, and must not have its content mistaken for the real one.
    #[test]
    fn a_stale_temporary_file_is_replaced() {
        let dir = TempDir::new();
        let path = dir.path().join("device.key");
        fs::write(dir.path().join("device.tmp"), b"half of an old key").unwrap();

        assert_eq!(read_bounded(&path, 32).unwrap(), None);
        write_private(&path, b"new").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"new");
        assert!(!dir.path().join("device.tmp").exists());
    }

    #[cfg(unix)]
    #[test]
    fn only_the_owner_can_read_what_is_written() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new();
        let path = dir.path().join("made-here").join("device.key");
        write_private(&path, b"secret").unwrap();

        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);
    }

    #[test]
    fn reading_stops_at_the_expected_size() {
        let dir = TempDir::new();
        let path = dir.path().join("token");

        assert_eq!(read_bounded(&path, 4).unwrap(), None);
        fs::write(&path, b"1234").unwrap();
        assert_eq!(read_bounded(&path, 4).unwrap(), Some(b"1234".to_vec()));
        fs::write(&path, b"12345").unwrap();
        assert_eq!(
            read_bounded(&path, 4).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        // A directory is not a file that is missing.
        assert!(read_bounded(dir.path(), 4).is_err());
    }
}
