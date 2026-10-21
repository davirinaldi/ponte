//! Files on ground a local user may share with the agent (ADR-0011, "Opening a file on the
//! user's ground").
//!
//! The agent runs as SYSTEM, and the user of the machine can plant junctions, hard links
//! and named pipes wherever they can write. Every path that comes from a manifest, the
//! configuration or the token is opened here:
//!
//! - with identification-level SQOS, so a named pipe at the end of a path learns who is
//!   asking and cannot act as SYSTEM;
//! - without following a reparse point at the end of the path (it is opened, then
//!   refused);
//! - without `FILE_SHARE_DELETE`, so nobody renames or deletes it while the agent holds it;
//! - then checked on the handle: a file on a disk, not a pipe or a device.
//!
//! The agent's own files (journal, mark, identity, key, token, lock, logs) must also be a
//! regular file with one link. Their folders pass the owner and ACL rules when the agent
//! starts elevated, so nobody but an administrator can swap what lies above them.
//!
//! Paths a manifest names are also checked by where they end up: Windows still follows
//! reparse points in the middle of a path, so the final path of the handle must lie inside
//! a root as the roots resolved at start, compared segment by segment the way the file
//! system compares names. A file is deleted through the handle that was checked.
#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the machine of Windows, the roots and the logs use the rest, later in step 5"
    )
)]

use std::ffi::c_void;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;

use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND};
use windows_sys::Win32::Globalization::{CSTR_EQUAL, CompareStringOrdinal};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, DELETE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_DISPOSITION_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TYPE_DISK,
    FileDispositionInfo, GetFileInformationByHandle, GetFileType, GetFinalPathNameByHandleW,
    MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW, SECURITY_IDENTIFICATION,
    SYNCHRONIZE, SetFileInformationByHandle, VOLUME_NAME_DOS,
};

/// The impersonation level a server at the end of a path gets: it may learn who opened it,
/// and nothing more. The standard library adds `SECURITY_SQOS_PRESENT` when this is set.
const SQOS: u32 = SECURITY_IDENTIFICATION;
/// Others may read and write what the agent holds, never delete or rename it.
const SHARE: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE;
/// The longest path Windows hands back, in UTF-16 units.
const MAX_PATH_UNITS: usize = 32_768;

/// A path for a Windows call: UTF-16, ending in NUL.
pub(crate) fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

/// The agent's own file is not a regular file of one link on a disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("refused: not a regular file with one link on this machine's disk (ADR-0011)")]
pub(crate) struct NotPlain;

/// Never `InvalidData`: the identity takes that for "no key here" and would enroll again
/// over a key that was swapped for a link.
fn not_plain() -> io::Error {
    io::Error::other(NotPlain)
}

/// "File not found" or "path not found", and nothing else: an invalid name, a denied
/// access or a busy pipe is not a missing file.
pub(crate) fn is_not_found(error: &io::Error) -> bool {
    error.raw_os_error().is_some_and(|code| {
        u32::try_from(code)
            .is_ok_and(|code| code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND)
    })
}

/// What the handle says about the file it holds.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Facts {
    disk: bool,
    attributes: u32,
    links: u32,
}

impl Facts {
    pub(crate) fn of(file: &File) -> io::Result<Self> {
        let handle = file.as_raw_handle();
        // SAFETY: `handle` belongs to `file`, which outlives the call.
        let disk = unsafe { GetFileType(handle) } == FILE_TYPE_DISK;
        if !disk {
            // A pipe or a device: nothing more to ask of it.
            return Ok(Self {
                disk,
                attributes: 0,
                links: 0,
            });
        }
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: `handle` is open, and `info` is a valid place for the answer.
        if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            disk,
            attributes: info.dwFileAttributes,
            links: info.nNumberOfLinks,
        })
    }

    pub(crate) fn is_reparse_point(&self) -> bool {
        self.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }

    pub(crate) fn is_directory(&self) -> bool {
        self.attributes & FILE_ATTRIBUTE_DIRECTORY != 0
    }

    pub(crate) fn is_disk(&self) -> bool {
        self.disk
    }

    /// A regular file with exactly one link, on a disk.
    fn is_plain(&self) -> bool {
        self.disk && !self.is_reparse_point() && !self.is_directory() && self.links == 1
    }
}

/// Opens `path` as one of the agent's own files, with `options` saying how, and refuses
/// anything but a regular file of one link on a disk.
fn own(path: &Path, options: &mut OpenOptions) -> io::Result<File> {
    let file = open_own_unchecked(path, options)?;
    if !Facts::of(&file)?.is_plain() {
        return Err(not_plain());
    }
    Ok(file)
}

/// The open of [`own`], before the checks. Separate so a test can hold the handle a named
/// pipe saw.
fn open_own_unchecked(path: &Path, options: &mut OpenOptions) -> io::Result<File> {
    options
        .share_mode(SHARE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .security_qos_flags(SQOS)
        .open(path)
}

/// Reads the agent's file at `path` if it has at most `max` bytes. `None` if there is no
/// such file, `InvalidData` if it is larger.
pub(crate) fn read_bounded(path: &Path, max: usize) -> io::Result<Option<Vec<u8>>> {
    let file = match own(path, OpenOptions::new().read(true)) {
        Ok(file) => file,
        Err(error) if is_not_found(&error) => return Ok(None),
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

/// Writes `bytes` to `path` so that after a crash or a power cut the file holds the old
/// content or the new one: a new temporary file, flushed, then renamed over `path` with
/// the rename itself written through. Its folder must exist: folders are made when the
/// agent starts, never later.
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let temporary = path.with_extension("tmp");
    // One may be left from a write that was cut short. It is never the file anyone reads.
    remove(&temporary)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .security_qos_flags(SQOS)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    replace_through(&temporary, path)
}

/// Renames `from` over `to`, and returns once the rename is on the disk.
fn replace_through(from: &Path, to: &Path) -> io::Result<()> {
    let (from, to) = (wide(from), wide(to));
    // SAFETY: both are NUL-terminated UTF-16 strings that live through the call.
    let moved = unsafe {
        MoveFileExW(
            from.as_ptr(),
            to.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if moved == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Renames `from` over `to`, for the logs: written through like the rest.
pub(crate) fn replace(from: &Path, to: &Path) -> io::Result<()> {
    replace_through(from, to)
}

/// Removes the agent's file at `path`, through the handle that was checked. Nothing to do
/// if there is none.
pub(crate) fn remove(path: &Path) -> io::Result<()> {
    let file = match own(
        path,
        OpenOptions::new().access_mode(DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE),
    ) {
        Ok(file) => file,
        Err(error) if is_not_found(&error) => return Ok(()),
        Err(error) => return Err(error),
    };
    dispose(&file)
}

/// Opens, creating it if needed, the file whose lock keeps a second agent off the journal.
pub(crate) fn open_lock(path: &Path) -> io::Result<File> {
    own(path, OpenOptions::new().read(true).write(true).create(true))
}

/// Opens a log file to append to, creating it if needed.
pub(crate) fn open_append(path: &Path) -> io::Result<File> {
    own(path, OpenOptions::new().append(true).create(true))
}

/// Marks the file `file` holds for deletion: it goes when the handle closes.
fn dispose(file: &File) -> io::Result<()> {
    let info = FILE_DISPOSITION_INFO { DeleteFile: true };
    let size = u32::try_from(size_of::<FILE_DISPOSITION_INFO>()).unwrap_or(u32::MAX);
    // SAFETY: the handle belongs to `file`, and `info` is a FILE_DISPOSITION_INFO of the
    // size given, alive through the call.
    let disposed = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfo,
            (&raw const info).cast::<c_void>(),
            size,
        )
    };
    if disposed == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The path `file` ends up at, as Windows reports it (`\\?\C:\...`).
pub(crate) fn final_path(file: &File) -> io::Result<Vec<u16>> {
    let mut buffer = vec![0_u16; 512];
    loop {
        let capacity = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
        // SAFETY: the handle belongs to `file`, and `buffer` has room for `capacity` units.
        let written = unsafe {
            GetFinalPathNameByHandleW(
                file.as_raw_handle(),
                buffer.as_mut_ptr(),
                capacity,
                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
            )
        };
        let written = usize::try_from(written).unwrap_or(usize::MAX);
        if written == 0 {
            return Err(io::Error::last_os_error());
        }
        if written < buffer.len() {
            buffer.truncate(written);
            return Ok(buffer);
        }
        // Too small: `written` is the room needed, NUL included.
        if written > MAX_PATH_UNITS {
            return Err(io::ErrorKind::InvalidData.into());
        }
        buffer.resize(written, 0);
    }
}

/// Whether two names are the same name to the file system: ordinal, ignoring case the
/// way NTFS does. Look-alike letters (dotless `ı`, KELVIN SIGN) stay apart.
pub(crate) fn same_name(a: &[u16], b: &[u16]) -> bool {
    let (Ok(a_len), Ok(b_len)) = (i32::try_from(a.len()), i32::try_from(b.len())) else {
        return false;
    };
    // SAFETY: both slices live through the call and hold the number of units given.
    unsafe { CompareStringOrdinal(a.as_ptr(), a_len, b.as_ptr(), b_len, 1) == CSTR_EQUAL }
}

/// A path on a drive with a letter, in segments: the drive (`C:`), then each name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Segments(Vec<Vec<u16>>);

impl Segments {
    /// Reads a final path. Only `\\?\X:\...` is one: a path under `\\?\UNC\` (a share), on a
    /// volume with no letter (`\\?\Volume{...}`) or with a stream (`:` in a name) is not.
    pub(crate) fn of_final(path: &[u16]) -> Option<Self> {
        let prefix: Vec<u16> = r"\\?\".encode_utf16().collect();
        let rest = path.strip_prefix(prefix.as_slice())?;
        Self::of_drive_path(rest)
    }

    /// Reads `X:\...` as written in a configuration, with `\` or `/`.
    pub(crate) fn of_written(path: &str) -> Option<Self> {
        let units: Vec<u16> = path.encode_utf16().collect();
        Self::of_drive_path(&units)
    }

    fn of_drive_path(path: &[u16]) -> Option<Self> {
        let separator = |unit: &u16| *unit == u16::from(b'\\') || *unit == u16::from(b'/');
        let mut parts = path.split(separator);
        let drive = parts.next()?;
        let is_letter = |unit: u16| u8::try_from(unit).is_ok_and(|byte| byte.is_ascii_alphabetic());
        if drive.len() != 2 || !is_letter(drive[0]) || drive[1] != u16::from(b':') {
            return None;
        }
        let mut segments = vec![drive.to_vec()];
        let mut names: Vec<&[u16]> = parts.collect();
        // `C:\` is the drive alone, and Windows may end a folder's path with a separator.
        if names.last().is_some_and(|name| name.is_empty()) {
            names.pop();
        }
        for name in names {
            if name.is_empty() || name.contains(&u16::from(b':')) {
                return None;
            }
            segments.push(name.to_vec());
        }
        Some(Self(segments))
    }

    /// Whether this path is `root` or lies inside it.
    pub(crate) fn inside(&self, root: &Self) -> bool {
        self.0.len() >= root.0.len()
            && root
                .0
                .iter()
                .zip(&self.0)
                .all(|(root, name)| same_name(root, name))
    }

    /// How many segments, the drive included.
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    /// `C:\name\name`, if every name is text.
    pub(crate) fn to_text(&self) -> Option<String> {
        let names: Option<Vec<String>> = self
            .0
            .iter()
            .map(|name| String::from_utf16(name).ok())
            .collect();
        let names = names?;
        Some(if names.len() == 1 {
            format!("{}\\", names[0])
        } else {
            names.join("\\")
        })
    }
}

/// Where a manifest's path ended: a file or a folder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Found {
    File,
    Directory,
}

/// Why a manifest's path was not used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PathError {
    /// A reparse point, more than one link where one is needed, not a disk file, or a
    /// final path outside the roots (ADR-0011).
    Refused,
    /// Windows refused or failed. Never "absent".
    Failed,
}

/// Opens a path a manifest names, without following a reparse point at its end.
fn open_named(path: &str, access: u32) -> io::Result<File> {
    OpenOptions::new()
        .access_mode(access)
        .share_mode(SHARE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .security_qos_flags(SQOS)
        .open(path)
}

/// Whether the final path of `file` lies inside one of `roots`.
fn lands_inside(file: &File, roots: &[Segments]) -> bool {
    final_path(file)
        .ok()
        .and_then(|path| Segments::of_final(&path))
        .is_some_and(|path| roots.iter().any(|root| path.inside(root)))
}

/// What is at `path`, for `path_exists` and `path_absent`: `None` only when Windows
/// answers "file not found" or "path not found". A regular file or a folder whose final
/// path lies in `roots` is found; a reparse point, a pipe or a device, or a final path
/// elsewhere is refused.
pub(crate) fn probe(path: &str, roots: &[Segments]) -> Result<Option<Found>, PathError> {
    let file = match open_named(path, FILE_READ_ATTRIBUTES | SYNCHRONIZE) {
        Ok(file) => file,
        Err(error) if is_not_found(&error) => return Ok(None),
        Err(_) => return Err(PathError::Failed),
    };
    let facts = Facts::of(&file).map_err(|_| PathError::Failed)?;
    if !facts.is_disk() || facts.is_reparse_point() || !lands_inside(&file, roots) {
        return Err(PathError::Refused);
    }
    Ok(Some(if facts.is_directory() {
        Found::Directory
    } else {
        Found::File
    }))
}

/// Deletes the regular file of one link at `path`, whose final path must lie in `roots`,
/// through the handle that was checked.
pub(crate) fn delete(path: &str, roots: &[Segments]) -> Result<(), PathError> {
    let file = open_named(path, DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE)
        .map_err(|_| PathError::Failed)?;
    let facts = Facts::of(&file).map_err(|_| PathError::Failed)?;
    if !facts.is_plain() || !lands_inside(&file, roots) {
        return Err(PathError::Refused);
    }
    dispose(&file).map_err(|_| PathError::Failed)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::process::Command;

    use super::*;
    use crate::testkit::TempDir;

    /// A junction at `link` pointing at the folder `target`. No privilege needed.
    pub(crate) fn junction(link: &Path, target: &Path) {
        let status = Command::new("cmd")
            .arg("/c")
            .arg("mklink")
            .arg("/J")
            .arg(link)
            .arg(target)
            .output()
            .unwrap();
        assert!(status.status.success(), "mklink /J failed");
    }

    /// A symbolic link to a file, or `false` if this account may not make one (the
    /// Windows job of CI runs elevated, where it may).
    fn symlink_file(link: &Path, target: &Path) -> bool {
        match std::os::windows::fs::symlink_file(target, link) {
            Ok(()) => true,
            Err(error) if error.raw_os_error() == Some(1314) => false,
            Err(error) => panic!("{error}"),
        }
    }

    fn segments(path: &Path) -> Segments {
        let file = OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)
            .unwrap();
        Segments::of_final(&final_path(&file).unwrap()).unwrap()
    }

    fn text(path: &Path) -> String {
        path.to_str().unwrap().to_owned()
    }

    fn units(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    // ----- The agent's own files -------------------------------------------------------

    #[test]
    fn own_files_are_read_written_and_removed() {
        let dir = TempDir::new();
        let path = dir.path().join("journal.json");
        assert_eq!(read_bounded(&path, 16).unwrap(), None);
        write_private(&path, b"first").unwrap();
        write_private(&path, b"second").unwrap();
        assert_eq!(read_bounded(&path, 16).unwrap(), Some(b"second".to_vec()));
        assert_eq!(
            read_bounded(&path, 3).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        remove(&path).unwrap();
        remove(&path).unwrap();
        assert!(!path.exists());
    }

    /// Folders are made when the agent starts: a write never makes one.
    #[test]
    fn a_write_makes_no_folder() {
        let dir = TempDir::new();
        let path = dir.path().join("missing").join("journal.json");
        assert!(write_private(&path, b"x").is_err());
        assert!(!dir.path().join("missing").exists());
    }

    /// A temporary file left by a write cut short is replaced, and a link planted under
    /// its name is removed as a link: what it points at stays as it was.
    #[test]
    fn a_stale_temporary_file_is_removed_and_never_followed() {
        let dir = TempDir::new();
        let path = dir.path().join("identity.toml");
        fs::write(dir.path().join("identity.tmp"), b"half").unwrap();
        write_private(&path, b"whole").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"whole");
        assert!(!dir.path().join("identity.tmp").exists());

        let elsewhere = TempDir::new();
        let target = elsewhere.path().join("someone-elses.txt");
        fs::write(&target, b"theirs").unwrap();
        if symlink_file(&dir.path().join("identity.tmp"), &target) {
            // A link is not a regular file: refused, and the target is untouched.
            assert!(write_private(&path, b"again").is_err());
            assert_eq!(fs::read(&target).unwrap(), b"theirs");
        }
    }

    /// A hard link to the agent's file would let whoever holds the other name read or
    /// change it: refused. Replacing the file replaces the name, never the other link.
    #[test]
    fn an_own_file_with_two_links_is_refused() {
        let dir = TempDir::new();
        let path = dir.path().join("device.key");
        write_private(&path, b"key").unwrap();
        let other = dir.path().join("copy");
        fs::hard_link(&path, &other).unwrap();

        let refused = read_bounded(&path, 16).unwrap_err();
        assert!(
            refused
                .get_ref()
                .is_some_and(|inner| inner.is::<NotPlain>())
        );
        assert_ne!(refused.kind(), io::ErrorKind::InvalidData);
        assert!(open_lock(&path).is_err());
        assert!(open_append(&path).is_err());
        assert!(remove(&path).is_err());

        write_private(&path, b"new").unwrap();
        assert_eq!(fs::read(&other).unwrap(), b"key");
        assert_eq!(read_bounded(&path, 16).unwrap(), Some(b"new".to_vec()));
    }

    /// A junction or a link where the agent's file should be is opened as itself, not
    /// followed, and refused.
    #[test]
    fn an_own_file_that_is_a_reparse_point_is_refused() {
        let dir = TempDir::new();
        let elsewhere = TempDir::new();
        let path = dir.path().join("journal.json");
        junction(&path, elsewhere.path());
        assert!(read_bounded(&path, 16).is_err());
        assert!(open_lock(&path).is_err());

        let target = elsewhere.path().join("theirs.txt");
        fs::write(&target, b"theirs").unwrap();
        let link = dir.path().join("clock.toml");
        if symlink_file(&link, &target) {
            let refused = read_bounded(&link, 16).unwrap_err();
            assert!(
                refused
                    .get_ref()
                    .is_some_and(|inner| inner.is::<NotPlain>())
            );
            assert!(open_append(&link).is_err());
            assert!(remove(&link).is_err());
            assert_eq!(fs::read(&target).unwrap(), b"theirs");
        }
    }

    #[test]
    fn the_lock_and_the_log_are_made_once_and_opened_again() {
        let dir = TempDir::new();
        let lock = dir.path().join("journal.lock");
        drop(open_lock(&lock).unwrap());
        drop(open_lock(&lock).unwrap());
        let log = dir.path().join("agent.log");
        open_append(&log).unwrap().write_all(b"one\n").unwrap();
        open_append(&log).unwrap().write_all(b"two\n").unwrap();
        assert_eq!(fs::read(&log).unwrap(), b"one\ntwo\n");
        replace(&log, &dir.path().join("agent.1.log")).unwrap();
        assert!(!log.exists());
    }

    /// Nobody may delete or rename the agent's file while it holds it.
    #[test]
    fn a_held_file_cannot_be_deleted_or_renamed() {
        let dir = TempDir::new();
        let lock = dir.path().join("journal.lock");
        let held = open_lock(&lock).unwrap();
        assert!(fs::remove_file(&lock).is_err());
        assert!(fs::rename(&lock, dir.path().join("moved")).is_err());
        drop(held);
        fs::remove_file(&lock).unwrap();
    }

    // ----- Named pipes -----------------------------------------------------------------

    mod pipe {
        use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::Security::{
            GetTokenInformation, RevertToSelf, SECURITY_IMPERSONATION_LEVEL, TOKEN_QUERY,
            TokenImpersonationLevel,
        };
        use windows_sys::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
        use windows_sys::Win32::System::Pipes::{
            CreateNamedPipeW, ImpersonateNamedPipeClient, PIPE_TYPE_BYTE, PIPE_WAIT,
        };
        use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};

        /// The server's end of a named pipe, made by the test as a local user would.
        pub(super) struct Server(HANDLE);

        impl Server {
            pub(super) fn new(name: &str) -> Self {
                let name: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
                // SAFETY: `name` is NUL-terminated and lives through the call; the null
                // security attributes give the default descriptor.
                let handle = unsafe {
                    CreateNamedPipeW(
                        name.as_ptr(),
                        PIPE_ACCESS_DUPLEX,
                        PIPE_TYPE_BYTE | PIPE_WAIT,
                        1,
                        512,
                        512,
                        0,
                        std::ptr::null(),
                    )
                };
                assert_ne!(handle, INVALID_HANDLE_VALUE);
                Self(handle)
            }

            /// Impersonates the client that opened the pipe and reports the level it got,
            /// or `None` if it got nothing at all.
            pub(super) fn impersonation_level(&self) -> Option<SECURITY_IMPERSONATION_LEVEL> {
                // SAFETY: `self.0` is the pipe this server made, with a client on it.
                if unsafe { ImpersonateNamedPipeClient(self.0) } == 0 {
                    return None;
                }
                let mut token: HANDLE = std::ptr::null_mut();
                let mut level: SECURITY_IMPERSONATION_LEVEL = 0;
                let mut returned = 0_u32;
                // SAFETY: the thread is impersonating; `token` receives a handle that is
                // closed below; `level` has the size passed.
                let read = unsafe {
                    OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) != 0
                        && GetTokenInformation(
                            token,
                            TokenImpersonationLevel,
                            (&raw mut level).cast(),
                            u32::try_from(size_of::<SECURITY_IMPERSONATION_LEVEL>()).unwrap(),
                            &mut returned,
                        ) != 0
                };
                // SAFETY: undoes the impersonation of this thread; `token` is closed once.
                unsafe {
                    RevertToSelf();
                    if !token.is_null() {
                        CloseHandle(token);
                    }
                }
                read.then_some(level)
            }
        }

        impl Drop for Server {
            fn drop(&mut self) {
                // SAFETY: the handle was made by `new` and is closed once.
                unsafe { CloseHandle(self.0) };
            }
        }
    }

    /// A named pipe at the end of a path learns who opened it and can do nothing as them,
    /// and the agent refuses it as one of its files.
    #[test]
    fn a_named_pipe_cannot_impersonate_the_agent() {
        use windows_sys::Win32::Security::SecurityIdentification;

        let name = format!(r"\\.\pipe\ponte-test-{}", std::process::id());
        let server = pipe::Server::new(&name);
        let client = open_own_unchecked(Path::new(&name), OpenOptions::new().read(true)).unwrap();
        assert_eq!(server.impersonation_level(), Some(SecurityIdentification));
        drop(client);
        drop(server);

        // One instance per client: a pipe a client left must be reset before the next.
        let server = pipe::Server::new(&name);
        let refused = read_bounded(Path::new(&name), 16).unwrap_err();
        assert!(
            refused
                .get_ref()
                .is_some_and(|inner| inner.is::<NotPlain>())
        );
        drop(server);
        let anywhere = [Segments::of_written(r"C:\").unwrap()];
        let server = pipe::Server::new(&name);
        assert_eq!(probe(&name, &anywhere), Err(PathError::Refused));
        drop(server);
        let server = pipe::Server::new(&name);
        assert_eq!(delete(&name, &anywhere), Err(PathError::Refused));
        drop(server);
    }

    // ----- Final paths -----------------------------------------------------------------

    #[test]
    fn a_final_path_is_a_drive_letter_and_plain_names() {
        let read = |text: &str| Segments::of_final(&units(text));
        let path = read(r"\\?\C:\FakeErp\run\erp.lock").unwrap();
        assert_eq!(path.len(), 4);
        assert_eq!(path.to_text().unwrap(), r"C:\FakeErp\run\erp.lock");
        assert_eq!(read(r"\\?\C:\").unwrap().to_text().unwrap(), r"C:\");
        assert!(read(r"\\?\C:\FakeErp\").is_some());

        for refused in [
            r"\\?\UNC\server\share\FakeErp",
            r"\\?\Volume{0c1f5a7e-0000-0000-0000-100000000000}\FakeErp",
            r"\\?\GLOBALROOT\Device\NamedPipe\x",
            r"C:\FakeErp",
            r"\\.\C:\FakeErp",
            r"\\?\C:\FakeErp\erp.lock:stream",
            r"\\?\C:\FakeErp\\run",
            r"\\?\CC:\FakeErp",
            r"\\?\1:\FakeErp",
            r"\\?\C:FakeErp",
            "",
        ] {
            assert_eq!(read(refused), None, "{refused}");
        }
    }

    /// Names compare as NTFS compares them: case folded, look-alikes kept apart.
    #[test]
    fn names_compare_as_the_file_system_compares_them() {
        let same = |a: &str, b: &str| same_name(&units(a), &units(b));
        assert!(same("FakeErp", "fakeerp"));
        assert!(same("Relat\u{f3}rios", "RELAT\u{d3}RIOS"));
        assert!(!same("FakeErp", "FakeErp2"));
        assert!(!same("kit", "\u{212a}it"));
        assert!(!same("file", "f\u{131}le"));
        assert!(!same("stra\u{df}e", "strasse"));

        let root = Segments::of_written(r"C:\FakeErp").unwrap();
        assert!(
            Segments::of_written(r"c:\FAKEERP\run")
                .unwrap()
                .inside(&root)
        );
        assert!(Segments::of_written(r"C:\FakeErp").unwrap().inside(&root));
        assert!(
            !Segments::of_written(r"C:\FakeErpX\run")
                .unwrap()
                .inside(&root)
        );
        assert!(!Segments::of_written(r"C:\").unwrap().inside(&root));
        assert!(!Segments::of_written(r"D:\FakeErp").unwrap().inside(&root));
    }

    // ----- Paths a manifest names -------------------------------------------------------

    /// A root on the disk, its segments, and a file inside it.
    struct Ground {
        root: TempDir,
        roots: Vec<Segments>,
    }

    impl Ground {
        fn new() -> Self {
            let root = TempDir::new();
            let roots = vec![segments(root.path())];
            Self { root, roots }
        }

        fn path(&self, name: &str) -> PathBuf {
            self.root.path().join(name)
        }
    }

    #[test]
    fn a_path_check_finds_files_and_folders_and_tells_absent_from_failed() {
        let ground = Ground::new();
        fs::write(ground.path("erp.lock"), b"").unwrap();
        fs::create_dir(ground.path("run")).unwrap();
        let probe = |name: &str| probe(&text(&ground.path(name)), &ground.roots);

        assert_eq!(probe("erp.lock"), Ok(Some(Found::File)));
        assert_eq!(probe("run"), Ok(Some(Found::Directory)));
        assert_eq!(probe("missing.lock"), Ok(None));
        assert_eq!(probe(r"missing\erp.lock"), Ok(None));
        // An invalid name is a failed check, never "absent".
        assert_eq!(probe("a<b"), Err(PathError::Failed));
        // A hard link is still the file a check asks about.
        fs::hard_link(ground.path("erp.lock"), ground.path("other")).unwrap();
        assert_eq!(probe("erp.lock"), Ok(Some(Found::File)));
    }

    /// A junction in the middle of the path, pointing out of the roots: the final path is
    /// elsewhere, and the check and the delete are refused.
    #[test]
    fn a_junction_in_the_middle_of_the_path_is_followed_and_refused() {
        let ground = Ground::new();
        let outside = TempDir::new();
        fs::write(outside.path().join("erp.db"), b"data").unwrap();
        junction(&ground.path("run"), outside.path());
        let path = text(&ground.path(r"run\erp.db"));

        assert_eq!(probe(&path, &ground.roots), Err(PathError::Refused));
        assert_eq!(delete(&path, &ground.roots), Err(PathError::Refused));
        assert_eq!(fs::read(outside.path().join("erp.db")).unwrap(), b"data");

        // Inside the roots, the same junction is fine: what counts is where it ends.
        let both = vec![ground.roots[0].clone(), segments(outside.path())];
        assert_eq!(probe(&path, &both), Ok(Some(Found::File)));
    }

    /// A junction or a link at the end of the path is opened as itself and refused.
    #[test]
    fn a_reparse_point_at_the_end_is_refused() {
        let ground = Ground::new();
        let inside = ground.path("data");
        fs::create_dir(&inside).unwrap();
        fs::write(inside.join("erp.db"), b"data").unwrap();
        junction(&ground.path("run"), &inside);
        let link = text(&ground.path("run"));
        assert_eq!(probe(&link, &ground.roots), Err(PathError::Refused));
        assert_eq!(delete(&link, &ground.roots), Err(PathError::Refused));
        assert!(inside.join("erp.db").exists());

        if symlink_file(&ground.path("erp.lock"), &inside.join("erp.db")) {
            let link = text(&ground.path("erp.lock"));
            assert_eq!(probe(&link, &ground.roots), Err(PathError::Refused));
            assert_eq!(delete(&link, &ground.roots), Err(PathError::Refused));
            assert!(inside.join("erp.db").exists());
        }
    }

    /// A root that is itself a junction resolves where it points, and only that counts.
    #[test]
    fn a_junction_as_the_root_counts_where_it_points() {
        let real = TempDir::new();
        let parent = TempDir::new();
        let root = parent.path().join("root");
        junction(&root, real.path());
        fs::write(real.path().join("erp.lock"), b"").unwrap();
        let roots = vec![segments(&root)];
        assert_eq!(roots[0], segments(real.path()));
        assert_eq!(
            probe(&text(&root.join("erp.lock")), &roots),
            Ok(Some(Found::File))
        );
    }

    #[test]
    fn a_delete_takes_one_regular_file_through_its_handle() {
        let ground = Ground::new();
        fs::write(ground.path("erp.lock"), b"").unwrap();
        let lock = text(&ground.path("erp.lock"));
        delete(&lock, &ground.roots).unwrap();
        assert!(!ground.path("erp.lock").exists());
        // Gone already: the precondition said otherwise, so this is a failure.
        assert_eq!(delete(&lock, &ground.roots), Err(PathError::Failed));

        // A folder is never deleted, nor a file with a second name somewhere else.
        fs::create_dir(ground.path("run")).unwrap();
        assert_eq!(
            delete(&text(&ground.path("run")), &ground.roots),
            Err(PathError::Refused)
        );
        fs::write(ground.path("erp.db"), b"data").unwrap();
        fs::hard_link(ground.path("erp.db"), ground.path("second")).unwrap();
        assert_eq!(
            delete(&text(&ground.path("erp.db")), &ground.roots),
            Err(PathError::Refused)
        );
        assert!(ground.path("erp.db").exists());

        // Outside every root.
        fs::write(ground.path("erp.log"), b"").unwrap();
        let elsewhere = vec![Segments::of_written(r"C:\FakeErpThatIsNotHere").unwrap()];
        assert_eq!(
            delete(&text(&ground.path("erp.log")), &elsewhere),
            Err(PathError::Refused)
        );
        assert!(ground.path("erp.log").exists());
    }

    /// A file someone else holds open without sharing delete stays, and that is a failure.
    #[test]
    fn a_file_in_use_is_not_deleted() {
        let ground = Ground::new();
        let path = ground.path("erp.lock");
        fs::write(&path, b"").unwrap();
        let held = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(&path)
            .unwrap();
        assert_eq!(delete(&text(&path), &ground.roots), Err(PathError::Failed));
        drop(held);
        delete(&text(&path), &ground.roots).unwrap();
    }

    /// An alternate data stream is never a path the agent acts on.
    #[test]
    fn a_stream_is_refused() {
        let ground = Ground::new();
        let path = ground.path("erp.lock");
        fs::write(&path, b"").unwrap();
        fs::write(format!("{}:hidden", text(&path)), b"x").unwrap();
        let stream = format!("{}:hidden", text(&path));
        assert!(matches!(
            delete(&stream, &ground.roots),
            Err(PathError::Refused | PathError::Failed)
        ));
        assert!(path.exists());
    }
}
