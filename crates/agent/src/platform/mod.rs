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

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::Arc;

use ponte_actions::Roots;

use crate::actions::machine::{Machine, Unsupported};

/// What runs the steps and checks of actions here. Step 5 of M2 gives Windows its own,
/// which checks the final path of every file it opens against `roots` as they resolved
/// when the agent started (ADR-0011). Until then every platform refuses everything.
pub(crate) fn machine(_roots: &Roots) -> Arc<dyn Machine> {
    Arc::new(Unsupported)
}

/// Creates `dir` and whatever is missing above it. Where files have modes, only the
/// owner gets in.
pub(crate) fn create_private_dir(dir: &Path) -> io::Result<()> {
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
/// have modes, only the owner can read the result.
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
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
/// path that points somewhere else must not be pulled into memory.
pub(crate) fn read_bounded(path: &Path, max: usize) -> io::Result<Option<Vec<u8>>> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::TempDir;

    #[test]
    fn a_write_replaces_the_file_and_leaves_nothing_else_behind() {
        let dir = TempDir::new();
        let path = dir.path().join("nested").join("identity.toml");

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
