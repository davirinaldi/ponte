//! Running signed actions (ADR-0010 to ADR-0013), outside the session that receives them.
//!
//! | Module | What it does |
//! |---|---|
//! | `clock` | The clock and its high-water mark |
//! | `journal` | What already ran, or was answered, by `RequestId` |
//! | `machine` | What the executor asks of the operating system |
//! | `runner` | The executor: the queue, the order of the checks, one action at a time |
//!
//! The files live in the data directory, which only administrators may change.

pub(crate) mod clock;
pub(crate) mod journal;
pub(crate) mod machine;
pub(crate) mod runner;

use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use journal::{JournalFile, MAX_ENDED_BYTES, MAX_STARTED_BYTES};

use crate::platform;

/// The mark is one short line.
const MAX_MARK_BYTES: usize = 256;

/// The files of this module in the agent's data directory.
pub(crate) struct ActionFiles {
    mark: PathBuf,
    started: PathBuf,
    ended: PathBuf,
    lock: PathBuf,
    /// Held, and locked, for as long as the agent runs once [`journal::JournalDisk::lock`]
    /// took it.
    held: Mutex<Option<File>>,
}

impl ActionFiles {
    pub(crate) fn new(data_dir: &Path) -> Self {
        Self {
            mark: data_dir.join("clock.toml"),
            started: data_dir.join("journal.json"),
            ended: data_dir.join("ended.json"),
            lock: data_dir.join("journal.lock"),
            held: Mutex::new(None),
        }
    }
}

/// What a bounded read found, as text. Bytes that are not UTF-8 are not the file it
/// should be.
fn text(bytes: Option<Vec<u8>>) -> io::Result<Option<String>> {
    bytes
        .map(|bytes| String::from_utf8(bytes).map_err(|_| io::ErrorKind::InvalidData.into()))
        .transpose()
}

impl clock::MarkDisk for ActionFiles {
    fn read_mark(&self) -> io::Result<Option<String>> {
        text(platform::read_bounded(&self.mark, MAX_MARK_BYTES)?)
    }

    fn write_mark(&self, text: &str) -> io::Result<()> {
        platform::write_private(&self.mark, text.as_bytes())
    }
}

impl journal::JournalDisk for ActionFiles {
    fn read(&self, file: JournalFile) -> io::Result<Option<String>> {
        match file {
            JournalFile::Started => text(platform::read_bounded(&self.started, MAX_STARTED_BYTES)?),
            JournalFile::Ended => text(platform::read_bounded(&self.ended, MAX_ENDED_BYTES)?),
        }
    }

    fn write(&self, file: JournalFile, text: &str) -> io::Result<()> {
        let path = match file {
            JournalFile::Started => &self.started,
            JournalFile::Ended => &self.ended,
        };
        platform::write_private(path, text.as_bytes())
    }

    fn lock(&self) -> io::Result<()> {
        let mut held = self.held.lock().map_err(|_| io::Error::other("poisoned"))?;
        if held.is_some() {
            return Ok(());
        }
        // Often the first file of a new data directory, which is then made as the identity
        // makes it: private where files have modes (step 5 gives Windows its ACL).
        if let Some(dir) = self.lock.parent().filter(|dir| !dir.as_os_str().is_empty()) {
            platform::create_private_dir(dir)?;
        }
        // Nothing is ever written to it: the lock is the point.
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&self.lock)?;
        file.try_lock().map_err(|error| match error {
            std::fs::TryLockError::WouldBlock => io::ErrorKind::WouldBlock.into(),
            std::fs::TryLockError::Error(error) => error,
        })?;
        *held = Some(file);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::clock::MarkDisk;
    use super::*;
    use crate::testkit::TempDir;

    #[test]
    fn the_journal_rests_in_the_data_directory() {
        use super::journal::JournalDisk;

        let dir = TempDir::new();
        let files = ActionFiles::new(&dir.path().join("made-here"));
        files.lock().unwrap();
        // Taking it again in the same process is a no-op.
        files.lock().unwrap();
        assert_eq!(files.read(JournalFile::Started).unwrap(), None);
        assert_eq!(files.read(JournalFile::Ended).unwrap(), None);
        files.write(JournalFile::Started, "started").unwrap();
        files.write(JournalFile::Ended, "ended").unwrap();
        assert_eq!(
            files.read(JournalFile::Started).unwrap().as_deref(),
            Some("started")
        );
        assert_eq!(
            files.read(JournalFile::Ended).unwrap().as_deref(),
            Some("ended")
        );

        let ended = dir.path().join("made-here").join("ended.json");
        std::fs::write(&ended, vec![b'x'; MAX_ENDED_BYTES + 1]).unwrap();
        assert_eq!(
            files.read(JournalFile::Ended).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    /// The lock is often the first file of a new data directory, which it then makes
    /// private, as the identity would.
    #[cfg(unix)]
    #[test]
    fn the_data_directory_the_lock_makes_is_private() {
        use std::os::unix::fs::PermissionsExt;

        use super::journal::JournalDisk;

        let dir = TempDir::new();
        let data = dir.path().join("made-here");
        ActionFiles::new(&data).lock().unwrap();
        let mode = std::fs::metadata(&data).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    /// Two agents on one data directory, a service and a console: the second gets no
    /// journal, and so runs nothing.
    #[test]
    fn one_process_at_a_time_holds_the_journal() {
        use super::journal::JournalDisk;

        let dir = TempDir::new();
        let first = ActionFiles::new(dir.path());
        first.lock().unwrap();
        let second = ActionFiles::new(dir.path());
        assert_eq!(second.lock().unwrap_err().kind(), io::ErrorKind::WouldBlock);
        drop(first);
        second.lock().unwrap();
    }

    #[test]
    fn the_mark_rests_in_the_data_directory() {
        let dir = TempDir::new();
        let files = ActionFiles::new(dir.path());
        assert_eq!(files.read_mark().unwrap(), None);
        files.write_mark("high_water = 1\n").unwrap();
        assert_eq!(
            files.read_mark().unwrap().as_deref(),
            Some("high_water = 1\n")
        );
        assert!(dir.path().join("clock.toml").is_file());

        std::fs::write(dir.path().join("clock.toml"), vec![b'1'; 257]).unwrap();
        assert_eq!(
            files.read_mark().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        std::fs::write(dir.path().join("clock.toml"), [0xff, 0xfe]).unwrap();
        assert_eq!(
            files.read_mark().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
