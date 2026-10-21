//! The service's log: two files of at most 5 MB in `<data_dir>\logs` (ADR-0013).
//!
//! `agent.log` is written until the next line would take it past the limit; it then
//! becomes `agent.1.log`, replacing the one before, and a new `agent.log` starts. Each file
//! is opened as the agent's own files are (no reparse point, one link, a disk file). A
//! line that cannot be written is dropped: logging never stops the agent.

use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use tracing_subscriber::fmt::MakeWriter;

use super::files;

/// The most each of the two files holds.
pub(crate) const MAX_FILE_BYTES: u64 = 5 * 1024 * 1024;

/// The two files of the log, in their folder.
pub(crate) struct FileLog {
    current: PathBuf,
    previous: PathBuf,
    limit: u64,
    open: Mutex<Option<(File, u64)>>,
}

impl FileLog {
    /// The log in `folder`, which must exist.
    pub(crate) fn in_folder(folder: &Path) -> io::Result<Self> {
        Self::with_limit(folder, MAX_FILE_BYTES)
    }

    fn with_limit(folder: &Path, limit: u64) -> io::Result<Self> {
        let log = Self {
            current: folder.join("agent.log"),
            previous: folder.join("agent.1.log"),
            limit,
            open: Mutex::new(None),
        };
        // Opened once now, so a log that cannot be opened is known before anything runs.
        let file = files::open_append(&log.current)?;
        let size = file.metadata()?.len();
        *log.open.lock().unwrap_or_else(PoisonError::into_inner) = Some((file, size));
        Ok(log)
    }

    /// Writes one whole line, turning the files over first if it would not fit.
    fn write_line(&self, line: &[u8]) {
        let mut open = self.open.lock().unwrap_or_else(PoisonError::into_inner);
        let length = u64::try_from(line.len()).unwrap_or(u64::MAX);
        if open
            .as_ref()
            .is_some_and(|(_, size)| size.saturating_add(length) > self.limit)
        {
            // Closed before it is renamed.
            *open = None;
            let _ = files::replace(&self.current, &self.previous);
        }
        if open.is_none() {
            *open = files::open_append(&self.current)
                .ok()
                .and_then(|file| Some((file.metadata().ok()?.len(), file)))
                .map(|(size, file)| (file, size));
        }
        if let Some((file, size)) = open.as_mut() {
            if file.write_all(line).is_ok() {
                *size = size.saturating_add(length);
            } else {
                *open = None;
            }
        }
    }
}

/// One event's worth of output: `tracing` writes an event in one call.
pub(crate) struct Line<'a>(&'a FileLog);

impl Write for Line<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write_line(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for FileLog {
    type Writer = Line<'a>;

    fn make_writer(&'a self) -> Self::Writer {
        Line(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::TempDir;

    #[test]
    fn the_log_turns_over_at_its_limit_and_keeps_two_files() {
        let dir = TempDir::new();
        let log = FileLog::with_limit(dir.path(), 10).unwrap();
        let write = |line: &[u8]| log.make_writer().write_all(line).unwrap();
        write(b"one\n");
        write(b"two\n");
        assert_eq!(
            std::fs::read(dir.path().join("agent.log")).unwrap(),
            b"one\ntwo\n"
        );
        write(b"three\n");
        assert_eq!(
            std::fs::read(dir.path().join("agent.log")).unwrap(),
            b"three\n"
        );
        assert_eq!(
            std::fs::read(dir.path().join("agent.1.log")).unwrap(),
            b"one\ntwo\n"
        );
        // 6 + 5 bytes would pass 10: the older file goes, the newer one takes its place.
        write(b"four\n");
        write(b"five\n");
        assert_eq!(
            std::fs::read(dir.path().join("agent.log")).unwrap(),
            b"four\nfive\n"
        );
        assert_eq!(
            std::fs::read(dir.path().join("agent.1.log")).unwrap(),
            b"three\n"
        );
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 2);
        assert_eq!(MAX_FILE_BYTES, 5 * 1024 * 1024);
    }

    /// A log that grew before the agent started counts from where it stands.
    #[test]
    fn the_log_continues_where_it_stopped() {
        let dir = TempDir::new();
        std::fs::write(dir.path().join("agent.log"), b"12345678").unwrap();
        let log = FileLog::with_limit(dir.path(), 10).unwrap();
        log.make_writer().write_all(b"abc\n").unwrap();
        assert_eq!(
            std::fs::read(dir.path().join("agent.log")).unwrap(),
            b"abc\n"
        );
        assert_eq!(
            std::fs::read(dir.path().join("agent.1.log")).unwrap(),
            b"12345678"
        );
    }

    /// A hard link planted as the log is not written through.
    #[test]
    fn a_log_with_another_name_is_refused() {
        let dir = TempDir::new();
        let elsewhere = TempDir::new();
        let target = elsewhere.path().join("theirs.txt");
        std::fs::write(&target, b"theirs").unwrap();
        std::fs::hard_link(&target, dir.path().join("agent.log")).unwrap();
        assert!(FileLog::in_folder(dir.path()).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"theirs");
    }
}
