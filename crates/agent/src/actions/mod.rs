//! Running signed actions (ADR-0010 to ADR-0013), outside the session that receives them.
//!
//! | Module | What it does |
//! |---|---|
//! | `clock` | The clock and its high-water mark |
//!
//! The files live in the data directory, which only administrators may change.

pub(crate) mod clock;

use std::io;
use std::path::{Path, PathBuf};

use crate::platform;

/// The mark is one short line.
const MAX_MARK_BYTES: usize = 256;

/// The files of this module in the agent's data directory.
pub(crate) struct ActionFiles {
    mark: PathBuf,
}

impl ActionFiles {
    pub(crate) fn new(data_dir: &Path) -> Self {
        Self {
            mark: data_dir.join("clock.toml"),
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

#[cfg(test)]
mod tests {
    use super::clock::MarkDisk;
    use super::*;
    use crate::testkit::TempDir;

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
