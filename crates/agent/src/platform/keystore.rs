//! Where the device's private key rests (RF-02).
//!
//! **Development only until M2.** The key is a plain file: where files have modes only its
//! owner can read it, and on Windows it has whatever protection its directory has. From M2
//! the Windows build keeps it under DPAPI (RNF-04) and this module is where that goes, so
//! nothing else in the agent learns how a key is stored.

use std::io;
use std::path::Path;

/// Whether the key is encrypted at rest. The agent says so in its log when it starts.
pub(crate) const PROTECTED: bool = false;

/// The 32 secret bytes of an ed25519 key.
pub(crate) type Secret = [u8; 32];

pub(crate) fn save(path: &Path, secret: &Secret) -> io::Result<()> {
    super::write_private(path, secret)
}

/// `None` if no key was ever stored, and `InvalidData` if the file is not a key.
pub(crate) fn load(path: &Path) -> io::Result<Option<Secret>> {
    let Some(mut bytes) = super::read_bounded(path, size_of::<Secret>())? else {
        return Ok(None);
    };
    let secret = Secret::try_from(bytes.as_slice());
    bytes.fill(0);
    secret
        .map(Some)
        .map_err(|_| io::ErrorKind::InvalidData.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::TempDir;

    #[test]
    fn a_key_comes_back_as_it_was_stored() {
        let dir = TempDir::new();
        let path = dir.path().join("device.key");
        let secret: Secret = std::array::from_fn(|i| u8::try_from(i).unwrap());

        assert_eq!(load(&path).unwrap(), None);
        save(&path, &secret).unwrap();
        assert_eq!(load(&path).unwrap(), Some(secret));
        assert_eq!(std::fs::read(&path).unwrap(), secret);
    }

    /// A file of the wrong size is not a shorter or a longer key.
    #[test]
    fn a_file_of_another_size_is_not_a_key() {
        let dir = TempDir::new();
        let path = dir.path().join("device.key");
        for len in [0, 1, 31, 33, 64, 10_000] {
            std::fs::write(&path, vec![7; len]).unwrap();
            assert_eq!(
                load(&path).unwrap_err().kind(),
                io::ErrorKind::InvalidData,
                "{len}"
            );
        }
    }
}
