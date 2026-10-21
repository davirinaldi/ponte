//! Where the device's private key rests (RF-02, RNF-04).
//!
//! On Windows the file holds a DPAPI blob for the account that runs the agent (ADR-0013).
//! The plain key file of M1 is refused, not migrated: migrating would leave the plain key
//! recoverable on the disk. A blob this account cannot open, typically one an
//! administrator's elevated console made before the service was installed, is an error the
//! identity does not paper over: it never enrolls again over a key it could not read.
//!
//! Elsewhere the key is a plain file only its owner can read: those builds are for
//! development. Nothing else in the agent learns how a key is stored.

use std::io;
use std::path::Path;

use zeroize::Zeroizing;

/// Whether the key is encrypted at rest. The agent says so in its log when it is not.
pub(crate) const PROTECTED: bool = cfg!(windows);

/// The 32 secret bytes of an ed25519 key, wiped when dropped.
pub(crate) type Secret = Zeroizing<[u8; 32]>;

/// The key under DPAPI could not be opened by this account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "the device key cannot be opened by the account the agent runs as: it was most likely \
     made by another account (an elevated console before the service was installed). \
     Remove device.key and identity.toml from the data directory and enroll again with a \
     new token (ADR-0013)"
)]
pub(crate) struct NotThisAccount;

pub(crate) fn save(path: &Path, secret: &[u8; 32]) -> io::Result<()> {
    #[cfg(windows)]
    return super::write_private(path, &super::windows::dpapi::protect(secret)?);
    #[cfg(not(windows))]
    super::write_private(path, secret)
}

/// The most a stored key may take: a DPAPI blob of 32 bytes is a few hundred.
const MAX_STORED_BYTES: usize = 4 * 1024;

/// `None` if no key was ever stored, and `InvalidData` if the file is not a key.
pub(crate) fn load(path: &Path) -> io::Result<Option<Secret>> {
    let Some(bytes) = super::read_bounded(path, MAX_STORED_BYTES)? else {
        return Ok(None);
    };
    let bytes = Zeroizing::new(bytes);
    #[cfg(windows)]
    {
        if bytes.len() == 32 {
            // Treated as no key: the identity enrolls again if a new token is waiting, and
            // the new key, under DPAPI, replaces this file.
            tracing::error!(
                "the device key is a plain file from an earlier version of the agent: it is \
                 refused, not migrated. Enroll again with a new token (ADR-0013)"
            );
            return Err(io::ErrorKind::InvalidData.into());
        }
        super::windows::dpapi::unprotect(&bytes)
            .map(Some)
            .map_err(|_| io::Error::other(NotThisAccount))
    }
    #[cfg(not(windows))]
    {
        let mut secret = Secret::default();
        if bytes.len() != secret.len() {
            return Err(io::ErrorKind::InvalidData.into());
        }
        secret.copy_from_slice(&bytes);
        Ok(Some(secret))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::TempDir;

    #[test]
    fn a_key_comes_back_as_it_was_stored() {
        let dir = TempDir::new();
        let path = dir.path().join("device.key");
        let secret: [u8; 32] = std::array::from_fn(|i| u8::try_from(i).unwrap());

        assert_eq!(load(&path).unwrap(), None);
        save(&path, &secret).unwrap();
        assert_eq!(load(&path).unwrap().as_deref(), Some(&secret));
        let stored = std::fs::read(&path).unwrap();
        if PROTECTED {
            assert!(!stored.windows(32).any(|window| window == secret));
        } else {
            assert_eq!(stored, secret);
        }
    }

    /// A file of the wrong size is not a shorter or a longer key.
    #[test]
    fn a_file_of_another_size_is_not_a_key() {
        let dir = TempDir::new();
        let path = dir.path().join("device.key");
        for len in [0, 1, 31, 33, 64] {
            std::fs::write(&path, vec![7; len]).unwrap();
            assert!(load(&path).is_err(), "{len}");
        }
        std::fs::write(&path, vec![7; 10_000]).unwrap();
        assert_eq!(load(&path).unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    /// The plain key of M1 is refused as "no key", so a new enrollment replaces it. A blob
    /// this account cannot open is another matter: an error, never "no key", so nothing
    /// enrolls over a key that may still be good.
    #[cfg(windows)]
    #[test]
    fn a_plain_key_is_no_key_and_a_foreign_blob_is_an_error() {
        let dir = TempDir::new();
        let path = dir.path().join("device.key");
        std::fs::write(&path, [7; 32]).unwrap();
        assert_eq!(load(&path).unwrap_err().kind(), io::ErrorKind::InvalidData);

        save(&path, &[7; 32]).unwrap();
        let mut blob = std::fs::read(&path).unwrap();
        for byte in &mut blob[24..40] {
            *byte ^= 0x5a;
        }
        std::fs::write(&path, &blob).unwrap();
        let refused = load(&path).unwrap_err();
        assert_ne!(refused.kind(), io::ErrorKind::InvalidData);
        assert!(
            refused
                .get_ref()
                .is_some_and(|inner| inner.is::<NotThisAccount>())
        );
    }
}
