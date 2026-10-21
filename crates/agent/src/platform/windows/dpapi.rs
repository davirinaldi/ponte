//! The device key under DPAPI (RNF-04, ADR-0013).
//!
//! In the scope of the account that runs the agent (SYSTEM in production), never the
//! machine's, with no prompt, and a fixed string as entropy so the blob is not
//! interchangeable with other DPAPI data of that account. DPAPI keeps the key from a copy
//! or a backup of the data directory and from users who are not administrators; it does not
//! keep it from an administrator, from code running as SYSTEM, or from whoever holds an
//! unencrypted disk.

use std::ffi::c_void;
use std::io;

use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};
use zeroize::{Zeroize, Zeroizing};

/// Binds the blob to this use: data this account protected for anything else does not open
/// as a device key, and a device key does not open as anything else.
const ENTROPY: &[u8] = b"ponte.device-key.v1";

fn blob(bytes: &[u8]) -> CRYPT_INTEGER_BLOB {
    CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(bytes.len()).unwrap_or(u32::MAX),
        pbData: bytes.as_ptr().cast_mut(),
    }
}

/// A buffer DPAPI allocated, wiped and freed when dropped.
struct Output(CRYPT_INTEGER_BLOB);

impl Output {
    fn bytes(&self) -> &[u8] {
        if self.0.pbData.is_null() {
            return &[];
        }
        let length = usize::try_from(self.0.cbData).unwrap_or(0);
        // SAFETY: DPAPI wrote `cbData` bytes at `pbData`, which live until `Drop`.
        unsafe { std::slice::from_raw_parts(self.0.pbData, length) }
    }
}

impl Drop for Output {
    fn drop(&mut self) {
        if self.0.pbData.is_null() {
            return;
        }
        let length = usize::try_from(self.0.cbData).unwrap_or(0);
        // SAFETY: as in `bytes`; the buffer is wiped, then freed once with LocalFree, as
        // DPAPI asks.
        unsafe {
            std::slice::from_raw_parts_mut(self.0.pbData, length).zeroize();
            LocalFree(self.0.pbData.cast::<c_void>());
        }
    }
}

/// Protects `secret` for the account that runs the agent.
pub(crate) fn protect(secret: &[u8]) -> io::Result<Vec<u8>> {
    let (input, entropy) = (blob(secret), blob(ENTROPY));
    let mut output = Output(CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    });
    // SAFETY: the input and the entropy point to slices that live through the call; no
    // description, no reserved data, no prompt; `output` receives a LocalAlloc buffer that
    // its `Drop` frees.
    let protected = unsafe {
        CryptProtectData(
            &input,
            std::ptr::null(),
            &entropy,
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output.0,
        )
    };
    if protected == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(output.bytes().to_vec())
}

/// Opens a blob [`protect`] made for this account. The plaintext only ever lives in the
/// buffer DPAPI made, wiped before it is freed, and in what this returns, wiped when dropped.
pub(crate) fn unprotect(blob_bytes: &[u8]) -> io::Result<Zeroizing<[u8; 32]>> {
    let (input, entropy) = (blob(blob_bytes), blob(ENTROPY));
    let mut output = Output(CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    });
    // SAFETY: as in `protect`; the description is not asked for.
    let opened = unsafe {
        CryptUnprotectData(
            &input,
            std::ptr::null_mut(),
            &entropy,
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output.0,
        )
    };
    if opened == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut secret = Zeroizing::new([0_u8; 32]);
    let bytes = output.bytes();
    if bytes.len() != secret.len() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    secret.copy_from_slice(bytes);
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_comes_back_and_the_blob_does_not_show_it() {
        let secret: [u8; 32] = std::array::from_fn(|i| u8::try_from(i).unwrap() + 1);
        let blob = protect(&secret).unwrap();
        assert!(blob.len() > 32);
        assert!(!blob.windows(32).any(|window| window == secret));
        assert_eq!(*unprotect(&blob).unwrap(), secret);
        // Each blob is different: DPAPI salts every one.
        assert_ne!(protect(&secret).unwrap(), blob);
    }

    /// A blob of this account made with other entropy, as any other program of the account
    /// would make, is not a device key.
    #[test]
    fn other_entropy_does_not_open() {
        let (input, entropy) = (blob(&[7; 32]), blob(b"another program"));
        let mut output = Output(CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        });
        // SAFETY: as in `protect`.
        let made = unsafe {
            CryptProtectData(
                &input,
                std::ptr::null(),
                &entropy,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output.0,
            )
        };
        assert_ne!(made, 0);
        assert!(unprotect(output.bytes()).is_err());
    }

    /// What a blob of another account looks like to this one: a master key it does not
    /// have. The blob's header is a version (4 bytes), the provider (16), and then the
    /// version and the GUID of the master key that protects it.
    #[test]
    fn a_blob_of_another_account_does_not_open() {
        let mut blob = protect(&[7; 32]).unwrap();
        let master_key = 4 + 16 + 4..4 + 16 + 4 + 16;
        for byte in &mut blob[master_key] {
            *byte ^= 0x5a;
        }
        assert!(unprotect(&blob).is_err());
        assert!(unprotect(&[]).is_err());
        assert!(unprotect(&[0; 32]).is_err());
    }
}
