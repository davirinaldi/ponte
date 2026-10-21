//! Whether the agent's token is elevated (ADR-0013): the token decides, not how the agent
//! was started. SYSTEM counts as elevated.

use std::ffi::c_void;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::Security::{
    GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation, TokenUser,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::platform::Elevation;

/// The token of this process, closed when dropped.
struct Token(HANDLE);

impl Token {
    fn of_this_process() -> Option<Self> {
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: the pseudo handle of this process needs no closing; `token` receives a
        // handle that `Drop` closes.
        let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
        (opened != 0).then_some(Self(token))
    }

    /// Reads `class` into `buffer`, which must be at least as large as the answer. Some
    /// classes want the exact size of their structure, which `size` then is.
    fn read(&self, class: i32, buffer: &mut [u64], size: usize) -> bool {
        let size = u32::try_from(size.min(size_of_val(buffer))).unwrap_or(u32::MAX);
        let mut returned = 0_u32;
        // SAFETY: `self.0` is a token open for query; `buffer` is writable for at least
        // `size` bytes and aligned for any TOKEN_* structure.
        unsafe {
            GetTokenInformation(
                self.0,
                class,
                buffer.as_mut_ptr().cast::<c_void>(),
                size,
                &mut returned,
            ) != 0
        }
    }
}

impl Drop for Token {
    fn drop(&mut self) {
        // SAFETY: the handle came from OpenProcessToken and is closed once.
        unsafe { CloseHandle(self.0) };
    }
}

/// Reads the token. `Unknown` when it cannot be read, which the agent treats as elevated.
pub(crate) fn probe() -> Elevation {
    let Some(token) = Token::of_this_process() else {
        return Elevation::Unknown;
    };
    let mut buffer = [0_u64; 64];
    if !token.read(TokenElevation, &mut buffer, size_of::<TOKEN_ELEVATION>()) {
        return Elevation::Unknown;
    }
    // SAFETY: the call wrote a TOKEN_ELEVATION at the start of the aligned buffer.
    let elevation = unsafe { buffer.as_ptr().cast::<TOKEN_ELEVATION>().read() };
    if elevation.TokenIsElevated != 0 {
        return Elevation::Elevated;
    }
    // SYSTEM's token always reads as elevated; checked anyway, since the rules are for it.
    let mut user = [0_u64; 64];
    if !token.read(TokenUser, &mut user, usize::MAX) {
        return Elevation::Unknown;
    }
    // SAFETY: the call wrote a TOKEN_USER at the start of the aligned buffer, whose SID
    // points into the same buffer, alive while it is read.
    let sid = unsafe {
        user.as_ptr()
            .cast::<windows_sys::Win32::Security::TOKEN_USER>()
            .read()
            .User
            .Sid
    };
    if super::acl::is_system(sid) {
        Elevation::Elevated
    } else {
        Elevation::NotElevated
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The token of a test process can be read. Whether it is elevated depends on who runs
    /// the tests: the Windows job of CI runs elevated.
    #[test]
    fn the_token_is_read() {
        assert_ne!(probe(), Elevation::Unknown);
    }
}
