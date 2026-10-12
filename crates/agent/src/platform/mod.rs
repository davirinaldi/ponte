//! OS-specific code. This is the only module in the workspace where `unsafe` is allowed,
//! and every `unsafe` block must carry a `// SAFETY:` comment.

#[cfg(windows)]
#[allow(unsafe_code)]
mod windows;
#[cfg(windows)]
pub use windows::NAME;

#[cfg(not(windows))]
mod unsupported;
#[cfg(not(windows))]
pub use unsupported::NAME;
