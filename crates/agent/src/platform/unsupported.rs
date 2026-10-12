//! Non-Windows builds exist only so the workspace compiles and tests on Linux CI.
//! Platform operations here must fail loudly rather than pretend to succeed.

pub const NAME: &str = "unsupported (development build)";
