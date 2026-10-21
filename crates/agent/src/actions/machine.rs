//! What the executor asks of the operating system: read a service, evaluate a check, run
//! a step. A trait, so that the executor is the same on every platform and its tests run
//! anywhere.
//!
//! Every answer is a code. Nothing an implementation returns carries text from the
//! machine, so nothing Windows says can reach a log, the server or a model (invariant 4,
//! ADR-0012). Every call that waits gets the time the manifest has left and must return
//! within it: the executor waits for each call to return before it does anything else.

use std::time::Duration;

use ponte_actions::{Check, Primitive};

/// Why a service may not be touched, read from the service manager when the action runs
/// (ADR-0011): its type, its protection or where its binary lies, or that it could not be
/// read at all. A service that does not exist is refused by `Structure`; `Unreadable` and
/// `TimedOut` describe the machine at that moment and are not recorded (ADR-0013).
#[cfg_attr(
    not(any(test, windows)),
    expect(dead_code, reason = "only the machine of Windows gives these")
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServiceRefusal {
    Structure,
    Unreadable,
    /// The time the manifest had left ran out.
    TimedOut,
}

/// A check that could not be evaluated. A check that does not hold is `Ok(false)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CheckError {
    Failed,
    TimedOut,
}

/// A step that did not do what it says.
#[cfg_attr(
    not(any(test, windows)),
    expect(dead_code, reason = "only the machine of Windows gives these")
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StepError {
    /// The operating system refused or failed.
    Failed,
    /// A file failed the checks of ADR-0011: a reparse point, more than one link, not a
    /// disk file, or a final path outside the roots.
    PathRefused,
    /// The time the manifest had left ran out.
    TimedOut,
}

/// The operations of a platform. Calls block; the executor makes them from a blocking
/// task, one at a time.
pub(crate) trait Machine: Send + Sync + 'static {
    /// Whether the service `name` may be touched, by its structure (ADR-0011), within
    /// `remaining`. Asked of every service a manifest names, in steps and checks, before any
    /// precondition.
    fn service_allowed(&self, name: &str, remaining: Duration) -> Result<(), ServiceRefusal>;
    /// Whether `check` holds, within `remaining`.
    fn check(&self, check: &Check, remaining: Duration) -> Result<bool, CheckError>;
    /// Runs `step`, within `remaining`.
    fn step(&self, step: &Primitive, remaining: Duration) -> Result<(), StepError>;
}

/// A platform that runs nothing: every service is refused, every check and every step
/// fails. Outside Windows, which builds are for development. With the coverage rules of
/// `ponte_actions`, no manifest gets to "started" on it: a step that names a service has
/// that service refused first, and `delete_file` needs a `path_exists` precondition.
pub(crate) struct Unsupported;

impl Machine for Unsupported {
    /// Refused as by structure, so the refusal is recorded: a server cannot make the agent
    /// decide the same request again and again on a platform that runs nothing.
    fn service_allowed(&self, _: &str, _: Duration) -> Result<(), ServiceRefusal> {
        Err(ServiceRefusal::Structure)
    }

    fn check(&self, _: &Check, _: Duration) -> Result<bool, CheckError> {
        Err(CheckError::Failed)
    }

    fn step(&self, _: &Primitive, _: Duration) -> Result<(), StepError> {
        Err(StepError::Failed)
    }
}
