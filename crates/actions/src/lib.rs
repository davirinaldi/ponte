//! Typed actions: the closed catalog of things an agent is able to do on a machine.
//!
//! - A [`Primitive`] is a single operation compiled into the agent (restart a service,
//!   delete a file...). Adding one is a security decision and needs an ADR.
//! - A [`Manifest`] composes primitives into a named action with a declared
//!   [`RiskLevel`], preconditions and a post-action verification.
//! - [`PathPolicy`] restricts every file-touching step to allowed roots.
//!
//! There is deliberately no "run this script" primitive. See ADR-0002.

mod manifest;
mod path_policy;
mod primitive;
mod risk;

pub use manifest::{
    Check, CheckList, ExpectedServiceState, Location, MAX_CHECKS, MAX_DESCRIPTION_CHARS,
    MAX_ID_LEN, MAX_STEPS, MAX_TITLE_CHARS, Manifest, ManifestError, TextField, ValidManifest,
};
pub use path_policy::PathPolicy;
pub use primitive::Primitive;
pub use risk::RiskLevel;
