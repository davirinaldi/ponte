//! Typed actions: the closed catalog of things an agent is able to do on a machine.
//!
//! - A [`Primitive`] is a single operation compiled into the agent (restart a service,
//!   delete a file...). Adding one is a security decision and needs an ADR.
//! - A [`Manifest`] composes primitives into a named action with a declared
//!   [`RiskLevel`], preconditions and a post-action verification.
//! - [`PathPolicy`] restricts every file-touching step to allowed roots.
//!
//! A manifest only runs as a [`RunnableManifest`], and the only way to one is a typestate
//! (ADR-0011): [`Manifest::validate_shape`] gives a [`ValidManifest`] without knowing any
//! machine (the signer and the server stop there); [`verify`] gives a
//! [`VerifiedManifest`], checking the signature and the validity before the TOML is even
//! parsed (ADR-0010); [`VerifiedManifest::validate`] applies the machine's
//! [`LocalPolicy`].
//!
//! There is deliberately no "run this script" primitive. See ADR-0002.

mod manifest;
mod path_policy;
mod policy;
mod primitive;
mod risk;
mod signed;

pub use manifest::{
    Check, CheckList, ExpectedServiceState, Location, MAX_CHECKS, MAX_DESCRIPTION_CHARS,
    MAX_ID_LEN, MAX_STEPS, MAX_TITLE_CHARS, Manifest, ManifestError, TextField, ValidManifest,
};
pub use path_policy::{InvalidRoot, PathPolicy, RootRule, Roots};
pub use policy::{
    AllowedServices, AllowedServicesError, LocalPolicy, MAX_ALLOWED_SERVICES, PolicyError,
    REFUSED_SERVICES, RiskCeiling, RunnableManifest, is_refused_service,
};
pub use primitive::Primitive;
pub use risk::RiskLevel;
pub use signed::{
    MAX_CLOCK_BACK_SECS, MAX_CLOCK_SKEW_SECS, MAX_TRUSTED_KEYS, MAX_VALIDITY_SECS, TrustedKeys,
    TrustedKeysError, VerifiedManifest, VerifyError, verify,
};
