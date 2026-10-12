use serde::{Deserialize, Serialize};

use crate::{PathPolicy, Primitive, RiskLevel};

const MAX_TIMEOUT_SECS: u32 = 600;

/// A named, versioned action composed of primitives.
///
/// Manifests are data, written in TOML (see `manifests/examples/`). In production they
/// are signed with a key that never lives on the server, and the agent verifies the
/// signature before running anything (ADR-0003; signing is not implemented yet).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Lowercase dotted id, e.g. `erp.restart-service`.
    pub id: String,
    pub version: u32,
    pub title: String,
    /// What the action does, for technicians.
    pub description: String,
    /// When a model should (and should not) pick this action.
    pub ai_description: String,
    pub risk: RiskLevel,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u32,
    /// All must hold before any step runs; otherwise the action is rejected.
    #[serde(default)]
    pub preconditions: Vec<Check>,
    pub steps: Vec<Primitive>,
    /// All must hold after the steps for the action to count as succeeded.
    #[serde(default)]
    pub verify: Vec<Check>,
}

const fn default_timeout() -> u32 {
    60
}

/// A condition evaluated on the agent before or after the steps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "check", rename_all = "snake_case", deny_unknown_fields)]
pub enum Check {
    ServiceState {
        service: String,
        state: ExpectedServiceState,
    },
    PathExists {
        path: String,
    },
    DiskFreeAtLeast {
        mount: String,
        percent: u8,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedServiceState {
    Running,
    Stopped,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ManifestError {
    #[error("manifest id `{0}` must be lowercase dotted segments, e.g. `erp.restart-service`")]
    InvalidId(String),
    #[error("manifest must have at least one step")]
    NoSteps,
    #[error("timeout must be between 1 and {MAX_TIMEOUT_SECS} seconds, got {0}")]
    InvalidTimeout(u32),
    #[error("declared risk {declared:?} is lower than step {step} requires ({required:?})")]
    RiskUnderstated {
        declared: RiskLevel,
        required: RiskLevel,
        step: usize,
    },
    #[error("path `{path}` in step {step} is outside the allowed roots")]
    PathNotAllowed { path: String, step: usize },
}

impl Manifest {
    /// Parses a manifest from TOML. Parsing does not validate: call [`Manifest::validate`].
    ///
    /// # Errors
    /// Returns the TOML error for malformed input or unknown fields.
    pub fn from_toml(input: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(input)
    }

    /// Checks the invariants every manifest must satisfy before it can be signed or run.
    ///
    /// # Errors
    /// Returns the first violated invariant.
    pub fn validate(&self, paths: &PathPolicy) -> Result<(), ManifestError> {
        if !is_valid_id(&self.id) {
            return Err(ManifestError::InvalidId(self.id.clone()));
        }
        if self.steps.is_empty() {
            return Err(ManifestError::NoSteps);
        }
        if self.timeout_secs == 0 || self.timeout_secs > MAX_TIMEOUT_SECS {
            return Err(ManifestError::InvalidTimeout(self.timeout_secs));
        }
        for (step, primitive) in self.steps.iter().enumerate() {
            let required = primitive.inherent_risk();
            if self.risk < required {
                return Err(ManifestError::RiskUnderstated {
                    declared: self.risk,
                    required,
                    step,
                });
            }
            if let Some(path) = primitive.path() {
                if !paths.is_allowed(path) {
                    return Err(ManifestError::PathNotAllowed {
                        path: path.to_owned(),
                        step,
                    });
                }
            }
        }
        Ok(())
    }
}

/// `segment(.segment)+`, each segment `[a-z][a-z0-9-]*`.
fn is_valid_id(id: &str) -> bool {
    let mut segments = 0;
    for segment in id.split('.') {
        let mut chars = segment.chars();
        let starts_ok = chars.next().is_some_and(|c| c.is_ascii_lowercase());
        let rest_ok = chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
        if !starts_ok || !rest_ok {
            return false;
        }
        segments += 1;
    }
    segments >= 2
}

#[cfg(test)]
mod tests {
    use super::*;

    const RESTART: &str = include_str!("../../../manifests/examples/erp-restart-service.toml");
    const CLEAR_LOCK: &str = include_str!("../../../manifests/examples/erp-clear-stale-lock.toml");

    fn policy() -> PathPolicy {
        PathPolicy::new([r"C:\FakeErp"]).unwrap()
    }

    #[test]
    fn example_manifests_are_valid() {
        for source in [RESTART, CLEAR_LOCK] {
            let manifest = Manifest::from_toml(source).unwrap();
            assert_eq!(manifest.validate(&policy()), Ok(()), "{}", manifest.id);
        }
    }

    #[test]
    fn understated_risk_is_rejected() {
        let mut manifest = Manifest::from_toml(RESTART).unwrap();
        manifest.risk = RiskLevel::Low;
        assert_eq!(
            manifest.validate(&policy()),
            Err(ManifestError::RiskUnderstated {
                declared: RiskLevel::Low,
                required: RiskLevel::Medium,
                step: 0,
            })
        );
    }

    #[test]
    fn path_outside_roots_is_rejected() {
        let mut manifest = Manifest::from_toml(CLEAR_LOCK).unwrap();
        manifest.steps[0] = Primitive::DeleteFile {
            path: r"C:\Windows\win.ini".to_owned(),
        };
        assert!(matches!(
            manifest.validate(&policy()),
            Err(ManifestError::PathNotAllowed { step: 0, .. })
        ));
    }

    #[test]
    fn unknown_fields_are_rejected() {
        // At the top level...
        let top = format!("run_as_admin = true\n{RESTART}");
        assert!(Manifest::from_toml(&top).is_err());

        // ...and inside a step, where a silently ignored `recursive = true` would be dangerous.
        let step = CLEAR_LOCK.replace(
            "op = \"delete_file\"",
            "op = \"delete_file\"\nrecursive = true",
        );
        assert_ne!(step, CLEAR_LOCK);
        assert!(Manifest::from_toml(&step).is_err());
    }

    #[test]
    fn id_format() {
        assert!(is_valid_id("erp.restart-service"));
        assert!(is_valid_id("erp.db.check-connection2"));
        for bad in [
            "erp",
            "Erp.restart",
            "erp..x",
            "erp.-x",
            "erp.restart_service",
            "",
        ] {
            assert!(!is_valid_id(bad), "{bad:?}");
        }
    }
}
