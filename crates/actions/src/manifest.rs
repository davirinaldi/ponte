use serde::{Deserialize, Serialize};

use crate::path_policy::is_drive;
use crate::{PathPolicy, Primitive, RiskLevel};

const MAX_TIMEOUT_SECS: u32 = 600;
/// Upper bound for `read_file_tail`: enough log to diagnose with, small enough for the
/// agent's memory budget and for what may travel towards a model.
const MAX_READ_TAIL_BYTES: u64 = 64 * 1024;
const MAX_NAME_LEN: usize = 256;

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

/// Where in a manifest a problem was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Location {
    Step(usize),
    Precondition(usize),
    Verify(usize),
}

impl std::fmt::Display for Location {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Step(index) => write!(f, "step {index}"),
            Self::Precondition(index) => write!(f, "precondition {index}"),
            Self::Verify(index) => write!(f, "verify check {index}"),
        }
    }
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
    #[error("path `{path}` in {at} is outside the allowed roots")]
    PathNotAllowed { path: String, at: Location },
    #[error("`{name}` in {at} is not a plain service, process image or connection name")]
    InvalidName { name: String, at: Location },
    #[error("max_bytes in {at} must be between 1 and {MAX_READ_TAIL_BYTES}, got {max_bytes}")]
    InvalidMaxBytes { max_bytes: u64, at: Location },
    #[error("mount `{mount}` in {at} must be a drive such as `C:`")]
    InvalidMount { mount: String, at: Location },
    #[error("percent in {at} must be between 1 and 100, got {percent}")]
    InvalidPercent { percent: u8, at: Location },
    #[error("a manifest above read risk must have at least one verify check")]
    NoVerify,
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
            let at = Location::Step(step);
            let required = primitive.inherent_risk();
            if self.risk < required {
                return Err(ManifestError::RiskUnderstated {
                    declared: self.risk,
                    required,
                    step,
                });
            }
            check_step(primitive, paths, at)?;
        }
        for (index, check) in self.preconditions.iter().enumerate() {
            check.validate(paths, Location::Precondition(index))?;
        }
        for (index, check) in self.verify.iter().enumerate() {
            check.validate(paths, Location::Verify(index))?;
        }
        // A read-only action leaves nothing behind to verify; anything else must prove it worked.
        if self.risk > RiskLevel::Read && self.verify.is_empty() {
            return Err(ManifestError::NoVerify);
        }
        Ok(())
    }
}

impl Check {
    /// Checks run on the agent as well, so they get the same scrutiny as steps.
    fn validate(&self, paths: &PathPolicy, at: Location) -> Result<(), ManifestError> {
        match self {
            Self::ServiceState { service, .. } => check_name(service, at),
            Self::PathExists { path } => check_path(paths, path, at),
            Self::DiskFreeAtLeast { mount, percent } => {
                // A bare drive only: a UNC "mount" would make the agent reach out to a file server.
                if !is_drive(mount) {
                    return Err(ManifestError::InvalidMount {
                        mount: mount.clone(),
                        at,
                    });
                }
                // 0 always holds and would pass for a verification without checking anything.
                if !(1..=100).contains(percent) {
                    return Err(ManifestError::InvalidPercent {
                        percent: *percent,
                        at,
                    });
                }
                Ok(())
            }
        }
    }
}

/// Checks every field of one step.
///
/// The match has no catch-all on purpose: a new primitive does not compile until
/// someone decides how each of its fields is checked.
fn check_step(step: &Primitive, paths: &PathPolicy, at: Location) -> Result<(), ManifestError> {
    match step {
        Primitive::ServiceStart { service }
        | Primitive::ServiceStop { service }
        | Primitive::ServiceRestart { service } => check_name(service, at),
        Primitive::KillProcess { image } => check_name(image, at),
        Primitive::DeleteFile { path } => check_path(paths, path, at),
        Primitive::ReadFileTail { path, max_bytes } => {
            check_path(paths, path, at)?;
            if (1..=MAX_READ_TAIL_BYTES).contains(max_bytes) {
                Ok(())
            } else {
                Err(ManifestError::InvalidMaxBytes {
                    max_bytes: *max_bytes,
                    at,
                })
            }
        }
        Primitive::ClearTempDir {} => Ok(()),
        // `connection` names an entry configured on the agent, so it gets the name rule: a
        // server address or connection string must not pass. What `query` may contain is
        // still open (see `docs/roadmap.md`), so it is not checked here.
        Primitive::SqlReadonly {
            connection,
            query: _,
        } => check_name(connection, at),
    }
}

fn check_path(paths: &PathPolicy, path: &str, at: Location) -> Result<(), ManifestError> {
    if paths.is_allowed(path) {
        Ok(())
    } else {
        Err(ManifestError::PathNotAllowed {
            path: path.to_owned(),
            at,
        })
    }
}

/// The shape of a service, process image or connection name: letters, digits, `.`, `_`,
/// `-`, `$` and single inner spaces, starting with a letter or digit.
///
/// An allow-list, so paths, wildcards, quoting and invisible characters are all out. It
/// says nothing about which services or processes are safe to touch, and it does not
/// tell look-alike letters apart.
fn check_name(name: &str, at: Location) -> Result<(), ManifestError> {
    let plain = name.chars().next().is_some_and(char::is_alphanumeric)
        && name.chars().count() <= MAX_NAME_LEN
        && !name.ends_with([' ', '.'])
        && !name.contains("  ")
        && name
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '.' | '_' | '-' | '$' | ' '));
    if plain {
        Ok(())
    } else {
        Err(ManifestError::InvalidName {
            name: name.to_owned(),
            at,
        })
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
            Err(ManifestError::PathNotAllowed {
                at: Location::Step(0),
                ..
            })
        ));
    }

    #[test]
    fn check_paths_go_through_the_path_policy() {
        for path in [
            // The SYSTEM service would authenticate to someone else's file server.
            r"\\attacker.example\share\x",
            r"C:\Users\joao\Documents\receita.pdf",
            r"C:\FakeErp\NUL",
        ] {
            let check = Check::PathExists {
                path: path.to_owned(),
            };
            let not_allowed = |at| {
                Err(ManifestError::PathNotAllowed {
                    path: path.to_owned(),
                    at,
                })
            };

            let mut manifest = Manifest::from_toml(CLEAR_LOCK).unwrap();
            manifest.preconditions[1] = check.clone();
            assert_eq!(
                manifest.validate(&policy()),
                not_allowed(Location::Precondition(1))
            );

            let mut manifest = Manifest::from_toml(CLEAR_LOCK).unwrap();
            manifest.verify.push(check);
            assert_eq!(
                manifest.validate(&policy()),
                not_allowed(Location::Verify(1))
            );
        }
    }

    #[test]
    fn disk_check_needs_a_drive_and_a_real_percentage() {
        for mount in [r"\\attacker.example\share", r"C:\", "C", "1:", "CC:", ""] {
            let mut manifest = Manifest::from_toml(RESTART).unwrap();
            manifest.preconditions[0] = Check::DiskFreeAtLeast {
                mount: mount.to_owned(),
                percent: 2,
            };
            assert_eq!(
                manifest.validate(&policy()),
                Err(ManifestError::InvalidMount {
                    mount: mount.to_owned(),
                    at: Location::Precondition(0),
                })
            );
        }

        let percent = |percent| {
            let mut manifest = Manifest::from_toml(RESTART).unwrap();
            manifest.preconditions[0] = Check::DiskFreeAtLeast {
                mount: "C:".to_owned(),
                percent,
            };
            manifest.validate(&policy())
        };
        assert_eq!(percent(1), Ok(()));
        assert_eq!(percent(100), Ok(()));
        // 0 is always true: it would satisfy the verify requirement without checking anything.
        for invalid in [0, 101, u8::MAX] {
            assert_eq!(
                percent(invalid),
                Err(ManifestError::InvalidPercent {
                    percent: invalid,
                    at: Location::Precondition(0),
                })
            );
        }
    }

    #[test]
    fn read_tail_is_bounded() {
        let read = |max_bytes| {
            let mut manifest = Manifest::from_toml(RESTART).unwrap();
            manifest.steps[0] = Primitive::ReadFileTail {
                path: r"C:\FakeErp\logs\error.log".to_owned(),
                max_bytes,
            };
            manifest.validate(&policy())
        };
        assert_eq!(read(1), Ok(()));
        assert_eq!(read(MAX_READ_TAIL_BYTES), Ok(()));
        for max_bytes in [0, MAX_READ_TAIL_BYTES + 1, u64::MAX] {
            assert_eq!(
                read(max_bytes),
                Err(ManifestError::InvalidMaxBytes {
                    max_bytes,
                    at: Location::Step(0),
                })
            );
        }
    }

    /// One manifest per place a name can appear, each valid unless `name` is not.
    fn manifests_naming(name: &str) -> Vec<(Manifest, Location)> {
        let name = name.to_owned();
        let step = |primitive| {
            let mut manifest = Manifest::from_toml(RESTART).unwrap();
            manifest.risk = RiskLevel::High;
            manifest.steps[0] = primitive;
            (manifest, Location::Step(0))
        };
        let check = || Check::ServiceState {
            service: name.clone(),
            state: ExpectedServiceState::Running,
        };
        let mut precondition = Manifest::from_toml(RESTART).unwrap();
        precondition.preconditions[0] = check();
        let mut verify = Manifest::from_toml(RESTART).unwrap();
        verify.verify[0] = check();

        vec![
            step(Primitive::ServiceStart {
                service: name.clone(),
            }),
            step(Primitive::ServiceStop {
                service: name.clone(),
            }),
            step(Primitive::ServiceRestart {
                service: name.clone(),
            }),
            step(Primitive::KillProcess {
                image: name.clone(),
            }),
            step(Primitive::SqlReadonly {
                connection: name.clone(),
                query: "select 1".to_owned(),
            }),
            (precondition, Location::Precondition(0)),
            (verify, Location::Verify(0)),
        ]
    }

    #[test]
    fn names_must_be_plain() {
        let too_long = "x".repeat(MAX_NAME_LEN + 1);
        for name in [
            "",
            " FakeErp",
            "FakeErp ",
            "Fake  Erp",
            "erp.exe.",
            // Paths, and the server a "connection" could otherwise point at.
            r"C:\FakeErp\erp.exe",
            r"..\erp.exe",
            r"\\evil.example\share\db.fdb",
            "bin/erp.exe",
            "erp.exe:stream",
            ".",
            "..",
            // Wildcards, quoting and whatever a query or a shell would interpret.
            "erp*.exe",
            "erp?.exe",
            "x' OR Name LIKE '%",
            "FakeErp&calc.exe",
            "%COMSPEC%",
            "$(calc)",
            "-h",
            "Server=evil.example;Database=erp",
            // Characters that make a name read differently from what it matches.
            "erp\0.exe",
            "FakeErp\nWinDefend",
            "Fake\u{200b}Erp",
            "\u{202e}exe.prE",
            "\u{feff}FakeErp",
            too_long.as_str(),
        ] {
            for (manifest, at) in manifests_naming(name) {
                assert_eq!(
                    manifest.validate(&policy()),
                    Err(ManifestError::InvalidName {
                        name: name.to_owned(),
                        at,
                    }),
                    "{name:?} in {at}"
                );
            }
        }

        let longest = "x".repeat(MAX_NAME_LEN);
        for name in [
            "FakeErp",
            "MSSQL$SQLEXPRESS",
            "postgresql-x64-14",
            "erp.exe",
            "erp_backup.exe",
            "ERP Sistema.exe",
            "Gest\u{e3}o.exe",
            longest.as_str(),
        ] {
            for (manifest, at) in manifests_naming(name) {
                assert_eq!(manifest.validate(&policy()), Ok(()), "{name:?} in {at}");
            }
        }
    }

    #[test]
    fn changing_the_machine_requires_verification() {
        let mut manifest = Manifest::from_toml(RESTART).unwrap();
        manifest.verify.clear();
        assert_eq!(manifest.validate(&policy()), Err(ManifestError::NoVerify));

        // Starting a service is only low risk, and it still changes the machine.
        manifest.risk = RiskLevel::Low;
        manifest.steps[0] = Primitive::ServiceStart {
            service: "FakeErp".to_owned(),
        };
        assert_eq!(manifest.validate(&policy()), Err(ManifestError::NoVerify));

        // A read-only action leaves nothing behind to verify.
        manifest.risk = RiskLevel::Read;
        manifest.steps[0] = Primitive::ReadFileTail {
            path: r"C:\FakeErp\logs\error.log".to_owned(),
            max_bytes: 4096,
        };
        assert_eq!(manifest.validate(&policy()), Ok(()));
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

        // ...including a step that takes no fields at all: the leftover `service` must not pass.
        let fieldless = CLEAR_LOCK.replace("op = \"service_start\"", "op = \"clear_temp_dir\"");
        assert_ne!(fieldless, CLEAR_LOCK);
        assert!(Manifest::from_toml(&fieldless).is_err());
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
