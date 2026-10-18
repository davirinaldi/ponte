use std::fmt;

use ponte_protocol::ServiceName;
use serde::{Deserialize, Serialize};

use crate::path_policy::{is_drive, normalize};
use crate::{Primitive, RiskLevel};

const MAX_TIMEOUT_SECS: u32 = 600;
/// Upper bound for `read_file_tail`: enough log to diagnose with, small enough for the
/// agent's memory budget and for what may travel towards a model.
const MAX_READ_TAIL_BYTES: u64 = 64 * 1024;
const MAX_NAME_LEN: usize = 256;
/// Longest manifest id, in bytes (ids are ASCII). The id keys the agent's rate limits and
/// the server's catalog.
pub const MAX_ID_LEN: usize = 64;
/// Most steps in one manifest (ADR-0011).
pub const MAX_STEPS: usize = 16;
/// Most checks in each of `preconditions` and `verify` (ADR-0011).
pub const MAX_CHECKS: usize = 16;
/// Longest title, in characters (ADR-0011).
pub const MAX_TITLE_CHARS: usize = 120;
/// Longest `description` and `ai_description`, in characters each (ADR-0011).
pub const MAX_DESCRIPTION_CHARS: usize = 2_000;

/// A named, versioned action composed of primitives, as parsed from TOML.
///
/// Manifests are data, written in TOML (see `manifests/examples/`) and signed offline
/// (ADR-0010). A value of this type has only been parsed: it becomes a [`ValidManifest`]
/// through [`Manifest::validate_shape`], and nothing runs anything short of a
/// [`RunnableManifest`](crate::RunnableManifest).
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
    /// Holds only when Windows answers "file not found" or "path not found" (ADR-0011):
    /// any other error is a failed check, never "absent".
    PathAbsent {
        path: String,
    },
    DiskFreeAtLeast {
        mount: String,
        percent: u8,
    },
}

impl Check {
    /// The service this check names, if any.
    #[must_use]
    pub fn service(&self) -> Option<&str> {
        match self {
            Self::ServiceState { service, .. } => Some(service),
            Self::PathExists { .. } | Self::PathAbsent { .. } | Self::DiskFreeAtLeast { .. } => {
                None
            }
        }
    }

    /// The filesystem path this check names, if any. A mount is a drive, not a path.
    #[must_use]
    pub fn path(&self) -> Option<&str> {
        match self {
            Self::PathExists { path } | Self::PathAbsent { path } => Some(path),
            Self::ServiceState { .. } | Self::DiskFreeAtLeast { .. } => None,
        }
    }
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

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Step(index) => write!(f, "step {index}"),
            Self::Precondition(index) => write!(f, "precondition {index}"),
            Self::Verify(index) => write!(f, "verify check {index}"),
        }
    }
}

/// A free-text field of a manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextField {
    Title,
    Description,
    AiDescription,
}

impl fmt::Display for TextField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Title => "title",
            Self::Description => "description",
            Self::AiDescription => "ai_description",
        })
    }
}

/// One of the two lists of checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckList {
    Preconditions,
    Verify,
}

impl fmt::Display for CheckList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Preconditions => "preconditions",
            Self::Verify => "verify",
        })
    }
}

/// Why a manifest has no valid shape.
///
/// Says which rule and where, never the path, name or text at fault: the agent may log an
/// error, and a manifest names paths and services, which logs do not (ADR-0012). Whoever
/// wrote the manifest has it in front of them.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ManifestError {
    #[error(
        "the id must be lowercase dotted segments of at most {MAX_ID_LEN} bytes, e.g. \
         `erp.restart-service`"
    )]
    InvalidId,
    #[error("the version must be at least 1")]
    InvalidVersion,
    #[error("{0} must not be empty")]
    EmptyText(TextField),
    #[error("{field} must be at most {max} characters")]
    TextTooLong { field: TextField, max: usize },
    #[error("the title must be a single line")]
    TitleNotOneLine,
    #[error("manifest must have at least one step")]
    NoSteps,
    #[error("a manifest has at most {MAX_STEPS} steps")]
    TooManySteps,
    #[error("{0} has more than {MAX_CHECKS} checks")]
    TooManyChecks(CheckList),
    #[error("timeout must be between 1 and {MAX_TIMEOUT_SECS} seconds, got {0}")]
    InvalidTimeout(u32),
    #[error("declared risk {declared:?} is lower than step {step} requires ({required:?})")]
    RiskUnderstated {
        declared: RiskLevel,
        required: RiskLevel,
        step: usize,
    },
    #[error("{0} uses a primitive this release refuses (ADR-0011)")]
    PrimitiveRefused(Location),
    #[error(
        "the path in {0} must be an absolute Windows path below a drive, with no `..`, UNC, \
         device name, stream, wildcard or trailing dot or space"
    )]
    InvalidPath(Location),
    #[error("the name in {0} is not a plain service, process image or connection name")]
    InvalidName(Location),
    #[error("max_bytes in {at} must be between 1 and {MAX_READ_TAIL_BYTES}, got {max_bytes}")]
    InvalidMaxBytes { max_bytes: u64, at: Location },
    #[error("the mount in {0} must be a drive such as `C:`")]
    InvalidMount(Location),
    #[error("percent in {at} must be between 1 and 100, got {percent}")]
    InvalidPercent { percent: u8, at: Location },
    #[error("a manifest above read risk must have at least one verify check")]
    NoVerify,
    #[error(
        "{0} touches a service or path that no verify check names (`service_state` for a \
         service, `path_exists` or `path_absent` for a path)"
    )]
    NotVerified(Location),
    #[error("{0} deletes a file without a `path_exists` precondition on the same path")]
    DeleteNotPrechecked(Location),
}

/// A manifest whose shape is valid: limits, names, lexical paths, risk, coverage and the
/// primitives this release runs (ADR-0011). It says nothing about a signature or about any
/// machine: `ponte-sign` and the server's catalog stop here.
#[derive(Clone, PartialEq, Eq)]
pub struct ValidManifest(Manifest);

impl ValidManifest {
    #[must_use]
    pub fn manifest(&self) -> &Manifest {
        &self.0
    }
}

/// The id and version only: the rest names paths and services, which logs do not.
impl fmt::Debug for ValidManifest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ValidManifest({} v{})", self.0.id, self.0.version)
    }
}

impl Manifest {
    /// Parses a manifest from TOML. Parsing does not validate: call
    /// [`Manifest::validate_shape`].
    ///
    /// # Errors
    /// Returns the TOML error for malformed input, unknown fields or duplicate keys. The
    /// error quotes the input: show it to whoever wrote the file, never log it.
    pub fn from_toml(input: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(input)
    }

    /// Checks every rule that does not depend on a machine (ADR-0011).
    ///
    /// # Errors
    /// Returns the first rule the manifest breaks.
    pub fn validate_shape(self) -> Result<ValidManifest, ManifestError> {
        self.check_header()?;
        if self.steps.is_empty() {
            return Err(ManifestError::NoSteps);
        }
        if self.steps.len() > MAX_STEPS {
            return Err(ManifestError::TooManySteps);
        }
        if self.preconditions.len() > MAX_CHECKS {
            return Err(ManifestError::TooManyChecks(CheckList::Preconditions));
        }
        if self.verify.len() > MAX_CHECKS {
            return Err(ManifestError::TooManyChecks(CheckList::Verify));
        }
        for (step, primitive) in self.steps.iter().enumerate() {
            let at = Location::Step(step);
            if is_refused(primitive) {
                return Err(ManifestError::PrimitiveRefused(at));
            }
            let required = primitive.inherent_risk();
            if self.risk < required {
                return Err(ManifestError::RiskUnderstated {
                    declared: self.risk,
                    required,
                    step,
                });
            }
            check_step(primitive, at)?;
        }
        for (index, check) in self.preconditions.iter().enumerate() {
            check.validate(Location::Precondition(index))?;
        }
        for (index, check) in self.verify.iter().enumerate() {
            check.validate(Location::Verify(index))?;
        }
        // Anything above read risk changes the machine and must prove it worked.
        if self.risk > RiskLevel::Read && self.verify.is_empty() {
            return Err(ManifestError::NoVerify);
        }
        for (step, primitive) in self.steps.iter().enumerate() {
            self.check_coverage(primitive, Location::Step(step))?;
        }
        Ok(ValidManifest(self))
    }

    fn check_header(&self) -> Result<(), ManifestError> {
        if !is_valid_id(&self.id) {
            return Err(ManifestError::InvalidId);
        }
        if self.version == 0 {
            return Err(ManifestError::InvalidVersion);
        }
        for (field, text, max) in [
            (TextField::Title, &self.title, MAX_TITLE_CHARS),
            (
                TextField::Description,
                &self.description,
                MAX_DESCRIPTION_CHARS,
            ),
            (
                TextField::AiDescription,
                &self.ai_description,
                MAX_DESCRIPTION_CHARS,
            ),
        ] {
            if text.trim().is_empty() {
                return Err(ManifestError::EmptyText(field));
            }
            if text.chars().count() > max {
                return Err(ManifestError::TextTooLong { field, max });
            }
        }
        if self.title.contains(['\n', '\t']) {
            return Err(ManifestError::TitleNotOneLine);
        }
        if self.timeout_secs == 0 || self.timeout_secs > MAX_TIMEOUT_SECS {
            return Err(ManifestError::InvalidTimeout(self.timeout_secs));
        }
        Ok(())
    }

    /// Every service and path a step touches is named by a verify check, and every delete
    /// has a `path_exists` precondition on its path (ADR-0011). The expected state is the
    /// signer's to choose.
    ///
    /// No catch-all: a primitive that becomes runnable must say what covers it.
    fn check_coverage(&self, step: &Primitive, at: Location) -> Result<(), ManifestError> {
        match step {
            Primitive::ServiceStart { service }
            | Primitive::ServiceStop { service }
            | Primitive::ServiceRestart { service } => {
                let covered = self.verify.iter().any(|check| {
                    matches!(check, Check::ServiceState { service: named, .. }
                        if named.eq_ignore_ascii_case(service))
                });
                if !covered {
                    return Err(ManifestError::NotVerified(at));
                }
            }
            Primitive::DeleteFile { path } => {
                let covered = self.verify.iter().any(|check| {
                    matches!(check, Check::PathExists { path: named } | Check::PathAbsent { path: named }
                        if same_path(named, path))
                });
                if !covered {
                    return Err(ManifestError::NotVerified(at));
                }
                let prechecked = self.preconditions.iter().any(
                    |check| matches!(check, Check::PathExists { path: named } if same_path(named, path)),
                );
                if !prechecked {
                    return Err(ManifestError::DeleteNotPrechecked(at));
                }
            }
            // Refused before coverage is looked at. The ADR that re-enables one of these
            // decides what covers it.
            Primitive::ReadFileTail { .. }
            | Primitive::ClearTempDir {}
            | Primitive::KillProcess { .. }
            | Primitive::SqlReadonly { .. } => return Err(ManifestError::PrimitiveRefused(at)),
        }
        Ok(())
    }
}

/// The primitives no manifest may use in this release (ADR-0011). `clear_temp_dir` works
/// in a folder the user controls, `read_file_tail` is how a compromised server would pull
/// personal data, and `kill_process` and `sql_readonly` have no design of their own yet.
const fn is_refused(step: &Primitive) -> bool {
    match step {
        Primitive::ServiceStart { .. }
        | Primitive::ServiceStop { .. }
        | Primitive::ServiceRestart { .. }
        | Primitive::DeleteFile { .. } => false,
        Primitive::ReadFileTail { .. }
        | Primitive::ClearTempDir {}
        | Primitive::KillProcess { .. }
        | Primitive::SqlReadonly { .. } => true,
    }
}

/// Whether two paths, both of a valid shape, name the same file as far as a lexical check
/// can tell: same segments, ASCII case folded, either slash.
fn same_path(a: &str, b: &str) -> bool {
    matches!((normalize(a), normalize(b)), (Some(a), Some(b)) if a == b)
}

impl Check {
    /// Checks run on the agent as well, so they get the same scrutiny as steps.
    fn validate(&self, at: Location) -> Result<(), ManifestError> {
        match self {
            Self::ServiceState { service, .. } => check_service(service, at),
            Self::PathExists { path } | Self::PathAbsent { path } => check_path(path, at),
            Self::DiskFreeAtLeast { mount, percent } => {
                // A bare drive only: a UNC "mount" would make the agent reach out to a file server.
                if !is_drive(mount) {
                    return Err(ManifestError::InvalidMount(at));
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
/// someone decides how each of its fields is checked. The primitives this release
/// refuses keep their rules for the ADR that re-enables them.
fn check_step(step: &Primitive, at: Location) -> Result<(), ManifestError> {
    match step {
        Primitive::ServiceStart { service }
        | Primitive::ServiceStop { service }
        | Primitive::ServiceRestart { service } => check_service(service, at),
        Primitive::KillProcess { image } => check_name(image, at),
        Primitive::DeleteFile { path } => check_path(path, at),
        Primitive::ReadFileTail { path, max_bytes } => {
            check_path(path, at)?;
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

/// The lexical shape of a path: absolute, below a drive, nothing ambiguous. Which roots it
/// must lie in is the agent's to decide (`LocalPolicy`).
fn check_path(path: &str, at: Location) -> Result<(), ManifestError> {
    match normalize(path) {
        // The drive alone is not a file or a folder any primitive should touch.
        Some(segments) if segments.len() > 1 => Ok(()),
        _ => Err(ManifestError::InvalidPath(at)),
    }
}

/// A Windows service name, ASCII only: the agent refuses every other service anyway
/// (ADR-0011), so the signer finds out first.
fn check_service(name: &str, at: Location) -> Result<(), ManifestError> {
    name.parse::<ServiceName>()
        .map(drop)
        .map_err(|_| ManifestError::InvalidName(at))
}

/// The shape of a process image or connection name: letters, digits, `.`, `_`, `-`, `$`
/// and single inner spaces, starting with a letter or digit.
///
/// An allow-list, so paths, wildcards, quoting and invisible characters are all out. It
/// says nothing about which processes are safe to touch, and it does not tell look-alike
/// letters apart.
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
        Err(ManifestError::InvalidName(at))
    }
}

/// `segment(.segment)+`, each segment `[a-z][a-z0-9-]*`, at most [`MAX_ID_LEN`] bytes.
fn is_valid_id(id: &str) -> bool {
    if id.len() > MAX_ID_LEN {
        return false;
    }
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
    const LOCK: &str = r"C:\FakeErp\run\erp.lock";

    fn parsed(source: &str) -> Manifest {
        Manifest::from_toml(source).unwrap()
    }

    fn shape(manifest: Manifest) -> Result<(), ManifestError> {
        manifest.validate_shape().map(drop)
    }

    fn service_state(service: &str) -> Check {
        Check::ServiceState {
            service: service.to_owned(),
            state: ExpectedServiceState::Running,
        }
    }

    #[test]
    fn example_manifests_are_valid() {
        for source in [RESTART, CLEAR_LOCK] {
            let manifest = parsed(source);
            let id = manifest.id.clone();
            assert_eq!(shape(manifest), Ok(()), "{id}");
        }
    }

    /// The limits of ADR-0011, in numbers the tests below cannot move.
    #[test]
    fn limits_are_pinned() {
        assert_eq!(MAX_STEPS, 16);
        assert_eq!(MAX_CHECKS, 16);
        assert_eq!(MAX_TITLE_CHARS, 120);
        assert_eq!(MAX_DESCRIPTION_CHARS, 2_000);
        assert_eq!(MAX_ID_LEN, 64);
        assert_eq!(MAX_TIMEOUT_SECS, 600);
        assert_eq!(MAX_NAME_LEN, 256);
    }

    #[test]
    fn steps_are_bounded() {
        let with_steps = |count| {
            let mut manifest = parsed(RESTART);
            manifest.steps = vec![manifest.steps[0].clone(); count];
            shape(manifest)
        };
        assert_eq!(with_steps(MAX_STEPS), Ok(()));
        assert_eq!(with_steps(MAX_STEPS + 1), Err(ManifestError::TooManySteps));
        assert_eq!(with_steps(0), Err(ManifestError::NoSteps));
    }

    #[test]
    fn checks_are_bounded() {
        let mut manifest = parsed(RESTART);
        manifest.preconditions = vec![manifest.preconditions[0].clone(); MAX_CHECKS];
        manifest.verify = vec![manifest.verify[0].clone(); MAX_CHECKS];
        assert_eq!(shape(manifest.clone()), Ok(()));

        let mut preconditions = manifest.clone();
        preconditions
            .preconditions
            .push(preconditions.preconditions[0].clone());
        assert_eq!(
            shape(preconditions),
            Err(ManifestError::TooManyChecks(CheckList::Preconditions))
        );

        let mut verify = manifest;
        verify.verify.push(verify.verify[0].clone());
        assert_eq!(
            shape(verify),
            Err(ManifestError::TooManyChecks(CheckList::Verify))
        );
    }

    #[test]
    fn texts_are_bounded_and_not_empty() {
        type Field = fn(&mut Manifest) -> &mut String;
        let fields: [(TextField, usize, Field); 3] = [
            (TextField::Title, MAX_TITLE_CHARS, |m| &mut m.title),
            (TextField::Description, MAX_DESCRIPTION_CHARS, |m| {
                &mut m.description
            }),
            (TextField::AiDescription, MAX_DESCRIPTION_CHARS, |m| {
                &mut m.ai_description
            }),
        ];
        for (field, max, get) in fields {
            let with = |text: String| {
                let mut manifest = parsed(RESTART);
                *get(&mut manifest) = text;
                shape(manifest)
            };
            // Characters, not bytes: an accented letter counts once.
            assert_eq!(with("é".repeat(max)), Ok(()), "{field}");
            assert_eq!(
                with("é".repeat(max + 1)),
                Err(ManifestError::TextTooLong { field, max }),
                "{field}"
            );
            for empty in ["", " ", "\n\t"] {
                assert_eq!(
                    with(empty.to_owned()),
                    Err(ManifestError::EmptyText(field)),
                    "{field}"
                );
            }
        }

        for title in ["Restart\nthe ERP", "Restart\tthe ERP"] {
            let mut manifest = parsed(RESTART);
            manifest.title = title.to_owned();
            assert_eq!(shape(manifest), Err(ManifestError::TitleNotOneLine));
        }
        // Descriptions may span lines.
        let mut manifest = parsed(RESTART);
        manifest.description = "Restarts the ERP.\n\nThen checks it.".to_owned();
        assert_eq!(shape(manifest), Ok(()));
    }

    #[test]
    fn version_starts_at_one() {
        let mut manifest = parsed(RESTART);
        manifest.version = 0;
        assert_eq!(shape(manifest), Err(ManifestError::InvalidVersion));
    }

    #[test]
    fn timeout_is_bounded() {
        for (timeout, valid) in [(0, false), (1, true), (600, true), (601, false)] {
            let mut manifest = parsed(RESTART);
            manifest.timeout_secs = timeout;
            let expected = if valid {
                Ok(())
            } else {
                Err(ManifestError::InvalidTimeout(timeout))
            };
            assert_eq!(shape(manifest), expected, "{timeout}");
        }
    }

    #[test]
    fn refused_primitives_are_refused_whatever_the_risk() {
        for primitive in [
            Primitive::ClearTempDir {},
            Primitive::ReadFileTail {
                path: r"C:\FakeErp\logs\error.log".to_owned(),
                max_bytes: 4096,
            },
            Primitive::KillProcess {
                image: "erp.exe".to_owned(),
            },
            Primitive::SqlReadonly {
                connection: "erp".to_owned(),
                query: "select 1".to_owned(),
            },
        ] {
            let mut manifest = parsed(RESTART);
            manifest.risk = RiskLevel::High;
            manifest.steps.push(primitive.clone());
            assert_eq!(
                shape(manifest),
                Err(ManifestError::PrimitiveRefused(Location::Step(1))),
                "{primitive:?}"
            );
        }
    }

    #[test]
    fn understated_risk_is_rejected() {
        let mut manifest = parsed(RESTART);
        manifest.risk = RiskLevel::Low;
        assert_eq!(
            shape(manifest),
            Err(ManifestError::RiskUnderstated {
                declared: RiskLevel::Low,
                required: RiskLevel::Medium,
                step: 0,
            })
        );
    }

    #[test]
    fn every_touched_service_is_verified() {
        // A verify check on another service proves nothing about this one.
        let mut manifest = parsed(RESTART);
        manifest.verify[0] = service_state("OtherErp");
        assert_eq!(
            shape(manifest),
            Err(ManifestError::NotVerified(Location::Step(0)))
        );

        // A precondition is not a verification.
        let mut manifest = parsed(RESTART);
        manifest.preconditions.push(manifest.verify[0].clone());
        manifest.verify[0] = Check::DiskFreeAtLeast {
            mount: "C:".to_owned(),
            percent: 1,
        };
        assert_eq!(
            shape(manifest),
            Err(ManifestError::NotVerified(Location::Step(0)))
        );

        // Windows compares service names without case.
        let mut manifest = parsed(RESTART);
        manifest.verify[0] = service_state("FAKEERP");
        assert_eq!(shape(manifest), Ok(()));

        // The expected state is the signer's: stopping a service may verify "stopped".
        let mut manifest = parsed(RESTART);
        manifest.steps[0] = Primitive::ServiceStop {
            service: "FakeErp".to_owned(),
        };
        manifest.verify[0] = Check::ServiceState {
            service: "FakeErp".to_owned(),
            state: ExpectedServiceState::Stopped,
        };
        assert_eq!(shape(manifest), Ok(()));

        // Every step counts, not only the first.
        let mut manifest = parsed(CLEAR_LOCK);
        manifest.steps.push(Primitive::ServiceStart {
            service: "OtherErp".to_owned(),
        });
        assert_eq!(
            shape(manifest),
            Err(ManifestError::NotVerified(Location::Step(2)))
        );
    }

    #[test]
    fn every_deleted_path_is_verified_and_prechecked() {
        let without_verify = |manifest: &mut Manifest| {
            manifest
                .verify
                .retain(|check| !matches!(check, Check::PathExists { .. }));
        };
        let mut manifest = parsed(CLEAR_LOCK);
        without_verify(&mut manifest);
        assert_eq!(
            shape(manifest),
            Err(ManifestError::NotVerified(Location::Step(0)))
        );

        // The signer may expect the file gone, or back (an ERP recreates its lock).
        for check in [
            Check::PathAbsent {
                path: LOCK.to_owned(),
            },
            Check::PathExists {
                path: "c:/fakeerp/RUN/erp.lock".to_owned(),
            },
        ] {
            let mut manifest = parsed(CLEAR_LOCK);
            without_verify(&mut manifest);
            manifest.verify.push(check.clone());
            assert_eq!(shape(manifest), Ok(()), "{check:?}");
        }

        // A check on another file proves nothing about this one.
        let mut manifest = parsed(CLEAR_LOCK);
        without_verify(&mut manifest);
        manifest.verify.push(Check::PathAbsent {
            path: r"C:\FakeErp\run\erp.lock2".to_owned(),
        });
        assert_eq!(
            shape(manifest),
            Err(ManifestError::NotVerified(Location::Step(0)))
        );

        // Deleting needs to know the file is there first, on the same path.
        for precondition in [
            None,
            Some(Check::PathAbsent {
                path: LOCK.to_owned(),
            }),
            Some(Check::PathExists {
                path: r"C:\FakeErp\run".to_owned(),
            }),
        ] {
            let mut manifest = parsed(CLEAR_LOCK);
            manifest
                .preconditions
                .retain(|check| check.path().is_none());
            manifest.preconditions.extend(precondition.clone());
            assert_eq!(
                shape(manifest),
                Err(ManifestError::DeleteNotPrechecked(Location::Step(0))),
                "{precondition:?}"
            );
        }
    }

    #[test]
    fn paths_must_have_a_plain_shape() {
        for path in [
            // The SYSTEM service would authenticate to someone else's file server.
            r"\\attacker.example\share\x",
            r"\\?\C:\FakeErp\x",
            r"C:\FakeErp\..\Windows\win.ini",
            r"FakeErp\run\erp.lock",
            r"C:\FakeErp\NUL",
            r"C:\FakeErp\x.txt:hidden",
            r"C:\FakeErp\*.lock",
            "C:",
            r"C:\",
            "",
        ] {
            let check = |make: fn(String) -> Check| make(path.to_owned());
            let exists = check(|path| Check::PathExists { path });
            let absent = check(|path| Check::PathAbsent { path });

            let mut step = parsed(CLEAR_LOCK);
            step.steps[0] = Primitive::DeleteFile {
                path: path.to_owned(),
            };
            assert_eq!(
                shape(step),
                Err(ManifestError::InvalidPath(Location::Step(0))),
                "{path:?}"
            );

            for check in [exists, absent] {
                let mut precondition = parsed(CLEAR_LOCK);
                precondition.preconditions[1] = check.clone();
                assert_eq!(
                    shape(precondition),
                    Err(ManifestError::InvalidPath(Location::Precondition(1))),
                    "{path:?}"
                );

                let mut verify = parsed(CLEAR_LOCK);
                verify.verify.push(check);
                let at = Location::Verify(verify.verify.len() - 1);
                assert_eq!(
                    shape(verify),
                    Err(ManifestError::InvalidPath(at)),
                    "{path:?}"
                );
            }
        }
    }

    #[test]
    fn disk_check_needs_a_drive_and_a_real_percentage() {
        for mount in [r"\\attacker.example\share", r"C:\", "C", "1:", "CC:", ""] {
            let mut manifest = parsed(RESTART);
            manifest.preconditions[0] = Check::DiskFreeAtLeast {
                mount: mount.to_owned(),
                percent: 2,
            };
            assert_eq!(
                shape(manifest),
                Err(ManifestError::InvalidMount(Location::Precondition(0))),
                "{mount:?}"
            );
        }

        let percent = |percent| {
            let mut manifest = parsed(RESTART);
            manifest.preconditions[0] = Check::DiskFreeAtLeast {
                mount: "C:".to_owned(),
                percent,
            };
            shape(manifest)
        };
        assert_eq!(percent(1), Ok(()));
        assert_eq!(percent(100), Ok(()));
        // 0 is always true: it would satisfy a check without checking anything.
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

    /// The rules of the refused primitives stay for the ADR that re-enables them.
    #[test]
    fn read_tail_is_bounded() {
        let read = |max_bytes| {
            check_step(
                &Primitive::ReadFileTail {
                    path: r"C:\FakeErp\logs\error.log".to_owned(),
                    max_bytes,
                },
                Location::Step(0),
            )
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

    /// One manifest per place a service name can appear, each valid unless `name` is not.
    fn manifests_naming(name: &str) -> Vec<(Manifest, Location)> {
        let step = |primitive| {
            let mut manifest = parsed(RESTART);
            manifest.steps[0] = primitive;
            manifest.verify[0] = service_state(name);
            (manifest, Location::Step(0))
        };
        let mut precondition = parsed(RESTART);
        precondition.preconditions[0] = service_state(name);
        let mut verify = parsed(RESTART);
        verify.verify.push(service_state(name));

        let name = name.to_owned();
        vec![
            step(Primitive::ServiceStart {
                service: name.clone(),
            }),
            step(Primitive::ServiceStop {
                service: name.clone(),
            }),
            step(Primitive::ServiceRestart { service: name }),
            (precondition, Location::Precondition(0)),
            (verify, Location::Verify(1)),
        ]
    }

    /// Names that are neither a service, a process image nor a connection.
    const NOT_NAMES: &[&str] = &[
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
    ];

    #[test]
    fn service_names_must_be_plain_ascii() {
        let too_long = "x".repeat(MAX_NAME_LEN + 1);
        // Outside ASCII: the agent refuses such a service whatever the list says.
        let not_ascii = ["Gest\u{e3}o", "\u{212a}eyIso", "FakeErp\u{a0}"];
        for name in NOT_NAMES
            .iter()
            .copied()
            .chain([too_long.as_str()])
            .chain(not_ascii)
        {
            for (manifest, at) in manifests_naming(name) {
                assert_eq!(
                    shape(manifest),
                    Err(ManifestError::InvalidName(at)),
                    "{name:?} in {at}"
                );
            }
        }

        let longest = "x".repeat(MAX_NAME_LEN);
        for name in [
            "FakeErp",
            "MSSQL$SQLEXPRESS",
            "postgresql-x64-14",
            "erp_backup",
            "ERP Sistema",
            longest.as_str(),
        ] {
            for (manifest, at) in manifests_naming(name) {
                assert_eq!(shape(manifest), Ok(()), "{name:?} in {at}");
            }
        }
    }

    #[test]
    fn image_and_connection_names_must_be_plain() {
        let too_long = "x".repeat(MAX_NAME_LEN + 1);
        let named = |name: &str| {
            [
                Primitive::KillProcess {
                    image: name.to_owned(),
                },
                Primitive::SqlReadonly {
                    connection: name.to_owned(),
                    query: "select 1".to_owned(),
                },
            ]
            .map(|step| check_step(&step, Location::Step(0)))
        };
        for name in NOT_NAMES.iter().copied().chain([too_long.as_str()]) {
            for result in named(name) {
                assert_eq!(
                    result,
                    Err(ManifestError::InvalidName(Location::Step(0))),
                    "{name:?}"
                );
            }
        }
        for name in ["erp.exe", "ERP Sistema.exe", "Gest\u{e3}o.exe"] {
            for result in named(name) {
                assert_eq!(result, Ok(()), "{name:?}");
            }
        }
    }

    #[test]
    fn changing_the_machine_requires_verification() {
        let mut manifest = parsed(RESTART);
        manifest.verify.clear();
        assert_eq!(shape(manifest.clone()), Err(ManifestError::NoVerify));

        // Starting a service is only low risk, and it still changes the machine.
        manifest.risk = RiskLevel::Low;
        manifest.steps[0] = Primitive::ServiceStart {
            service: "FakeErp".to_owned(),
        };
        assert_eq!(shape(manifest), Err(ManifestError::NoVerify));
    }

    #[test]
    fn errors_do_not_quote_the_manifest() {
        let mut manifest = parsed(CLEAR_LOCK);
        manifest.steps[0] = Primitive::DeleteFile {
            path: r"C:\Clientes\cadastro.db\..\x".to_owned(),
        };
        let error = shape(manifest).unwrap_err().to_string();
        assert!(!error.contains("Clientes"), "{error}");

        let mut manifest = parsed(RESTART);
        manifest.verify[0] = service_state("Cliente Joana");
        let error = shape(manifest).unwrap_err();
        assert_eq!(error, ManifestError::NotVerified(Location::Step(0)));
        assert!(!error.to_string().contains("Joana"));
    }

    #[test]
    fn debug_shows_id_and_version_only() {
        let valid = parsed(CLEAR_LOCK).validate_shape().unwrap();
        assert_eq!(
            format!("{valid:?}"),
            "ValidManifest(erp.clear-stale-lock v2)"
        );
    }

    #[test]
    fn unknown_fields_and_duplicate_keys_are_rejected() {
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

        // ...and in the new check.
        let absent = "[[verify]]\ncheck = \"path_absent\"\npath = 'C:\\x\\y'\nrecursive = true\n";
        assert!(Manifest::from_toml(&format!("{RESTART}\n{absent}")).is_err());

        // A key given twice is not "the last one wins": a reviewer would read the first.
        let twice = RESTART.replace("risk = \"medium\"", "risk = \"medium\"\nrisk = \"read\"");
        assert_ne!(twice, RESTART);
        assert!(Manifest::from_toml(&twice).is_err());
    }

    #[test]
    fn id_format() {
        assert!(is_valid_id("erp.restart-service"));
        assert!(is_valid_id("erp.db.check-connection2"));
        let longest = format!("a.{}", "b".repeat(MAX_ID_LEN - 2));
        assert!(is_valid_id(&longest));
        let too_long = format!("{longest}b");
        for bad in [
            "erp",
            "Erp.restart",
            "erp..x",
            "erp.-x",
            "erp.restart_service",
            "",
            too_long.as_str(),
        ] {
            assert!(!is_valid_id(bad), "{bad:?}");
        }

        let mut manifest = parsed(RESTART);
        manifest.id = too_long;
        assert_eq!(shape(manifest), Err(ManifestError::InvalidId));
    }
}
