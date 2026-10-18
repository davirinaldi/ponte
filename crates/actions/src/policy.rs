//! The agent's own policy (ADR-0011), applied to every verified manifest whatever the
//! server decided: a risk ceiling, the services this machine lets a manifest touch, a
//! list of services never touched, and where a manifest may look and delete.
//!
//! A [`RunnableManifest`] is the end of the typestate and the only thing the agent runs.

use std::fmt;

use ponte_protocol::{PublicKey, RejectReason, ServiceName};
use serde::Deserialize;

use crate::{Location, Manifest, Primitive, RiskLevel, Roots, VerifiedManifest};

/// Most services one configuration may name (ADR-0011).
pub const MAX_ALLOWED_SERVICES: usize = 32;

/// Services no manifest touches, whatever `allowed_services` says (ADR-0011): Windows
/// security, the event log, the plumbing every other service needs, and the agent itself.
/// Compared without case, as Windows does. The agent also refuses by structure (shared
/// processes, drivers, protected services, binaries under `%SystemRoot%`) when it reads
/// the service manager; this list is what holds before that, and on every platform.
pub const REFUSED_SERVICES: &[&str] = &[
    // The agent itself.
    "PonteAgent",
    // Microsoft Defender, the firewall and the security center.
    "WinDefend",
    "WdNisSvc",
    "WdFilter",
    "WdNisDrv",
    "WdBoot",
    "Sense",
    "SecurityHealthService",
    "wscsvc",
    "MpsSvc",
    "BFE",
    "mpsdrv",
    // Logs and auditing.
    "EventLog",
    "EventSystem",
    // What every other service stands on.
    "RpcSs",
    "RpcEptMapper",
    "DcomLaunch",
    "LSM",
    "lsass",
    "SamSs",
    "KeyIso",
    "VaultSvc",
    "CryptSvc",
    "Netlogon",
    "gpsvc",
    "Winmgmt",
    "PlugPlay",
    "Power",
    "ProfSvc",
    "Schedule",
    "Dnscache",
    "nsi",
    "Dhcp",
    // Installing and updating software.
    "TrustedInstaller",
    "msiserver",
    "wuauserv",
    "UsoSvc",
    "BITS",
    // Recovery and remote access.
    "VSS",
    "swprv",
    "TermService",
    "WinRM",
];

/// Whether `name` is on [`REFUSED_SERVICES`].
#[must_use]
pub fn is_refused_service(name: &str) -> bool {
    REFUSED_SERVICES
        .iter()
        .any(|refused| refused.eq_ignore_ascii_case(name))
}

/// The highest risk a machine runs (`max_risk`). `high` is not a value: it waits for the
/// consent prompt of M4 (ADR-0011), so a configuration that asks for it does not parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskCeiling {
    Read,
    Low,
    #[default]
    Medium,
}

impl RiskCeiling {
    #[must_use]
    pub const fn level(self) -> RiskLevel {
        match self {
            Self::Read => RiskLevel::Read,
            Self::Low => RiskLevel::Low,
            Self::Medium => RiskLevel::Medium,
        }
    }
}

/// The services a manifest may name on this machine (`allowed_services`): at most
/// [`MAX_ALLOWED_SERVICES`], ASCII, none twice, none refused. Empty means none.
#[derive(Debug, Clone, Default)]
pub struct AllowedServices(Vec<ServiceName>);

/// Why a list of services was refused. Says which entry, counted from 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AllowedServicesError {
    #[error("at most {MAX_ALLOWED_SERVICES} services are allowed")]
    TooMany,
    #[error("service {0} is listed twice")]
    Duplicate(usize),
    #[error("service {0} is one the agent never touches")]
    Refused(usize),
}

impl AllowedServices {
    /// # Errors
    /// The list is too long, repeats a name (without case), or names a refused service.
    pub fn new(names: impl IntoIterator<Item = ServiceName>) -> Result<Self, AllowedServicesError> {
        let mut allowed: Vec<ServiceName> = Vec::new();
        for (index, name) in names.into_iter().enumerate() {
            if index == MAX_ALLOWED_SERVICES {
                return Err(AllowedServicesError::TooMany);
            }
            if is_refused_service(name.as_str()) {
                return Err(AllowedServicesError::Refused(index));
            }
            if allowed
                .iter()
                .any(|known| known.as_str().eq_ignore_ascii_case(name.as_str()))
            {
                return Err(AllowedServicesError::Duplicate(index));
            }
            allowed.push(name);
        }
        Ok(Self(allowed))
    }

    /// Whether `name` is on the list, without case.
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.0
            .iter()
            .any(|allowed| allowed.as_str().eq_ignore_ascii_case(name))
    }
}

/// What a machine allows, built from the agent's configuration.
#[derive(Debug, Clone, Default)]
pub struct LocalPolicy {
    pub roots: Roots,
    pub services: AllowedServices,
    pub max_risk: RiskCeiling,
}

/// Why the local policy refused a verified manifest. Says where, never what.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    #[error("the manifest's risk is above what this machine runs")]
    RiskAboveCeiling,
    #[error("{0} names a service the agent never touches")]
    ServiceRefused(Location),
    #[error("{0} names a service that is not in allowed_services")]
    ServiceNotAllowed(Location),
    #[error("{0} names a path outside the roots its use allows")]
    PathNotAllowed(Location),
}

impl PolicyError {
    /// The code the agent answers with (ADR-0012).
    #[must_use]
    pub const fn reject_reason(&self) -> RejectReason {
        match self {
            Self::RiskAboveCeiling => RejectReason::RiskAboveCeiling,
            Self::ServiceRefused(_) => RejectReason::ServiceRefused,
            Self::ServiceNotAllowed(_) => RejectReason::ServiceNotAllowed,
            Self::PathNotAllowed(_) => RejectReason::PathNotAllowed,
        }
    }
}

/// A manifest that is signed, valid, inside its validity and allowed by this machine's
/// policy. The only thing the agent executes; only [`VerifiedManifest::validate`] makes
/// one.
pub struct RunnableManifest(VerifiedManifest);

impl RunnableManifest {
    #[must_use]
    pub fn manifest(&self) -> &Manifest {
        self.0.manifest()
    }

    /// The trusted key that signed it.
    #[must_use]
    pub const fn public_key(&self) -> &PublicKey {
        self.0.public_key()
    }

    /// Seconds since the Unix epoch. Steps never start after it.
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.0.expires_at()
    }
}

/// The id and version only: the rest names paths and services, which logs do not.
impl fmt::Debug for RunnableManifest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let manifest = self.manifest();
        write!(f, "RunnableManifest({} v{})", manifest.id, manifest.version)
    }
}

impl VerifiedManifest {
    /// Applies this machine's policy (ADR-0011). `high` risk is refused whatever the
    /// ceiling; every service a step or a check names must be off [`REFUSED_SERVICES`] and
    /// on `allowed_services`; every path must lie in an allowed root, and the path of a
    /// `delete_file` in a delete root.
    ///
    /// # Errors
    /// The first rule the manifest breaks, steps first, then preconditions, then verify.
    pub fn validate(self, policy: &LocalPolicy) -> Result<RunnableManifest, PolicyError> {
        let manifest = self.manifest();
        if manifest.risk >= RiskLevel::High || manifest.risk > policy.max_risk.level() {
            return Err(PolicyError::RiskAboveCeiling);
        }
        for (index, step) in manifest.steps.iter().enumerate() {
            let at = Location::Step(index);
            check_service(policy, step.service(), at)?;
            check_path(policy, step.path(), at)?;
            // Listed one by one: a primitive that deletes must say where it may.
            let deletes = match step {
                Primitive::DeleteFile { path } => Some(path),
                Primitive::ServiceStart { .. }
                | Primitive::ServiceStop { .. }
                | Primitive::ServiceRestart { .. }
                | Primitive::ReadFileTail { .. }
                | Primitive::ClearTempDir {}
                | Primitive::KillProcess { .. }
                | Primitive::SqlReadonly { .. } => None,
            };
            if deletes.is_some_and(|path| !policy.roots.delete().is_allowed(path)) {
                return Err(PolicyError::PathNotAllowed(at));
            }
        }
        let checks = (manifest.preconditions.iter().enumerate())
            .map(|(index, check)| (check, Location::Precondition(index)))
            .chain(
                (manifest.verify.iter().enumerate())
                    .map(|(index, check)| (check, Location::Verify(index))),
            );
        for (check, at) in checks {
            check_service(policy, check.service(), at)?;
            check_path(policy, check.path(), at)?;
        }
        Ok(RunnableManifest(self))
    }
}

fn check_service(
    policy: &LocalPolicy,
    service: Option<&str>,
    at: Location,
) -> Result<(), PolicyError> {
    match service {
        Some(name) if is_refused_service(name) => Err(PolicyError::ServiceRefused(at)),
        Some(name) if !policy.services.contains(name) => Err(PolicyError::ServiceNotAllowed(at)),
        _ => Ok(()),
    }
}

fn check_path(policy: &LocalPolicy, path: Option<&str>, at: Location) -> Result<(), PolicyError> {
    match path {
        Some(path) if !policy.roots.allowed().is_allowed(path) => {
            Err(PolicyError::PathNotAllowed(at))
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Check, ExpectedServiceState};

    const RESTART: &str = include_str!("../../../manifests/examples/erp-restart-service.toml");
    const CLEAR_LOCK: &str = include_str!("../../../manifests/examples/erp-clear-stale-lock.toml");

    fn services(names: &[&str]) -> AllowedServices {
        AllowedServices::new(names.iter().map(|name| name.parse().unwrap())).unwrap()
    }

    /// What a lab machine with the FakeErp would configure.
    fn policy() -> LocalPolicy {
        LocalPolicy {
            roots: Roots::new([r"C:\FakeErp"], [r"C:\FakeErp\run"]).unwrap(),
            services: services(&["FakeErp"]),
            max_risk: RiskCeiling::Medium,
        }
    }

    fn verified(manifest: Manifest) -> VerifiedManifest {
        VerifiedManifest::for_test(manifest.validate_shape().unwrap())
    }

    fn parsed(source: &str) -> Manifest {
        Manifest::from_toml(source).unwrap()
    }

    fn run(manifest: Manifest, policy: &LocalPolicy) -> Result<(), PolicyError> {
        verified(manifest).validate(policy).map(drop)
    }

    /// The example manifests, with `FakeErp` swapped for `service`.
    fn naming(source: &str, service: &str) -> Manifest {
        parsed(&source.replace("\"FakeErp\"", &format!("\"{service}\"")))
    }

    #[test]
    fn the_examples_run_on_a_machine_that_allows_them() {
        for source in [RESTART, CLEAR_LOCK] {
            let runnable = verified(parsed(source)).validate(&policy()).unwrap();
            assert_eq!(runnable.manifest().id, parsed(source).id);
        }
        let runnable = verified(parsed(RESTART)).validate(&policy()).unwrap();
        assert_eq!(
            format!("{runnable:?}"),
            "RunnableManifest(erp.restart-service v1)"
        );
    }

    #[test]
    fn nothing_runs_under_the_default_policy() {
        for source in [RESTART, CLEAR_LOCK] {
            assert!(run(parsed(source), &LocalPolicy::default()).is_err());
        }
    }

    #[test]
    fn risk_above_the_ceiling_is_refused() {
        for ceiling in [RiskCeiling::Read, RiskCeiling::Low] {
            let policy = LocalPolicy {
                max_risk: ceiling,
                ..policy()
            };
            assert_eq!(
                run(parsed(RESTART), &policy),
                Err(PolicyError::RiskAboveCeiling),
                "{ceiling:?}"
            );
        }
        // Low risk under a low ceiling runs.
        let mut start = parsed(RESTART);
        start.risk = RiskLevel::Low;
        start.steps[0] = Primitive::ServiceStart {
            service: "FakeErp".to_owned(),
        };
        let low = LocalPolicy {
            max_risk: RiskCeiling::Low,
            ..policy()
        };
        assert_eq!(run(start, &low), Ok(()));

        // High is refused under every ceiling, the highest included.
        let mut high = parsed(RESTART);
        high.risk = RiskLevel::High;
        assert_eq!(run(high, &policy()), Err(PolicyError::RiskAboveCeiling));
    }

    #[test]
    fn a_ceiling_of_high_does_not_parse() {
        #[derive(Deserialize)]
        struct Config {
            #[serde(default)]
            max_risk: RiskCeiling,
        }
        let ceiling = |toml: &str| toml::from_str::<Config>(toml).map(|c| c.max_risk);
        assert_eq!(ceiling("").unwrap(), RiskCeiling::Medium);
        assert_eq!(ceiling("max_risk = \"read\"").unwrap(), RiskCeiling::Read);
        assert_eq!(ceiling("max_risk = \"low\"").unwrap(), RiskCeiling::Low);
        for refused in ["\"high\"", "\"High\"", "\"MEDIUM\"", "3"] {
            assert!(
                ceiling(&format!("max_risk = {refused}")).is_err(),
                "{refused}"
            );
        }
    }

    #[test]
    fn every_service_named_must_be_allowed() {
        // In a step, and through it in the verify check that covers it.
        assert_eq!(
            run(naming(RESTART, "OtherErp"), &policy()),
            Err(PolicyError::ServiceNotAllowed(Location::Step(0)))
        );
        // In a check alone: reading a service's state is touching it too.
        let mut manifest = parsed(RESTART);
        manifest.preconditions[0] = Check::ServiceState {
            service: "OtherErp".to_owned(),
            state: ExpectedServiceState::Running,
        };
        assert_eq!(
            run(manifest.clone(), &policy()),
            Err(PolicyError::ServiceNotAllowed(Location::Precondition(0)))
        );
        let mut verify = parsed(RESTART);
        verify.verify.push(manifest.preconditions[0].clone());
        assert_eq!(
            run(verify, &policy()),
            Err(PolicyError::ServiceNotAllowed(Location::Verify(1)))
        );
        // Windows compares service names without case.
        let lower = LocalPolicy {
            services: services(&["fakeerp"]),
            ..policy()
        };
        assert_eq!(run(parsed(RESTART), &lower), Ok(()));
    }

    #[test]
    fn refused_services_win_over_the_list() {
        for name in ["WinDefend", "windefend", "EVENTLOG", "PonteAgent", "lsass"] {
            // Even if a list got one in, which `AllowedServices::new` does not allow.
            let careless = LocalPolicy {
                services: AllowedServices(vec!["FakeErp".parse().unwrap(), name.parse().unwrap()]),
                ..policy()
            };
            assert_eq!(
                run(naming(RESTART, name), &careless),
                Err(PolicyError::ServiceRefused(Location::Step(0))),
                "{name}"
            );
            let mut check_only = parsed(RESTART);
            check_only.preconditions[0] = Check::ServiceState {
                service: name.to_owned(),
                state: ExpectedServiceState::Running,
            };
            assert_eq!(
                run(check_only, &careless),
                Err(PolicyError::ServiceRefused(Location::Precondition(0))),
                "{name}"
            );
        }
    }

    #[test]
    fn the_list_of_services_is_bounded_and_clean() {
        let name = |index: usize| format!("Erp{index}").parse::<ServiceName>().unwrap();
        assert!(AllowedServices::new((0..MAX_ALLOWED_SERVICES).map(name)).is_ok());
        assert_eq!(
            AllowedServices::new((0..=MAX_ALLOWED_SERVICES).map(name)).unwrap_err(),
            AllowedServicesError::TooMany
        );
        let parse =
            |names: &[&str]| AllowedServices::new(names.iter().map(|name| name.parse().unwrap()));
        assert_eq!(
            parse(&["FakeErp", "fakeERP"]).unwrap_err(),
            AllowedServicesError::Duplicate(1)
        );
        assert_eq!(
            parse(&["FakeErp", "windefend"]).unwrap_err(),
            AllowedServicesError::Refused(1)
        );
        assert!(!AllowedServices::default().contains("FakeErp"));
    }

    #[test]
    fn the_refused_list_is_pinned() {
        assert_eq!(MAX_ALLOWED_SERVICES, 32);
        for name in [
            "PonteAgent",
            "WinDefend",
            "MpsSvc",
            "EventLog",
            "RpcSs",
            "CryptSvc",
            "BFE",
            "Sense",
            "WdFilter",
            "lsass",
        ] {
            assert!(is_refused_service(name), "{name}");
            assert!(is_refused_service(&name.to_ascii_uppercase()), "{name}");
        }
        for name in REFUSED_SERVICES {
            assert!(name.parse::<ServiceName>().is_ok(), "{name}");
        }
        assert!(!is_refused_service("FakeErp"));
        // A prefix is not the name.
        assert!(!is_refused_service("WinDefendX"));
    }

    #[test]
    fn every_path_must_lie_in_an_allowed_root() {
        let elsewhere = r"C:\Other\run\erp.lock";
        let manifest = parsed(&CLEAR_LOCK.replace(r"C:\FakeErp\run\erp.lock", elsewhere));
        assert_eq!(
            run(manifest, &policy()),
            Err(PolicyError::PathNotAllowed(Location::Step(0)))
        );

        let mut check_only = parsed(RESTART);
        check_only.verify.push(Check::PathAbsent {
            path: r"C:\Users\joana\Documents\x.pdf".to_owned(),
        });
        assert_eq!(
            run(check_only, &policy()),
            Err(PolicyError::PathNotAllowed(Location::Verify(1)))
        );

        let mut precondition = parsed(RESTART);
        precondition.preconditions.push(Check::PathExists {
            path: r"C:\FakeErpEvil\x".to_owned(),
        });
        assert_eq!(
            run(precondition, &policy()),
            Err(PolicyError::PathNotAllowed(Location::Precondition(1)))
        );
    }

    #[test]
    fn deleting_needs_a_delete_root() {
        // Readable is not deletable: the database is in an allowed root, not a delete root.
        let database = r"C:\FakeErp\data\erp.db";
        let manifest = parsed(&CLEAR_LOCK.replace(r"C:\FakeErp\run\erp.lock", database));
        assert_eq!(
            run(manifest.clone(), &policy()),
            Err(PolicyError::PathNotAllowed(Location::Step(0)))
        );
        // Checking that it exists is fine.
        let mut check = parsed(RESTART);
        check.preconditions.push(Check::PathExists {
            path: database.to_owned(),
        });
        assert_eq!(run(check, &policy()), Ok(()));

        // No delete root at all: nothing is deleted.
        let no_delete = LocalPolicy {
            roots: Roots::new(vec![r"C:\FakeErp"], vec![]).unwrap(),
            ..policy()
        };
        assert_eq!(
            run(parsed(CLEAR_LOCK), &no_delete),
            Err(PolicyError::PathNotAllowed(Location::Step(0)))
        );
    }

    #[test]
    fn errors_map_to_reasons() {
        let at = Location::Step(0);
        for (error, reason) in [
            (
                PolicyError::RiskAboveCeiling,
                RejectReason::RiskAboveCeiling,
            ),
            (
                PolicyError::ServiceRefused(at),
                RejectReason::ServiceRefused,
            ),
            (
                PolicyError::ServiceNotAllowed(at),
                RejectReason::ServiceNotAllowed,
            ),
            (
                PolicyError::PathNotAllowed(at),
                RejectReason::PathNotAllowed,
            ),
        ] {
            assert_eq!(error.reject_reason(), reason);
        }
    }
}
