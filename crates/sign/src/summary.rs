//! What a manifest does, as `sign` and `show` print it for the person who answers for it
//! (ADR-0010): risk, steps, every path and service, the validity and the key.
//!
//! Every string printed here passed `ManifestText`, which has no control characters, so
//! a manifest cannot move the cursor or recolour the terminal.

use std::fmt::Write as _;

use chrono::DateTime;
use ponte_actions::{Check, ExpectedServiceState, Manifest, Primitive, RiskLevel};
use ponte_protocol::PublicKey;

const DAY: u64 = 24 * 60 * 60;

/// The text of the summary, ending with a newline.
pub(crate) fn summary(
    manifest: &Manifest,
    key: &PublicKey,
    issued_at: u64,
    expires_at: u64,
) -> String {
    let mut out = String::new();
    let mut line = |label: &str, value: &str| {
        let _ = writeln!(out, "{label:<14}{value}");
    };
    line(
        "Manifest",
        &format!("{}, version {}", manifest.id, manifest.version),
    );
    line("Title", &manifest.title);
    line("Risk", risk(manifest.risk));
    line("Timeout", &format!("{} s", manifest.timeout_secs));
    line("Signing key", &key.to_string());
    line("Valid", &validity(issued_at, expires_at));

    let mut section = |title: &str, items: Vec<String>| {
        let _ = writeln!(out, "\n{title}");
        if items.is_empty() {
            let _ = writeln!(out, "  (none)");
        }
        for (index, item) in items.iter().enumerate() {
            let _ = writeln!(out, "  {index}. {item}");
        }
    };
    section(
        "Description",
        vec![manifest.description.trim_end().to_owned()],
    );
    section(
        "For the AI",
        vec![manifest.ai_description.trim_end().to_owned()],
    );
    section(
        "Preconditions",
        manifest.preconditions.iter().map(check).collect(),
    );
    section("Steps", manifest.steps.iter().map(step).collect());
    section("Verify", manifest.verify.iter().map(check).collect());

    let mut services: Vec<&str> = Vec::new();
    let mut paths: Vec<&str> = Vec::new();
    let named = (manifest.steps.iter().map(|s| (s.service(), s.path())))
        .chain(
            manifest
                .preconditions
                .iter()
                .map(|c| (c.service(), c.path())),
        )
        .chain(manifest.verify.iter().map(|c| (c.service(), c.path())));
    for (service, path) in named {
        if let Some(service) = service
            && !services
                .iter()
                .any(|known| known.eq_ignore_ascii_case(service))
        {
            services.push(service);
        }
        if let Some(path) = path
            && !paths.contains(&path)
        {
            paths.push(path);
        }
    }
    let _ = writeln!(out);
    let mut line = |label: &str, value: &str| {
        let _ = writeln!(out, "{label:<14}{value}");
    };
    line("Services", &list(&services));
    line("Paths", &list(&paths));
    out
}

fn list(items: &[&str]) -> String {
    if items.is_empty() {
        "(none)".to_owned()
    } else {
        items.join(", ")
    }
}

const fn risk(risk: RiskLevel) -> &'static str {
    match risk {
        RiskLevel::Read => "read",
        RiskLevel::Low => "low",
        RiskLevel::Medium => "medium",
        RiskLevel::High => "high (agents refuse it until the consent prompt of M4)",
    }
}

fn validity(issued_at: u64, expires_at: u64) -> String {
    let days = expires_at.checked_sub(issued_at).map_or_else(
        || "ends before it starts".to_owned(),
        |window| {
            let days = window / DAY;
            if window % DAY == 0 {
                format!("{days} days")
            } else {
                format!("{days} days and {} s", window % DAY)
            }
        },
    );
    format!("{} to {} ({days})", date(issued_at), date(expires_at))
}

fn date(seconds: u64) -> String {
    i64::try_from(seconds)
        .ok()
        .and_then(|seconds| DateTime::from_timestamp(seconds, 0))
        .map_or_else(
            || format!("{seconds} (not a date)"),
            |date| date.format("%Y-%m-%d %H:%M UTC").to_string(),
        )
}

fn state(state: ExpectedServiceState) -> &'static str {
    match state {
        ExpectedServiceState::Running => "running",
        ExpectedServiceState::Stopped => "stopped",
    }
}

fn check(check: &Check) -> String {
    match check {
        Check::ServiceState {
            service,
            state: expected,
        } => {
            format!("service {service} is {}", state(*expected))
        }
        Check::PathExists { path } => format!("{path} exists"),
        Check::PathAbsent { path } => format!("{path} does not exist"),
        Check::DiskFreeAtLeast { mount, percent } => {
            format!("drive {mount} has at least {percent}% free")
        }
    }
}

fn step(step: &Primitive) -> String {
    match step {
        Primitive::ServiceStart { service } => format!("start service {service}"),
        Primitive::ServiceStop { service } => format!("stop service {service}"),
        Primitive::ServiceRestart { service } => format!("restart service {service}"),
        Primitive::DeleteFile { path } => format!("delete the file {path}"),
        Primitive::ReadFileTail { path, max_bytes } => {
            format!("read the last {max_bytes} bytes of {path}")
        }
        Primitive::ClearTempDir {} => "empty the ERP account's temp folder".to_owned(),
        Primitive::KillProcess { image } => format!("kill every process named {image}"),
        Primitive::SqlReadonly { connection, query } => {
            format!("run on {connection}, read-only: {query}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLEAR_LOCK: &str = include_str!("../../../manifests/examples/erp-clear-stale-lock.toml");

    #[test]
    fn the_summary_names_everything_the_action_touches() {
        let manifest = Manifest::from_toml(CLEAR_LOCK).unwrap();
        let key = PublicKey::from_bytes([0xab; 32]);
        // 2026-10-18 12:00 UTC, valid for 90 days.
        let issued_at = 1_792_324_800;
        let text = summary(&manifest, &key, issued_at, issued_at + 90 * DAY);
        for expected in [
            "Manifest      erp.clear-stale-lock, version 2\n",
            "Risk          medium\n",
            "Timeout       60 s\n",
            &format!("Signing key   {key}\n"),
            "Valid         2026-10-18 12:00 UTC to 2027-01-16 12:00 UTC (90 days)\n",
            "  0. service FakeErp is stopped\n",
            "  1. C:\\FakeErp\\run\\erp.lock exists\n",
            "  0. delete the file C:\\FakeErp\\run\\erp.lock\n",
            "  1. start service FakeErp\n",
            "  0. service FakeErp is running\n",
            "Services      FakeErp\n",
            "Paths         C:\\FakeErp\\run\\erp.lock\n",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in\n{text}");
        }
    }

    #[test]
    fn odd_dates_are_shown_as_numbers() {
        assert_eq!(
            validity(10, 5),
            "1970-01-01 00:00 UTC to 1970-01-01 00:00 UTC (ends before it starts)"
        );
        assert!(validity(0, u64::MAX).contains("18446744073709551615 (not a date)"));
        assert!(validity(0, DAY + 1).ends_with("(1 days and 1 s)"));
    }
}
