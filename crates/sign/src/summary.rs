//! What a manifest does, as `sign` and `show` print it for the person who answers for it
//! (ADR-0010): risk, steps, every path and service, the validity and the key.
//!
//! The bytes of a manifest pass `ManifestText`, but TOML decodes escapes into any
//! character, and `show` prints envelopes that were never validated. So every value is
//! escaped here: what `ManifestText` refuses is written as `<U+XXXX>`, a value meant for
//! one line stays on one line, and every line of a description is quoted with `|`, so no
//! manifest can move the cursor, hide text or print a section of its own.

use std::fmt::Write as _;

use chrono::DateTime;
use ponte_actions::{Check, ExpectedServiceState, Manifest, Primitive, RiskLevel};
use ponte_protocol::{ManifestText, PublicKey};

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
        &format!("{}, version {}", one_line(&manifest.id), manifest.version),
    );
    line("Title", &one_line(&manifest.title));
    line("Risk", risk(manifest.risk));
    line("Timeout", &format!("{} s", manifest.timeout_secs));
    line("Signing key", &key.to_string());
    line("Valid", &validity(issued_at, expires_at));

    let mut quote = |title: &str, text: &str| {
        let _ = writeln!(out, "\n{title}");
        for text_line in text.trim_end().lines() {
            let _ = writeln!(out, "  | {}", one_line(text_line));
        }
    };
    quote("Description", &manifest.description);
    quote("For the AI", &manifest.ai_description);

    let mut section = |title: &str, items: Vec<String>| {
        let _ = writeln!(out, "\n{title}");
        if items.is_empty() {
            let _ = writeln!(out, "  (none)");
        }
        for (index, item) in items.iter().enumerate() {
            let _ = writeln!(out, "  {index}. {}", one_line(item));
        }
    };
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
        items
            .iter()
            .map(|item| one_line(item))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// `text` as it may reach the terminal: its lines kept, each through [`one_line`]. For
/// messages that quote what a parser read, such as an unknown field of a stranger's
/// envelope, after its escapes were decoded.
pub(crate) fn printable(text: &str) -> String {
    text.split('\n')
        .map(one_line)
        .collect::<Vec<_>>()
        .join("\n")
}

/// `text` on one line, with every character `ManifestText` refuses, and the line feed and
/// the tab, written as `<U+XXXX>`.
fn one_line(text: &str) -> String {
    let mut shown = String::with_capacity(text.len());
    for c in text.chars() {
        if ManifestText::allows(c) && !matches!(c, '\n' | '\t') {
            shown.push(c);
        } else {
            let _ = write!(shown, "<U+{:04X}>", u32::from(c));
        }
    }
    shown
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

    /// What an escape in the TOML can decode into never reaches the terminal raw, and no
    /// value starts a line of its own.
    #[test]
    fn nothing_printed_can_steer_the_terminal() {
        let mut manifest = Manifest::from_toml(CLEAR_LOCK).unwrap();
        let esc = char::from(0x1b);
        let bell = char::from(0x07);
        let rlo = char::from_u32(0x202e).unwrap();
        manifest.title = format!("Restart\rRead-only check{esc}[8m");
        manifest.description = format!("Harmless.\nSteps\n  0. check the disk{esc}[8m");
        manifest.ai_description = format!("x{esc}]0;pwned{bell} {rlo}abc");
        manifest.steps[0] = Primitive::DeleteFile {
            path: format!(r"C:\FakeErp\run\a{rlo}kcol.bd") + "\nPaths  nothing",
        };
        let text = summary(&manifest, &PublicKey::from_bytes([1; 32]), 0, DAY);
        for c in text.chars() {
            assert!(c == '\n' || ManifestText::allows(c), "{c:?} in\n{text}");
        }
        assert!(text.contains("Title         Restart<U+000D>Read-only check<U+001B>[8m\n"));
        assert!(text.contains("  | Harmless.\n  | Steps\n  |   0. check the disk<U+001B>[8m\n"));
        assert!(text.contains("x<U+001B>]0;pwned<U+0007> <U+202E>abc"));
        assert!(text.contains("a<U+202E>kcol.bd<U+000A>Paths  nothing"));
        assert!(!text.contains("\nPaths  nothing"));
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
