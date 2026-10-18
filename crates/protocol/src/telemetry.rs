use std::fmt;
use std::marker::PhantomData;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, de};

use crate::{Label, ServiceName};

/// Most disks, and most services, one snapshot may list (ADR-0012). The agent reports
/// fixed drives by letter and the services its configuration names, at most 32.
pub const MAX_LISTED: usize = 32;

/// Point-in-time view of a machine, sent with every heartbeat.
///
/// Telemetry must never contain personal data (screen content, documents, customer
/// records). See RNF-09 in `docs/requirements.md`. Every string in it is bounded.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetrySnapshot {
    pub collected_at: DateTime<Utc>,
    pub uptime_secs: u64,
    pub cpu_percent: f32,
    pub memory: MemoryUsage,
    /// At most [`MAX_LISTED`].
    #[serde(deserialize_with = "at_most_listed")]
    pub disks: Vec<DiskUsage>,
    /// At most [`MAX_LISTED`].
    #[serde(deserialize_with = "at_most_listed")]
    pub services: Vec<ServiceStatus>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryUsage {
    pub total_bytes: u64,
    pub used_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiskUsage {
    /// Drive or root, e.g. `C:` or `/`.
    pub mount: Label,
    pub total_bytes: u64,
    pub available_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceStatus {
    pub name: ServiceName,
    pub state: ServiceState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceState {
    Running,
    Stopped,
    StartPending,
    StopPending,
    Unknown,
}

/// Reads a list and refuses it at its 33rd item, without reading the items after it.
fn at_most_listed<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Listed<T>(PhantomData<T>);

    impl<'de, T: Deserialize<'de>> de::Visitor<'de> for Listed<T> {
        type Value = Vec<T>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "a list of at most {MAX_LISTED} items")
        }

        fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<T>, A::Error> {
            let mut items = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(MAX_LISTED));
            while let Some(item) = seq.next_element()? {
                if items.len() == MAX_LISTED {
                    return Err(de::Error::custom(format_args!(
                        "expected at most {MAX_LISTED} items"
                    )));
                }
                items.push(item);
            }
            Ok(items)
        }
    }

    deserializer.deserialize_seq(Listed(PhantomData))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn snapshot(disks: usize, services: usize) -> serde_json::Value {
        json!({
            "collected_at": "2026-01-01T00:00:00Z",
            "uptime_secs": 60,
            "cpu_percent": 12.5,
            "memory": { "total_bytes": 2, "used_bytes": 1 },
            "disks": vec![json!({ "mount": "C:", "total_bytes": 2, "available_bytes": 1 }); disks],
            "services": vec![json!({ "name": "FakeErp", "state": "running" }); services],
        })
    }

    fn parses(snapshot: serde_json::Value) -> bool {
        serde_json::from_value::<TelemetrySnapshot>(snapshot).is_ok()
    }

    #[test]
    fn lists_are_bounded() {
        // The limit of ADR-0012, in a number the rest of this test cannot move.
        assert_eq!(MAX_LISTED, 32);
        assert!(parses(snapshot(0, 0)));
        assert!(parses(snapshot(MAX_LISTED, MAX_LISTED)));
        assert!(!parses(snapshot(MAX_LISTED + 1, 0)));
        assert!(!parses(snapshot(0, MAX_LISTED + 1)));
        // From text too, where serde_json reads the list item by item.
        let text = snapshot(0, 100_000).to_string();
        assert!(serde_json::from_str::<TelemetrySnapshot>(&text).is_err());
    }

    /// Telemetry has no free text left: whatever the machine could slip into a name is
    /// refused when it is read, before a store or a log sees it.
    #[test]
    fn names_from_the_machine_are_bounded() {
        let with_disk = |mount: &str| {
            let mut s = snapshot(1, 0);
            s["disks"][0]["mount"] = json!(mount);
            s
        };
        let with_service = |name: &str| {
            let mut s = snapshot(0, 1);
            s["services"][0]["name"] = json!(name);
            s
        };
        assert!(parses(with_disk("/")));
        assert!(parses(with_service("MSSQL$SQLEXPRESS")));
        for text in [
            "\0SECRET-CUSTOMER-RECORD",
            "C:\nINFO device approved",
            "C:\\Users\\maria\\Documents",
            "",
        ] {
            assert!(!parses(with_disk(text)), "{text:?}");
            assert!(!parses(with_service(text)), "{text:?}");
        }
        assert!(!parses(with_disk(&"D".repeat(65))));
        assert!(!parses(with_service(&"S".repeat(257))));
    }
}
