use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Point-in-time view of a machine, sent with every heartbeat.
///
/// Telemetry must never contain personal data (screen content, documents, patient
/// or customer records). See RNF-09 in `docs/requirements.md`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetrySnapshot {
    pub collected_at: DateTime<Utc>,
    pub uptime_secs: u64,
    pub cpu_percent: f32,
    pub memory: MemoryUsage,
    pub disks: Vec<DiskUsage>,
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
    /// Mount point or drive, e.g. `C:`.
    pub mount: String,
    pub total_bytes: u64,
    pub available_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceStatus {
    pub name: String,
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
