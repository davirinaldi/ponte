use serde::{Deserialize, Serialize};

use crate::RiskLevel;

/// One operation compiled into the agent.
///
/// This list is closed on purpose. If an action cannot be expressed with these
/// primitives, propose a new primitive in an ADR instead of adding a generic escape hatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Primitive {
    ServiceStart {
        service: String,
    },
    ServiceStop {
        service: String,
    },
    ServiceRestart {
        service: String,
    },
    /// Returns at most `max_bytes` from the end of a file under an allowed root.
    ReadFileTail {
        path: String,
        max_bytes: u64,
    },
    /// Deletes a single file under an allowed root. Never recursive.
    DeleteFile {
        path: String,
    },
    /// Empties the temp directory of the account the ERP runs as.
    ClearTempDir,
    /// Terminates every process with this image name, e.g. `erp.exe`.
    KillProcess {
        image: String,
    },
    /// Runs a fixed, read-only query against a connection configured on the agent.
    SqlReadonly {
        connection: String,
        query: String,
    },
}

impl Primitive {
    /// The minimum risk level a manifest must declare to contain this step.
    #[must_use]
    pub const fn inherent_risk(&self) -> RiskLevel {
        match self {
            Self::ReadFileTail { .. } | Self::SqlReadonly { .. } => RiskLevel::Read,
            Self::ServiceStart { .. } | Self::ClearTempDir => RiskLevel::Low,
            Self::ServiceStop { .. } | Self::ServiceRestart { .. } | Self::DeleteFile { .. } => {
                RiskLevel::Medium
            }
            Self::KillProcess { .. } => RiskLevel::High,
        }
    }

    /// The filesystem path this step touches, if any.
    #[must_use]
    pub fn path(&self) -> Option<&str> {
        match self {
            Self::ReadFileTail { path, .. } | Self::DeleteFile { path } => Some(path),
            _ => None,
        }
    }
}
