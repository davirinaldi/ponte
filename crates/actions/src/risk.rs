use serde::{Deserialize, Serialize};

/// How much damage an action can do if it runs at the wrong time or on the wrong machine.
///
/// Ordered from least to most dangerous, so `RiskLevel::Low < RiskLevel::High`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    /// Only reads state. Never changes the machine.
    Read,
    /// Changes the machine in an easily reversible way (clear a temp dir, start a service).
    Low,
    /// Interrupts the user or deletes something recoverable (restart a service).
    Medium,
    /// Can lose work or data (kill a process). Never auto-executed.
    High,
}
