//! Wire protocol shared by the agent, the server and (through generated types) the web console.
//!
//! Every message that crosses a process boundary is defined here, exactly once.
//! Changing a type in this crate changes the wire format: read `AGENTS.md` in this
//! crate before editing.

mod ids;
mod messages;
mod telemetry;

pub use ids::{DeviceId, RequestId};
pub use messages::{
    ActionOutcome, ActionRequest, ActionResult, AgentToServer, Initiator, ServerToAgent,
};
pub use telemetry::{DiskUsage, MemoryUsage, ServiceState, ServiceStatus, TelemetrySnapshot};

/// Version of the agent <-> server protocol. Bump it on any breaking wire change.
pub const PROTOCOL_VERSION: u16 = 1;
