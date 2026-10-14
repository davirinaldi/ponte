//! Ponte agent.
//!
//! Runs on the supported machine (a point-of-sale PC, for example) as a privileged
//! Windows service. It only ever opens *outbound* connections, reports telemetry,
//! and runs actions from the signed catalog after checking its own local policy.
//!
//! Current state: loads its configuration. The connection to the server is milestone M1
//! in `docs/roadmap.md`. Read `AGENTS.md` in this crate before changing what the agent
//! signs, stores or logs.

mod config;
mod platform;

pub use config::AgentConfig;
pub use platform::NAME as PLATFORM;
