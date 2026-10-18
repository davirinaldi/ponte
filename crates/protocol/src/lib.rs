//! Wire protocol shared by the agent, the server and (through generated types) the web console.
//!
//! Every message that crosses a process boundary is defined here, exactly once.
//! Changing a type in this crate changes the wire format: read `AGENTS.md` in this
//! crate before editing.

mod ids;
mod keys;
mod manifest;
mod messages;
mod telemetry;
mod text;
mod transcript;
mod version;

pub use ids::{DeviceId, RequestId};
pub use keys::{EnrollmentToken, InvalidHex, Nonce, PublicKey, Signature};
pub use manifest::{InvalidManifestText, MAX_MANIFEST_BYTES, ManifestText, SignedManifest};
pub use messages::{
    ActionOutcome, ActionRequest, ActionResult, AgentToServer, Confidence, FailReason, Initiator,
    InvalidOutput, Output, RejectReason, ServerToAgent,
};
pub use telemetry::{
    DiskUsage, MAX_LISTED, MemoryUsage, ServiceState, ServiceStatus, TelemetrySnapshot,
};
pub use text::{InvalidLabel, InvalidServiceName, Label, ServiceName};
pub use transcript::{Transcript, enroll_transcript, hello_transcript, manifest_transcript};
pub use version::ProtocolVersion;

/// Newest version of the agent <-> server protocol this build speaks. Bump it on every wire
/// change, additive ones included: peers reject unknown fields, so a sender needs the
/// version to know which fields the other side understands (ADR-0006).
///
/// This is not the version of a connection. That one is negotiated: see [`ProtocolVersion`].
///
/// Version 2 (ADR-0012) carries the signed manifest in `RunAction`, an expiry on every
/// request, reasons as codes, and a bound on every string.
pub const PROTOCOL_VERSION: u16 = 2;

/// Oldest version this build still speaks. Both sides speak every version from here to
/// [`PROTOCOL_VERSION`]. Raising it on the server locks out every agent older than the new
/// value, auto-update included (ADR-0007).
///
/// Version 1 is not spoken any more (ADR-0012): it had no agent in the field, and keeping it
/// would have meant two types for every message that changed.
pub const MIN_PROTOCOL_VERSION: u16 = 2;

const _: () = assert!(1 <= MIN_PROTOCOL_VERSION && MIN_PROTOCOL_VERSION <= PROTOCOL_VERSION);

/// Largest WebSocket message either side accepts, in bytes. Both ends set it on the socket,
/// so an oversized message is refused before it is buffered, let alone parsed.
pub const MAX_MESSAGE_BYTES: usize = 256 * 1024;

/// Largest message accepted before the handshake is over, in bytes. Every handshake message
/// has a fixed shape well under 1 KiB, and a peer that has proven nothing yet gets no more
/// room than that needs.
pub const MAX_HANDSHAKE_MESSAGE_BYTES: usize = 4 * 1024;

const _: () = assert!(MAX_HANDSHAKE_MESSAGE_BYTES <= MAX_MESSAGE_BYTES);
