//! Events that change what the server holds about a device (RF-40).
//!
//! Until the audit log exists (M3) they are written as structured log lines under their own
//! target. Every event goes through [`record`], so that is the one place M3 replaces.

use ponte_protocol::DeviceId;
use tracing::info;

use super::session::SessionEnd;
use super::store::{CustomerId, DeviceStatus, SessionId};

/// The `tracing` target of every audit event.
pub(crate) const TARGET: &str = "ponte::audit";

/// The actor of all of these is the device itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuditEvent {
    DeviceEnrolled {
        device: DeviceId,
        customer: CustomerId,
        status: DeviceStatus,
    },
    SessionStarted {
        device: DeviceId,
        session: SessionId,
    },
    /// The device authenticated again while `old` was still open, and `old` was dropped.
    /// Either the agent reconnected before the server noticed the old connection die, or
    /// two machines hold the same key.
    SessionReplaced {
        device: DeviceId,
        old: SessionId,
        new: SessionId,
    },
    SessionEnded {
        device: DeviceId,
        session: SessionId,
        reason: SessionEnd,
    },
}

pub(crate) fn record(event: &AuditEvent) {
    match *event {
        AuditEvent::DeviceEnrolled {
            device,
            customer,
            status,
        } => {
            info!(target: TARGET, event = "device_enrolled", %device, %customer, ?status);
        }
        AuditEvent::SessionStarted { device, session } => {
            info!(target: TARGET, event = "session_started", %device, %session);
        }
        AuditEvent::SessionReplaced { device, old, new } => {
            info!(target: TARGET, event = "session_replaced", %device, %old, %new);
        }
        AuditEvent::SessionEnded {
            device,
            session,
            reason,
        } => {
            info!(target: TARGET, event = "session_ended", %device, %session, ?reason);
        }
    }
}
