//! Events that change what the server holds about a device, or that say a token or a key
//! is in the wrong hands (RF-40).
//!
//! Until the audit log exists (M3) they are written as structured log lines under their own
//! target, which the server's log filter never turns off. Every event goes through
//! [`record`], so that is the one place M3 replaces.

use std::num::NonZeroU32;

use chrono::{DateTime, Utc};
use ponte_protocol::{DeviceId, PublicKey};
use tracing::{info, warn};

use super::handshake::{Claim, Rejection};
use super::session::SessionEnd;
use super::store::{CustomerId, DeviceStatus, SessionId, TokenHash};

/// The `tracing` target of every audit event.
pub const TARGET: &str = "ponte::audit";

/// The actor of all of these is the device itself, or whoever holds its key or a token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuditEvent {
    DeviceEnrolled {
        device: DeviceId,
        customer: CustomerId,
        public_key: PublicKey,
        status: DeviceStatus,
        /// The same token and key enrolled before, and the same device was given back.
        repeated: bool,
    },
    /// A handshake was refused after the peer showed a token the server issued or the key
    /// of a device it knows (see `Rejection::follows_a_real_credential`). `who` says which:
    /// the device, or the key that tried to enroll and the hash of the token it used.
    HandshakeRefused {
        reason: Rejection,
        who: Claim,
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
    /// What an operator did, through the server's subcommands. There are no accounts yet,
    /// so the actor is whoever runs them on the server host (`actor = "server_cli"`). A
    /// change the store may or may not have made is recorded too, as [`Outcome::Unknown`].
    CustomerAdded {
        /// `None` when the store failed before it said which id it gave.
        customer: Option<CustomerId>,
        outcome: Outcome,
    },
    TokenIssued {
        token: TokenHash,
        customer: CustomerId,
        max_uses: NonZeroU32,
        expires_at: DateTime<Utc>,
        outcome: Outcome,
    },
    TokenRevoked {
        token: TokenHash,
        outcome: Outcome,
    },
    DeviceApproved {
        device: DeviceId,
        outcome: Outcome,
    },
    DeviceRevoked {
        device: DeviceId,
        outcome: Outcome,
    },
}

/// Whether an operator's change happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    Done,
    /// The store failed. A database can commit and lose its answer, so the change may
    /// have happened all the same.
    Unknown,
}

/// The actor of the events an operator causes, until there are accounts (M3).
const OPERATOR: &str = "server_cli";

pub(crate) fn record(event: &AuditEvent) {
    match *event {
        AuditEvent::DeviceEnrolled {
            device,
            customer,
            public_key,
            status,
            repeated,
        } => {
            info!(target: TARGET, event = "device_enrolled", %device, %customer, %public_key, ?status, repeated);
        }
        AuditEvent::HandshakeRefused { reason, who } => {
            let device = who.device.map(tracing::field::display);
            let public_key = who.public_key.map(tracing::field::display);
            let token_hash = who.token.map(|token| token.short());
            warn!(
                target: TARGET,
                event = "handshake_refused",
                ?reason,
                device,
                public_key,
                token_hash = token_hash.as_deref().map(tracing::field::display),
            );
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
        AuditEvent::CustomerAdded { customer, outcome } => {
            // The id, not the name: the name is for people, the log is for finding things.
            let customer = customer.map(tracing::field::display);
            info!(target: TARGET, event = "customer_added", actor = OPERATOR, customer, ?outcome);
        }
        AuditEvent::TokenIssued {
            token,
            customer,
            max_uses,
            expires_at,
            outcome,
        } => {
            info!(
                target: TARGET,
                event = "token_issued",
                actor = OPERATOR,
                token_hash = %token.short(),
                %customer,
                max_uses = max_uses.get(),
                %expires_at,
                ?outcome,
            );
        }
        AuditEvent::TokenRevoked { token, outcome } => {
            info!(target: TARGET, event = "token_revoked", actor = OPERATOR, token_hash = %token.short(), ?outcome);
        }
        AuditEvent::DeviceApproved { device, outcome } => {
            info!(target: TARGET, event = "device_approved", actor = OPERATOR, %device, ?outcome);
        }
        AuditEvent::DeviceRevoked { device, outcome } => {
            info!(target: TARGET, event = "device_revoked", actor = OPERATOR, %device, ?outcome);
        }
    }
}
