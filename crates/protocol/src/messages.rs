//! Agent <-> server messages.
//!
//! Every type here rejects unknown fields (ADR-0006). Variants without fields are written
//! `Variant {}`, not `Variant`: serde ignores `deny_unknown_fields` on unit variants of an
//! internally tagged enum, and the JSON is the same either way.
//!
//! A connection starts with a handshake (ADR-0008). The protocol version is already agreed
//! by then, in the WebSocket upgrade (ADR-0007), so no message carries it.
//!
//! ```text
//! server: Challenge      a fresh nonce
//! agent:  Enroll         a signature over the nonce, see `transcript.rs`
//! server: Enrolled       and the server closes the connection
//! ```
//!
//! ```text
//! server: Challenge
//! agent:  Hello
//! server: Welcome        heartbeats and actions follow
//! ```
//!
//! Enrolling does not authenticate the connection it happens on. The agent stores its id
//! and connects again with `Hello`, so there is one way in and every session went through it.
//!
//! A handshake the server refuses gets no message. The server closes the connection the
//! same way whatever the cause, so the answer does not tell an unknown device from a
//! revoked one or a bad token from a bad signature.

use serde::{Deserialize, Serialize};

use crate::{
    DeviceId, EnrollmentToken, Label, Nonce, PublicKey, RequestId, Signature, TelemetrySnapshot,
};

/// Messages the agent sends to the server. The agent always opens the connection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentToServer {
    /// Answer to `Challenge` from a machine that has no identity yet. `signature` is made
    /// with the private half of `public_key` over [`enroll_transcript`](crate::enroll_transcript).
    Enroll {
        token: EnrollmentToken,
        public_key: PublicKey,
        /// Informational and untrusted, like `os`: the signature does not cover them.
        agent_version: Label,
        os: Label,
        signature: Signature,
    },
    /// Answer to `Challenge` from an enrolled device. `signature` is made with the device
    /// key over [`hello_transcript`](crate::hello_transcript).
    Hello {
        device_id: DeviceId,
        /// Informational and untrusted, like `os`: the signature does not cover them.
        agent_version: Label,
        os: Label,
        signature: Signature,
    },
    Heartbeat {
        telemetry: TelemetrySnapshot,
    },
    ActionResult(ActionResult),
}

/// Messages the server sends to the agent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ServerToAgent {
    /// First message on every connection. The server accepts nothing from the agent
    /// before a valid answer to it.
    Challenge {
        nonce: Nonce,
    },
    /// The token was accepted and the public key is stored under this id. Last message of
    /// the connection: the agent keeps the id and connects again with `Hello`.
    Enrolled {
        device_id: DeviceId,
    },
    /// The signature in `Hello` matched the key stored for the device.
    Welcome {},
    RunAction(ActionRequest),
    CancelAction {
        request_id: RequestId,
    },
    /// Ask for a telemetry snapshot now instead of waiting for the next heartbeat.
    CollectNow {},
}

/// A request to run one signed manifest from the action catalog.
///
/// The agent re-checks the manifest signature and its local policy before running
/// anything; the server's decision is never trusted on its own (ADR-0003).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionRequest {
    pub request_id: RequestId,
    pub manifest_id: String,
    pub manifest_version: u32,
    pub initiator: Initiator,
}

/// Who asked for an action. Recorded in the audit log.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Initiator {
    Human {
        user_id: String,
    },
    Ai {
        client_id: String,
        ticket_ref: Option<String>,
        /// Calibrated confidence of the decision that proposed this action, if known.
        confidence: Option<f32>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionResult {
    pub request_id: RequestId,
    pub outcome: ActionOutcome,
    /// Truncated, untrusted output. Never feed it to a model without marking it as data.
    pub output: Option<String>,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum ActionOutcome {
    Succeeded {},
    Failed {
        reason: String,
    },
    /// The agent refused to run it (bad signature, local policy, failed precondition).
    Rejected {
        reason: String,
    },
    Cancelled {},
    TimedOut {},
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};
    use serde_json::json;
    use uuid::Uuid;

    use super::*;
    use crate::{DiskUsage, MemoryUsage, ServiceState, ServiceStatus};

    const ID: &str = "00000000-0000-0000-0000-000000000000";
    const NONCE: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const PUBLIC_KEY: &str = "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf";
    const SIGNATURE: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
                             202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
    const TOKEN: &str = "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

    fn device_id() -> DeviceId {
        DeviceId::from_uuid(Uuid::nil())
    }

    fn request_id() -> RequestId {
        RequestId::from_uuid(Uuid::nil())
    }

    fn enroll() -> AgentToServer {
        AgentToServer::Enroll {
            token: TOKEN.parse().unwrap(),
            public_key: PUBLIC_KEY.parse().unwrap(),
            agent_version: "0.1.0".parse().unwrap(),
            os: "Windows 11".parse().unwrap(),
            signature: SIGNATURE.parse().unwrap(),
        }
    }

    /// Asserts that `message` is written as exactly `wire` and read back from it.
    fn assert_wire<T>(message: &T, wire: serde_json::Value)
    where
        T: Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
    {
        assert_eq!(serde_json::to_value(message).unwrap(), wire);
        assert_eq!(&serde_json::from_value::<T>(wire).unwrap(), message);
    }

    /// Pins the wire format of the handshake (ADR-0007, ADR-0008). If this test fails, you
    /// changed the protocol: bump `PROTOCOL_VERSION` and keep serving the old shape to
    /// connections that negotiated the old version.
    #[test]
    fn handshake_wire_format_is_stable() {
        assert_wire(
            &ServerToAgent::Challenge {
                nonce: NONCE.parse().unwrap(),
            },
            json!({ "type": "challenge", "nonce": NONCE }),
        );
        assert_wire(
            &enroll(),
            json!({
                "type": "enroll",
                "token": TOKEN,
                "public_key": PUBLIC_KEY,
                "agent_version": "0.1.0",
                "os": "Windows 11",
                "signature": SIGNATURE,
            }),
        );
        assert_wire(
            &ServerToAgent::Enrolled {
                device_id: device_id(),
            },
            json!({ "type": "enrolled", "device_id": ID }),
        );
        assert_wire(
            &AgentToServer::Hello {
                device_id: device_id(),
                agent_version: "0.1.0".parse().unwrap(),
                os: "Windows 11".parse().unwrap(),
                signature: SIGNATURE.parse().unwrap(),
            },
            json!({
                "type": "hello",
                "device_id": ID,
                "agent_version": "0.1.0",
                "os": "Windows 11",
                "signature": SIGNATURE,
            }),
        );
        assert_wire(&ServerToAgent::Welcome {}, json!({ "type": "welcome" }));
    }

    /// Same pin for everything sent after the handshake.
    #[test]
    fn session_wire_format_is_stable() {
        let collected_at: DateTime<Utc> = "2026-01-01T00:00:00Z".parse().unwrap();
        assert_wire(
            &AgentToServer::Heartbeat {
                telemetry: TelemetrySnapshot {
                    collected_at,
                    uptime_secs: 60,
                    cpu_percent: 12.5,
                    memory: MemoryUsage {
                        total_bytes: 2,
                        used_bytes: 1,
                    },
                    disks: vec![DiskUsage {
                        mount: "C:".to_owned(),
                        total_bytes: 2,
                        available_bytes: 1,
                    }],
                    services: vec![ServiceStatus {
                        name: "FakeErp".to_owned(),
                        state: ServiceState::StartPending,
                    }],
                },
            },
            json!({
                "type": "heartbeat",
                "telemetry": {
                    "collected_at": "2026-01-01T00:00:00Z",
                    "uptime_secs": 60,
                    "cpu_percent": 12.5,
                    "memory": { "total_bytes": 2, "used_bytes": 1 },
                    "disks": [{ "mount": "C:", "total_bytes": 2, "available_bytes": 1 }],
                    "services": [{ "name": "FakeErp", "state": "start_pending" }],
                },
            }),
        );
        assert_wire(
            &AgentToServer::ActionResult(ActionResult {
                request_id: request_id(),
                outcome: ActionOutcome::Rejected {
                    reason: "bad signature".to_owned(),
                },
                output: None,
                duration_ms: 1,
            }),
            json!({
                "type": "action_result",
                "request_id": ID,
                "outcome": { "status": "rejected", "reason": "bad signature" },
                "output": null,
                "duration_ms": 1,
            }),
        );
        assert_wire(
            &ServerToAgent::RunAction(ActionRequest {
                request_id: request_id(),
                manifest_id: "erp.restart-service".to_owned(),
                manifest_version: 1,
                initiator: Initiator::Ai {
                    client_id: "n1-bot".to_owned(),
                    ticket_ref: None,
                    confidence: Some(0.5),
                },
            }),
            json!({
                "type": "run_action",
                "request_id": ID,
                "manifest_id": "erp.restart-service",
                "manifest_version": 1,
                "initiator": {
                    "kind": "ai",
                    "client_id": "n1-bot",
                    "ticket_ref": null,
                    "confidence": 0.5,
                },
            }),
        );
        assert_wire(
            &ServerToAgent::CancelAction {
                request_id: request_id(),
            },
            json!({ "type": "cancel_action", "request_id": ID }),
        );
        assert_wire(
            &ServerToAgent::CollectNow {},
            json!({ "type": "collect_now" }),
        );
    }

    #[test]
    fn run_action_round_trips() {
        let msg = ServerToAgent::RunAction(ActionRequest {
            request_id: RequestId::new(),
            manifest_id: "erp.restart-service".to_owned(),
            manifest_version: 1,
            initiator: Initiator::Ai {
                client_id: "n1-bot".to_owned(),
                ticket_ref: Some("ZAM-123".to_owned()),
                confidence: Some(0.93),
            },
        });

        let json = serde_json::to_string(&msg).unwrap();
        let back: ServerToAgent = serde_json::from_str(&json).unwrap();
        assert_eq!(back, msg);
    }

    /// A message is logged with `{:?}` sooner or later. The token must not come along.
    #[test]
    fn debug_of_enroll_hides_the_token() {
        let debug = format!("{:?}", enroll());
        assert!(debug.contains("Enroll"), "{debug}");
        assert!(debug.contains(PUBLIC_KEY), "{debug}");
        assert!(
            debug.contains("token: EnrollmentToken(<redacted>),"),
            "{debug}"
        );
        assert!(!debug.contains(&TOKEN[..8]), "{debug}");
        assert!(!debug.contains(&TOKEN[56..]), "{debug}");
    }

    /// A message that fails to parse is logged with its error. Wherever the mistake is,
    /// the error must not carry the token that came in the same message.
    #[test]
    fn parse_errors_of_enroll_hide_the_token() {
        let valid = json!({
            "type": "enroll",
            "token": TOKEN,
            "public_key": PUBLIC_KEY,
            "agent_version": "0.1.0",
            "os": "Windows 11",
            "signature": SIGNATURE,
        });
        let with = |field: &str, value: serde_json::Value| {
            let mut message = valid.clone();
            message[field] = value;
            message
        };
        let without = |field: &str| {
            let mut message = valid.clone();
            message.as_object_mut().unwrap().remove(field);
            message
        };

        for broken in [
            with("token", json!(TOKEN.to_uppercase())),
            with("token", json!(&TOKEN[..63])),
            with("public_key", json!("not a key")),
            with("signature", json!(PUBLIC_KEY)),
            with("os", json!("Windows 11\n")),
            with("agent_version", json!(1)),
            with("skip_signature_check", json!(true)),
            without("signature"),
            without("public_key"),
        ] {
            let error = serde_json::from_value::<AgentToServer>(broken.clone())
                .unwrap_err()
                .to_string()
                .to_lowercase();
            assert!(!error.contains(&TOKEN[..8]), "{error}");
            assert!(!error.contains(&TOKEN[56..]), "{error}");

            let error = serde_json::from_str::<AgentToServer>(&broken.to_string())
                .unwrap_err()
                .to_string()
                .to_lowercase();
            assert!(!error.contains(&TOKEN[..8]), "{error}");
            assert!(!error.contains(&TOKEN[56..]), "{error}");
        }
    }

    /// `agent_version` and `os` arrive before the peer has proven anything.
    #[test]
    fn handshake_text_is_bounded() {
        let hello = |agent_version: &str, os: &str| {
            json!({
                "type": "hello",
                "device_id": ID,
                "agent_version": agent_version,
                "os": os,
                "signature": SIGNATURE,
            })
        };
        let parses =
            |message: serde_json::Value| serde_json::from_value::<AgentToServer>(message).is_ok();

        assert!(parses(hello("0.1.0", "Windows 11")));
        assert!(!parses(hello("0.1.0", &"W".repeat(65))));
        assert!(!parses(hello(&"1".repeat(125_000), "Windows 11")));
        assert!(!parses(hello("0.1.0", "")));
        assert!(!parses(hello("0.1.0", "Windows 11\nINFO device approved")));
        assert!(!parses(hello("<script>", "Windows 11")));
    }

    /// Asserts that `message` parses as `T`, and no longer does once any of its objects
    /// (named by JSON pointer) carries a field `T` does not know. An ignored field is a
    /// constraint the receiver silently dropped.
    fn assert_strict<T: serde::de::DeserializeOwned>(
        message: &serde_json::Value,
        objects: &[&str],
    ) {
        assert!(
            serde_json::from_value::<T>(message.clone()).is_ok(),
            "{message}"
        );
        for pointer in objects {
            let mut tampered = message.clone();
            tampered
                .pointer_mut(pointer)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert("skip_signature_check".to_owned(), json!(true));
            assert!(
                serde_json::from_value::<T>(tampered).is_err(),
                "{message} accepted an unknown field at {pointer:?}"
            );
        }
    }

    #[test]
    fn server_messages_reject_unknown_fields() {
        let run_action = |initiator: serde_json::Value| {
            json!({
                "type": "run_action",
                "request_id": ID,
                "manifest_id": "erp.restart-service",
                "manifest_version": 1,
                "initiator": initiator,
            })
        };
        let human = json!({ "kind": "human", "user_id": "u1" });
        let ai =
            json!({ "kind": "ai", "client_id": "n1-bot", "ticket_ref": null, "confidence": 0.9 });

        assert_strict::<ServerToAgent>(&json!({ "type": "challenge", "nonce": NONCE }), &[""]);
        assert_strict::<ServerToAgent>(&json!({ "type": "enrolled", "device_id": ID }), &[""]);
        assert_strict::<ServerToAgent>(&json!({ "type": "welcome" }), &[""]);
        assert_strict::<ServerToAgent>(&run_action(human), &["", "/initiator"]);
        assert_strict::<ServerToAgent>(&run_action(ai), &["", "/initiator"]);
        assert_strict::<ServerToAgent>(
            &json!({ "type": "cancel_action", "request_id": ID }),
            &[""],
        );
        assert_strict::<ServerToAgent>(&json!({ "type": "collect_now" }), &[""]);
    }

    #[test]
    fn agent_messages_reject_unknown_fields() {
        let enroll = json!({
            "type": "enroll",
            "token": TOKEN,
            "public_key": PUBLIC_KEY,
            "agent_version": "0.1.0",
            "os": "Windows 11",
            "signature": SIGNATURE,
        });
        let hello = json!({
            "type": "hello",
            "device_id": ID,
            "agent_version": "0.1.0",
            "os": "Windows 11",
            "signature": SIGNATURE,
        });
        let heartbeat = json!({
            "type": "heartbeat",
            "telemetry": {
                "collected_at": "2026-01-01T00:00:00Z",
                "uptime_secs": 60,
                "cpu_percent": 12.5,
                "memory": { "total_bytes": 2, "used_bytes": 1 },
                "disks": [{ "mount": "C:", "total_bytes": 2, "available_bytes": 1 }],
                "services": [{ "name": "FakeErp", "state": "running" }],
            },
        });
        let action_result = |outcome: serde_json::Value| {
            json!({
                "type": "action_result",
                "request_id": ID,
                "outcome": outcome,
                "output": null,
                "duration_ms": 1,
            })
        };

        assert_strict::<AgentToServer>(&enroll, &[""]);
        assert_strict::<AgentToServer>(&hello, &[""]);
        assert_strict::<AgentToServer>(
            &heartbeat,
            &[
                "",
                "/telemetry",
                "/telemetry/memory",
                "/telemetry/disks/0",
                "/telemetry/services/0",
            ],
        );
        for outcome in [
            json!({ "status": "succeeded" }),
            json!({ "status": "failed", "reason": "service did not start" }),
            json!({ "status": "rejected", "reason": "bad signature" }),
            json!({ "status": "cancelled" }),
            json!({ "status": "timed_out" }),
        ] {
            assert_strict::<AgentToServer>(&action_result(outcome), &["", "/outcome"]);
        }
    }

    /// The version is agreed in the WebSocket upgrade (ADR-0007). A message that still
    /// carries it comes from a peer that speaks something else.
    #[test]
    fn version_inside_the_handshake_is_rejected() {
        let hello = json!({
            "type": "hello",
            "protocol_version": 1,
            "device_id": ID,
            "agent_version": "0.1.0",
            "os": "Windows 11",
            "signature": SIGNATURE,
        });
        assert!(serde_json::from_value::<AgentToServer>(hello).is_err());

        let welcome = json!({ "type": "welcome", "protocol_version": 1 });
        assert!(serde_json::from_value::<ServerToAgent>(welcome).is_err());
    }

    /// Nothing proves who is connecting without a signature, and nothing may stand in for
    /// a missing one.
    #[test]
    fn handshake_without_a_signature_is_rejected() {
        let hello = json!({
            "type": "hello",
            "device_id": ID,
            "agent_version": "0.1.0",
            "os": "Windows 11",
        });
        assert!(serde_json::from_value::<AgentToServer>(hello).is_err());

        for signature in [json!(null), json!(""), json!(&SIGNATURE[..64])] {
            let enroll = json!({
                "type": "enroll",
                "token": TOKEN,
                "public_key": PUBLIC_KEY,
                "agent_version": "0.1.0",
                "os": "Windows 11",
                "signature": signature,
            });
            assert!(serde_json::from_value::<AgentToServer>(enroll).is_err());
        }
    }

    /// `Variant {}` must stay indistinguishable on the wire from the unit variant it replaced.
    #[test]
    fn fieldless_variants_are_tag_only() {
        assert_eq!(
            serde_json::to_value(ServerToAgent::CollectNow {}).unwrap(),
            json!({ "type": "collect_now" })
        );
        for (outcome, status) in [
            (ActionOutcome::Succeeded {}, "succeeded"),
            (ActionOutcome::Cancelled {}, "cancelled"),
            (ActionOutcome::TimedOut {}, "timed_out"),
        ] {
            assert_eq!(
                serde_json::to_value(outcome).unwrap(),
                json!({ "status": status })
            );
        }
    }
}
