//! Agent <-> server messages.
//!
//! Every type here rejects unknown fields (ADR-0006). Variants without fields are written
//! `Variant {}`, not `Variant`: serde ignores `deny_unknown_fields` on unit variants of an
//! internally tagged enum, and the JSON is the same either way.

use serde::{Deserialize, Serialize};

use crate::{DeviceId, RequestId, TelemetrySnapshot};

/// Messages the agent sends to the server. The agent always opens the connection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentToServer {
    /// First message on every connection.
    Hello {
        protocol_version: u16,
        agent_version: String,
        device_id: DeviceId,
        os: String,
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
    Welcome {
        protocol_version: u16,
    },
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
    use serde_json::json;
    use uuid::Uuid;

    use super::*;

    /// Pins the wire format. If this test fails, you changed the protocol:
    /// bump `PROTOCOL_VERSION` or make the change backward compatible.
    #[test]
    fn hello_wire_format_is_stable() {
        let msg = AgentToServer::Hello {
            protocol_version: 1,
            agent_version: "0.1.0".to_owned(),
            device_id: DeviceId::from_uuid(Uuid::nil()),
            os: "Windows 11".to_owned(),
        };

        assert_eq!(
            serde_json::to_value(&msg).unwrap(),
            json!({
                "type": "hello",
                "protocol_version": 1,
                "agent_version": "0.1.0",
                "device_id": "00000000-0000-0000-0000-000000000000",
                "os": "Windows 11",
            })
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

    const ID: &str = "00000000-0000-0000-0000-000000000000";

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

        assert_strict::<ServerToAgent>(&json!({ "type": "welcome", "protocol_version": 1 }), &[""]);
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
        let hello = json!({
            "type": "hello",
            "protocol_version": 1,
            "agent_version": "0.1.0",
            "device_id": ID,
            "os": "Windows 11",
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
