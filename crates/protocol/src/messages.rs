use serde::{Deserialize, Serialize};

use crate::{DeviceId, RequestId, TelemetrySnapshot};

/// Messages the agent sends to the server. The agent always opens the connection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
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
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerToAgent {
    Welcome {
        protocol_version: u16,
    },
    RunAction(ActionRequest),
    CancelAction {
        request_id: RequestId,
    },
    /// Ask for a telemetry snapshot now instead of waiting for the next heartbeat.
    CollectNow,
}

/// A request to run one signed manifest from the action catalog.
///
/// The agent re-checks the manifest signature and its local policy before running
/// anything; the server's decision is never trusted on its own (ADR-0003).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActionRequest {
    pub request_id: RequestId,
    pub manifest_id: String,
    pub manifest_version: u32,
    pub initiator: Initiator,
}

/// Who asked for an action. Recorded in the audit log.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
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
pub struct ActionResult {
    pub request_id: RequestId,
    pub outcome: ActionOutcome,
    /// Truncated, untrusted output. Never feed it to a model without marking it as data.
    pub output: Option<String>,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ActionOutcome {
    Succeeded,
    Failed {
        reason: String,
    },
    /// The agent refused to run it (bad signature, local policy, failed precondition).
    Rejected {
        reason: String,
    },
    Cancelled,
    TimedOut,
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

    #[test]
    fn unit_variant_is_tag_only() {
        assert_eq!(
            serde_json::to_value(ServerToAgent::CollectNow).unwrap(),
            json!({ "type": "collect_now" })
        );
    }
}
