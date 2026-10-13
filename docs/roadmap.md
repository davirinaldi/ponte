# Roadmap

Phase 1 alone is a complete story: an AI fixes a real ticket with typed actions and human
approval, without any screen sharing. Each milestone should end with something worth a post.

## Phase 1: telemetry and typed actions

- [x] **M0 Skeleton**: workspace, protocol types, manifest validation, path policy,
  routing policy, server health endpoint, CI, agent instructions.
- [ ] **M1 Connected agent**: agent connects over WSS, with the server certificate checked
  against the OS trust store (ADR-0009) and the protocol version negotiated in the WebSocket
  upgrade (ADR-0007); enrollment token, then a device key proven on every connection
  (ADR-0008); heartbeats with real telemetry (`sysinfo`); server tracks online devices in
  Postgres; reconnect with backoff and jitter. Dependencies agreed for this milestone:
  `tokio-tungstenite` with rustls, `sysinfo`, `sqlx` and an ed25519 crate.
  *Post: Rust agent footprint (binary size, idle RAM).*
- [ ] **M2 Signed actions on Windows**: ed25519 manifest signing (offline key) and agent-side
  verification first, so that no primitive ever runs unverified; windows-service lifecycle;
  service control and file primitives; resolved-path re-check; preconditions and
  verification; idempotent `RequestId`; device key under DPAPI.
- [ ] **M3 Approvals and audit**: approval queue; hash-chained audit log; fake-erp failure
  modes. *Post: why typed actions are the defence against prompt injection.*
- [ ] **M4 MCP and helpdesk**: MCP tools; decision layer with a classifier provider and LLM
  fallback; Zammad connector; demo clip end to end. Session helper with consent prompt.
  *Post: the 60-second demo.*
- [ ] **M5 Hardening**: MSI installer, auto-update, swarm load test (10k agents), calibration
  report, opt-in pin of the server key (ADR-0009), threat model review.
  *Post: 10,000 simulated agents on one small server.*

## Phase 2: view the screen

- [ ] Windows.Graphics.Capture in the session helper, H.264 encode, WebRTC (`str0m`) to the
  browser, TURN relay, "being viewed" indicator.

## Phase 3: full control

- [ ] Input injection, clipboard, file transfer, multi-party sessions, recording, login/UAC.

## Open questions

- `str0m` or `webrtc-rs` for media.
- Plain Postgres or TimescaleDB for telemetry.
- Local consent for high-risk actions already in phase 1, or only with the helper in M4.
- What binds an `ActionRequest` to one device and a time window? T4 promises short-lived
  requests, but the type has no expiry, and a compromised server can replay any signed
  manifest on any machine with a made-up initiator.
- Agent-local policy beyond `allowed_roots`. ADR-0003 names a risk ceiling and consent for
  high risk, and `AgentConfig` has neither. Do services and processes need an allowlist too?
  Today any signed manifest may stop `WinDefend` or kill `lsass.exe`.
- How does the signed catalog reach the agent? `RunAction` carries an id and a version only.
- Who computes the confidence that drives routing: the classifier, or the model that calls
  `request_action`? `IntentClassifier` scores a ticket's intent, not an action on a machine.
- `RoutingPolicy::default()` auto-executes low-risk actions at 0.9 before any calibration
  report exists (RF-48). Should the default be "nothing runs alone"?
- What may `SqlReadonly` run? The query is free text rated `read`; its safety rests entirely
  on the database account behind the connection.
- A verify check can still be filler. Nothing ties it to what the steps touched, and there
  is no "path is gone" check for `delete_file` or `clear_temp_dir` to use.
- `Manifest::validate` is opt-in and manifests have no size limits (steps, strings). Should
  only a validated type be runnable?
- May an allowed root be a whole drive? `C:\` is accepted today and allows everything on it.
