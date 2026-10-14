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
  `tokio-tungstenite` with rustls, `sysinfo`, `sqlx` and an ed25519 crate (`ed25519-dalek`),
  plus three small ones other crates already brought in: `getrandom`, `sha2`, `futures-util`.
  The agent also names `rustls` (to pick the `ring` provider and TLS 1.3) and
  `rustls-platform-verifier` (ADR-0009).
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
- A wire message has more than one spelling. serde also reads a struct written as a JSON
  array, in field order, and a UUID in upper case, braced or without hyphens. No constraint
  is dropped that way, but anything that looks at JSON keys (a log scrubber, a proxy, the
  web console) sees something else than the receiver. Our senders only write the canonical
  form, so a stricter reader can come later without a new protocol version.
- The handshake signs the version the server selected, not what the agent offered (ADR-0007).
  Whoever terminates TLS can strip the newer names from the offer unnoticed. Sign the offered
  range too, once a second version exists?
- Outside the handshake, strings and lists are bounded only by `MAX_MESSAGE_BYTES`: telemetry
  names, `output`, `reason`, `manifest_id`, the initiator fields. Which get a limit of their own?
- The cap on connections that have not authenticated yet is one number for everyone. A
  single host that opens 256 of them and says nothing keeps every agent from reconnecting
  for as long as it keeps going. A limit per source needs a decision first: the server sits
  behind a proxy, so which address does it trust? And when the cap is reached, refuse the
  newest (what M1 does, and what lets a fleet reconnect in order) or drop the oldest (what
  makes a silent connection cheap to push out)? Planned for M5 with the other rate limits.
- Nothing limits how often a connected device sends heartbeats, and each one is a write.
- Whoever holds a spent, expired or revoked token, or the key of a revoked device, gets one
  audit event per connection, as fast as they connect. Worth a line each today; in M3
  these become rows in an append-only table. Count them per token and per device instead?
- The server never pings. A connection that died without a close stays "online" until the
  device connects again or the session reaches its time limit. A ping needs the agent to
  answer it, and a heartbeat deadline needs the server to know the agent's interval.
- Revoking a device ends its session at the next status check, up to a minute later. RF-04
  says "immediately": that takes the revocation and the session in the same process, which
  comes with the console.
- When the server stops, open sessions are cut without their end being recorded. The store
  has to clear "online" when the server starts.
