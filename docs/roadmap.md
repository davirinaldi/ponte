# Roadmap

Phase 1 alone is a complete story: an AI fixes a real ticket with typed actions and human
approval, without any screen sharing. Each milestone should end with something worth a post.

## Phase 1: telemetry and typed actions

- [x] **M0 Skeleton**: workspace, protocol types, manifest validation, path policy,
  routing policy, server health endpoint, CI, agent instructions.
- [ ] **M1 Connected agent**: agent connects over WSS, sends `Hello` and heartbeats with real
  telemetry (`sysinfo`); server tracks online devices in Postgres; reconnect with backoff
  and jitter. *Post: Rust agent footprint (binary size, idle RAM).*
- [ ] **M2 Actions on Windows**: windows-service lifecycle; service control and file primitives;
  resolved-path re-check; preconditions and verification; idempotent `RequestId`.
- [ ] **M3 Signed catalog and approvals**: ed25519 manifest signing (offline key), agent-side
  verification; approval queue; hash-chained audit log; fake-erp failure modes.
  *Post: why typed actions are the defence against prompt injection.*
- [ ] **M4 MCP and helpdesk**: MCP tools; decision layer with a classifier provider and LLM
  fallback; Zammad connector; demo clip end to end. Session helper with consent prompt.
  *Post: the 60-second demo.*
- [ ] **M5 Hardening**: MSI installer, auto-update, swarm load test (10k agents), calibration
  report, threat model review. *Post: 10,000 simulated agents on one small server.*

## Phase 2: view the screen

- [ ] Windows.Graphics.Capture in the session helper, H.264 encode, WebRTC (`str0m`) to the
  browser, TURN relay, "being viewed" indicator.

## Phase 3: full control

- [ ] Input injection, clipboard, file transfer, multi-party sessions, recording, login/UAC.

## Open questions

- `str0m` or `webrtc-rs` for media.
- Plain Postgres or TimescaleDB for telemetry.
- Local consent for high-risk actions already in phase 1, or only with the helper in M4.
