# Roadmap

Phase 1 alone is a complete story: an AI fixes a real ticket with typed actions and human
approval, without any screen sharing. Each milestone should end with something worth a post.

## Phase 1: telemetry and typed actions

- [x] **M0 Skeleton**: workspace, protocol types, manifest validation, path policy,
  routing policy, server health endpoint, CI, agent instructions.
- [x] **M1 Connected agent**: agent connects over WSS, with the server certificate checked
  against the OS trust store (ADR-0009) and the protocol version negotiated in the WebSocket
  upgrade (ADR-0007); enrollment token, then a device key proven on every connection
  (ADR-0008); heartbeats with real telemetry (`sysinfo`); server tracks online devices in
  Postgres; reconnect with backoff and jitter. Dependencies agreed for this milestone:
  `tokio-tungstenite` with rustls, `sysinfo`, `sqlx` and an ed25519 crate (`ed25519-dalek`),
  plus three small ones other crates already brought in: `getrandom`, `sha2`, `futures-util`.
  The agent also names `rustls` (to pick the `ring` provider and TLS 1.3) and
  `rustls-platform-verifier` (ADR-0009).
  *Post: Rust agent footprint (binary size, idle RAM).* Measured on 2026-10-14 (Windows 10,
  x86_64, release build of the agent alone, enrolled and connected to a local server, idle
  for 15 minutes): binary 2.1 MB, working set 14.4 MB at peak (8.6 MB private), CPU
  0.007% of one core. Budget (RNF-12): 15 MB, 40 MB, 1%. `scripts/measure-agent.ps1`
  repeats it.
- [ ] **M2 Signed actions on Windows**: manifests signed offline with `ponte-sign` and
  verified by the agent first, so that no primitive ever runs unverified; each request
  carries its whole signed manifest, the agent's trusted keys live in its configuration,
  and expiry is checked against a high-water mark of the clock (ADR-0010). The agent's own
  policy (ADR-0011): `service_start`, `service_stop`, `service_restart` and `delete_file`,
  with the checks `service_state`, `path_exists`, `path_absent` and `disk_free_at_least`;
  `clear_temp_dir`, `read_file_tail`, `kill_process`, `sql_readonly` and `high` risk are
  refused; a risk ceiling, a service list backed by structural refusals, read and delete
  roots kept apart (never a drive or a system folder), verification that covers what the
  steps touched, rate limits, and files opened so that a local user cannot redirect them.
  Protocol v2 only (ADR-0012): expiring requests, typed reasons, bounded strings, a journal
  so that each `RequestId` runs at most once even across a crash, results kept until
  delivered, and `action run` in the server's CLI. A windows-service lifecycle under
  SYSTEM (ADR-0013); device key under DPAPI, in a data directory only SYSTEM and
  administrators can open, with renames written through to the disk; key bytes wiped
  with `zeroize`; service stop bounded by `shutdown_timeout`. End to end over real
  `wss://`, with Caddy in `deploy/docker-compose.yml`. No agent is installed outside a lab
  before that. Dependencies agreed for this milestone: `windows-service` and `windows-sys`
  (agent and fake-erp, Windows only), `zeroize` (agent), and `argon2`, `chacha20poly1305`
  and `rpassword` (`ponte-sign` only).
- [ ] **M3 Approvals and audit**: approval queue on `action_requests`, with each request
  bound to a technician's approval signed outside the server; hash-chained audit log, with
  counters for repeated refusals; the server pings and revokes at once; routing that runs
  nothing alone by default; network facts for RF-05; fake-erp failure modes.
  *Post: why typed actions are the defence against prompt injection.*
- [ ] **M4 MCP and helpdesk**: MCP tools; decision layer with a classifier provider and LLM
  fallback, which computes the routing confidence; Zammad connector; demo clip end to end.
  Session helper with consent prompt, which `high` risk then requires.
  *Post: the 60-second demo.*
- [ ] **M5 Hardening**: MSI installer with an explicit "enroll again" action, a random
  delay when the agent process starts (a fleet restarting together), rate limits on the
  agent endpoint (per source, and heartbeats per device), auto-update, swarm
  load test (10k agents), calibration report, opt-in pin of the server key (ADR-0009),
  threat model review.
  *Post: 10,000 simulated agents on one small server.*

## Phase 2: view the screen

- [ ] Windows.Graphics.Capture in the session helper, H.264 encode, WebRTC (`str0m`) to the
  browser, TURN relay, "being viewed" indicator.

## Phase 3: full control

- [ ] Input injection, clipboard, file transfer, multi-party sessions, recording, login/UAC.

## Decided

Questions that were open, with the answer and the date.

- **2026-10-14. A repeated enrollment is honoured after the token's deadline, not after the
  token is revoked.** The agent stores its key, sends `Enroll` and may lose the answer. A
  repetition with the same token and key gives back the device that already exists: it
  creates nothing, spends no use, and only the holder of the key can ask, so the deadline
  has nothing left to protect. Revoking a token is a person saying no, and it holds for
  the machines that enrolled with it too. A revoked device stays refused. Repetitions are
  audited like first enrollments.
- **2026-10-14. TLS 1.3 only (RNF-01).** rustls with TLS 1.2 would be safe, but no customer
  is known to sit behind a proxy that stops at 1.2. If a pilot meets one, an ADR adds an
  explicit `allow_tls12` option to the agent's configuration, never on by default.
- **2026-10-14. Enrolling again stays manual on the agent**: remove its data directory and
  bring a new token. Enrolling again by itself whenever a new token file appears would turn
  every re-run of the installer into a second device. The installer of M5 gets an explicit
  "enroll again" action that does it.
- **2026-10-14. A test over `wss://` comes with the end-to-end step of M1**, with a
  certificate made on the spot (`rcgen`, `ring` feature, as a dev-dependency): a refused
  certificate, a refused TLS 1.2 server and an accepted connection to a root trusted in the
  test only. Done: `ws_loopback_wss_*` in `crates/agent/src/transport/wss_tests.rs`, on
  Linux and Windows in CI.

The questions below were decided with the plan of M2 (2026-10-15) and recorded in ADR-0010
to ADR-0013.

- **2026-10-15. The signed manifest travels in each request** (M2, ADR-0010). The agent
  keeps no catalog; `RunAction` carries the whole envelope.
- **2026-10-15. A request expires within 24 hours and its `RequestId` runs at most once**
  (M2, ADR-0012). The journal on the agent remembers each one past its expiry. Binding a
  request to one device and one person takes a technician's approval signed outside the
  server, which comes with the console (M3, with an ADR). Until then a compromised server
  can run allowed manifests on any device, within the limits ADR-0012 lists.
- **2026-10-15. The agent has a policy beyond `allowed_roots`** (M2, ADR-0011): a risk
  ceiling, a list of services backed by a compiled deny list and structural refusals (no
  shared or protected service, nothing under `%SystemRoot%`), separate delete roots, and
  rate limits. A signed manifest can no longer stop `WinDefend`, and killing processes is
  refused altogether.
- **2026-10-15. Local consent for high risk comes with the helper of M4.** Until then the
  agent refuses `high`, and a configuration that allows it is refused (ADR-0011).
- **2026-10-15. Verification covers what the steps touched** (M2, ADR-0011). Every service
  and path a step names is named by a verify check, every `delete_file` has a
  `path_exists` precondition, and `path_absent` exists.
- **2026-10-15. Only a validated type runs, within size limits** (M2, ADR-0011):
  `Manifest`, `ValidManifest`, `RunnableManifest`; 16 KiB, 16 steps, 16 checks per list.
- **2026-10-15. No root may be a whole drive**, a system folder, a `Program Files` folder,
  `ProgramData`, the profiles folder or a profile root (M2, ADR-0011).
- **2026-10-15. `sql_readonly`, `clear_temp_dir`, `read_file_tail` and `kill_process` do
  not run in M2.** The agent and `ponte-sign` refuse them until each has an ADR;
  `read_file_tail` waits for the approvals of M3. What `SqlReadonly` may run is decided in
  its ADR.
- **2026-10-15. Strings on the wire get limits of their own in protocol v2** (M2,
  ADR-0012): `output` 64 KiB, reasons become enums, `manifest_id` gives way to the signed
  envelope (16 KiB of manifest), the initiator's fields become `Label`s, and telemetry
  names are bounded, with 32 services and 32 disks at most.
- **2026-10-15. A wire message keeps more than one spelling for now.** Manifests are signed
  as bytes, so no spelling changes what runs. The strict reader comes with the console (M4).
- **2026-10-15. The handshake does not sign the offered range yet.** With
  `MIN_PROTOCOL_VERSION = 2`, removing a version from the offer fails the connection
  instead of downgrading it. It returns when a range of versions exists again or the
  handshake gains a guarantee worth protecting.
- **2026-10-15. The server's decision layer computes the routing confidence**, over the
  ticket. The confidence a model states is recorded and never decides (M4).
- **2026-10-15. `RoutingPolicy::default()` runs nothing alone** until a calibration report
  (RF-48) enables it (M3).
- **2026-10-15. Network facts for RF-05 are numbers and booleans only**: how many adapters
  are up, whether a default route exists, and the latency to the server from the ping the
  agent already makes. No address, adapter name or MAC (M3).
- **2026-10-15. The server starts pinging, and revocation becomes immediate**, with the
  console (M3).
- **2026-10-15. Repeated refusals become counters per token and per device** when the
  audit log is a table (M3).

## Open questions

- `str0m` or `webrtc-rs` for media. Decided with a prototype at the start of phase 2, by
  2027-06-30 at the latest.
- Plain Postgres or TimescaleDB for telemetry. Decided with the load test of M5, by
  2027-03-31 at the latest.
- The design of each primitive the agent refuses in M2 (`clear_temp_dir`, `read_file_tail`,
  `kill_process`, `sql_readonly`), one ADR each. `read_file_tail` comes first, with M3.
- Should the agent refuse, or at least report, a service whose binary a local user can
  change? Today it is an accepted risk with install guidance (`docs/threat-model.md`);
  the threat model review of M5 decides.
- The cap on connections that have not authenticated yet is one number for everyone. A
  single host that opens 256 of them and says nothing keeps every agent from reconnecting
  for as long as it keeps going. A limit per source needs a decision first: the server sits
  behind a proxy, so which address does it trust? And when the cap is reached, refuse the
  newest (what M1 does, and what lets a fleet reconnect in order) or drop the oldest (what
  makes a silent connection cheap to push out)? Planned for M5 with the other rate limits.
- Nothing limits how often a connected device sends heartbeats, and each one is a write.
- Connections that have not authenticated share the database pool with the sessions: a
  stranger's `Hello` with a made-up id costs one query, like a real one. The 256-place cap
  and the store's time limits bound it, and a healthy database answers in milliseconds.
  While the database is down, each of those refusals is an `error` line. Give the handshake
  a share of the pool of its own, and log store failures at a bounded rate?
