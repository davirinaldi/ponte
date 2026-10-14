# crates/agent

Privileged Windows service installed on customer machines. It runs as SYSTEM on weak
point-of-sale PCs, so bugs here are expensive and visible.

- **Resource budget (RNF-12):** under 1% CPU and 40 MB RAM at idle, binary under 15 MB.
  Justify any dependency by its size; check with `cargo bloat` when in doubt.
- **Never panic, never exit on bad input.** Reject, log, keep running. The service manager
  restarts a crashed agent, but a crash loop on 10,000 machines is an incident.
- **Outbound connections only.** No listening sockets, no local HTTP server.
- Windows-specific code lives in `src/platform/windows.rs` (and submodules). It is the only
  place where `unsafe` is allowed; every block needs a `// SAFETY:` comment.
- The crate must still compile and test on Linux: Windows dependencies go under
  `[target.'cfg(windows)'.dependencies]`, and `platform/unsupported.rs` fails loudly.
- UI, consent prompts and screen capture belong to `crates/agent-helper`, not here
  (a service in session 0 cannot reach the user's desktop).
- Reconnect with exponential backoff plus jitter (RNF-16). Execute each `RequestId` at most once (RNF-18).

## The connection to the server (`src/`)

ADR-0007, ADR-0008 and ADR-0009 say what the agent does to connect. "Agent connections" in
`crates/server/AGENTS.md` says what the other side accepts, refuses and closes. These rules
keep the agent's half, and most of them exist because the server is not trusted (invariant 2).

- **The device key signs two things.** The transcripts of `ponte_protocol`, through
  `DeviceKey::sign_hello` and `DeviceKey::sign_enroll`. Never add a method that signs bytes it
  is handed. One signature per connection, for the first message and only if it is a
  `Challenge`. The session never holds the key, so nothing sent later can be signed.
- **Disk before wire.** A new key and its `enrolling` record are stored before `Enroll` is
  sent, and the `enrolled` record before the token file is removed. `identity.rs` says why;
  its tests fail the disk at every write. Keep both orders and every write atomic.
- **Same token, same key. Another token, another key.** If the answer to `Enroll` is lost
  the server may hold the key, and only the same pair gets the same device back. A key
  enrolls once, so a new token never reuses an old key.
- **A key and a record that do not name each other are no identity.** Unknown fields and
  unknown states in `identity.toml` are refused. Its format is pinned by a test: changing
  it strands every enrolled machine.
- **A message never decides who the device is or what the machine does.** `Enrolled` counts
  only as the answer to `Enroll`, `Welcome` only as the answer to `Hello`. `RunAction` is
  refused until manifests are verified (M2). `CollectNow` reads the machine at most once per
  `Timing::min_collect_gap`. A handshake message after `Welcome` ends the session.
- **No version, no connection.** The answer to the upgrade must select exactly one of the
  versions offered (`transport::negotiated_version`); the agent never assumes one. The
  request carries no `Origin`.
- **No token and no signature without TLS, except to this machine.** A `ServerUrl` only
  exists for `wss://` or for `ws://` to `localhost`, and the transport checks the address it
  connected to. TLS is 1.3 only (RNF-01), with the provider named in the code and the
  operating system's verifier. Always hand the connector to the WebSocket library: it must
  never build a TLS configuration of its own. Redirects are not followed.
- **Every failure before `Welcome` is the same failure.** A refused upgrade (503, 400), a
  certificate that does not verify and a close without a message all mean: wait and come
  back (`backoff.rs`). The server never says why it refused, so the agent never guesses,
  and never throws its identity away over a refusal. Only a session that lasted
  (`Timing::stable_session`) starts the count of failures again.
- **The agent pings, the server does not.** Only after `Welcome`: before it, the server ends
  the connection on anything but the answer to its challenge. Any frame is a sign of life,
  and `Timing::silence` without one ends the session. Every send has a deadline.
- **Never log a frame, a message, a token, a transcript, or the text of a parse error.**
  `Enroll` holds the token and the rest is text the server chose. Log `error.classify()`,
  an id, a count. Errors of libraries go through `transport::bounded`. The workspace is
  built without the `log` bridge of `tracing-subscriber`, because the WebSocket library logs
  every frame at `trace`: do not turn it on. `tests/agent_logs.rs` reads the whole log.
- **Telemetry is numbers and a drive letter** (RNF-09). Never read processes, users, host
  names or network interfaces, and never send a path: `telemetry::mount_name` keeps `C:`
  and `/` and drops the rest.
- **The key file is not encrypted until M2.** `platform::keystore` is where DPAPI goes
  (RNF-04); the agent says so in its log on every start. M1 builds are for development.
- Tests of the handshake and the session run without a socket and with a paused clock. A
  test of a deadline asserts the time that passed and the reason the wait ended, and has
  a twin in which the thing waited for arrives: a wait that ends for any reason at all
  must not pass for a working check. Tests named `ws_loopback_*` bind `127.0.0.1`, most of
  them against the real server.
