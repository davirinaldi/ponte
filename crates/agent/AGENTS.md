# crates/agent

Privileged Windows service installed on customer machines. It runs as SYSTEM on weak
point-of-sale PCs, so bugs here are expensive and visible.

- **Resource budget (RNF-12):** under 1% CPU and 40 MB RAM at idle, binary under 15 MB.
  Justify any dependency by its size; check with `cargo bloat` when in doubt.
  `scripts/measure-agent.ps1` measures it (numbers in `docs/roadmap.md`, M1).
- **Build a release of the agent on its own** (`cargo build --release -p ponte-agent`). A
  build that includes the server unifies features: sqlx brings rustls's `tls12`, and with
  it 64 KB of TLS 1.2 code the configuration never enables. CI checks the agent's own
  build has neither `tls12` nor a test-only crate.
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
- **The configuration is a root of trust** (ADR-0010, ADR-0011). `manifest_keys` and the
  local policy decide what SYSTEM runs, so `config.rs` builds `TrustedKeys` and
  `LocalPolicy` once and refuses the whole file on any doubt: no key list means no action,
  an empty one is an error, `high` does not parse, the agent's own service name and the
  refused services never go on `allowed_services`, and the agent's own files (executable
  folder, configuration, `data_dir`, token) never overlap a root (`Roots::overlaps`).
  Errors name the setting, never repair it.

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
  connected to. TLS is 1.3 only (RNF-01), with the provider named in the code
  (`transport::base` holds both) and the operating system's verifier (`client_config`). Only
  `#[cfg(test)]` code may give that builder another verifier: `transport::trusting` is the
  system's verifier with one more root, a test's, and `clippy.toml` refuses the two calls
  that does everywhere else. The `ws_loopback_wss_*` tests connect over real TLS to servers made
  on the spot, and the agent's own configuration is among them. Always hand the connector
  to the WebSocket library: it must never build a TLS configuration of its own. The
  verifier can block the thread it runs on, so the connection is made on a task of its
  own. Redirects are not followed.
- **Every failure before `Welcome` is the same failure.** A refused upgrade (503, 400), a
  certificate that does not verify and a close without a message all mean: wait and come
  back (`backoff.rs`). The server never says why it refused, so the agent never guesses,
  and never throws its identity away over a refusal. Only a session that lasted
  (`Timing::stable_session`) starts the count of failures again.
- **The agent pings, the server does not.** Only after `Welcome`: before it, the server ends
  the connection on anything but the answer to its challenge. Any frame is a sign of life,
  and `Timing::silence` without one ends the session. Every send has a deadline, and what
  waits to be written has a limit (`transport::socket_limits`): otherwise a server that
  stops reading and keeps pinging fills the memory with the pongs it is owed.
- **Never log a frame, a message, a token, a transcript, or the text of a parse error.**
  `Enroll` holds the token and the rest is text the server chose. Log `error.classify()`,
  an id, a count. Errors of libraries go through `transport::bounded`, and a failed TLS
  handshake through `transport::tls_problem`, which names the problem and never repeats
  what the certificate says. The workspace is built without the `log` bridge of
  `tracing-subscriber`, because the WebSocket library logs every frame at `trace`: do not
  turn it on. `tests/agent_logs.rs` reads the whole log.
- **Telemetry is numbers and a drive letter** (RNF-09). Never read processes, users, host
  names or network interfaces, and never send a path: `telemetry::mount_name` keeps `C:`
  and `/` and drops the rest.
- **The key file is not encrypted until M2.** `platform::keystore` is where DPAPI goes
  (RNF-04); the agent says so in its log on every start. M1 builds are for development.
- Tests of the handshake and the session run without a socket and with a paused clock. A
  test of a deadline asserts the time that passed and the reason the wait ended, and has
  a twin in which the thing waited for arrives: a wait that ends for any reason at all
  must not pass for a working check. Tests named `ws_loopback_*` bind this machine only,
  most of them the real server on `127.0.0.1`.

## Actions (`src/actions/`)

ADR-0010 to ADR-0013 say what the agent runs and when. These rules keep its half; the
server is not trusted, and neither is the user of the machine.

- **Only a `RunnableManifest` reaches the machine.** `runner.rs` decides in the order of
  ADR-0012 (journal, clock, the request's expiry, the hourly limit, `verify`, the interval
  per manifest, `validate`) and only then calls `Machine`. Keep the order; a test sends a
  request that breaks two rules and expects the first.
- **The journal is what "at most once" rests on** (`journal.rs`, RNF-18). A start is
  serialized and on disk before it joins the journal in memory and before the first step;
  nothing runs without it. A `RequestId` is in one entry of both files at most, and an
  unreadable journal refuses everything. The executor is the only writer of the journal,
  and `journal.lock` keeps a second process off it. If the files cannot be repaired, an
  administrator may remove `journal.json` and `ended.json`, which forgets what ran in the
  last day; say so in support guidance, never do it in code.
- **One action at a time, and the lock is the blocking task itself.** Everything that
  touches the machine or the disk for one request runs in one `spawn_blocking`, awaited to
  its end with no `timeout` around it. Each `Machine` call gets the time the manifest has
  left and must return within it. A running action is never cancelled; only the queue is.
- **The clock has a high-water mark** (`clock.rs`): the latest of the stored mark, the
  clock and the journal at start, then moved by a monotonic clock only. A mark that cannot
  be read refuses everything and is never written over.
- **Refusals that describe the agent are sent, not recorded**: no keys, a full queue or
  journal, a journal or clock that cannot be trusted, a stop. A repeat is decided again,
  which is safe because nothing started. Refusals of the request go to the ring, written
  at most once a minute, so a server cannot make the agent write per request.
- **`Machine` answers with codes.** No implementation returns text from the system, and
  the executor logs request ids, manifest ids and versions, step indexes and reason codes
  only: never a service name, a path, or anything of the request the server wrote, the
  text of a parse error included (`runner::tests::the_log_holds_no_name_*`).
