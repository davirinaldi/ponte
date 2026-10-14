# crates/server

Control plane: agent WebSocket endpoint, REST API for the console, approvals, audit log,
MCP server for models, helpdesk connectors.

- Keep handlers thin: parse and authorize, call a domain function, map the result to HTTP.
- `router()` in `lib.rs` must stay constructible without a network or database, so tests can
  drive it in-process (see `tests/http.rs`).
- Database (from milestone M1): PostgreSQL via `sqlx`, migrations in `crates/server/migrations`.
  Never edit a migration that has been merged; add a new one.
- Every state-changing operation writes an audit event with actor (human or AI), device,
  action and outcome (RF-40). The audit table is append-only.
- MCP tools expose the catalog, never a shell (AGENTS.md, invariant 3). Machine-originated
  text returned to a model is truncated and labelled as untrusted data (invariant 4).
- The server can never make an agent run something unsigned: it forwards signed manifests only.

## Agent connections (`src/agents`)

`GET /agent` is the one endpoint anyone on the network can reach before proving anything.
ADR-0007 and ADR-0008 say what it does; these rules keep it that way.

- **No version, no connection.** axum's `protocols()` completes the upgrade even when no
  subprotocol matched. `ws.rs` checks `selected_protocol()` and answers 400 instead. Offer
  the versions newest first. A request with an `Origin` header comes from a browser and is
  refused with 403.
- **Before authentication, one message.** The server sends `Challenge` and accepts exactly
  one `Enroll` or `Hello`, as text, within `MAX_HANDSHAKE_MESSAGE_BYTES` and the handshake
  deadline. Anything else ends the connection, ping and binary frames included. The "log it
  and keep running" of ADR-0006 starts after `Welcome`, and `Enroll` or `Hello` after
  `Welcome` ends the session.
- **The deadline is for the peer, not for the store.** It covers sending the challenge and
  reading the answer. Once the message is in, the store call runs to its end: cut short, it
  could leave a device enrolled with no audit event, at a moment the peer picked.
- **Every refusal looks the same.** The server closes with no code and no text, at once,
  whatever was wrong. The reason goes to the log as a `Rejection`. Never add a message, a
  close code, a delay or a different HTTP status for one reason only: that turns the
  handshake into a way to ask which devices and tokens exist.
- **Verify, then look things up.** `Enroll` is checked with `verify_strict` before the store
  hears of the token. `Hello` costs one verification whether or not the device exists (see
  `DECOY_KEY`). A weak or malformed key is refused before it is stored.
- **The nonce** is 32 bytes from the operating system, lives in the connection's own state
  and is never reused. No random bytes means no challenge.
- **Never log a frame, a parsed message, a `serde_json::Value` of one, or a transcript.**
  A frame before authentication is whatever a stranger sent, and `Enroll` holds a token. A
  message that fails to parse is logged by `error.classify()` only: the error's text can
  repeat what the peer wrote. The tests in `session.rs` read the logs to check this.
- **Dependencies do not log for us.** The WebSocket library writes every frame it reads to
  the `log` crate at `trace`. The workspace builds `tracing-subscriber` without its
  `tracing-log` feature, so none of that reaches the output. `tests/agent_logs.rs` fails
  if it ever does, and `deny.toml` bans the crate. Do not turn the feature back on to see
  a dependency's logs.
- **A stranger gets no log line at the default level.** A refusal anyone can cause is
  logged at `debug`. A refusal that followed a real token or a real device key is an audit
  event (`Rejection::follows_a_real_credential`) that names the device, or the key and
  the hash prefix of the token. After `Welcome`, only the first few dropped messages of a
  session are logged.
- **Limits are set on the socket** (`ws::limited`): `max_message_size`, `max_frame_size` and
  what may wait to be written. axum leaves the last one unbounded, and a peer that pings
  without reading would fill the memory with the pongs it is owed. Connections that have
  not authenticated yet are counted and capped (`Limits`).
- **Revocation does not wait for the device.** A session reads the device's status again at
  least every `Limits::status_check`, with or without a heartbeat, and ends when the device
  is revoked. The store has the last word when a session starts, too.
- **One session per device, started one at a time.** A session is recorded in the store
  first and takes the device's place in the registry second, both under the device's turn
  (`Registry::starting`). The old session is only replaced once the store accepted the new
  one, and the takeover is audited. A session also ends at a time limit, so the key is
  proven again.
- **A device waits only behind itself.** The turn is per device, never shared, and only a
  few connections of one device may hold or wait for it; the rest are dropped. Whoever
  holds one device key must not be able to slow down the others.
- **A store keeps the hash of a token, never the token** (`TokenHash`), and follows the
  rules written on `DeviceStore`: enrollment is atomic and repeatable, a key enrolls once,
  telemetry of a device that is not active is dropped (RF-49), and its error type never
  carries the values of a call.
- Audit events go through `audit::record`. Until the audit log exists (M3) they are log
  lines under the `ponte::audit` target. `log_filter` lets them through with a filter of
  its own, beside the one built from `RUST_LOG`: a directive could be outranked.
- Tests run without a socket (`testkit::Peer`) and with a paused clock. Tests named
  `ws_loopback_*` bind `127.0.0.1` and cover only what needs a real socket.
