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
  the versions newest first.
- **Before authentication, one message.** The server sends `Challenge` and accepts exactly
  one `Enroll` or `Hello`, as text, within `MAX_HANDSHAKE_MESSAGE_BYTES` and the handshake
  deadline. Anything else ends the connection, ping and binary frames included. The "log it
  and keep running" of ADR-0006 starts after `Welcome`, and `Enroll` or `Hello` after
  `Welcome` ends the session.
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
- **Limits are set on the socket**, both `max_message_size` and `max_frame_size`, and
  connections that have not authenticated yet are counted and capped (`Limits`).
- **One session per device.** A new one replaces the old one and the takeover is audited.
  A session also ends at a time limit, so the key is proven again.
- **A store keeps the hash of a token, never the token** (`TokenHash`), and follows the
  rules written on `DeviceStore`: enrollment is atomic and repeatable, a key enrolls once,
  and telemetry of a device that is not active is dropped (RF-49).
- Audit events go through `audit::record`. Until the audit log exists (M3) they are log
  lines under the `ponte::audit` target.
- Tests run without a socket (`testkit::Peer`) and with a paused clock. Tests named
  `ws_loopback_*` bind `127.0.0.1` and cover only what needs a real socket.
