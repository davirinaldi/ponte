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
