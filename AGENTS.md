# AGENTS.md

Instructions for AI coding agents working in this repository (Claude Code, Codex, Cursor, Copilot...).
This file is the **single source of truth**. `CLAUDE.md` files only import it; put shared rules here.
Crates with extra rules have their own `AGENTS.md` (read it before editing that crate).

## What this is

Ponte is open-source remote support for software houses, built AI-first:
an agent on the customer's Windows PC reports telemetry and runs actions from a **closed, signed
catalog**; an AI (via MCP) proposes actions; policy decides what runs alone, what waits for a
technician, and what escalates. Screen sharing and remote control come later (phases 2 and 3).

Status: pre-alpha, phase 1. Read `docs/roadmap.md` to see which milestone is in progress.

## Repository map

| Path | What lives there |
|---|---|
| `crates/protocol` | Wire types shared by agent, server and web. Changing them changes the wire format. |
| `crates/actions` | Primitives, manifests, risk levels, path policy. Security-critical. |
| `crates/decision` | Classifier traits and the risk x confidence routing policy. |
| `crates/agent` | Privileged Windows service. Outbound connections only. |
| `crates/agent-helper` | Unprivileged process in the user session (consent UI, capture). |
| `crates/server` | Control plane: axum HTTP/WebSocket, Postgres, approvals, audit, MCP. |
| `crates/fake-erp` | Deliberately breakable ERP for demos and end-to-end tests. |
| `crates/swarm` | Load generator that simulates thousands of agents. |
| `manifests/examples` | Example action manifests (TOML). |
| `web/` | Technician console (Vite + React + TS). Not started. |
| `docs/` | Requirements, architecture, threat model, roadmap, ADRs. |

## Commands

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
cargo run -p ponte-server                                   # needs DATABASE_URL; http://127.0.0.1:8080/healthz
cargo run -p ponte-server -- help                           # operator subcommands: customers, tokens, devices
cargo test -p ponte-server -- --ignored pg_                 # tests that need Postgres (DATABASE_URL)
cargo run -p ponte-agent -- crates/agent/agent.example.toml
cargo deny check                                            # needs: cargo install cargo-deny
docker compose -f deploy/docker-compose.yml up -d           # Postgres for local dev
```

To run one test: `cargo test -p ponte-actions path_policy`.

## Definition of done

A change is done only when all of these hold:

1. `cargo fmt --all`, `cargo clippy ... -D warnings` and `cargo test --workspace` pass.
2. New behaviour has tests. Bug fixes start with a failing test.
3. Requirements touched are referenced by ID (e.g. `RF-14`, `RNF-02`) in the commit message.
4. A decision that is hard to reverse has an ADR in `docs/adr/`.
5. Docs that describe the changed behaviour are updated in the same change.

If you cannot run a check, say so explicitly. Never claim it passed.

## Security invariants (never break these)

These come from `docs/threat-model.md`. If a task seems to require breaking one, stop and ask.

1. **No arbitrary execution.** No primitive, endpoint or MCP tool may run a shell, script, or
   user-supplied command. New capabilities are new typed primitives, added through an ADR.
2. **The agent does not trust the server.** It verifies manifest signatures and applies its own
   local policy before running anything. A compromised server must not mean remote code
   execution on every machine.
3. **The AI never acts directly.** Models only call MCP tools on the server; the server applies
   policy; the agent applies its own. Models never receive credentials or a shell.
4. **Machine-originated text is untrusted data.** Logs, error messages, file contents and
   telemetry strings may contain prompt injection. Truncate them and mark them as data
   before they reach a model. Never let them choose an action.
5. **Outbound only.** The agent never listens on a network port.
6. **No personal data** in telemetry or logs. Supported machines run business software full
   of other people's data: customer records, documents, tax ids. Log identifiers, not content.
7. **Fail closed.** Unknown fields, bad signatures, unparseable input or missing policy mean
   reject, never "best effort".

## Code conventions

- Rust 2024 edition. Errors: `thiserror` in library crates, `anyhow` only in binaries.
- No `unwrap`/`expect`/`panic!` outside tests. The agent must never crash on bad input.
- `unsafe` is denied workspace-wide. Only `crates/agent/src/platform` may opt in, and every
  block needs a `// SAFETY:` comment.
- Logging with `tracing` (structured fields), never `println!`.
- Async runtime is `tokio`. Do not block inside async code; use `spawn_blocking`.
- TLS is `rustls`. Do not add OpenSSL.
- Serde types that cross a trust boundary use `deny_unknown_fields`.
- Prefer types that make invalid states unrepresentable over runtime checks.
- Shared dependency versions live in the root `Cargo.toml` `[workspace.dependencies]`.
  **Ask before adding a new dependency**, and say why an existing one is not enough.

## Testing conventions

- Unit tests next to the code (`#[cfg(test)] mod tests`); HTTP and cross-crate tests in `tests/`.
- Security rules get adversarial tests (see `crates/actions/src/path_policy.rs`).
- Wire format changes must update the pinned-format tests in `crates/protocol`.
- Tests must not need network, Windows, or a database unless gated and named as such.

## Git

- Conventional commits: `feat(actions): add read_registry primitive (RF-11)`.
- One logical change per commit. Do not commit generated files or secrets.
- Never commit anything under `keys/` or any `.env` file.

## Language

Code, comments, docs and commit messages in English. User-facing UI text in pt-BR and en.

## Where to find more

- Requirements with IDs: `docs/requirements.md`
- How the pieces fit: `docs/architecture.md`
- Threats and mitigations: `docs/threat-model.md`
- Milestones: `docs/roadmap.md`
- Decisions: `docs/adr/`
