# Ponte

**Open-source remote support for software houses, where AI handles the ticket first and a
technician takes over the same session.**

> Status: pre-alpha. Phase 1 (telemetry and typed actions) is in progress: the agent connects,
> enrolls and reports telemetry (M1); signed actions come next. Not for production.

Remote-access tools were built for a human clicking pixels. Ponte starts from the support
ticket instead:

1. An agent on the customer's Windows PC reports telemetry (services, disk, ERP health).
2. A customer opens a ticket: "the system will not open".
3. An AI reads the telemetry, sees the ERP service stopped and the disk at 99%, and picks two
   fixes from a **closed, signed catalog** of typed actions.
4. Policy weighs risk against the model's calibrated confidence: low-risk fixes run on their
   own, riskier ones wait for one click from a technician.
5. The agent re-checks the signature and its own local policy, runs the fix, verifies it worked,
   and the summary goes back to the ticket.

No one opened the screen. When the catalog cannot fix it, a technician joins with full context
(screen sharing and control arrive in phases 2 and 3).

## Why it is built this way

- **The AI never gets a shell.** It chooses from typed actions with declared risk, preconditions
  and verification. Prompt injection cannot invent a capability that does not exist.
- **The agent does not trust the server.** Manifests are signed with a key the server never
  holds, so a compromised server is not remote code execution on every customer.
- **Automation is earned.** Actions run alone only when risk is low *and* a calibrated classifier
  is confident, with thresholds set from measured calibration.
- **Small and boring on the customer PC.** One Rust binary, outbound connections only, with a
  budget of under 40 MB RAM at idle. Measured in M1: a 2.1 MB binary, 14.4 MB of RAM and
  0.007% of one core, connected and idle.

## Architecture

```
Customer PC                         Control plane                 People and models
ponte-agent (Windows service) ──WSS──▶ ponte-server ◀──── web console (technicians)
  └ ponte-agent-helper (user UI)       policy, audit ◀──── AI via MCP
                                       helpdesk  ────────▶ Zammad / webhooks
```

More in [docs/architecture.md](docs/architecture.md).

## Repository layout

| Crate | Purpose |
|---|---|
| `protocol` | Wire types shared by every component |
| `actions` | Primitives, manifests, risk levels, path policy |
| `decision` | Classifier traits and the risk x confidence routing policy |
| `agent` / `agent-helper` | Windows service and its unprivileged session helper |
| `server` | Control plane (axum, Postgres, MCP) |
| `sign` | `ponte-sign`, which signs manifests offline |
| `fake-erp` / `swarm` | Breakable demo ERP and a 10k-agent load generator |

## Getting started

Requires Rust (the version is pinned in `rust-toolchain.toml`; rustup installs it) and, to
run the server, Docker for PostgreSQL.

```sh
cargo test --workspace
docker compose -f deploy/docker-compose.yml up -d
export DATABASE_URL=postgres://ponte:ponte@127.0.0.1:5432/ponte
cargo run -p ponte-server -- migrate                            # creates the tables
cargo run -p ponte-server -- customer create "Demo Customer"     # prints the customer id
mkdir -p keys/agent-dev                                          # ignored by git
cargo run -p ponte-server -- token create <customer-id> --out keys/agent-dev/enrollment-token
cargo run -p ponte-server            # then open http://127.0.0.1:8080/healthz
cargo run -p ponte-agent -- run crates/agent/agent.example.toml
cargo run -p ponte-server -- device list
```

`cargo run -p ponte-server -- help` lists the other subcommands. The
[walkthrough](docs/walkthrough.md) goes further: approval, revocation, reconnection, and the
agent's measured footprint.

## Documentation

- [Walkthrough](docs/walkthrough.md): everything that runs today, on one machine
- [Architecture](docs/architecture.md), with the agent's connection
- [Requirements](docs/requirements.md) with stable IDs
- [Threat model](docs/threat-model.md)
- [Roadmap](docs/roadmap.md)
- [Architecture decisions](docs/adr/README.md)

## Working on it with AI coding agents

`AGENTS.md` holds the project rules for any coding agent; `CLAUDE.md` imports it and adds Claude
Code specifics (skills, a security-review subagent, permissions and a format hook in `.claude/`).

## License

[Apache-2.0](LICENSE)
