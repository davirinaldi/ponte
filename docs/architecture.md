# Architecture

## The four pieces

```
 Customer PC (Windows)                    Control plane                      People and models
┌────────────────────────┐   WSS, outbound  ┌──────────────────────┐   HTTPS   ┌──────────────────┐
│ ponte-agent (SYSTEM)   │ ───────────────▶ │ ponte-server         │ ◀──────── │ Technician web   │
│  telemetry, actions    │                  │  devices, policy     │           │ console          │
│        ▲ named pipe    │                  │  approvals, audit    │   MCP     ├──────────────────┤
│ ponte-agent-helper     │                  │  MCP, helpdesk       │ ◀──────── │ AI (any model)   │
│  (user session: UI)    │                  └──────────┬───────────┘           ├──────────────────┤
└────────────────────────┘                             │ webhooks / API        │ Helpdesk (Zammad)│
                                                       └─────────────────────▶ └──────────────────┘
```

- **Agent**: a Windows service that watches the machine and knows a closed list of fixes.
  It never obeys anyone directly: it checks signatures and its own policy first.
- **Server**: where every agent connects. Stores devices, telemetry, approvals and the audit log,
  and is the only thing models and technicians talk to. Today it stores devices and their
  last telemetry; approvals and the audit log arrive in M3.
- **Web console**: technicians see devices, approve actions and (later) open sessions.
- **AI**: proposes actions through MCP. Never touches a machine.

## A ticket, end to end

1. The agent sends a heartbeat every minute: "service running, disk 97%".
2. 09:02 the customer opens a ticket: "the system will not open".
3. The AI asks the server for the device's telemetry: "ERP service stopped at 08:55, disk 99%".
4. The AI picks candidate actions from the catalog (`list_actions`) and calls `request_action`.
5. The server routes each request through the risk x confidence policy (`crates/decision`):
   low risk and high confidence runs; medium risk waits for a technician; low confidence escalates.
6. The technician approves in the console. The server forwards the signed manifest to the agent.
7. The agent re-verifies the signature, checks local policy and preconditions, runs the steps,
   runs the verification checks and returns a structured result.
8. The server writes the audit event, the AI answers the customer, the summary goes to the ticket.

If nothing in the catalog fixes it, the AI hands the ticket to a technician, who sees everything
already tried. Phases 2 and 3 add screen viewing and control at this point.

## Agent connection (M1)

What exists today is the agent's half of the diagram: an agent that enrolls, proves who it
is on every connection and reports telemetry, and a server that keeps track of devices in
PostgreSQL. Approvals, audit storage, MCP and the console come later (see `roadmap.md`).
`docs/walkthrough.md` runs all of it on one machine.

### The connection

1. **TLS.** The agent opens `wss://` with rustls (`ring`), TLS 1.3 only (RNF-01), and checks
   the server certificate with the operating system's verifier, name included (ADR-0009).
   Plain `ws://` is accepted for this machine only (`localhost`, `127.0.0.1`), checked on
   the address the socket reached. The agent never listens on a port (RNF-01).
2. **Upgrade.** `GET /agent` offers the protocol versions as WebSocket subprotocols, newest
   first (`ponte.v2`; version 1 is not spoken since M2, ADR-0012). The server selects one
   or answers 400; a request with an `Origin` header (a browser) gets 403. No selected
   version, no connection (ADR-0007).
3. **Challenge.** The server speaks first: `Challenge` with 32 random bytes.
4. **Who the agent is.** The first time, `Enroll`: the token, a public key made on the
   machine and a signature over the nonce. The server consumes one use of the token,
   stores the key and answers `Enrolled` with the device id. After that, every connection
   is `Hello`: the device id and a signature over the nonce, the selected version and the
   id. The server answers `Welcome` (ADR-0008). The key never leaves the machine.
5. **Session.** The agent sends a heartbeat with telemetry every `heartbeat_secs` (60 by
   default) and pings every 30 seconds; 90 seconds without a frame ends the session on its
   side. The server reads the device's status again every minute and ends the session of
   a revoked device. A session ends after 24 hours at most, so the key is proven again.
6. **Failure.** Every failure before `Welcome` looks the same to the agent: a refused
   upgrade, a certificate that does not verify, a close without a word. It waits with
   exponential backoff and jitter and comes back (RNF-16). A failed TLS handshake is logged
   as its problem ("the server's certificate has expired"), never as what the certificate
   says.

### What the server accepts before authentication

`GET /agent` is the one endpoint a stranger can reach. Before `Welcome` the server accepts
one text message of at most 4 KiB, `Enroll` or `Hello`, within 10 seconds, and nothing else:
no ping, no binary frame. Every refusal is the same close, with no code and no text, so the
handshake cannot be used to ask which tokens or devices exist; the reason goes to the log.
At most 256 connections may be unauthenticated at once. After `Welcome` messages are
limited to 256 KiB, and what may wait to be written is bounded on both sides.

### Devices in PostgreSQL

- Tables `customers`, `enrollment_tokens` and `devices` (migration `0001_devices.sql`). A
  token is stored as its SHA-256 only. A device has a status (`active`, `pending`,
  `revoked`), its public key (unique), its session while online and its last telemetry.
- A device enrolled with a token for more than one machine waits as `pending` until an
  operator approves it (RF-49). Revoking a device refuses its next connection and ends the
  current one at the next status check.
- Each rule is one atomic step: enrollment is one transaction that locks the token's row;
  every other change checks and writes in one statement. Every call has a time limit.
- **One server per database.** `serve` takes a PostgreSQL advisory lock for the life of the
  process and checks it every 30 seconds; a second server on the same database refuses to
  start. Holding it is what makes `clear_online` safe at startup: sessions open when the
  last server stopped ended without a record, so every device starts offline and comes
  back as its agent reconnects.
- PostgreSQL 14 or newer. A database on another host needs `sslmode=verify-full`.

### Operator subcommands

Until the console exists, `ponte-server <subcommand>` is the operator's tool: `migrate`,
`customer create|list`, `token create|list|revoke`, `device list|approve|revoke`
(`ponte-server help`). A token is written once, to a new file (`--out`), and is named
everywhere else by a prefix of its hash. Every change is an audit line on the command's
stderr until the audit log of M3 exists.

## Three layers of access

| Layer | What | Risk | Who |
|---|---|---|---|
| Telemetry | Read state, no screen | Low | AI freely |
| Typed actions | Signed catalog of fixes | Medium | AI, gated by policy |
| Screen and control | See and drive the machine | High | Technician; AI as last resort |

## Trust boundaries

Each arrow crosses one. Data crossing a boundary is validated (`deny_unknown_fields`, size
limits) and the receiver re-checks authorisation instead of trusting the sender.
See `threat-model.md`.

## Technology

| Concern | Choice | Why |
|---|---|---|
| Language | Rust everywhere except the web UI | Small, fast agent; types shared with the server (ADR-0001) |
| Agent ↔ server | WebSocket over TLS on 443, JSON messages | Passes proxies and firewalls; easy to debug (ADR-0004) |
| Agent TLS | rustls with `ring`, TLS 1.3 only, the OS trust store | Works behind TLS inspection and internal authorities (ADR-0009) |
| Server | axum, sqlx, PostgreSQL 14+ | Mature async stack; compile-time checked SQL |
| AI | MCP (`rmcp`) | Model-agnostic |
| Decision layer | Pluggable classifier + routing policy | Calibrated confidence drives automation (ADR-0005) |
| Web | Vite, React, TypeScript, types generated from `crates/protocol` | SPA embedded in the server binary |
| Media (P2) | WebRTC (`str0m`), Windows.Graphics.Capture, H.264 | Browser viewer, NAT traversal, E2E encryption |
| Packaging | MSI (cargo-wix), Authenticode signing | Mass deployment, antivirus reputation |
