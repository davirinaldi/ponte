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
  and is the only thing models and technicians talk to.
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
| Server | axum, sqlx, PostgreSQL | Mature async stack; compile-time checked SQL |
| AI | MCP (`rmcp`) | Model-agnostic |
| Decision layer | Pluggable classifier + routing policy | Calibrated confidence drives automation (ADR-0005) |
| Web | Vite, React, TypeScript, types generated from `crates/protocol` | SPA embedded in the server binary |
| Media (P2) | WebRTC (`str0m`), Windows.Graphics.Capture, H.264 | Browser viewer, NAT traversal, E2E encryption |
| Packaging | MSI (cargo-wix), Authenticode signing | Mass deployment, antivirus reputation |
