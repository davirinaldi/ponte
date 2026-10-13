# Requirements

IDs are stable: reference them in commits, ADRs and tests. Never reuse a retired ID.
Phase tags: **P1** core (telemetry and typed actions), **P2** view the screen, **P3** full control.

## Actors

- **Admin**: configures customers, the action catalog and policies.
- **Technician** (N1/N2): handles tickets, approves actions, opens sessions.
- **End user**: the person at the supported PC. Consents and can stop a session.
- **AI**: any model connected through MCP. Proposes and requests, never executes directly.
- **Helpdesk**: external ticketing system (Zammad in the demo).

## Functional requirements

### A. Devices and identity
- **RF-01 (P1)** Enrollment token per customer, passed to the installer, with an expiry and a use limit (one by default).
- **RF-02 (P1)** Agent generates a local key pair on enrollment and receives a device identity.
- **RF-03 (P1)** List, search and group devices by customer and tags, with online status and last contact.
- **RF-04 (P1)** Revoke a device: drop its connection immediately and refuse reconnection.
- **RF-49 (P1)** A device enrolled with a multi-use token stays pending until a technician approves it: nothing from it reaches the AI and it receives no actions.

### B. Telemetry
- **RF-05 (P1)** Inventory: OS, CPU, RAM, disks, network, uptime.
- **RF-06 (P1)** State of monitored services and processes.
- **RF-07 (P1)** Collectors declared by the software house (ERP version, DB reachability, DB size, error log tail).
- **RF-08 (P1)** Event history ("service stopped at 08:55", "disk crossed 90%").
- **RF-09 (P1)** On-demand snapshot in addition to periodic heartbeats.
- **RF-10 (P1)** Simple alert rules (threshold, state change).

### C. Typed action catalog
- **RF-11 (P1)** Primitives compiled into the agent: service control, read/delete file under allowed roots, read registry, kill process, read-only SQL, clear temp.
- **RF-12 (P1)** Declarative manifests composing primitives: id, descriptions for humans and AI, schema-validated parameters, risk, timeout.
- **RF-13 (P1)** Preconditions before and verification after every action. An action that changes the machine (risk above read) must declare at least one verification check.
- **RF-14 (P1)** Versioned, signed manifests. The agent rejects any manifest without a valid signature.
- **RF-15 (P1)** Structured results (outcome, output, duration) and cancellation.

### D. Policy and approval
- **RF-16 (P1)** Risk levels: read, low, medium, high.
- **RF-17 (P1)** Per-organisation policy: what the AI runs alone, what needs a technician, what needs N2.
- **RF-18 (P1)** Approval queue: approve or deny with reason, automatic expiry.
- **RF-19 (P2)** Local consent prompt on the machine for screen access and high-risk actions.
- **RF-20 (P1)** "Suggest only" mode: the AI proposes, a human executes.

### E. AI integration (MCP)
- **RF-21 (P1)** MCP server with `list_devices`, `get_telemetry`, `list_actions`, `request_action`, `get_action_result`.
- **RF-22 (P1)** Scoped access tokens for AI clients, per customer and per action type.
- **RF-23 (P1)** Actions awaiting approval return `pending`; the model polls for the result.
- **RF-24 (P1)** Machine-originated content is truncated and labelled as untrusted data.
- **RF-25 (P1)** Per-ticket limits on action count and call rate.

### F. Helpdesk integration
- **RF-26 (P1)** Generic connector interface, a Zammad connector and a generic webhook connector.
- **RF-27 (P1)** Link ticket, customer and devices.
- **RF-28 (P1)** Post the action log and an AI summary back to the ticket (and the recording link in P3).
- **RF-29 (P2)** Open a remote session from a link in the ticket.

### G. Remote session
- **RF-30 (P2)** View the screen in the browser, multi-monitor.
- **RF-31 (P2)** Visible "being viewed" indicator on the machine and a button to end the session.
- **RF-32 (P3)** Keyboard and mouse control.
- **RF-33 (P3)** Clipboard and file transfer.
- **RF-34 (P3)** Multiple participants: the technician joins the session where the AI is.
- **RF-35 (P3)** Session recording with configurable retention.
- **RF-36 (P3, stretch)** Access to the login screen and UAC prompts.

### H. Web console
- **RF-37 (P1)** Login, users and roles (admin, technician, auditor).
- **RF-38 (P1)** Device page: telemetry, history, actions run.
- **RF-39 (P1)** Manage the action catalog and policies.

### I. Audit
- **RF-40 (P1)** Every relevant event recorded: who (human or AI), what, when, on which device.
- **RF-41 (P1)** Hash-chained append-only log with integrity verification and export.

### J. Agent lifecycle
- **RF-42 (P1)** MSI installer with silent install for mass deployment.
- **RF-43 (P1)** Signed auto-update with staged rollout and rollback.
- **RF-44 (P1)** Self-recovery: the service restarts if it crashes.
- **RF-45 (P1)** Clean uninstall.

### K. Decision layer
- **RF-46 (P1)** Pluggable decision providers (calibrated classifier API, LLM fallback) behind one interface.
- **RF-47 (P1)** The confidence behind every AI-initiated action is stored in the audit log.
- **RF-48 (P1)** Calibration report (Brier score, ECE) on labelled Portuguese tickets before any threshold enables automatic execution.

## Non-functional requirements

### Security
- **RNF-01** No inbound ports on supported machines; outbound TLS 1.3 only.
- **RNF-02** A compromised server cannot cause mass remote execution: signing key off-server, signature and policy checked on the agent.
- **RNF-03** Least privilege: privileged service executes; unprivileged session helper handles UI and capture.
- **RNF-04** Agent private key protected by DPAPI (TPM when available).
- **RNF-05** Session media end-to-end encrypted; relay cannot see content.
- **RNF-06** The AI never receives free-form command execution.
- **RNF-07** Signed binaries (Authenticode), dependency audit and SBOM on every release.
- **RNF-08** Threat model maintained in the repository.

### Privacy (LGPD)
- **RNF-09** Minimal telemetry: no screen content, documents or patient data.
- **RNF-10** Recording only with consent, configurable retention, restricted and audited access.
- **RNF-11** No personal data in system logs.

### Performance
- **RNF-12** Agent idle: under 1% CPU and 40 MB RAM; binary under 15 MB.
- **RNF-13** Command reaches an online agent in under 1 s (p95).
- **RNF-14** One modest server instance holds 10,000 connected agents, proven by load test.
- **RNF-15** (P2) Video usable at 1-2 Mbps and adaptive to poor links.

### Reliability
- **RNF-16** Reconnect with exponential backoff and jitter (no thundering herd).
- **RNF-17** Local event queue while offline.
- **RNF-18** Idempotent actions: a retried `RequestId` never runs twice.
- **RNF-19** Failed update rolls back automatically.

### Compatibility and maintainability
- **RNF-20** Agent supports Windows 10 and 11. Windows 7 is out of scope.
- **RNF-21** Versioned protocol: older agents keep working with newer servers.
- **RNF-22** Platform layer isolated so Linux agents are possible later.

### Observability
- **RNF-23** Structured logs and metrics.
- **RNF-24** End-to-end trace of an action: ticket, AI, approval, agent, result.

### Deployment and documentation
- **RNF-25** Self-hosted server starts with one command.
- **RNF-26** English README, ADRs, Apache-2.0 license.
- **RNF-27** UI in pt-BR and en.

## Out of scope

macOS, Linux and mobile as supported machines; free-form script execution by anyone;
full RMM (patching, antivirus, software inventory); multi-tenant SaaS billing; VPN.
