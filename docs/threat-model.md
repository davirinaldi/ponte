# Threat model

Ponte puts a privileged agent on thousands of customer machines and lets software, including
AI models, cause actions on them. That is a high-value target. This document is the reference
for the security invariants in `AGENTS.md`; update it whenever a trust boundary changes.

## Assets

- Code execution on customer machines (the most valuable asset an attacker can gain).
- Personal data visible on those machines (pharmacy context: patients, prescriptions, CPF).
- Agent identities and the manifest signing key.
- Audit log integrity.

## Adversaries

| Adversary | Capability |
|---|---|
| External attacker | Network access to the server; may steal tokens or exploit bugs |
| Server compromise | Full control of the control plane and its database |
| Malicious content on a customer machine | Text in logs, files or window titles crafted to manipulate the AI |
| Compromised or misbehaving AI client | Calls MCP tools with arbitrary arguments |
| Malicious or careless insider | Technician or admin abusing access |
| Stolen machine or installer | Possession of an agent's files or an enrollment token |

## Threats and mitigations

| # | Threat | Mitigation | Requirements |
|---|---|---|---|
| T1 | Server compromise becomes RCE on every agent | Signing key never on the server; agent verifies signatures and enforces local policy; no arbitrary-execution primitive | RNF-02, RF-14, RNF-06 |
| T2 | Prompt injection via machine-originated text makes the AI request harmful actions | Text labelled as untrusted and truncated; closed catalog; risk x confidence policy; per-ticket limits; approval for medium/high | RF-24, RF-25, RF-17 |
| T3 | Path tricks escape allowed directories (`..`, UNC, ADS, trailing dots, device names, look-alike letters, junctions) | Strict lexical `PathPolicy` on every path in steps and checks, plus resolved-path re-check at execution | RF-11 |
| T4 | Replay or duplicate execution of an action | `RequestId` idempotency on the agent; short-lived requests | RNF-18 |
| T5 | Enrollment token leak clones devices | Single-use tokens; device keys generated locally; per-device revocation | RF-01, RF-02, RF-04 |
| T6 | Agent key theft from disk | DPAPI/TPM protection; revocation | RNF-04 |
| T7 | Malicious update | Signed binaries, verified by the agent before install; staged rollout; rollback | RF-43, RNF-07 |
| T8 | Personal data leaks through telemetry, logs or recordings | Minimal telemetry; no content in logs; consent, retention and audited access for recordings | RNF-09..11 |
| T9 | Audit tampering hides abuse | Hash-chained append-only log with verification | RF-41 |
| T10 | Insider abuse | Roles, approvals, local consent for screen access, full audit | RF-18, RF-19, RF-37 |
| T11 | Antivirus flags the agent as malware, or attackers impersonate it | Authenticode signing, stable publisher, documented behaviour | RNF-07 |

## Accepted risks (for now)

- Phase 1 runs without code signing on development builds.
- Lexical path checks alone do not stop junctions; the execution-time check lands with the
  first file primitive (milestone M2).
