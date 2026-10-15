# Threat model

Ponte puts a privileged agent on thousands of customer machines and lets software, including
AI models, cause actions on them. That is a high-value target. This document is the reference
for the security invariants in `AGENTS.md`; update it whenever a trust boundary changes.

## Assets

- Code execution on customer machines (the most valuable asset an attacker can gain).
- Personal data visible on those machines (customer records, documents, tax ids).
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
| T5 | Enrollment token leak clones devices | Expiring, use-limited tokens (single-use by default) that an operator can revoke; devices from a multi-use token wait for approval; device keys generated locally; per-device revocation. The server stores only the SHA-256 of a token, shows only a prefix of that hash, and refuses a bad token exactly like any other bad handshake. Enrolling again after the deadline gives back the existing device only to the same token and the same key (ADR-0008) | RF-01, RF-02, RF-04, RF-49 |
| T6 | Agent key theft from disk | The key is proven on every connection with a signature over a fresh nonce and is never sent. DPAPI from M2 (until then a plain file: see accepted risks); revocation | RNF-04, RF-04 |
| T7 | Malicious update | Signed binaries, verified by the agent before install; staged rollout; rollback | RF-43, RNF-07 |
| T8 | Personal data leaks through telemetry, logs or recordings | Minimal telemetry; no content in logs; consent, retention and audited access for recordings | RNF-09..11 |
| T9 | Audit tampering hides abuse | Hash-chained append-only log with verification | RF-41 |
| T10 | Insider abuse | Roles, approvals, local consent for screen access, full audit | RF-18, RF-19, RF-37 |
| T11 | Antivirus flags the agent as malware, or attackers impersonate it | Authenticode signing, stable publisher, documented behaviour | RNF-07 |
| T12 | The server's database leaks or its traffic is read | Token hashes and public keys only, never a token or a private key; `sslmode=verify-full` required unless the database is on the same machine; the URL and the database's error texts never reach a log or a message; one server per database (an advisory lock), so a second server cannot mark the first one's devices offline | RF-01, RF-02, RNF-11 |
| T13 | Someone exhausts the agent endpoint, the one any stranger can reach | Before authentication: one text message of at most 4 KiB within 10 seconds, at most 256 such connections at once; after it, size limits both ways and on what waits to be written; the store's own time limits; one turn per device, so one device key cannot slow down the others. A limit per source address waits for M5 (see the roadmap) | RNF-14, RNF-16 |

## Accepted risks (for now)

- Phase 1 runs without code signing on development builds.
- Until M2 the agent's device key and enrollment token are plain files with whatever
  permissions their folder gives them. Under `C:\ProgramData` every local user can read
  them, and can create files beside them. M2 gives the data directory an access list of
  its own (SYSTEM and administrators only), refuses one that others can write to, and keeps
  the key under DPAPI for the SYSTEM account rather than for the whole machine (T6).
- One host can hold the 256 places for connections that have not authenticated, by opening
  them and saying nothing, and keep every agent of the fleet from reconnecting for as long
  as it goes on (T13). A silent connection holds its place for the handshake and close
  deadlines, about 12 seconds, so it takes a steady stream. A limit per source address comes with the other rate limits in
  M5; it needs a decision about which address to trust behind a proxy (see the roadmap).
- Lexical path checks alone do not stop junctions; the execution-time check lands with the
  first file primitive (milestone M2).
- Until M3 the audit trail is log lines. What an operator does through the server's
  subcommands (issue or revoke a token, approve or revoke a device) is written to the
  stderr of that command, which the operator controls, so whoever runs the server must
  capture it to storage the operator cannot rewrite. An insider who holds `DATABASE_URL`
  can change the tables directly in any case: M3 brings a hash-chained audit log written
  in the same transaction as the change, under credentials of its own (RF-40).
