# Threat model

Ponte puts a privileged agent on thousands of customer machines and lets software, including
AI models, cause actions on them. That is a high-value target. This document is the reference
for the security invariants in `AGENTS.md`; update it whenever a trust boundary changes.

## Assets

- Code execution on customer machines (the most valuable asset an attacker can gain).
- Personal data visible on those machines (customer records, documents, tax ids).
- Agent identities and the manifest signing key.
- The agent's configuration, which names the manifest keys it trusts (ADR-0010) and its
  local policy (ADR-0011): whoever can change it decides what SYSTEM runs.
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
| Unprivileged local user (from M2) | The everyday user of a supported PC, with no administrator rights. Often writes in the ERP's folders, always in their own profile; can create folders under `C:\` and `C:\ProgramData`, plant junctions, hard links and named pipes, race the agent's file operations, bind a loopback port first, and make the ERP fail so that an action gets proposed |

## Threats and mitigations

| # | Threat | Mitigation | Requirements |
|---|---|---|---|
| T1 | Server compromise becomes RCE on every agent | No arbitrary-execution primitive (ADR-0002); today the agent refuses every action. From M2: each request carries a manifest signed offline (ADR-0010) by a key the agent's configuration lists, a file only administrators can change (ADR-0011); the agent checks the signature and the validity, against a high-water mark of its clock so a clock set back revives nothing, then its own policy: risk ceiling, service list and structural refusals, roots, verification coverage, rate limits (ADR-0011). What a compromised server can still do is listed in ADR-0012 | RNF-02, RF-14, RNF-06 |
| T2 | Prompt injection via machine-originated text makes the AI request harmful actions | Text labelled as untrusted and truncated; closed catalog; risk x confidence policy; per-ticket limits; approval for medium/high | RF-24, RF-25, RF-17 |
| T3 | Path tricks escape allowed directories (`..`, UNC, ADS, trailing dots, device names, look-alike letters, junctions, hard links, named pipes, races) | Strict lexical `PathPolicy` on every path in steps and checks. From M2 (ADR-0011): no root may be a drive, a system folder or a profile root, checked as written and as resolved at start; read and delete roots kept apart; each file opened without following a final reparse point and with identification-level SQOS, then checked for disk type and a single link, held without delete sharing, its final path compared with the resolved roots, and deleted through the same handle | RF-11 |
| T4 | Replay or duplicate execution of an action | From M2 (ADR-0012): a journal on the agent's disk keyed by `RequestId`, marked "started" before anything acts; a repeat gets the stored answer and never runs; a run cut short by a crash is recorded as interrupted and never runs again; requests expire within 24 hours and the journal remembers each one a day past its expiry, counted by the clock's high-water mark; a start is on disk before it can be seen or acted on, and one process at a time holds the journal, so a second agent on the same data directory runs nothing. Manifests expire too (ADR-0010) | RNF-18 |
| T5 | Enrollment token leak clones devices | Expiring, use-limited tokens (single-use by default) that an operator can revoke; devices from a multi-use token wait for approval; device keys generated locally; per-device revocation. The server stores only the SHA-256 of a token, shows only a prefix of that hash, and refuses a bad token exactly like any other bad handshake. Enrolling again after the deadline gives back the existing device only to the same token and the same key (ADR-0008) | RF-01, RF-02, RF-04, RF-49 |
| T6 | Agent key theft from disk | The key is proven on every connection with a signature over a fresh nonce and is never sent; revocation. Until M2 a plain file (see accepted risks). From M2 (ADR-0013): DPAPI in the scope of SYSTEM, in a data directory only SYSTEM and administrators can open, key bytes wiped after use. DPAPI does not stop an administrator, code running as SYSTEM, or offline access to an unencrypted disk | RNF-04, RF-04 |
| T7 | Malicious update | Signed binaries, verified by the agent before install; staged rollout; rollback | RF-43, RNF-07 |
| T8 | Personal data leaks through telemetry, logs, action results or recordings | Minimal telemetry; no content in logs; consent, retention and audited access for recordings. From M2 (ADR-0011, ADR-0012): `read_file_tail` and `sql_readonly` are refused until approvals and their own design exist; results carry typed reasons, never text from Windows, and a bounded `output`; telemetry strings are bounded; the agent logs codes and step indexes, never names or paths from a manifest | RNF-09..11 |
| T9 | Audit tampering hides abuse | Hash-chained append-only log with verification | RF-41 |
| T10 | Insider abuse | Roles, approvals, local consent for screen access, full audit | RF-18, RF-19, RF-37 |
| T11 | Antivirus flags the agent as malware, or attackers impersonate it | Authenticode signing, stable publisher, documented behaviour | RNF-07 |
| T12 | The server's database leaks or its traffic is read | Token hashes and public keys only, never a token or a private key; `sslmode=verify-full` required unless the database is on the same machine; the URL and the database's error texts never reach a log or a message; one server per database (an advisory lock), so a second server cannot mark the first one's devices offline | RF-01, RF-02, RNF-11 |
| T13 | Someone exhausts the agent endpoint, the one any stranger can reach | Before authentication: one text message of at most 4 KiB within 10 seconds, at most 256 such connections at once; after it, size limits both ways and on what waits to be written; the store's own time limits; one turn per device, so one device key cannot slow down the others. A limit per source address waits for M5 (see the roadmap) | RNF-14, RNF-16 |
| T14 | A local user takes over what the agent trusts: its configuration, data directory, token or logs, or the server's place on a loopback port | From M2 (ADR-0011, ADR-0013): an elevated agent refuses to start unless those files and the folders above them pass ownership and ACL rules, and unless its own executable is only administrators'; the data directory is created with a protected ACL; logs, journal and key are opened without following reparse points and with a single link; an elevated agent refuses `ws://` | RNF-03, RNF-04 |
| T15 | The manifest signing key is stolen or lost, or its holder is misled into signing something other than what they read | From M2 (ADR-0010): `ponte-sign` keeps the key offline, encrypted with a password (argon2id at a cost recorded and bounded in the file, XChaCha20-Poly1305 with the public key bound to it), reads the password from the terminal only, and never overwrites a key file; the validity, 90 days by default and 365 at most, bounds a leak, and two configured keys let one be retired. `sign` checks the manifest's shape first, including the values TOML decodes from escapes, prints every step, check, path and service, the validity and the key with every value escaped, so no manifest can hide or fake part of the summary, and writes nothing without `--yes` | RF-14, RNF-02 |

## Accepted risks (for now)

- Phase 1 runs without code signing on development builds.
- Until M2 the agent's device key and enrollment token are plain files with whatever
  permissions their folder gives them. Under `C:\ProgramData` every local user can read
  them, and can create files beside them. M2 gives the data directory an access list of
  its own (SYSTEM and administrators only), refuses one that others can write to, and keeps
  the key under DPAPI for the SYSTEM account rather than for the whole machine (T6,
  ADR-0013). The plain key is not migrated: lab machines of M1 on Windows enroll again.
- One host can hold the 256 places for connections that have not authenticated, by opening
  them and saying nothing, and keep every agent of the fleet from reconnecting for as long
  as it goes on (T13). A silent connection holds its place for the handshake and close
  deadlines, about 12 seconds, so it takes a steady stream. A limit per source address
  comes with the other rate limits in M5; it needs a decision about which address to trust
  behind a proxy (see the roadmap).
- Lexical path checks alone do not stop junctions; the execution-time check lands with the
  first file primitive (milestone M2), as ADR-0011 describes (T3).
- From M2, restarting a service whose binary, or the folder it loads code from, a local
  user can change gives that user the service's account, often SYSTEM. Windows already
  starts that service at every boot and on its recovery actions, so on a PC the user can
  restart the agent adds little; on a shared terminal server, where users cannot restart
  the machine, the agent becomes the trigger. The agent cannot see it in M2. The guidance
  for installers (walkthrough of M2, MSI of M5) is to keep ERP binaries in folders only
  administrators can change and to leave out of `allowed_services` any service whose
  binary is not. The threat model review of M5 decides whether the agent should check it.
- Until M3 nothing ties a request to a person. A compromised server, or whoever terminates
  TLS in front of it, can run any manifest that is signed, unexpired and allowed by a
  device's local policy, at a moment of its choosing, up to the rate limits (ADR-0012).
- Revoking a manifest signing key means changing the configuration of every agent that
  trusts it, by hand until M5. The validity of what it signed, 90 days by default and 365
  at most, bounds a leak (ADR-0010).
- Until M3 the audit trail is log lines. What an operator does through the server's
  subcommands (issue or revoke a token, approve or revoke a device) is written to the
  stderr of that command, which the operator controls, so whoever runs the server must
  capture it to storage the operator cannot rewrite. An insider who holds `DATABASE_URL`
  can change the tables directly in any case: M3 brings a hash-chained audit log written
  in the same transaction as the change, under credentials of its own (RF-40).
