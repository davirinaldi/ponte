# 0010. Carry the whole signed manifest in each request, with keys from the agent's configuration

- Status: Accepted
- Date: 2026-10-18
- Requirements: RF-12, RF-14, RNF-02

## Context

ADR-0003 says manifests are signed with a key that never lives on the server and that the
agent "ships with the public key". Nothing of it exists yet. `Manifest` is plain TOML that
`Manifest::validate` checks when someone calls it, `ActionRequest` names a manifest by
`manifest_id` and `manifest_version` only, and the agent refuses every `RunAction`. M2 is
the milestone where actions run, so how a manifest is signed, how it reaches the agent and
which keys the agent accepts must be settled before any primitive is implemented.

Three facts shape the answer. Each software house writes and signs its own catalog, so one
key compiled into the agent would mean one agent build per software house. A signature made
offline must outlive releases of the agent and of the protocol. And the server is not
trusted (invariant 2), so it can neither be the place where keys live nor the judge of
which manifest is current.

## Decision

**The request carries the signed manifest.** `RunAction` holds a whole `SignedManifest`
(ADR-0012). The agent keeps no catalog: there is nothing to sync, cache or invalidate, and
a manifest is a few KB.

**The envelope.** `SignedManifest { manifest, issued_at, expires_at, public_key, signature }`
is a type in `crates/protocol`, written as JSON everywhere: on the wire, in the file
`ponte-sign` writes and in the server's catalog.

- `manifest` is the exact TOML text a person reviewed, comments included. It is UTF-8 with
  no `\r` and no byte order mark; `ponte-sign` and the agent both refuse anything else, so
  the bytes that were read are the bytes that were signed. It is at most 16 KiB (ADR-0011).
  Step 2 of M2 widened the rule before anything was signed: no control character but the
  line feed and the tab, and none of the invisible characters that change how text reads
  (zero-width characters, bidirectional overrides and isolates, line and paragraph
  separators), so a reviewer cannot be shown one text while the parser reads another.
- `issued_at` and `expires_at` are seconds since the Unix epoch, as integers.
- `public_key` and `signature` follow the rules of `src/keys.rs`: lowercase hex of their
  exact length.

**The signed bytes** are a transcript in the style of `src/transcript.rs`: the label
`ponte.manifest.v1\0`, `issued_at` and `expires_at` as u64 big-endian, the length of the
TOML as u32 big-endian, then the TOML bytes. Every field has a fixed size or a length in
front of it, and nothing is re-serialized: the TOML is never parsed back into a structure
and written again, because `[[steps]]` inside a `[manifest]` table would not survive the
round trip and TOML dates are not read reliably by serde. The protocol version is not in
the transcript, so a signature made offline survives protocol versions. The agent verifies
with `verify_strict`, then parses the TOML, never before.

**Validity is the revocation that works offline.**

- `ponte-sign` sets `issued_at` one hour before the signing machine's clock, so an agent
  whose clock runs up to an hour late still accepts a fresh manifest. The validity is
  counted from `issued_at`: 90 days by default, 365 at most.
- The agent refuses a window (`expires_at - issued_at`) longer than 365 days, an
  `issued_at` more than 5 minutes ahead of its clock, and an `expires_at` that has passed.
- The agent keeps a high-water mark of its own clock in its data directory. Expiry is
  checked against the later of the clock and the mark, so setting the clock back never
  revives an expired manifest. A clock more than one hour behind the mark refuses every
  action with `ClockWentBack`, because the request's expiry, the rate limits and the
  journal (ADR-0012) read the clock too.
- When the agent starts, the mark becomes the later of the stored mark and the clock, and
  a clock more than one hour behind the stored mark is refused as above. While the agent
  runs, the mark moves forward only by the time that passed on `QueryInterruptTime`, an
  interrupt-time counter that also counts time asleep, so a clock that jumps ahead and is
  corrected while the agent runs (a bad time sync on a weak PC) leaves no mark behind. A
  clock that is already more than one hour ahead when the agent starts, and is corrected
  later, does: that machine refuses actions until an administrator removes the mark. A
  user who sets the clock to local time instead of choosing the time zone causes exactly
  that, so support should expect it.
- The mark is written through (ADR-0012) every five minutes and when the agent stops, so
  a clock set back across a restart finds a mark at most five minutes old, well inside
  the one-hour tolerance.
- A mark that cannot be read or does not parse refuses every action, like a missing
  policy (invariant 7); it is never taken as zero. Only a missing file means "no mark
  yet".
- The server shows each device's clock offset, from `collected_at` in its telemetry, so a
  machine refusing for this reason is found before anyone asks why.

**The agent's keys come from its configuration.** `manifest_keys` in `AgentConfig` holds 1
to 4 ed25519 public keys in lowercase hex; a weak key (`is_weak`) refuses the whole
configuration. Without the field the agent runs no action at all, and an empty list is a
configuration error rather than a quiet way of saying the same thing. More than one key
allows a rotation: add the new key, re-sign, then remove the old one. The agent looks up
the envelope's `public_key` in this list; a key that is not there is refused before any
verification. This amends ADR-0003, which compiled the key into the agent. It is only safe
because the configuration is a root of trust that nobody but an administrator can change
("The configuration is a root of trust" in ADR-0011, and ADR-0013).

**`ponte-sign`**, a new binary (`crates/sign`), runs offline:

- `keygen` writes the public key in hex and the private key encrypted with a password:
  argon2id (64 MiB, 3 passes, recorded in the file so they can rise later) and
  XChaCha20-Poly1305. The password is read without echo.
- `sign` validates the manifest's shape (ADR-0011), refuses the primitives the agent
  refuses, prints what the action does (risk, steps, every path and service, the
  validity, the key) and writes the envelope only with `--yes`.
- `verify` checks an envelope against a public key; `show` prints the summary of `sign`
  for an envelope.

A signing ceremony is part of the walkthrough of M2: the private key lives on a machine
that is not the server, its encrypted file is backed up, and two keys are configured on
agents from the start so one can be retired.

**The server keeps its own list of trusted keys** (`catalog key add | list | remove`).
`catalog add` verifies an envelope against that list, never against the key the envelope
names, and refuses one that has expired or whose manifest has no valid shape. An envelope
is identified by the SHA-256 of its public key followed by its transcript, so the same
envelope has one id whatever JSON spelling carried it, and re-signing the same version to
renew its validity adds a second envelope instead of colliding. `action run` picks, for an
`(id, version)`, the unexpired envelope with the latest `issued_at` signed by a key the
server still trusts. One server serves one software house; multi-tenancy is out of scope.

## Consequences

- A compromised server can only send manifests that were signed offline, and only until
  they expire (ADR-0012 lists what else it can still do). It cannot change one byte of a
  manifest, its validity or its key.
- Revoking a key means changing the configuration of every agent that trusts it, by hand
  until the installer and auto-update of M5. Until then the validity is the only bound on
  a leaked key: up to 365 days, 90 by default. A leaked key also needs the server (or
  whoever terminates TLS, ADR-0009) to deliver what it signs.
- A manifest cannot be withdrawn from agents, only from the server's catalog. A version
  found to be wrong stays runnable by a compromised server until it expires. New or risky
  manifests should get a short validity.
- Every manifest must be re-signed at least once a year, and a catalog left to expire
  stops every action. That failure is safe and loud, but it is a chore someone owns.
- An agent whose clock is wrong by more than the tolerances refuses actions. The clock
  offset in `device list` is how that gets noticed; a mark left by a clock that was more
  than one hour ahead when the agent started needs a person on the machine. Following the
  interrupt-time counter while running means the mark falls behind the real time when the
  clock is corrected forward, which only weakens the mark, never refuses.
- The signature covers bytes, and what they mean depends on the TOML parser of the agent's
  build. Signer and agent share `crates/actions` and the parser refuses unknown fields and
  duplicate keys, but a signer built from another version could read a document
  differently from the agent. Upgrading the `toml` crate is reviewed as a change to what
  signatures mean.
- The manifest format is versioned by the transcript label. A field an older agent does
  not know is refused there (invariant 7). Re-enabling a primitive the agent refuses today
  is an ADR that also decides what happens to manifests signed before it, for instance
  with a new label.
- Losing the password loses the key. The second configured key is the way out.
- The trust root moved from the binary to a file, which makes the ACL rules of ADR-0011
  and ADR-0013 load-bearing: a configuration a user can write lets that user choose the
  keys, and with them what SYSTEM runs.

## Alternatives considered

- **The agent keeps a synced copy of the catalog**: saves a few KB per request, but adds
  state to keep consistent, a sync message the server controls, and the question of what
  a stale copy may run.
- **A key compiled into the agent (ADR-0003 as written)**: no configuration to protect,
  but one agent build per software house, and a rotation is a release.
- **Sign a canonical re-serialization of the parsed manifest**: lets the TOML be
  reformatted freely, but canonical forms of TOML or JSON are fragile, and the signer
  would approve a text other than the one that was signed.
- **An existing signature format (minisign, JWS, COSE)**: proven, but each brings a format
  or a dependency, JWS brings algorithm negotiation, and none puts our validity fields in
  the signed bytes without an extra layer. The transcript is a few lines on top of the
  ed25519 crate both sides already use.
- **Revocation lists or an online check**: the only path from a signer to the agent goes
  through the server, which is untrusted and could withhold the list. Expiry needs no
  path at all.
- **An online signing service the server can reach**: it signs whatever the server asks
  for, which is what RNF-02 forbids. A hardware key behind `ponte-sign` can come later
  without changing the envelope.
