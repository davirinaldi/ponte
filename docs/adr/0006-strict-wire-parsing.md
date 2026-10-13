# 0006. Reject unknown fields on the wire and gate new fields by protocol version

- Status: Proposed
- Date: 2026-10-12
- Requirements: RNF-21

## Context

Security invariant 7 says unknown fields mean reject, and manifests already follow it. The
wire types in `crates/protocol` did not: an agent accepted a `run_action` carrying a field it
had never heard of and simply dropped it. That is harmless until the field is a constraint.
If a later server adds an expiry or a "needs local consent" flag to a request, an older agent
would run the action without it and nobody would notice.

Rejecting unknown fields has a price. Older agents must keep working with newer servers
(RNF-21), and an agent that cannot parse the server's messages cannot even be told to update.

## Decision

Every type in `crates/protocol` has `deny_unknown_fields`, in both directions. A receiver that
meets an unknown field must reject that message. The connection loop (M1) is to log it and
keep running, never to exit.

A new field is therefore never free. It is added as an `Option`, left out of the JSON when
unset (`skip_serializing_if`), and comes with a `PROTOCOL_VERSION` bump. A sender only emits it
to a peer that announced a version that knows the field; the server learns the agent's version
from `Hello` before it sends anything. The same gate applies to a new message type, variant
or enum value, which an older peer rejects just the same. Renaming, removing or retyping a
field stays a breaking change that needs its own ADR.

## Consequences

- An old agent facing a constraint it does not understand fails loudly instead of ignoring it.
- The server must know what each protocol version understands and serve a range of versions,
  not only the latest.
- The handshake is the dangerous part. An old agent that cannot parse `Welcome` is locked
  out, auto-update included. `Hello` has the same problem in the other direction: the agent
  sends it before it knows the server's version, so after a server rollback a newer `Hello`
  is rejected. Treat both as frozen; changing either needs its own ADR, for example to
  negotiate the version before `Hello` (URL path or WebSocket subprotocol).
- More version bumps than a tolerant protocol would need. The number is cheap; forgetting the
  gate is not.
- Nothing in the types enforces the omission. Forgetting `skip_serializing_if` emits
  `"field": null`, which older peers reject. The pinned-format tests are the only guard.
- serde does not apply `deny_unknown_fields` to unit variants of internally tagged enums, so
  variants without fields are written `Variant {}`. The JSON is the same.

## Alternatives considered

- **Tolerant reader (ignore unknown fields)**: what most evolvable protocols do, and painless
  to roll out. Lost because its failure is silent and lands on the security-relevant fields.
- **Capability flags negotiated in the handshake**: finer-grained than one number, but more
  machinery than phase 1 needs. Revisit if versions start to branch.
