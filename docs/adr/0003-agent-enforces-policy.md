# 0003. The agent verifies signatures and enforces policy itself

- Status: Accepted
- Date: 2026-10-12
- Requirements: RF-14, RNF-02

## Context

If the agent runs whatever the server sends, compromising one server means code execution on
every connected machine.

## Decision

Manifests are signed with an ed25519 key that never lives on the server (offline, or a separate
signing service). The agent ships with the public key, rejects unsigned or tampered manifests,
and applies its own local policy (allowed roots, risk ceiling, consent for high risk) regardless
of what the server decided.

## Consequences

- A server compromise can only run already-signed actions, within local policy.
- Key management becomes a real concern: rotation, revocation, a documented signing ceremony.
- Policy exists in two places (server and agent) and must not diverge; the agent's is the floor.

## Alternatives considered

- **Trust the TLS connection to the server**: simple, but makes the server a single point of total compromise.
