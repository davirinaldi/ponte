# 0008. Enroll with an expiring token and prove a device key on every connection

- Status: Accepted
- Date: 2026-10-12
- Requirements: RF-01, RF-02, RF-04, RF-49, RNF-04

## Context

`Hello` carries a `device_id` the agent states on its own. Whoever learns an id can pose as
that machine: feed the AI telemetry of their choosing and receive the actions meant for it.
RF-01, RF-02 and RF-04 already ask for an enrollment token, a locally generated key pair and
revocation, but no milestone delivered them. M1 creates the device table and the handshake,
which is the cheapest moment to get identity right.

## Decision

**Enrollment, once per machine.** The installer carries an enrollment token (RF-01). On first
start the agent generates an ed25519 key pair; the private key never leaves the machine
(RF-02). The agent connects, presents the token and its public key, and signs the server's
nonce to show it holds the private key. The server consumes the token, stores the public key
and answers with the `device_id`.

**Every connection.** After the upgrade the server speaks first and sends a fresh random
nonce. The agent's `Hello` carries its `device_id` and a signature over a fixed context
string, the negotiated protocol version (ADR-0007), the nonce and the device id. The server
checks it against the stored key. An unknown or revoked device, or a bad signature, closes the
connection (RF-04). Nothing else is accepted from a connection before that check passes.

**Tokens.** A token belongs to one customer, expires, and is good for a fixed number of
enrollments: one by default (RF-01). A rollout to many PCs uses a token issued for that many
machines with a short deadline. A device enrolled with a multi-use token starts as pending:
the server shows nothing from it to the AI and sends it no actions until a technician
approves it (RF-49).

Enrollment travels on the same WebSocket, so the agent needs no HTTP client. M1 delivers both
parts. The private key is protected with DPAPI (RNF-04) from M2, when the Windows platform
layer exists; until then it sits in a file and M1 builds are for development only.

## Consequences

- A stolen `device_id` or a recorded handshake is worthless. Cloning a device takes its
  private key (T5, T6), and a leak of the server database exposes public keys only.
- The device key is unrelated to the manifest signing key. It says who is connecting, never
  what the server may ask for (ADR-0003).
- One new dependency on both sides, an ed25519 implementation. M2 needs the same one to
  verify manifests.
- The handshake gains a message and the server now speaks first.
- The proof holds for the moment of connection. Whoever terminates the TLS session can still
  alter what follows (ADR-0009).
- A re-imaged machine, or one that lost its key, enrolls again and appears as a new device.
  The console will need a way to replace the old record.
- A leaked multi-use token can enroll at most the machines it has left, before its deadline,
  and those wait for approval. The price of a silent rollout (RF-42) is one bulk approval.

## Alternatives considered

- **A bearer token per device**: simpler, but a copied token clones the device and a captured
  one can be replayed.
- **Mutual TLS with client certificates**: standard, but it breaks behind proxies that inspect
  TLS and load balancers that terminate it, and it needs a certificate authority to run.
- **No authentication in M1, enrollment later**: the device table and the handshake would
  both be migrated right after being built.
