# 0007. Negotiate the protocol version in the WebSocket upgrade

- Status: Proposed
- Date: 2026-10-12
- Requirements: RNF-16, RNF-21

## Context

Today the version travels inside `Hello` and `Welcome`. Since every message is parsed
strictly (ADR-0006), each side learns the other's version only after parsing a message whose
shape depends on that version. ADR-0006 had to freeze both messages for that reason, and one
case stayed unsolved: after a server rollback, a newer agent sends a `Hello` the server
rejects, and nothing tells the agent to speak the older dialect.

## Decision

The version is agreed during the WebSocket upgrade, before any JSON is exchanged.

- The agent lists every version it speaks in `Sec-WebSocket-Protocol`, newest first
  (`ponte.v2, ponte.v1`).
- The server picks the newest version it also speaks and echoes it. With no version in
  common it refuses the upgrade, and the agent backs off like on any failed connection (RNF-16).
- The chosen version fixes the shape of every message on that connection, handshake included.
- An upgrade answered without a selected subprotocol is a failed handshake. The agent never
  assumes a default.

`protocol_version` leaves `Hello` and `Welcome`. `PROTOCOL_VERSION` stays as the newest version
a build speaks, and each build also declares the oldest one it still speaks.

## Consequences

- `Hello` and `Welcome` are no longer frozen: they change with a version like everything else.
  This lifts that restriction from ADR-0006; the rest of ADR-0006 stands.
- A rollback works without guessing: the agent offers both versions and the older server picks
  the one it knows.
- The range a server speaks is a support promise. An agent older than the range cannot connect
  at all, auto-update included, so the server must not drop a version while agents still use it.
  That needs a per-version count of connected agents before any version is retired.
- Both sides carry code for every version in their range.
- Removing `protocol_version` from `Hello` and `Welcome` changes the pinned wire format. No
  agent is in the field yet, so the version stays at 1.
- A middlebox that strips the header breaks the connection. It fails closed, and the agent's
  log must say so, because nobody on site will debug it.

## Alternatives considered

- **Version in the URL path (`/agent/v1`)**: easy to see in logs and to route, but the agent
  can only name one version per attempt, so a rollback means trial and error.
- **Keep the version inside `Hello`**: nothing to build, and the handshake stays frozen forever.
- **Ask the server's version over HTTP first**: an extra round trip and an HTTP client in an
  agent that otherwise needs none.
