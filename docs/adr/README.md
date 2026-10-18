# Architecture decision records

One file per decision that is hard to reverse. Create new ones with the `/adr` skill in
Claude Code, or copy `0000-template.md` by hand.

| # | Decision | Status |
|---|---|---|
| [0001](0001-rust-workspace-shared-protocol.md) | Rust on both sides, with a shared protocol crate | Accepted |
| [0002](0002-typed-actions-not-scripts.md) | Typed actions from a closed catalog, never scripts | Accepted |
| [0003](0003-agent-enforces-policy.md) | The agent verifies signatures and enforces policy itself | Accepted, amended by 0010 |
| [0004](0004-websocket-control-channel.md) | Outbound WebSocket over TLS for the control channel | Accepted |
| [0005](0005-pluggable-decision-layer.md) | Pluggable decision layer with risk x confidence routing | Accepted |
| [0006](0006-strict-wire-parsing.md) | Reject unknown fields on the wire and gate new fields by protocol version | Accepted |
| [0007](0007-version-in-websocket-subprotocol.md) | Negotiate the protocol version in the WebSocket upgrade | Accepted |
| [0008](0008-device-key-enrollment.md) | Enroll with an expiring token and prove a device key on every connection | Accepted |
| [0009](0009-os-trust-store.md) | Verify the server certificate against the operating system's trust store | Accepted |
| [0010](0010-signed-manifest-envelope.md) | Carry the whole signed manifest in each request, with keys from the agent's configuration | Accepted |
