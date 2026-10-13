# Architecture decision records

One file per decision that is hard to reverse. Create new ones with the `/adr` skill in
Claude Code, or copy `0000-template.md` by hand.

| # | Decision | Status |
|---|---|---|
| [0001](0001-rust-workspace-shared-protocol.md) | Rust on both sides, with a shared protocol crate | Accepted |
| [0002](0002-typed-actions-not-scripts.md) | Typed actions from a closed catalog, never scripts | Accepted |
| [0003](0003-agent-enforces-policy.md) | The agent verifies signatures and enforces policy itself | Accepted |
| [0004](0004-websocket-control-channel.md) | Outbound WebSocket over TLS for the control channel | Accepted |
| [0005](0005-pluggable-decision-layer.md) | Pluggable decision layer with risk x confidence routing | Accepted |
| [0006](0006-strict-wire-parsing.md) | Reject unknown fields on the wire and gate new fields by protocol version | Accepted |
