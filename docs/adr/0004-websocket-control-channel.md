# 0004. Outbound WebSocket over TLS for the control channel

- Status: Accepted
- Date: 2026-10-12
- Requirements: RNF-01, RNF-13, RNF-16

## Context

Supported machines sit behind NAT, small-shop routers and sometimes corporate proxies. Nobody
will open inbound ports. Commands must reach an online agent in under a second.

## Decision

The agent opens a long-lived WebSocket over TLS (rustls) on port 443 and keeps it alive.
Messages are JSON, typed by `crates/protocol`. Media (phase 2) uses WebRTC separately.

## Consequences

- Works through almost any firewall or HTTP proxy.
- JSON is easy to inspect while debugging; the control channel is low-volume, so size does not matter.
- The server holds one connection per agent: needs load testing (RNF-14) and, later, a message
  bus to scale horizontally.

## Alternatives considered

- **gRPC streaming**: typed and efficient, but HTTP/2 is mangled by some proxies.
- **QUIC**: modern, but UDP is often blocked.
- **Polling**: simplest, but slow and wasteful at 10,000 agents.
