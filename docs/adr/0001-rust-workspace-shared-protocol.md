# 0001. Use Rust on both sides, with a shared protocol crate

- Status: Accepted
- Date: 2026-10-12
- Requirements: RNF-12, RNF-21

## Context

The agent runs as SYSTEM on weak point-of-sale PCs and must be small, fast and hard to crash.
The server must hold thousands of long-lived connections. Agent and server exchange many
message types that must never drift apart.

## Decision

One Cargo workspace. Agent and server in Rust. All wire types live in `crates/protocol`, used by
both, and TypeScript types for the web console are generated from it.

## Consequences

- One definition per message; a mismatch is a compile error, not a production incident.
- Memory safety in the privileged agent without a garbage collector or runtime to install.
- Slower to build than the author's usual NestJS stack; fewer people can contribute.

## Alternatives considered

- **NestJS server + Rust agent**: faster server development, but two type systems to keep in sync.
- **Go agent**: simpler, but larger binaries with a GC, and no shared types with a Rust server.
