# crates/protocol

Wire types for every message between agent, server and web console.

- Any change here is a wire format change. Old agents in the field must keep working (RNF-21).
- Adding an optional field (`Option<T>` with `#[serde(default)]`) is backward compatible.
  Renaming, removing or retyping a field is not: bump `PROTOCOL_VERSION` and add an ADR.
- Keep the pinned-format tests in `src/messages.rs` passing. If one fails, you changed the
  wire format: decide deliberately, never just update the expected JSON.
- No business logic here. Types, serde attributes and tiny constructors only.
- Fields named `output` or containing free text from a machine are untrusted (AGENTS.md, invariant 4).
