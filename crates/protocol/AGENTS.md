# crates/protocol

Wire types for every message between agent, server and web console.

- Any change here is a wire format change. Old agents in the field must keep working (RNF-21).
- Every type has `deny_unknown_fields`: receivers reject what they do not know (ADR-0006).
  Write a variant without fields as `Variant {}`, never `Variant`: serde ignores
  `deny_unknown_fields` on unit variants of internally tagged enums.
- A new field is an `Option<T>` left out of the JSON when unset (`skip_serializing_if`). It
  bumps `PROTOCOL_VERSION` and is only sent to a peer that announced a version that knows it.
  Renaming, removing or retyping a field is breaking: bump `PROTOCOL_VERSION` and add an ADR.
- Keep the pinned-format tests in `src/messages.rs` passing. If one fails, you changed the
  wire format: decide deliberately, never just update the expected JSON. A new type or
  variant needs a case in the `*_reject_unknown_fields` tests.
- No business logic here. Types, serde attributes and tiny constructors only.
- Fields named `output` or containing free text from a machine are untrusted (AGENTS.md, invariant 4).
