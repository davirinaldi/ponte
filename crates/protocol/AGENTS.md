# crates/protocol

Wire types for every message between agent, server and web console.

- Any change here is a wire format change. Old agents in the field must keep working (RNF-21).
- Every type has `deny_unknown_fields`: receivers reject what they do not know (ADR-0006).
  Write a variant without fields as `Variant {}`, never `Variant`: serde ignores
  `deny_unknown_fields` on unit variants of internally tagged enums.
- The version is negotiated in the WebSocket upgrade as `ponte.v<N>` (ADR-0007), never inside
  a message. A build speaks every version from `MIN_PROTOCOL_VERSION` to `PROTOCOL_VERSION`.
  Raising the minimum locks out older agents, auto-update included: that needs an ADR.
- The version of a connection is a `ProtocolVersion`, which only comes out of a negotiated
  subprotocol name. Never pass `PROTOCOL_VERSION` where the connection's version is meant.
- A new field is an `Option<T>` left out of the JSON when unset (`skip_serializing_if`). It
  bumps `PROTOCOL_VERSION` and is only sent on a connection that negotiated a version that
  knows it. Renaming, removing or retyping a field is breaking: bump `PROTOCOL_VERSION` and
  add an ADR. The handshake messages follow the same rule; they are no longer frozen.
- Keep the pinned-format tests in `src/messages.rs`, `src/manifest.rs` and
  `src/transcript.rs` passing. If one fails, you changed the wire format: decide
  deliberately, never just update the expected value. The limits the ADRs set are pinned
  as literal numbers for the same reason. A new type or variant needs a case in the
  `*_wire_format_is_stable` and `*_reject_unknown_fields` tests.
- `src/transcript.rs` is the bytes a device signs (ADR-0008). Changing them stops every
  enrolled device from authenticating, so a new layout is a new protocol version and the old
  layout stays for connections that negotiated the old one. Every field has a fixed size and
  every transcript its own label; keep both true.
- `manifest_transcript` is the bytes a manifest signing key signs (ADR-0010). It carries no
  protocol version, because a manifest is signed offline and outlives versions; its label
  `ponte.manifest.v1` versions its layout instead. Changing it invalidates every manifest
  ever signed: a new layout is a new label, and the old one keeps verifying.
- Text that ends up signed, logged or shown has one door each, and the door holds the rule:
  `ManifestText` (16 KiB, no control character but line feed and tab, no invisible
  character, `Debug` shows the size only), `Label`, `ServiceName`, `Output` (64 KiB once
  serialized, no NUL, `Debug` shows the size only), `Confidence` (finite, 0 to 1). Never add
  a `String` field to a wire type; a field of free text needs a bounded type and a reason.
- Keys, signatures, nonces and tokens (`src/keys.rs`) are lowercase hex of their exact
  length. One value, one spelling: never accept uppercase, padding or a prefix.
- A type that holds a secret has a redacted `Debug`, no `Display`, and an accessor named
  `expose_*`. See `EnrollmentToken` and `Transcript`.
- A parse error never quotes its input, secret or not: the peer chose the text and the error
  goes to a log.
- Text a peer says about itself before it has proven anything is a `Label`, never a `String`.
  Handshake messages stay under `MAX_HANDSHAKE_MESSAGE_BYTES`.
- No business logic here. Types, serde attributes, tiny constructors and the layout of signed
  bytes only. No cryptography: signing and verifying belong to the agent and the server.
- Fields named `output` or containing free text from a machine are untrusted (AGENTS.md,
  invariant 4). A `Label` is bounded, and still untrusted.
- Why something failed or was refused is a `FailReason` or a `RejectReason`, never text: what
  the machine says reaches neither the server nor a model (ADR-0012). A new value is a new
  protocol version, like a new field, and goes into `reasons_are_stable`.
- Every list a peer sends has a limit (`MAX_LISTED` for telemetry), checked while it is read,
  so a long list is refused at its first item too many.
