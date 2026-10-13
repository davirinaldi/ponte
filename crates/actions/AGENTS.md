# crates/actions

The closed catalog of what an agent can do. This crate is the main security boundary.

- **Adding a primitive is a security decision.** It needs an ADR, an `inherent_risk`, adversarial
  tests, and an agent implementation behind the platform layer. Prefer composing existing ones.
- Never add a primitive that executes a command, script, DLL or arbitrary SQL. `SqlReadonly`
  runs a fixed query from a signed manifest on a read-only connection, nothing else.
- Every path, in a step or in a check, must go through `PathPolicy`. Keep the lexical check
  strict; the agent re-checks the resolved path at execution time.
- `Manifest::validate` checks the shape of every field that names something on the machine
  (service, process image, connection, mount). It does not decide which services or
  processes may be touched, and `SqlReadonly.query` is not checked at all yet.
- The per-step match in `check_step` has no catch-all: a new primitive must say how each of
  its fields is checked, with an adversarial test.
- `inherent_risk` may only move up, never down, without an ADR.
- Manifests and checks keep `deny_unknown_fields`: a silently ignored field is a vulnerability.
  Write a primitive or check without fields as `Variant {}`, never `Variant`: serde ignores
  `deny_unknown_fields` on unit variants of internally tagged enums.
- Use the `/new-action` skill to add manifests.
