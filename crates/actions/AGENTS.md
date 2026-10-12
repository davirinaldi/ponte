# crates/actions

The closed catalog of what an agent can do. This crate is the main security boundary.

- **Adding a primitive is a security decision.** It needs an ADR, an `inherent_risk`, adversarial
  tests, and an agent implementation behind the platform layer. Prefer composing existing ones.
- Never add a primitive that executes a command, script, DLL or arbitrary SQL. `SqlReadonly`
  runs a fixed query from a signed manifest on a read-only connection, nothing else.
- Every file-touching primitive must go through `PathPolicy`. Keep the lexical check strict;
  the agent re-checks the resolved path at execution time.
- `inherent_risk` may only move up, never down, without an ADR.
- Manifests and checks keep `deny_unknown_fields`: a silently ignored field is a vulnerability.
- Use the `/new-action` skill to add manifests.
