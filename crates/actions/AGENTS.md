# crates/actions

The closed catalog of what an agent can do. This crate is the main security boundary.

- **Adding a primitive is a security decision.** It needs an ADR, an `inherent_risk`, adversarial
  tests, and an agent implementation behind the platform layer. Prefer composing existing ones.
- Never add a primitive that executes a command, script, DLL or arbitrary SQL. `SqlReadonly`
  runs a fixed query from a signed manifest on a read-only connection, nothing else.
- Every path, in a step or in a check, must go through `PathPolicy`. Keep the lexical check
  strict; the agent re-checks the resolved path at execution time.
- `Manifest::validate_shape` checks everything that does not depend on a machine: limits,
  the shape of every field that names something (service, process image, connection,
  mount, path), risk, the primitives this release runs, and verification coverage
  (ADR-0011). It does not decide which services or roots a machine allows; that is the
  agent's local policy. `SqlReadonly.query` is not checked at all yet.
- **Only a `RunnableManifest` runs.** `Manifest` → `validate_shape` → `ValidManifest` →
  `verify` → `VerifiedManifest` → `validate(&LocalPolicy)` → `RunnableManifest`. Each
  state has private fields, no `Deserialize`, and one constructor: never add another (a
  `From`, a `new`, a `Deserialize`) or a way back. `VerifiedManifest::for_test` exists
  under `cfg(test)` only.
- `verify` checks the key, then the signature (`verify_strict`), then the dates, and only
  then parses the TOML. Keep that order; the tests prove it.
- `REFUSED_SERVICES` may only grow without an ADR. It wins over `allowed_services`.
- **Check decoded values, not only bytes.** `ManifestText` checks the signed bytes, but
  TOML decodes escapes into any character (ESC, a bidirectional mark). Every string read
  out of a manifest passes `ManifestText::allows` (text) or `is_path_char` (paths) in
  `validate_shape`; a new string field needs the same.
- Errors say which rule and where (`Location`), never the path, name or text at fault: the
  agent may log them, and a manifest names paths and services (ADR-0012).
- `clear_temp_dir`, `read_file_tail`, `kill_process` and `sql_readonly` are refused by
  `validate_shape` (ADR-0011). Their field rules stay, tested through `check_step`, for the
  ADR that re-enables one; that ADR also says what covers it in `check_coverage`.
- The per-step matches in `check_step`, `check_coverage` and `is_refused` have no
  catch-all: a new primitive must say how each of its fields is checked, what covers it and
  whether it runs, with an adversarial test.
- `inherent_risk` may only move up, never down, without an ADR.
- Manifests and checks keep `deny_unknown_fields`: a silently ignored field is a vulnerability.
  Write a primitive or check without fields as `Variant {}`, never `Variant`: serde ignores
  `deny_unknown_fields` on unit variants of internally tagged enums.
- Use the `/new-action` skill to add manifests.
