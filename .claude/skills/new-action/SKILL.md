---
name: new-action
description: Add or change a typed action (manifest) in the catalog. Use when the user asks for a new action, a new automated fix, or to edit a file under manifests/.
argument-hint: <action-id> <what it should fix>
---

Add the action described in: $ARGUMENTS

Work through these steps in order. Stop and ask if any step needs a new primitive.

1. **Reuse primitives.** Read `crates/actions/src/primitive.rs`. Express the fix with existing
   primitives. If that is impossible, stop: a new primitive needs an ADR (`/adr`) and the
   user's approval, because it widens what every agent can do.
2. **Write the manifest** at `manifests/examples/<id-with-dashes>.toml`, following the
   existing examples:
   - `id`: lowercase dotted, e.g. `erp.clear-stale-lock`. `version` starts at 1; bump it on
     any change to steps or checks.
   - `description`: what it does, for a technician.
   - `ai_description`: when a model should use it **and when it must not**.
   - `risk`: at least the highest `inherent_risk` of its steps. When unsure, go higher.
   - `preconditions`: what must be true for the fix to be safe (e.g. service stopped).
   - `verify`: how to prove it worked. Every action above `read` risk needs at least one
     verify check; `validate` rejects it otherwise.
   - Paths as TOML literal strings (`'C:\...'`) under an allowed root, in steps and in checks
     alike. No `..`, no UNC. Accented letters must match the configured root exactly, case
     included: `C:\FARMÁCIA` is not `C:\Farmácia`.
   - Service, image and connection names are plain names (`FakeErp`, `erp.exe`): letters,
     digits, `.`, `_`, `-`, `$` and single spaces, never paths or patterns.
   - `max_bytes` is at most 64 KiB; a disk `percent` is between 1 and 100.
3. **Test it.** Add the file to `example_manifests_are_valid` in
   `crates/actions/src/manifest.rs`, plus a negative test if the action has a non-obvious
   safety condition.
4. **Check.** Run `cargo test -p ponte-actions` and `cargo clippy --workspace --all-targets -- -D warnings`.
5. **Report** the manifest, its risk level and why, and how the routing policy will treat it
   (`crates/decision`: medium and high risk always need a technician by default).
