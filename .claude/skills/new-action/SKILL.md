---
name: new-action
description: Add or change a typed action (manifest) in the catalog. Use when the user asks for a new action, a new automated fix, or to edit a file under manifests/.
argument-hint: <action-id> <what it should fix>
---

Add the action described in: $ARGUMENTS

Work through these steps in order. Stop and ask if any step needs a new primitive.

1. **Reuse primitives.** Read `crates/actions/src/primitive.rs`. Express the fix with the
   primitives this release runs: `service_start`, `service_stop`, `service_restart` and
   `delete_file`, with the checks `service_state`, `path_exists`, `path_absent` and
   `disk_free_at_least`. `clear_temp_dir`, `read_file_tail`, `kill_process` and
   `sql_readonly` are refused by `validate_shape` and by every agent (ADR-0011). If the fix
   needs one of them or something new, stop: that needs an ADR (`/adr`) and the user's
   approval, because it widens what every agent can do.
2. **Write the manifest** at `manifests/examples/<id-with-dashes>.toml`, following the
   existing examples. Save it as UTF-8 in NFC with LF line endings and no BOM; only
   printable ASCII, tabs, Latin letters and typographic dashes, quotes and ellipsis are
   allowed (`ManifestText`), and the file is at most 16 KiB.
   - `id`: lowercase dotted, at most 64 bytes, e.g. `erp.clear-stale-lock`. `version`
     starts at 1; bump it on any change to steps or checks.
   - `title`: one line, at most 120 characters. `description` (what it does, for a
     technician) and `ai_description` (when a model should use it **and when it must
     not**): at most 2,000 characters each. None may be blank.
   - `risk`: at least the highest `inherent_risk` of its steps. When unsure, go higher.
     Agents refuse `high` until the consent prompt of M4.
   - At most 16 steps and 16 checks in each list; `timeout_secs` from 1 to 600.
   - `preconditions`: what must be true for the fix to be safe (e.g. service stopped).
     Every `delete_file` needs a `path_exists` precondition on the same path.
   - `verify`: how to prove it worked. **Every service and every path a step touches must
     be named by a verify check**: `service_state` for a service, `path_exists` or
     `path_absent` for a path. The expected state is yours to choose: a lock the service
     recreates when it starts is verified with `path_exists`, not `path_absent`.
   - Paths as TOML literal strings (`'C:\...'`), absolute and below a drive. No `..`, no
     UNC, no device names or streams. Accented letters must match the configured root
     exactly, case included: `C:\GESTÃO` is not `C:\Gestão`. Which roots a machine allows
     (and where `delete_file` may act, `delete_roots`) is the agent's configuration.
   - Service names are plain ASCII names (`FakeErp`, `MSSQL$SQLEXPRESS`): letters, digits,
     `.`, `_`, `-`, `$` and single spaces, never paths or patterns. They must also be in
     the agent's `allowed_services` and not on its list of refused services.
   - A disk `percent` is between 1 and 100.
3. **Test it.** Add the file to `example_manifests_are_valid` in
   `crates/actions/src/manifest.rs`, plus a negative test if the action has a non-obvious
   safety condition.
4. **Check.** Run `cargo test -p ponte-actions` and
   `cargo clippy --workspace --all-targets -- -D warnings`. Then
   `cargo run -p ponte-sign -- sign --key <key file> <manifest>` without `--yes`: it
   validates the manifest and prints what it does without signing. Signing (`--yes`) is
   for the person who holds the key; never sign on their behalf.
5. **Report** the manifest, its risk level and why, what its verify checks prove, and how
   the routing policy will treat it (`crates/decision`: medium and high risk always need a
   technician by default).
