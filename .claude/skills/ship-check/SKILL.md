---
name: ship-check
description: Run every check from the definition of done and summarise the result. Use before saying a change is finished or before committing.
allowed-tools: Bash(cargo fmt *) Bash(cargo clippy *) Bash(cargo test *) Bash(cargo deny *) Bash(cargo sqlx *) Bash(git status *) Bash(git diff *)
---

Run these in order and keep going after a failure, so the summary is complete:

1. `cargo fmt --all --check`. If it fails, run `cargo fmt --all` and note that you did.
2. `cargo clippy --workspace --all-targets -- -D warnings`
3. `cargo test --workspace`
4. If `DATABASE_URL` reaches a running PostgreSQL (see "Database" in
   `crates/server/AGENTS.md`): `cargo test -p ponte-server -- --ignored pg_`, and, from
   `crates/server`, `cargo sqlx prepare --check`. Otherwise say both were skipped.
5. `cargo deny check` if `cargo deny` is installed; otherwise say it was skipped.
6. `git status --short` and `git diff --stat`.

Then review the diff against the definition of done in `AGENTS.md`:
- Are there tests for the new behaviour?
- Does the change touch `crates/actions`, `crates/protocol`, the agent, MCP or auth? If so,
  recommend running the `security-reviewer` agent.
- Are requirement IDs ready for the commit message?

Reply with a short table (check, result) and a list of anything that still blocks the change.
Do not fix clippy or test failures silently: report them with file and line.
