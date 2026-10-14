@AGENTS.md

## Claude Code

Everything above is shared with other agents. This section only adds Claude Code specifics.

### Workflow

- For anything that touches `crates/protocol`, `crates/actions`, the agent's privileges or the
  security invariants: **use plan mode first** and get the plan approved before editing.
- Prefer small, verifiable steps: write or update the test, make it pass, run clippy.
- Read the relevant doc before designing, not the whole `docs/` folder. The map in
  `AGENTS.md` says which file covers what.
- Before saying a task is done, run `/ship-check` (or the same commands by hand).

### Project skills and agents

- `/new-action <id> <goal>`: add or change an action manifest the right way.
- `/adr <title>`: record an architecture decision from the template.
- `/ship-check`: run every check from the definition of done and summarise.
- `security-reviewer` subagent: ask it to review any diff that touches actions, policy,
  the agent, the server's handshake, store or database, MCP, auth, dependencies or CI. It
  has not seen your reasoning, which is the point. For a fix commit, ask for a re-review
  of that commit with the earlier findings.

### Guard rails already configured

- `.claude/settings.json` allows cargo build/test/clippy/fmt without prompting, asks before
  `cargo add`, `cargo update` and `git push`, and blocks reading `.env` files and `keys/`.
- A PostToolUse hook formats every `.rs` file right after you edit it, so do not spend
  turns on formatting.

Personal, uncommitted preferences go in `CLAUDE.local.md` (gitignored).
