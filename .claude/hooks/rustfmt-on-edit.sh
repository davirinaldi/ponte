#!/usr/bin/env bash
# PostToolUse hook: format a Rust file right after Claude edits it.
#
# Formatting is deterministic, so it lives in a hook instead of an instruction:
# instructions are advisory, hooks always run. Never fails the edit; if jq or
# rustfmt is missing (e.g. a fresh Windows box), it simply does nothing.
set -uo pipefail

command -v jq >/dev/null 2>&1 || exit 0
command -v rustfmt >/dev/null 2>&1 || exit 0

file=$(jq -r '.tool_input.file_path // empty')
[[ "$file" == *.rs && -f "$file" ]] || exit 0

# rustfmt picks up rustfmt.toml from the file's parent directories.
rustfmt --edition 2024 "$file" >/dev/null 2>&1 || true
exit 0
