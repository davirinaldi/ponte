---
name: adr
description: Record an architecture decision record in docs/adr from the template.
disable-model-invocation: true
argument-hint: <decision title>
---

Create an ADR for: $ARGUMENTS

1. List `docs/adr/` and take the next free four-digit number.
2. Copy `docs/adr/0000-template.md` to `docs/adr/NNNN-short-kebab-title.md`.
3. Fill in Context, Decision, Consequences and Alternatives from this conversation. Keep it
   under one page. State trade-offs honestly, including what gets worse.
4. Set status to `Proposed` unless the user said it is accepted.
5. Add a line for it in the index in `docs/adr/README.md`.
6. If it supersedes an earlier ADR, set that one's status to `Superseded by NNNN`.
7. Show the user the ADR and ask whether to mark it `Accepted`.
