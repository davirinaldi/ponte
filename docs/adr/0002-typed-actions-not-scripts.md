# 0002. Typed actions from a closed catalog, never scripts

- Status: Accepted
- Date: 2026-10-12
- Requirements: RF-11, RF-12, RNF-06

## Context

An AI will request actions on customer machines, influenced by text that may come from those
machines (logs, errors). A "run this PowerShell" capability would turn any prompt injection or
server bug into arbitrary code execution.

## Decision

The agent ships a closed set of primitives (service control, bounded file access, read-only SQL...).
Actions are declarative manifests that compose primitives, declare a risk level at least as high
as their riskiest step, and include preconditions and verification. No primitive executes a
command, script or library.

## Consequences

- The AI chooses from a menu; it cannot invent capabilities.
- Every action is reviewable, auditable and testable as data.
- New capabilities need an agent release. Some fixes a technician could script will be slower to
  automate. Phase 3 remote control remains the escape hatch, with a human driving.

## Alternatives considered

- **Signed PowerShell scripts**: flexible, but signing proves origin, not safety.
- **WebAssembly plugins with declared capabilities**: promising; revisit once the primitive set is stable.
