# Web console

Technician console: devices, telemetry, approval queue, action catalog and (phase 2) sessions.

Planned stack: Vite + React + TypeScript, TanStack Query, shadcn/ui. TypeScript types are
generated from `crates/protocol` (ts-rs or specta), never written by hand. The built SPA is
embedded in the `ponte-server` binary, so self-hosting stays one executable plus Postgres.

Not started yet: see `docs/roadmap.md`.
