# crates/agent

Privileged Windows service installed on customer machines. It runs as SYSTEM on weak
point-of-sale PCs, so bugs here are expensive and visible.

- **Resource budget (RNF-12):** under 1% CPU and 40 MB RAM at idle, binary under 15 MB.
  Justify any dependency by its size; check with `cargo bloat` when in doubt.
- **Never panic, never exit on bad input.** Reject, log, keep running. The service manager
  restarts a crashed agent, but a crash loop on 10,000 machines is an incident.
- **Outbound connections only.** No listening sockets, no local HTTP server.
- Windows-specific code lives in `src/platform/windows.rs` (and submodules). It is the only
  place where `unsafe` is allowed; every block needs a `// SAFETY:` comment.
- The crate must still compile and test on Linux: Windows dependencies go under
  `[target.'cfg(windows)'.dependencies]`, and `platform/unsupported.rs` fails loudly.
- UI, consent prompts and screen capture belong to `crates/agent-helper`, not here
  (a service in session 0 cannot reach the user's desktop).
- Reconnect with exponential backoff plus jitter (RNF-16). Execute each `RequestId` at most once (RNF-18).
