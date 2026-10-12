//! Unprivileged helper that runs in the interactive user session.
//!
//! A Windows service lives in session 0 and cannot show UI or capture the user's
//! desktop, so this process does that work on its behalf: consent prompts, the
//! "someone is viewing your screen" indicator and, in phase 2, screen capture.
//! It talks to the agent over a named pipe restricted by ACL and holds no privileges.
//!
//! Placeholder until milestone M4 (see `docs/roadmap.md`).

fn main() {
    tracing_subscriber::fmt().init();
    tracing::info!("ponte-agent-helper is a placeholder; see docs/roadmap.md (M4)");
}
