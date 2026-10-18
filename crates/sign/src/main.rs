//! `ponte-sign`: signs action manifests offline (ADR-0010).
//!
//! It runs on a machine that is not the server. The private key never leaves its file
//! unencrypted, and the password is only ever read from the terminal.

mod cli;
mod hex;
mod keyfile;
mod summary;
mod text;

use std::io::{self, Write};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use cli::Console;
use keyfile::Password;

/// The real terminal: stdout, stderr, and passwords typed without echo.
struct Terminal {
    out: io::Stdout,
    err: io::Stderr,
}

impl Console for Terminal {
    fn out(&mut self) -> &mut dyn Write {
        &mut self.out
    }

    fn err(&mut self) -> &mut dyn Write {
        &mut self.err
    }

    fn password(&mut self, prompt: &str) -> io::Result<Password> {
        rpassword::prompt_password(prompt).map(Password::new)
    }
}

fn main() -> ExitCode {
    let mut terminal = Terminal {
        out: io::stdout(),
        err: io::stderr(),
    };
    let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        let _ = writeln!(terminal.err, "error: the clock reads before 1970");
        return ExitCode::from(cli::FAILED);
    };
    ExitCode::from(cli::run(
        std::env::args_os().skip(1),
        &mut terminal,
        now.as_secs(),
    ))
}

#[cfg(test)]
mod tests;
