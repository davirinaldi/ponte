//! The command line of `ponte-sign` (ADR-0010), with the terminal behind a trait.
//!
//! The password is the one thing a test cannot type. [`Console`] is how the binary reads
//! it from the terminal and how the tests hand one in; there is no flag, environment
//! variable or pipe that takes a password, so a script or a shell history never holds one.

use std::ffi::{OsStr, OsString};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use ed25519_dalek::{Signer, SigningKey};
use ponte_actions::{Manifest, TrustedKeys, VerifyError, verify};
use ponte_protocol::{
    MAX_MANIFEST_BYTES, ManifestText, PublicKey, Signature, SignedManifest, manifest_transcript,
};

use crate::keyfile::{KeyFile, MIN_PASSWORD_CHARS, Password};
use crate::summary::summary;
use crate::text::why_not_manifest_text;

pub(crate) const USAGE: &str = "\
usage:
  ponte-sign keygen <key-file>
      Make a signing key. Writes <key-file>, encrypted with a password you type twice,
      and <key-file>.pub with the public key for the agents' manifest_keys.
  ponte-sign sign --key <key-file> [--days <1-365>] [--out <envelope>] [--yes] <manifest>
      Check a manifest and show what it does. With --yes, ask for the password and write
      the signed envelope (default <manifest>.signed.json), valid for 90 days by default.
  ponte-sign verify --key <public-key | .pub file> <envelope>
      Check an envelope as an agent would: key, signature, validity and manifest.
  ponte-sign show <envelope>
      Show what an envelope's manifest does, and whether it is signed by the key it names.
  ponte-sign help";

/// Exit codes, as the server's subcommands use them.
pub(crate) const OK: u8 = 0;
pub(crate) const FAILED: u8 = 1;
pub(crate) const USAGE_ERROR: u8 = 2;

const DAY: u64 = 24 * 60 * 60;
const DEFAULT_DAYS: u64 = 90;
const MAX_DAYS: u64 = 365;
/// `ponte-sign` puts `issued_at` this far before its clock, so an agent whose clock runs
/// up to an hour late still accepts a fresh manifest (ADR-0010).
const ISSUED_BEFORE_NOW: u64 = 60 * 60;
/// Largest key file or envelope read. Both are a few KB.
const MAX_FILE_BYTES: u64 = 64 * 1024;

/// Where `ponte-sign` writes and where it reads a password from.
pub(crate) trait Console {
    fn out(&mut self) -> &mut dyn Write;
    fn err(&mut self) -> &mut dyn Write;
    /// Reads a password without echo. The binary only ever reads the terminal.
    fn password(&mut self, prompt: &str) -> io::Result<Password>;
}

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Help,
    Keygen {
        key_file: PathBuf,
    },
    Sign {
        key_file: PathBuf,
        days: u64,
        out: Option<PathBuf>,
        yes: bool,
        manifest: PathBuf,
    },
    Verify {
        key: String,
        envelope: PathBuf,
    },
    Show {
        envelope: PathBuf,
    },
}

/// The command line was not one of [`USAGE`]. Says which part, never repeats it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
enum UsageError {
    #[error("unknown command")]
    UnknownCommand,
    #[error("an argument is not valid text")]
    NotText,
    #[error("unknown option")]
    UnknownOption,
    #[error("an option is given twice")]
    Repeated,
    #[error("an option is missing its value")]
    MissingValue,
    #[error("a required argument is missing")]
    Missing,
    #[error("too many arguments")]
    TooMany,
    #[error("--days must be a whole number from 1 to {MAX_DAYS}")]
    Days,
}

/// Runs one command and returns its exit code. `now` is seconds since the Unix epoch.
pub(crate) fn run(
    args: impl IntoIterator<Item = OsString>,
    console: &mut dyn Console,
    now: u64,
) -> u8 {
    let command = match parse(args) {
        Ok(command) => command,
        Err(error) => {
            let _ = writeln!(console.err(), "error: {error}\n\n{USAGE}");
            return USAGE_ERROR;
        }
    };
    let result = match command {
        Command::Help => writeln!(console.out(), "{USAGE}").map_err(Into::into),
        Command::Keygen { key_file } => keygen(&key_file, console),
        Command::Sign {
            key_file,
            days,
            out,
            yes,
            manifest,
        } => sign(&key_file, days, out, yes, &manifest, console, now),
        Command::Verify { key, envelope } => check(&key, &envelope, console, now),
        Command::Show { envelope } => show(&envelope, console, now),
    };
    match result {
        Ok(()) => OK,
        Err(error) => {
            let _ = writeln!(console.err(), "error: {error:#}");
            FAILED
        }
    }
}

fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Command, UsageError> {
    let args = args
        .into_iter()
        .map(|arg| arg.into_string().map_err(|_| UsageError::NotText))
        .collect::<Result<Vec<_>, _>>()?;
    let Some((command, rest)) = args.split_first() else {
        return Err(UsageError::UnknownCommand);
    };

    let mut key = None;
    let mut days = None;
    let mut out = None;
    let mut yes = false;
    let mut positional = Vec::new();
    let mut rest = rest.iter();
    while let Some(arg) = rest.next() {
        let slot = match arg.as_str() {
            "--key" => &mut key,
            "--days" => &mut days,
            "--out" => &mut out,
            "--yes" => {
                if yes {
                    return Err(UsageError::Repeated);
                }
                yes = true;
                continue;
            }
            option if option.starts_with("--") => return Err(UsageError::UnknownOption),
            value => {
                positional.push(value);
                continue;
            }
        };
        if slot.is_some() {
            return Err(UsageError::Repeated);
        }
        *slot = Some(rest.next().ok_or(UsageError::MissingValue)?.as_str());
    }

    let one = |positional: &[&str]| match positional {
        [one] => Ok(PathBuf::from(one)),
        [] => Err(UsageError::Missing),
        _ => Err(UsageError::TooMany),
    };
    let none_of = |options: &[bool]| {
        if options.iter().any(|&given| given) {
            Err(UsageError::UnknownOption)
        } else {
            Ok(())
        }
    };
    match command.as_str() {
        "help" | "--help" | "-h" => {
            none_of(&[key.is_some(), days.is_some(), out.is_some(), yes])?;
            if !positional.is_empty() {
                return Err(UsageError::TooMany);
            }
            Ok(Command::Help)
        }
        "keygen" => {
            none_of(&[key.is_some(), days.is_some(), out.is_some(), yes])?;
            Ok(Command::Keygen {
                key_file: one(&positional)?,
            })
        }
        "sign" => {
            let days = match days {
                None => DEFAULT_DAYS,
                Some(days) => days
                    .parse()
                    .ok()
                    .filter(|days| (1..=MAX_DAYS).contains(days))
                    .ok_or(UsageError::Days)?,
            };
            Ok(Command::Sign {
                key_file: key.ok_or(UsageError::Missing)?.into(),
                days,
                out: out.map(PathBuf::from),
                yes,
                manifest: one(&positional)?,
            })
        }
        "verify" => {
            none_of(&[days.is_some(), out.is_some(), yes])?;
            Ok(Command::Verify {
                key: key.ok_or(UsageError::Missing)?.to_owned(),
                envelope: one(&positional)?,
            })
        }
        "show" => {
            none_of(&[key.is_some(), days.is_some(), out.is_some(), yes])?;
            Ok(Command::Show {
                envelope: one(&positional)?,
            })
        }
        _ => Err(UsageError::UnknownCommand),
    }
}

fn keygen(key_file: &Path, console: &mut dyn Console) -> anyhow::Result<()> {
    let public_file = with_suffix(key_file, ".pub");
    for path in [key_file, public_file.as_path()] {
        if path.exists() {
            bail!(
                "{} already exists; a key is never overwritten",
                path.display()
            );
        }
    }
    let password = console.password("Password for the new key: ")?;
    if password.chars() < MIN_PASSWORD_CHARS {
        bail!("the password must have at least {MIN_PASSWORD_CHARS} characters");
    }
    if console.password("The same password again: ")? != password {
        bail!("the two passwords differ");
    }

    let mut secret = [0; 32];
    getrandom::fill(&mut secret).context("the system gave no random bytes")?;
    let key = SigningKey::from_bytes(&secret);
    secret.fill(0);
    let sealed = KeyFile::seal(&key, &password)?;
    let public_key = *sealed.public_key();

    let text = serde_json::to_string_pretty(&sealed)? + "\n";
    write_new(key_file, &text, Access::Owner)?;
    write_new(&public_file, &format!("{public_key}\n"), Access::Public)?;
    writeln!(
        console.out(),
        "Public key: {public_key}\n\
         Wrote {} (encrypted) and {}.\n\
         Back the key file up somewhere safe: without it, or without the password, nothing \
         more can be signed with this key. Configure a second key on agents too, so this one \
         can be retired.",
        key_file.display(),
        public_file.display()
    )?;
    Ok(())
}

fn sign(
    key_file: &Path,
    days: u64,
    out: Option<PathBuf>,
    yes: bool,
    manifest_file: &Path,
    console: &mut dyn Console,
    now: u64,
) -> anyhow::Result<()> {
    let text = read_bounded(manifest_file, MAX_MANIFEST_BYTES as u64)?;
    let text = String::from_utf8(text)
        .map_err(|_| anyhow::anyhow!("{} is not UTF-8", manifest_file.display()))?;
    let manifest_text: ManifestText = text.parse().map_err(|_| {
        let reason = why_not_manifest_text(&text).unwrap_or_default();
        anyhow::anyhow!("{} cannot be signed: {reason}", manifest_file.display())
    })?;
    // The author's own file: the parser's error, which quotes it, is what helps here.
    let manifest = Manifest::from_toml(manifest_text.as_str())
        .with_context(|| format!("{} is not a manifest", manifest_file.display()))?;
    let manifest = manifest
        .validate_shape()
        .with_context(|| format!("{} cannot be signed", manifest_file.display()))?;

    let key_file_contents: KeyFile = read_json(key_file)?;
    let public_key = *key_file_contents.public_key();
    let issued_at = now
        .checked_sub(ISSUED_BEFORE_NOW)
        .context("the clock reads before 1970")?;
    let expires_at = issued_at
        .checked_add(days * DAY)
        .context("the clock reads past the year 292 billion")?;

    let out_file = out.unwrap_or_else(|| manifest_file.with_extension("signed.json"));
    // Only an envelope is ever replaced, to renew a signature: never a key (the second one
    // is the way out of a lost password), a manifest or anything else.
    if out_file.exists() && read_json::<SignedManifest>(&out_file).is_err() {
        bail!(
            "{} exists and is not a signed envelope; choose another --out",
            out_file.display()
        );
    }
    write!(
        console.out(),
        "{}",
        summary(manifest.manifest(), &public_key, issued_at, expires_at)
    )?;
    if !yes {
        writeln!(
            console.out(),
            "\nNothing was signed. Check everything above, then run again with --yes."
        )?;
        return Ok(());
    }

    let password = console.password(&format!("Password for {}: ", key_file.display()))?;
    let key = key_file_contents.unlock(&password)?;
    drop(password);
    let mut signed = SignedManifest {
        manifest: manifest_text,
        issued_at,
        expires_at,
        public_key,
        signature: Signature::from_bytes([0; 64]),
    };
    let signature = key.sign(manifest_transcript(&signed).expose_bytes());
    drop(key);
    signed.signature = Signature::from_bytes(signature.to_bytes());

    // What an agent will do with it, before anyone gets the file.
    let trusted = TrustedKeys::new([public_key]).context("the key is not usable")?;
    verify(&signed, &trusted, now, now).context("the envelope just signed does not verify")?;

    // Written beside it and renamed over it, so a crash never leaves half an envelope.
    let envelope = serde_json::to_string_pretty(&signed)? + "\n";
    let temporary = with_suffix(&out_file, ".tmp");
    write_new(&temporary, &envelope, Access::Public)?;
    if let Err(error) = std::fs::rename(&temporary, &out_file) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error).with_context(|| format!("cannot write {}", out_file.display()));
    }
    writeln!(console.out(), "\nSigned. Wrote {}.", out_file.display())?;
    Ok(())
}

fn check(
    key: &str,
    envelope_file: &Path,
    console: &mut dyn Console,
    now: u64,
) -> anyhow::Result<()> {
    let key = match key.parse::<PublicKey>() {
        Ok(key) => key,
        Err(_) => {
            let text = read_bounded(Path::new(key), MAX_FILE_BYTES)?;
            let text = String::from_utf8_lossy(&text);
            let line = text.strip_suffix('\n').unwrap_or(&text);
            line.strip_suffix('\r')
                .unwrap_or(line)
                .parse()
                .with_context(|| format!("{key} is neither a public key nor a .pub file"))?
        }
    };
    let trusted = TrustedKeys::new([key]).context("the key is not usable")?;
    let signed: SignedManifest = read_json(envelope_file)?;
    let verified = verify(&signed, &trusted, now, now).map_err(|error| refused(&error))?;
    write!(
        console.out(),
        "{}",
        summary(
            verified.manifest(),
            verified.public_key(),
            verified.issued_at(),
            verified.expires_at()
        )
    )?;
    writeln!(
        console.out(),
        "\nValid: signed by {key}, inside its validity."
    )?;
    Ok(())
}

fn show(envelope_file: &Path, console: &mut dyn Console, now: u64) -> anyhow::Result<()> {
    let signed: SignedManifest = read_json(envelope_file)?;
    // Shown even when it would not verify: that is what this command is for. `verify` is
    // the one that decides.
    let manifest = Manifest::from_toml(signed.manifest.as_str())
        .context("the envelope's text is not a manifest")?;
    write!(
        console.out(),
        "{}",
        summary(
            &manifest,
            &signed.public_key,
            signed.issued_at,
            signed.expires_at
        )
    )?;
    let status = match TrustedKeys::new([signed.public_key]) {
        Err(_) => "the key it names is not a usable key".to_owned(),
        Ok(own) => match verify(&signed, &own, now, now) {
            Ok(_) => "signed by the key it names, inside its validity".to_owned(),
            Err(error) => refused(&error).to_string(),
        },
    };
    writeln!(
        console.out(),
        "\nStatus: {status}. Not checked against a list of trusted keys: use verify."
    )?;
    Ok(())
}

fn refused(error: &VerifyError) -> anyhow::Error {
    anyhow::anyhow!("refused: {error}")
}

/// `path` with `suffix` appended to its last component (`key.json` → `key.json.pub`).
fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name: OsString = path.as_os_str().to_owned();
    name.push(OsStr::new(suffix));
    PathBuf::from(name)
}

/// Reads at most `max` bytes, and refuses a file that has more.
fn read_bounded(path: &Path, max: u64) -> anyhow::Result<Vec<u8>> {
    let file =
        std::fs::File::open(path).with_context(|| format!("cannot read {}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(max.saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("cannot read {}", path.display()))?;
    if bytes.len() as u64 > max {
        bail!("{} is larger than {max} bytes", path.display());
    }
    Ok(bytes)
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> anyhow::Result<T> {
    let bytes = read_bounded(path, MAX_FILE_BYTES)?;
    serde_json::from_slice(&bytes).with_context(|| format!("cannot read {}", path.display()))
}

/// Who may read a file `write_new` makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Access {
    /// Its owner only, where files have modes. On Windows the folder's access list
    /// decides; the key is encrypted either way.
    Owner,
    /// Whatever the folder gives.
    Public,
}

/// Writes a file that must not exist yet: a key is never overwritten.
pub(crate) fn write_new(path: &Path, text: &str, access: Access) -> anyhow::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    if access == Access::Owner {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = access;
    let mut file = options
        .open(path)
        .with_context(|| format!("cannot create {}", path.display()))?;
    file.write_all(text.as_bytes())
        .and_then(|()| file.sync_all())
        .with_context(|| format!("cannot write {}", path.display()))
}
