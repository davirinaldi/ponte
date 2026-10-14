//! The server's subcommands: what an operator does until the console exists.
//!
//! ```text
//! ponte-server                                         serve agents (the default)
//! ponte-server customer create <name>
//! ponte-server customer list
//! ponte-server token create <customer-id> --out <file> [--uses N] [--hours H]
//! ponte-server token list [<customer-id>]
//! ponte-server token revoke <hash-prefix>
//! ponte-server device list [<customer-id>]
//! ponte-server device approve <device-id>
//! ponte-server device revoke <device-id>
//! ```
//!
//! **A token is shown once, to a file, and nowhere else.** `token create` writes it to a new
//! file (never over an existing one) and prints only the first bytes of its hash, which is
//! also how audit events and `token revoke` name it. The token never goes to the terminal,
//! the log or the shell history: it is made here, not typed.
//!
//! Every change is an audit event (RF-40) with `actor = "server_cli"`.

use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

use chrono::{DateTime, SubsecRound, TimeDelta, Utc};
use ponte_protocol::{DeviceId, EnrollmentToken};
use uuid::Uuid;

use crate::agents::audit::{self, AuditEvent};
use crate::agents::{
    CustomerId, CustomerName, DeviceAdmin, DeviceRecord, TokenGrant, TokenHash, TokenInfo,
};

/// What `ponte-server --help` and a mistyped command print.
pub const USAGE: &str = "\
usage:
  ponte-server                                         serve agents
  ponte-server customer create <name>
  ponte-server customer list
  ponte-server token create <customer-id> --out <file> [--uses N] [--hours H]
  ponte-server token list [<customer-id>]
  ponte-server token revoke <hash-prefix>
  ponte-server device list [<customer-id>]
  ponte-server device approve <device-id>
  ponte-server device revoke <device-id>

DATABASE_URL names the PostgreSQL database. A token is written to the --out file only,
for the agent's enrollment_token_file; --uses is 1 to 10000 (default 1), --hours 1 to 720
(default 24).";

/// Machines one token may enroll, at most. A rollout larger than this takes more tokens.
pub const MAX_USES: u32 = 10_000;
/// How long a token may stay valid, in hours: thirty days.
pub const MAX_HOURS: u32 = 720;

const DEFAULT_HOURS: u32 = 24;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Serve,
    Help,
    CustomerCreate {
        name: CustomerName,
    },
    CustomerList,
    TokenCreate {
        customer: CustomerId,
        out: PathBuf,
        uses: NonZeroU32,
        hours: u32,
    },
    TokenList {
        customer: Option<CustomerId>,
    },
    TokenRevoke {
        prefix: [u8; 8],
    },
    DeviceList {
        customer: Option<CustomerId>,
    },
    DeviceApprove {
        device: DeviceId,
    },
    DeviceRevoke {
        device: DeviceId,
    },
}

/// The command line was not one of [`USAGE`]. Says which part, never repeats it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum UsageError {
    #[error("unknown command")]
    UnknownCommand,
    #[error("an argument is not valid text")]
    NotText,
    #[error("missing argument: {0}")]
    Missing(&'static str),
    #[error("too many arguments")]
    TooMany,
    #[error("not valid: {0}")]
    Invalid(&'static str),
    #[error("given twice: {0}")]
    Repeated(&'static str),
}

/// Reads the arguments after the program's name.
pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Command, UsageError> {
    let args = args
        .into_iter()
        .map(|arg| arg.into_string().map_err(|_| UsageError::NotText))
        .collect::<Result<Vec<_>, _>>()?;
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        [] => Ok(Command::Serve),
        ["help" | "--help" | "-h"] => Ok(Command::Help),
        ["customer", "create", name] => Ok(Command::CustomerCreate {
            name: name
                .parse()
                .map_err(|_| UsageError::Invalid("customer name"))?,
        }),
        ["customer", "list"] => Ok(Command::CustomerList),
        ["token", "create", rest @ ..] => token_create(rest),
        ["token", "list", rest @ ..] => Ok(Command::TokenList {
            customer: optional_customer(rest)?,
        }),
        ["token", "revoke", prefix] => Ok(Command::TokenRevoke {
            prefix: hash_prefix(prefix)?,
        }),
        ["device", "list", rest @ ..] => Ok(Command::DeviceList {
            customer: optional_customer(rest)?,
        }),
        ["device", "approve", id] => Ok(Command::DeviceApprove {
            device: device_id(id)?,
        }),
        ["device", "revoke", id] => Ok(Command::DeviceRevoke {
            device: device_id(id)?,
        }),
        [
            "customer" | "token" | "device",
            "create" | "revoke" | "approve",
        ] => Err(UsageError::Missing("an argument")),
        _ => Err(UsageError::UnknownCommand),
    }
}

fn token_create(args: &[&str]) -> Result<Command, UsageError> {
    let Some((customer, mut flags)) = args.split_first() else {
        return Err(UsageError::Missing("customer id"));
    };
    let customer = customer_id(customer)?;
    let (mut out, mut uses, mut hours) = (None, None, None);
    while let [flag, rest @ ..] = flags {
        let [value, rest @ ..] = rest else {
            return Err(UsageError::Missing("a value after a flag"));
        };
        match *flag {
            "--out" => set(&mut out, "--out", PathBuf::from(value))?,
            "--uses" => set(&mut uses, "--uses", bounded(value, 1, MAX_USES, "--uses")?)?,
            "--hours" => set(
                &mut hours,
                "--hours",
                bounded(value, 1, MAX_HOURS, "--hours")?,
            )?,
            _ => return Err(UsageError::Invalid("flag")),
        }
        flags = rest;
    }
    let out = out.ok_or(UsageError::Missing("--out <file>"))?;
    if out.as_os_str().is_empty() {
        return Err(UsageError::Invalid("--out"));
    }
    Ok(Command::TokenCreate {
        customer,
        out,
        uses: NonZeroU32::new(uses.unwrap_or(1)).ok_or(UsageError::Invalid("--uses"))?,
        hours: hours.unwrap_or(DEFAULT_HOURS),
    })
}

fn set<T>(slot: &mut Option<T>, name: &'static str, value: T) -> Result<(), UsageError> {
    if slot.replace(value).is_some() {
        return Err(UsageError::Repeated(name));
    }
    Ok(())
}

fn bounded(value: &str, min: u32, max: u32, name: &'static str) -> Result<u32, UsageError> {
    value
        .parse::<u32>()
        .ok()
        .filter(|value| (min..=max).contains(value))
        .ok_or(UsageError::Invalid(name))
}

fn uuid(value: &str, name: &'static str) -> Result<Uuid, UsageError> {
    // The hyphenated lower-case form only, the one every listing prints.
    Uuid::try_parse(value)
        .ok()
        .filter(|uuid| uuid.hyphenated().to_string() == value)
        .ok_or(UsageError::Invalid(name))
}

fn customer_id(value: &str) -> Result<CustomerId, UsageError> {
    uuid(value, "customer id").map(CustomerId::from_uuid)
}

fn device_id(value: &str) -> Result<DeviceId, UsageError> {
    uuid(value, "device id").map(DeviceId::from_uuid)
}

fn optional_customer(args: &[&str]) -> Result<Option<CustomerId>, UsageError> {
    match args {
        [] => Ok(None),
        [customer] => customer_id(customer).map(Some),
        _ => Err(UsageError::TooMany),
    }
}

/// Sixteen lower-case hex characters: the first eight bytes of a token's hash.
fn hash_prefix(value: &str) -> Result<[u8; 8], UsageError> {
    let invalid = UsageError::Invalid("hash prefix: 16 lower-case hex characters");
    if value.len() != 16
        || !value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(invalid);
    }
    let mut prefix = [0; 8];
    for (byte, pair) in prefix.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let pair = std::str::from_utf8(pair).map_err(|_| invalid)?;
        *byte = u8::from_str_radix(pair, 16).map_err(|_| invalid)?;
    }
    Ok(prefix)
}

/// Why a command did not do what it was asked. Names what, never a secret.
#[derive(Debug, thiserror::Error)]
pub enum AdminError<E: std::error::Error + 'static> {
    #[error(transparent)]
    Store(E),
    #[error("a customer with that name already exists")]
    CustomerExists,
    #[error("no customer with that id")]
    UnknownCustomer,
    #[error("no token starts with that prefix")]
    UnknownToken,
    #[error("more than one token starts with that prefix")]
    AmbiguousToken,
    #[error("no device with that id")]
    UnknownDevice,
    #[error("the device is not pending: only a pending device can be approved")]
    NotPending,
    #[error("the token file: {0}")]
    TokenFile(io::ErrorKind),
    #[error("the operating system gave no random bytes for a token")]
    NoRandomness,
    #[error("writing the output: {0}")]
    Output(io::ErrorKind),
}

/// Runs one command other than [`Command::Serve`] and [`Command::Help`], writing what it
/// shows to `out`.
pub async fn run<S: DeviceAdmin>(
    store: &S,
    command: Command,
    out: &mut impl Write,
    now: DateTime<Utc>,
) -> Result<(), AdminError<S::Error>> {
    let store_failed = AdminError::Store;
    let written = |error: io::Error| AdminError::Output(error.kind());
    match command {
        Command::Serve | Command::Help => {}
        Command::CustomerCreate { name } => {
            let customer = store
                .add_customer(&name)
                .await
                .map_err(store_failed)?
                .ok_or(AdminError::CustomerExists)?;
            audit::record(&AuditEvent::CustomerAdded { customer });
            writeln!(out, "{customer}").map_err(written)?;
        }
        Command::CustomerList => {
            for customer in store.customers().await.map_err(store_failed)? {
                writeln!(out, "{}  {}", customer.id, customer.name).map_err(written)?;
            }
        }
        Command::TokenCreate {
            customer,
            out: file,
            uses,
            hours,
        } => {
            let grant = TokenGrant {
                customer,
                // Whole seconds: what is shown is exactly what every store keeps.
                expires_at: now.trunc_subsecs(0) + TimeDelta::hours(i64::from(hours)),
                max_uses: uses,
            };
            let hash = issue_to_file(store, &file, grant).await?;
            audit::record(&AuditEvent::TokenIssued {
                token: hash,
                customer,
                max_uses: uses,
                expires_at: grant.expires_at,
            });
            writeln!(
                out,
                "token {} for customer {customer}: {} machine(s) until {}, written to {}",
                hash.short(),
                uses,
                grant.expires_at.to_rfc3339(),
                file.display()
            )
            .map_err(written)?;
        }
        Command::TokenList { customer } => {
            for token in store.tokens(customer).await.map_err(store_failed)? {
                writeln!(out, "{}", token_line(&token, now)).map_err(written)?;
            }
        }
        Command::TokenRevoke { prefix } => {
            let tokens = store.tokens(None).await.map_err(store_failed)?;
            let mut matching = tokens
                .iter()
                .filter(|token| token.hash.as_bytes()[..8] == prefix);
            let token = matching.next().ok_or(AdminError::UnknownToken)?.hash;
            if matching.next().is_some() {
                return Err(AdminError::AmbiguousToken);
            }
            if !store.revoke_token(&token).await.map_err(store_failed)? {
                return Err(AdminError::UnknownToken);
            }
            audit::record(&AuditEvent::TokenRevoked { token });
            writeln!(out, "token {} revoked", token.short()).map_err(written)?;
        }
        Command::DeviceList { customer } => {
            for device in store.devices(customer).await.map_err(store_failed)? {
                writeln!(out, "{}", device_line(&device)).map_err(written)?;
            }
        }
        Command::DeviceApprove { device } => {
            if !store.approve_device(device).await.map_err(store_failed)? {
                let known = store.device_record(device).await.map_err(store_failed)?;
                return Err(known.map_or(AdminError::UnknownDevice, |_| AdminError::NotPending));
            }
            audit::record(&AuditEvent::DeviceApproved { device });
            writeln!(out, "device {device} approved").map_err(written)?;
        }
        Command::DeviceRevoke { device } => {
            if !store.revoke_device(device).await.map_err(store_failed)? {
                return Err(AdminError::UnknownDevice);
            }
            audit::record(&AuditEvent::DeviceRevoked { device });
            writeln!(
                out,
                "device {device} revoked: a session it has ends within a minute"
            )
            .map_err(written)?;
        }
    }
    Ok(())
}

/// Makes a token, writes it to a new file at `path`, and issues it. If the store does not
/// take it, the file is removed: a token that enrolls nobody is not left lying around.
async fn issue_to_file<S: DeviceAdmin>(
    store: &S,
    path: &Path,
    grant: TokenGrant,
) -> Result<TokenHash, AdminError<S::Error>> {
    let mut secret = [0; 32];
    getrandom::fill(&mut secret).map_err(|_| AdminError::NoRandomness)?;
    let token = EnrollmentToken::from_bytes(secret);
    secret.fill(0);
    let hash = TokenHash::of(&token);

    write_new(path, &token).map_err(|error| AdminError::TokenFile(error.kind()))?;
    let issued = store.issue_token(hash, grant).await;
    match issued {
        Ok(true) => Ok(hash),
        Ok(false) => {
            let _ = std::fs::remove_file(path);
            // A hash of 32 random bytes that is already there is not going to happen;
            // the customer that is not there is.
            Err(AdminError::UnknownCustomer)
        }
        Err(error) => {
            let _ = std::fs::remove_file(path);
            Err(AdminError::Store(error))
        }
    }
}

/// Writes the token to a file that did not exist, readable by its owner only where the
/// system has such permissions. On Windows the file takes the permissions of its folder.
fn write_new(path: &Path, token: &EnrollmentToken) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    let written = file
        .write_all(format!("{}\n", token.expose_hex()).as_bytes())
        .and_then(|()| file.sync_all());
    if written.is_err() {
        drop(file);
        let _ = std::fs::remove_file(path);
    }
    written
}

#[cfg(test)]
mod tests;

fn token_line(token: &TokenInfo, now: DateTime<Utc>) -> String {
    let state = if token.revoked {
        "revoked"
    } else if now >= token.grant.expires_at {
        "expired"
    } else if token.uses_left() == 0 {
        "used up"
    } else {
        "valid"
    };
    format!(
        "{}  customer {}  {}/{} used  until {}  {state}",
        token.hash.short(),
        token.grant.customer,
        token.uses,
        token.grant.max_uses,
        token.grant.expires_at.to_rfc3339(),
    )
}

fn device_line(device: &DeviceRecord) -> String {
    let status = match device.status {
        crate::agents::DeviceStatus::Pending => "pending",
        crate::agents::DeviceStatus::Active => "active",
        crate::agents::DeviceStatus::Revoked => "revoked",
    };
    let online = if device.online.is_some() {
        "online"
    } else {
        "offline"
    };
    let last_seen = device
        .last_seen
        .map_or_else(|| "never".to_owned(), |at| at.to_rfc3339());
    // Labels are ASCII without control characters (`Label`): safe in a terminal.
    format!(
        "{}  customer {}  {status}  {online}  last seen {last_seen}  agent {}  {}",
        device.id, device.customer, device.about.agent_version, device.about.os,
    )
}
