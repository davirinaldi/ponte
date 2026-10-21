//! The server's subcommands: what an operator does until the console exists.
//!
//! ```text
//! ponte-server                                         serve agents (the default)
//! ponte-server migrate                                 bring the schema up to date
//! ponte-server customer create <name>
//! ponte-server customer list
//! ponte-server token create <customer-id> --out <file> [--uses N] [--hours H]
//! ponte-server token list [<customer-id>]
//! ponte-server token revoke <hash-prefix>
//! ponte-server device list [<customer-id>]
//! ponte-server device approve <device-id>
//! ponte-server device revoke <device-id>
//! ponte-server catalog ...                             keys, manifests (see `catalog`)
//! ponte-server action ...                              requests (see `catalog`)
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
use ponte_actions::TrustedKeysError;
use ponte_protocol::{DeviceId, EnrollmentToken, PublicKey, RequestId};
use uuid::Uuid;

use crate::agents::audit::{self, AuditEvent, Outcome};
use crate::agents::{
    ActionAdmin, CatalogError, CustomerId, CustomerName, DeviceRecord, DeviceStatus, ManifestId,
    RequestRefusal, TokenGrant, TokenHash, TokenInfo,
};

mod catalog;

pub use catalog::{LISTED_REQUESTS, MAX_ENVELOPE_FILE_BYTES, MAX_MINUTES};

/// What `ponte-server --help` and a mistyped command print.
pub const USAGE: &str = "\
usage:
  ponte-server                                         serve agents
  ponte-server migrate                                 bring the schema up to date
  ponte-server customer create <name>
  ponte-server customer list
  ponte-server token create <customer-id> --out <file> [--uses N] [--hours H]
  ponte-server token list [<customer-id>]
  ponte-server token revoke <hash-prefix>
  ponte-server device list [<customer-id>]
  ponte-server device approve <device-id>
  ponte-server device revoke <device-id>
  ponte-server catalog key add <public-key>
  ponte-server catalog key list
  ponte-server catalog key remove <public-key>
  ponte-server catalog add <envelope-file>
  ponte-server catalog list
  ponte-server action run <device-id> <manifest-id> [--version N] [--minutes M]
  ponte-server action show <request-id>
  ponte-server action list [<device-id>]
  ponte-server action cancel <request-id>

DATABASE_URL names the PostgreSQL database; serving and migrate bring its schema up to
date, the other subcommands only use it. A token is written to the --out file only,
for the agent's enrollment_token_file; --uses is 1 to 10000 (default 1), --hours 1 to 720
(default 24). catalog add takes an envelope written by ponte-sign and verifies it against
the keys the server trusts; action run sends the newest envelope that verifies, of the
highest version unless --version says which, to an active device; --minutes is 1 to 1440
(default 60). Only a queued request can be cancelled.";

/// Machines one token may enroll, at most. A rollout larger than this takes more tokens.
pub const MAX_USES: u32 = 10_000;
/// How long a token may stay valid, in hours: thirty days.
pub const MAX_HOURS: u32 = 720;

const DEFAULT_HOURS: u32 = 24;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Serve,
    Help,
    Migrate,
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
    CatalogKeyAdd {
        key: PublicKey,
    },
    CatalogKeyList,
    CatalogKeyRemove {
        key: PublicKey,
    },
    CatalogAdd {
        file: PathBuf,
    },
    CatalogList,
    ActionRun {
        device: DeviceId,
        manifest: ManifestId,
        /// The highest version with a valid envelope when `None`.
        version: Option<u32>,
        minutes: u32,
    },
    ActionShow {
        request: RequestId,
    },
    ActionList {
        device: Option<DeviceId>,
    },
    ActionCancel {
        request: RequestId,
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
        ["migrate"] => Ok(Command::Migrate),
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
        ["catalog" | "action", ..] => catalog::parse(args.as_slice()),
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
    #[error("the key cannot be trusted: {0}")]
    KeyNotUsable(TrustedKeysError),
    #[error(
        "the server trusts {} keys already: remove one first",
        ponte_actions::MAX_TRUSTED_KEYS
    )]
    TooManyKeys,
    #[error("the server does not trust that key")]
    UnknownKey,
    #[error("the server trusts no key yet: add one with catalog key add")]
    NoTrustedKeys,
    #[error("the keys the server stored cannot be used: {0}")]
    TrustedKeys(TrustedKeysError),
    #[error("the envelope file: {0}")]
    EnvelopeFile(io::ErrorKind),
    #[error(
        "the envelope file is larger than {} bytes",
        catalog::MAX_ENVELOPE_FILE_BYTES
    )]
    EnvelopeTooLarge,
    #[error("the file is not an envelope written by ponte-sign")]
    NotAnEnvelope,
    #[error("the envelope is refused: {0}")]
    Catalog(#[from] CatalogError),
    #[error("no envelope of that manifest verifies now against the keys the server trusts")]
    NoValidManifest,
    #[error("{}", refusal_text(*.0))]
    Refused(RequestRefusal),
    #[error("no request with that id")]
    UnknownRequest,
    #[error("only a queued request can be cancelled: this one was sent to the agent, or has ended")]
    NotQueued,
}

fn refusal_text(refusal: RequestRefusal) -> &'static str {
    match refusal {
        RequestRefusal::UnknownDevice => "no device with that id",
        RequestRefusal::DeviceNotActive(DeviceStatus::Pending) => {
            "the device is pending: approve it first"
        }
        RequestRefusal::DeviceNotActive(_) => "the device is revoked: it is sent nothing",
        RequestRefusal::TooManyOpen => {
            "the device has too many requests waiting: wait, or cancel some"
        }
        RequestRefusal::UnknownManifest => "the envelope is no longer in the catalog",
        RequestRefusal::ExpiryOutOfRange => "the expiry does not fit the database",
    }
}

/// Runs one command other than [`Command::Serve`], [`Command::Help`] and
/// [`Command::Migrate`], writing what it shows to `out`.
pub async fn run<S: ActionAdmin>(
    store: &S,
    command: Command,
    out: &mut impl Write,
    now: DateTime<Utc>,
) -> Result<(), AdminError<S::Error>> {
    let store_failed = AdminError::Store;
    let written = |error: io::Error| AdminError::Output(error.kind());
    match command {
        Command::Serve | Command::Help | Command::Migrate => {}
        Command::CustomerCreate { name } => {
            let added = store.add_customer(&name).await;
            let customer = may_have_changed(added, || AuditEvent::CustomerAdded {
                customer: None,
                outcome: Outcome::Unknown,
            })?
            .ok_or(AdminError::CustomerExists)?;
            audit::record(&AuditEvent::CustomerAdded {
                customer: Some(customer),
                outcome: Outcome::Done,
            });
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
                outcome: Outcome::Done,
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
            let revoked = store.revoke_token(&token).await;
            let unknown = || AuditEvent::TokenRevoked {
                token,
                outcome: Outcome::Unknown,
            };
            if !may_have_changed(revoked, unknown)? {
                return Err(AdminError::UnknownToken);
            }
            audit::record(&AuditEvent::TokenRevoked {
                token,
                outcome: Outcome::Done,
            });
            writeln!(out, "token {} revoked", token.short()).map_err(written)?;
        }
        Command::DeviceList { customer } => {
            for device in store.devices(customer).await.map_err(store_failed)? {
                writeln!(out, "{}", device_line(&device)).map_err(written)?;
            }
        }
        Command::DeviceApprove { device } => {
            let approved = store.approve_device(device).await;
            let unknown = || AuditEvent::DeviceApproved {
                device,
                outcome: Outcome::Unknown,
            };
            if !may_have_changed(approved, unknown)? {
                let known = store.device_record(device).await.map_err(store_failed)?;
                return Err(known.map_or(AdminError::UnknownDevice, |_| AdminError::NotPending));
            }
            audit::record(&AuditEvent::DeviceApproved {
                device,
                outcome: Outcome::Done,
            });
            writeln!(out, "device {device} approved").map_err(written)?;
        }
        Command::DeviceRevoke { device } => {
            let revoked = store.revoke_device(device).await;
            let unknown = || AuditEvent::DeviceRevoked {
                device,
                outcome: Outcome::Unknown,
            };
            if !may_have_changed(revoked, unknown)? {
                return Err(AdminError::UnknownDevice);
            }
            audit::record(&AuditEvent::DeviceRevoked {
                device,
                outcome: Outcome::Done,
            });
            writeln!(
                out,
                "device {device} revoked: a session it has ends within a minute"
            )
            .map_err(written)?;
        }
        command @ (Command::CatalogKeyAdd { .. }
        | Command::CatalogKeyList
        | Command::CatalogKeyRemove { .. }
        | Command::CatalogAdd { .. }
        | Command::CatalogList
        | Command::ActionRun { .. }
        | Command::ActionShow { .. }
        | Command::ActionList { .. }
        | Command::ActionCancel { .. }) => catalog::run(store, command, out, now).await?,
    }
    Ok(())
}

/// The answer of a call that changes the store. When it failed, the change may have
/// happened all the same (a database can commit and lose its answer), so `unknown` is
/// audited before the error is returned (RF-40).
fn may_have_changed<T, E: std::error::Error + 'static>(
    result: Result<T, E>,
    unknown: impl FnOnce() -> AuditEvent,
) -> Result<T, AdminError<E>> {
    result.map_err(|error| {
        audit::record(&unknown());
        AdminError::Store(error)
    })
}

/// Makes a token, writes it to a new file at `path`, and issues it. If the store does not
/// take it, the file is removed: a token that enrolls nobody is not left lying around.
async fn issue_to_file<S: ActionAdmin>(
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
            // The token may be in the store all the same. Nobody holds it any more, but the
            // record says it was issued.
            audit::record(&AuditEvent::TokenIssued {
                token: hash,
                customer: grant.customer,
                max_uses: grant.max_uses,
                expires_at: grant.expires_at,
                outcome: Outcome::Unknown,
            });
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
        DeviceStatus::Pending => "pending",
        DeviceStatus::Active => "active",
        DeviceStatus::Revoked => "revoked",
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
        "{}  customer {}  {status}  {online}  last seen {last_seen}  {}  agent {}  {}",
        device.id,
        device.customer,
        clock_offset(device),
        device.about.agent_version,
        device.about.os,
    )
}

/// How far the device's clock was from the server's at its last heartbeat (ADR-0010): the
/// time it says it collected the reading, less the time the server stored it. A device
/// whose clock is off refuses actions, and this is where that gets noticed. The delay of
/// the network and of the heartbeat itself makes it a little negative on a good clock.
fn clock_offset(device: &DeviceRecord) -> String {
    match (&device.telemetry, device.telemetry_at) {
        (Some(telemetry), Some(stored)) => {
            let offset = (telemetry.collected_at - stored).num_seconds();
            format!("clock {offset:+}s")
        }
        _ => "clock unknown".to_owned(),
    }
}
