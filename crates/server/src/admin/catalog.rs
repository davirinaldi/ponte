//! The operator's half of actions (ADR-0010, ADR-0012): the keys the server trusts, the
//! catalog of signed manifests, and the requests sent to devices.
//!
//! ```text
//! ponte-server catalog key add <public-key>
//! ponte-server catalog key list
//! ponte-server catalog key remove <public-key>
//! ponte-server catalog add <envelope-file>
//! ponte-server catalog list
//! ponte-server action run <device-id> <manifest-id> [--version N] [--minutes M]
//! ponte-server action show <request-id>
//! ponte-server action list [<device-id>]
//! ponte-server action cancel <request-id>
//! ```
//!
//! **`catalog add` verifies against the server's keys**, never the key the envelope names,
//! and refuses what has expired or has no valid shape: the same `ponte_actions::verify` the
//! agent runs. `action run` verifies the envelope it picks once more. Neither makes the
//! agent trust anything: it verifies with the keys of its own configuration.
//!
//! **Nothing of a manifest's text reaches the terminal or the log**: ids, versions, risk,
//! dates and hashes. The `output` of a result is text from the machine, so `action show`
//! gives its size only (invariant 4).

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use ponte_actions::{TrustedKeys, TrustedKeysError};
use ponte_protocol::{ActionOutcome, Initiator, Label, PublicKey, RequestId, SignedManifest};

use super::{AdminError, Command, UsageError, bounded, device_id, may_have_changed, set, uuid};
use crate::agents::audit::{self, AuditEvent, Outcome};
use crate::agents::{
    ActionAdmin, CancelOutcome, CatalogEntry, KeyAdded, ManifestId, NewRequest, RequestOutcome,
    RequestRecord, RequestState,
};

/// The longest a request may wait, in minutes: the 24 hours of ADR-0012.
pub const MAX_MINUTES: u32 = 24 * 60;
const DEFAULT_MINUTES: u32 = 60;

/// The largest envelope file `catalog add` reads. A manifest is at most 16 KiB; written as
/// JSON, with its escapes, it stays well under this.
pub const MAX_ENVELOPE_FILE_BYTES: u64 = 64 * 1024;

/// How many requests `action list` shows, newest first.
pub const LISTED_REQUESTS: usize = 100;

/// Who asks, until people have accounts (M3).
const OPERATOR: &str = "server_cli";

pub(super) fn parse(args: &[&str]) -> Result<Command, UsageError> {
    match args {
        ["catalog", "key", "add", key] => Ok(Command::CatalogKeyAdd {
            key: public_key(key)?,
        }),
        ["catalog", "key", "list"] => Ok(Command::CatalogKeyList),
        ["catalog", "key", "remove", key] => Ok(Command::CatalogKeyRemove {
            key: public_key(key)?,
        }),
        ["catalog", "add", file] if !file.is_empty() => Ok(Command::CatalogAdd {
            file: PathBuf::from(file),
        }),
        ["catalog", "list"] => Ok(Command::CatalogList),
        ["action", "run", device, manifest, flags @ ..] => action_run(device, manifest, flags),
        ["action", "show", request] => Ok(Command::ActionShow {
            request: request_id(request)?,
        }),
        ["action", "list"] => Ok(Command::ActionList { device: None }),
        ["action", "list", device] => Ok(Command::ActionList {
            device: Some(device_id(device)?),
        }),
        ["action", "cancel", request] => Ok(Command::ActionCancel {
            request: request_id(request)?,
        }),
        ["catalog" | "action", ..] => Err(UsageError::Missing("an argument, or one too many")),
        _ => Err(UsageError::UnknownCommand),
    }
}

fn public_key(value: &str) -> Result<PublicKey, UsageError> {
    // Lowercase hex of exactly 32 bytes, the one spelling `ponte-sign keygen` writes.
    value
        .parse()
        .map_err(|_| UsageError::Invalid("public key: 64 lower-case hex characters"))
}

fn request_id(value: &str) -> Result<RequestId, UsageError> {
    uuid(value, "request id").map(RequestId::from_uuid)
}

fn action_run(device: &str, manifest: &str, mut flags: &[&str]) -> Result<Command, UsageError> {
    let device = device_id(device)?;
    let manifest = manifest
        .parse()
        .map_err(|_| UsageError::Invalid("manifest id"))?;
    let (mut version, mut minutes) = (None, None);
    while let [flag, rest @ ..] = flags {
        let [value, rest @ ..] = rest else {
            return Err(UsageError::Missing("a value after a flag"));
        };
        match *flag {
            "--version" => set(
                &mut version,
                "--version",
                bounded(value, 1, u32::MAX, "--version")?,
            )?,
            "--minutes" => set(
                &mut minutes,
                "--minutes",
                bounded(value, 1, MAX_MINUTES, "--minutes")?,
            )?,
            _ => return Err(UsageError::Invalid("flag")),
        }
        flags = rest;
    }
    Ok(Command::ActionRun {
        device,
        manifest,
        version,
        minutes: minutes.unwrap_or(DEFAULT_MINUTES),
    })
}

/// Seconds since the Unix epoch of `now`. The server's clock is never before 1970.
fn epoch(now: DateTime<Utc>) -> u64 {
    u64::try_from(now.timestamp()).unwrap_or(0)
}

/// A date of the wire, as listings show it.
fn date(secs: u64) -> String {
    i64::try_from(secs)
        .ok()
        .and_then(|secs| DateTime::from_timestamp(secs, 0))
        .map_or_else(|| secs.to_string(), |at| at.to_rfc3339())
}

fn short_key(key: &PublicKey) -> String {
    key.to_string()[..16].to_owned()
}

/// The keys the server trusts, as `verify` takes them.
async fn trusted<S: ActionAdmin>(store: &S) -> Result<TrustedKeys, AdminError<S::Error>> {
    let keys = store.signing_keys().await.map_err(AdminError::Store)?;
    TrustedKeys::new(keys.iter().map(|key| key.public_key)).map_err(|error| match error {
        TrustedKeysError::Empty => AdminError::NoTrustedKeys,
        // A list the server itself stored and cannot use: refuse, never guess.
        other => AdminError::TrustedKeys(other),
    })
}

/// Reads an envelope written by `ponte-sign`, bounded, and never quotes it.
fn read_envelope<E: std::error::Error>(path: &Path) -> Result<SignedManifest, AdminError<E>> {
    let file = std::fs::File::open(path).map_err(|error| AdminError::EnvelopeFile(error.kind()))?;
    let mut text = String::new();
    file.take(MAX_ENVELOPE_FILE_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|error| AdminError::EnvelopeFile(error.kind()))?;
    if text.len() as u64 > MAX_ENVELOPE_FILE_BYTES {
        return Err(AdminError::EnvelopeTooLarge);
    }
    // The parser's error can repeat what the file holds: it stays here.
    serde_json::from_str(&text).map_err(|_| AdminError::NotAnEnvelope)
}

pub(super) async fn run<S: ActionAdmin>(
    store: &S,
    command: Command,
    out: &mut impl Write,
    now: DateTime<Utc>,
) -> Result<(), AdminError<S::Error>> {
    let written = |error: io::Error| AdminError::Output(error.kind());
    match command {
        Command::CatalogKeyAdd { key } => {
            let known = store.signing_keys().await.map_err(AdminError::Store)?;
            if known.iter().any(|known| known.public_key == key) {
                writeln!(out, "key {} is already trusted", short_key(&key)).map_err(written)?;
                return Ok(());
            }
            // The whole list as `verify` will take it: a key that would break it never gets in.
            let keys = known.iter().map(|known| known.public_key).chain([key]);
            TrustedKeys::new(keys).map_err(|error| match error {
                TrustedKeysError::TooMany => AdminError::TooManyKeys,
                other => AdminError::KeyNotUsable(other),
            })?;
            let added = store.add_signing_key(key, now).await;
            let unknown = || AuditEvent::SigningKeyAdded {
                key,
                outcome: Outcome::Unknown,
            };
            match may_have_changed(added, unknown)? {
                KeyAdded::Added => {
                    audit::record(&AuditEvent::SigningKeyAdded {
                        key,
                        outcome: Outcome::Done,
                    });
                    writeln!(out, "key {key} trusted").map_err(written)?;
                }
                KeyAdded::AlreadyTrusted => {
                    writeln!(out, "key {} is already trusted", short_key(&key)).map_err(written)?;
                }
                KeyAdded::Full => return Err(AdminError::TooManyKeys),
            }
        }
        Command::CatalogKeyList => {
            for key in store.signing_keys().await.map_err(AdminError::Store)? {
                writeln!(
                    out,
                    "{}  added {}",
                    key.public_key,
                    key.added_at.to_rfc3339()
                )
                .map_err(written)?;
            }
        }
        Command::CatalogKeyRemove { key } => {
            let removed = store.remove_signing_key(&key).await;
            let unknown = || AuditEvent::SigningKeyRemoved {
                key,
                outcome: Outcome::Unknown,
            };
            if !may_have_changed(removed, unknown)? {
                return Err(AdminError::UnknownKey);
            }
            audit::record(&AuditEvent::SigningKeyRemoved {
                key,
                outcome: Outcome::Done,
            });
            writeln!(
                out,
                "key {} removed: nothing it signed is sent from now on; agents trust what their \
                 own configuration lists",
                short_key(&key)
            )
            .map_err(written)?;
        }
        Command::CatalogAdd { file } => {
            let envelope = read_envelope(&file)?;
            let keys = trusted(store).await?;
            let entry = CatalogEntry::verify(envelope, &keys, epoch(now))?;
            let added = store.add_manifest(&entry, now).await;
            let event = |outcome| AuditEvent::ManifestAdded {
                envelope: *entry.hash(),
                manifest: entry.id().clone(),
                version: entry.version(),
                key: entry.envelope().public_key,
                outcome,
            };
            if may_have_changed(added, || event(Outcome::Unknown))? {
                audit::record(&event(Outcome::Done));
                writeln!(out, "{}", catalog_line(&entry, Some(&keys), now)).map_err(written)?;
            } else {
                writeln!(out, "already in the catalog: {}", entry.hash().short())
                    .map_err(written)?;
            }
        }
        Command::CatalogList => {
            let keys = trusted(store).await.ok();
            for entry in store.manifests(None).await.map_err(AdminError::Store)? {
                writeln!(out, "{}", catalog_line(&entry, keys.as_ref(), now)).map_err(written)?;
            }
        }
        Command::ActionRun {
            device,
            manifest,
            version,
            minutes,
        } => {
            let entry = pick(store, &manifest, version, now).await?;
            let request = NewRequest {
                id: RequestId::new(),
                device,
                manifest: *entry.hash(),
                expires_at: epoch(now) + u64::from(minutes) * 60,
                initiator: Initiator::Human {
                    user_id: Label::from_lossy(OPERATOR),
                },
            };
            let event = |outcome| AuditEvent::ActionRequested {
                request: request.id,
                device,
                manifest: entry.id().clone(),
                version: entry.version(),
                envelope: *entry.hash(),
                expires_at: request.expires_at,
                outcome,
            };
            let queued = store.request_action(&request, now).await;
            match may_have_changed(queued, || event(Outcome::Unknown))? {
                RequestOutcome::Queued => {
                    audit::record(&event(Outcome::Done));
                    writeln!(
                        out,
                        "request {} queued: {} v{} for device {device}, until {}",
                        request.id,
                        entry.id(),
                        entry.version(),
                        date(request.expires_at)
                    )
                    .map_err(written)?;
                }
                RequestOutcome::Refused(refusal) => return Err(AdminError::Refused(refusal)),
            }
        }
        Command::ActionShow { request } => {
            let record = store
                .request(request)
                .await
                .map_err(AdminError::Store)?
                .ok_or(AdminError::UnknownRequest)?;
            show(&record, out).map_err(written)?;
        }
        Command::ActionList { device } => {
            let records = store
                .requests(device, LISTED_REQUESTS)
                .await
                .map_err(AdminError::Store)?;
            for record in records {
                writeln!(out, "{}", request_line(&record)).map_err(written)?;
            }
        }
        Command::ActionCancel { request } => {
            let cancelled = store.cancel(request, now).await;
            let unknown = || AuditEvent::ActionCancelled {
                request,
                outcome: Outcome::Unknown,
            };
            match may_have_changed(cancelled, unknown)? {
                CancelOutcome::Cancelled => {
                    audit::record(&AuditEvent::ActionCancelled {
                        request,
                        outcome: Outcome::Done,
                    });
                    writeln!(out, "request {request} cancelled").map_err(written)?;
                }
                CancelOutcome::NotQueued => return Err(AdminError::NotQueued),
                CancelOutcome::Unknown => return Err(AdminError::UnknownRequest),
            }
        }
        _ => {}
    }
    Ok(())
}

/// The envelope `action run` sends (ADR-0010): of `id`, at `version` or the highest
/// version that has one, the one with the latest `issued_at` that verifies now against the
/// keys the server trusts.
async fn pick<S: ActionAdmin>(
    store: &S,
    id: &ManifestId,
    version: Option<u32>,
    now: DateTime<Utc>,
) -> Result<CatalogEntry, AdminError<S::Error>> {
    let keys = trusted(store).await?;
    let entries = store.manifests(Some(id)).await.map_err(AdminError::Store)?;
    entries
        .into_iter()
        .filter(|entry| version.is_none_or(|version| entry.version() == version))
        // Verified again: the catalog's rows are not trusted to be what was added.
        .filter_map(|entry| {
            let verified =
                CatalogEntry::verify(entry.envelope().clone(), &keys, epoch(now)).ok()?;
            (verified == entry).then_some(entry)
        })
        .max_by_key(|entry| (entry.version(), entry.envelope().issued_at))
        .ok_or(AdminError::NoValidManifest)
}

fn catalog_line(entry: &CatalogEntry, keys: Option<&TrustedKeys>, now: DateTime<Utc>) -> String {
    let envelope = entry.envelope();
    let now = epoch(now);
    let trusted = keys.is_some_and(|keys| keys.keys().any(|key| *key == envelope.public_key));
    let state = if !trusted {
        "key not trusted"
    } else if envelope.expires_at <= now {
        "expired"
    } else if envelope.issued_at > now.saturating_add(ponte_actions::MAX_CLOCK_SKEW_SECS) {
        "not yet valid"
    } else {
        "valid"
    };
    // Ids are lowercase ASCII (`ManifestId`); nothing of the manifest's text is shown.
    format!(
        "{}  {} v{}  {:?}  key {}  issued {}  expires {}  {state}",
        entry.hash().short(),
        entry.id(),
        entry.version(),
        entry.risk(),
        short_key(&envelope.public_key),
        date(envelope.issued_at),
        date(envelope.expires_at),
    )
}

/// The status of a request, with the code of its reason and the index of its step.
fn status(state: &RequestState) -> String {
    match state {
        RequestState::Answered {
            outcome: ActionOutcome::Failed { reason, step },
            ..
        } => {
            let step = step.map_or_else(String::new, |step| format!(" at step {step}"));
            format!("failed {reason:?}{step}")
        }
        RequestState::Answered {
            outcome: ActionOutcome::Rejected { reason },
            ..
        } => format!("rejected {reason:?}"),
        other => other.name().to_owned(),
    }
}

fn request_line(record: &RequestRecord) -> String {
    format!(
        "{}  device {}  {} v{}  {}  created {}",
        record.id,
        record.device,
        record.manifest_id,
        record.version,
        status(&record.state),
        record.created_at.to_rfc3339(),
    )
}

fn show(record: &RequestRecord, out: &mut impl Write) -> io::Result<()> {
    writeln!(out, "request   {}", record.id)?;
    writeln!(out, "device    {}", record.device)?;
    writeln!(
        out,
        "manifest  {} v{} (envelope {})",
        record.manifest_id,
        record.version,
        record.manifest.short()
    )?;
    // Labels are ASCII without control characters: safe in a terminal.
    match &record.initiator {
        Initiator::Human { user_id } => writeln!(out, "asked by  {user_id}")?,
        Initiator::Ai {
            client_id,
            ticket_ref,
            confidence,
        } => {
            let ticket = ticket_ref
                .as_ref()
                .map_or_else(String::new, |ticket| format!(" ticket {ticket}"));
            let confidence =
                confidence.map_or_else(String::new, |value| format!(" confidence {}", value.get()));
            writeln!(
                out,
                "asked by  model client {client_id}{ticket}{confidence}"
            )?;
        }
    }
    writeln!(out, "created   {}", record.created_at.to_rfc3339())?;
    writeln!(out, "expires   {}", date(record.expires_at))?;
    writeln!(out, "status    {}", status(&record.state))?;
    match &record.state {
        RequestState::Queued => {}
        RequestState::Sent { at } => writeln!(out, "sent      {}", at.to_rfc3339())?,
        RequestState::Cancelled { at } | RequestState::Expired { at } => {
            writeln!(out, "ended     {}", at.to_rfc3339())?;
        }
        RequestState::Answered {
            sent_at,
            at,
            duration_ms,
            output,
            ..
        } => {
            writeln!(out, "sent      {}", sent_at.to_rfc3339())?;
            writeln!(out, "answered  {}", at.to_rfc3339())?;
            writeln!(out, "duration  {duration_ms} ms")?;
            if let Some(output) = output {
                // Text from the machine: its size, never the text (invariant 4).
                writeln!(out, "output    {} bytes, not shown", output.as_str().len())?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
