use std::ffi::OsString;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use ponte_protocol::{
    ActionOutcome, ActionResult, DeviceId, Output, PublicKey, RejectReason, RequestId,
    SignedManifest,
};
use uuid::Uuid;

use super::*;
use crate::admin::{UsageError, parse, run as run_command};
use crate::agents::testkit::{
    Logs, about, at, envelope, grant, manifest_public, manifest_text, telemetry, token,
};
use crate::agents::{
    ActionStore, DeviceAdmin, DeviceStore, EnrollOutcome, EnrollRequest, MemoryStore, TokenHash,
};

const ID: &str = "erp.restart-service";
const DEVICE: &str = "0190f2c4-8d3a-7b1e-9c4d-5e6f7a8b9c0d";

fn parsed(line: &str) -> Result<Command, UsageError> {
    parse(line.split_whitespace().map(OsString::from))
}

async fn run_at(
    store: &MemoryStore,
    command: Command,
    now: DateTime<Utc>,
) -> (Result<(), String>, String) {
    let mut out = Vec::new();
    let result = run_command(store, command, &mut out, now)
        .await
        .map_err(|error| error.to_string());
    (result, String::from_utf8(out).unwrap())
}

async fn run_on(store: &MemoryStore, command: Command) -> (Result<(), String>, String) {
    run_at(store, command, at(0)).await
}

/// An enrolled device: active with a token for one machine, pending with one for two.
async fn enrolled(store: &MemoryStore, seed: u8, uses: u32) -> DeviceId {
    store.add_token(&token(seed), grant(uses));
    let request = EnrollRequest {
        token: TokenHash::of(&token(seed)),
        public_key: PublicKey::from_bytes([seed; 32]),
        about: about(),
    };
    match store.enroll(request, at(0)).await.unwrap() {
        EnrollOutcome::Enrolled { device_id, .. } => device_id,
        EnrollOutcome::Refused(refusal) => panic!("{refusal:?}"),
    }
}

/// Writes `envelope` as `ponte-sign` does, to a new file.
fn envelope_file(envelope: &SignedManifest) -> PathBuf {
    let path = std::env::temp_dir().join(format!("ponte-envelope-{}.json", Uuid::now_v7()));
    std::fs::write(&path, serde_json::to_string_pretty(envelope).unwrap()).unwrap();
    path
}

/// Signed by `manifest_key(key)`, `issued` seconds after `at(0)` less an hour.
fn signed(key: u8, version: u32, issued: i64) -> SignedManifest {
    envelope(key, &manifest_text(ID, version), at(issued - 3600))
}

async fn trust(store: &MemoryStore, key: u8) {
    let (result, _) = run_on(
        store,
        Command::CatalogKeyAdd {
            key: manifest_public(key),
        },
    )
    .await;
    result.unwrap();
}

async fn add(store: &MemoryStore, envelope: &SignedManifest) -> Result<(), String> {
    let file = envelope_file(envelope);
    let (result, _) = run_on(store, Command::CatalogAdd { file: file.clone() }).await;
    std::fs::remove_file(file).unwrap();
    result
}

fn ask(device: DeviceId, version: Option<u32>) -> Command {
    Command::ActionRun {
        device,
        manifest: ID.parse().unwrap(),
        version,
        minutes: 30,
    }
}

/// The request `action run` just queued, as the store holds it.
async fn last_request(store: &MemoryStore) -> RequestRecord {
    store.requests(None, 1).await.unwrap().remove(0)
}

#[test]
fn every_catalog_and_action_command_parses() {
    let key = manifest_public(1);
    let device = DeviceId::from_uuid(Uuid::parse_str(DEVICE).unwrap());
    assert_eq!(
        parsed(&format!("catalog key add {key}")),
        Ok(Command::CatalogKeyAdd { key })
    );
    assert_eq!(parsed("catalog key list"), Ok(Command::CatalogKeyList));
    assert_eq!(
        parsed(&format!("catalog key remove {key}")),
        Ok(Command::CatalogKeyRemove { key })
    );
    assert_eq!(
        parsed("catalog add restart.json"),
        Ok(Command::CatalogAdd {
            file: PathBuf::from("restart.json")
        })
    );
    assert_eq!(parsed("catalog list"), Ok(Command::CatalogList));
    assert_eq!(
        parsed(&format!("action run {DEVICE} {ID}")),
        Ok(Command::ActionRun {
            device,
            manifest: ID.parse().unwrap(),
            version: None,
            minutes: 60,
        })
    );
    assert_eq!(
        parsed(&format!(
            "action run {DEVICE} {ID} --minutes 1440 --version 2"
        )),
        Ok(Command::ActionRun {
            device,
            manifest: ID.parse().unwrap(),
            version: Some(2),
            minutes: 1440,
        })
    );
    let request = RequestId::from_uuid(Uuid::parse_str(DEVICE).unwrap());
    assert_eq!(
        parsed(&format!("action show {DEVICE}")),
        Ok(Command::ActionShow { request })
    );
    assert_eq!(
        parsed("action list"),
        Ok(Command::ActionList { device: None })
    );
    assert_eq!(
        parsed(&format!("action list {DEVICE}")),
        Ok(Command::ActionList {
            device: Some(device)
        })
    );
    assert_eq!(
        parsed(&format!("action cancel {DEVICE}")),
        Ok(Command::ActionCancel { request })
    );
}

/// ADR-0012: a request waits 24 hours at most. Everything else that is not exactly one of
/// the forms does nothing either.
#[test]
fn anything_else_is_refused() {
    let key = manifest_public(1).to_string();
    let upper = key.to_uppercase();
    for line in [
        "catalog",
        "catalog key",
        "catalog key add",
        &format!("catalog key add {upper}"),
        &format!("catalog key add {}", &key[..62]),
        &format!("catalog key add {key} {key}"),
        "catalog key remove 00",
        "catalog add",
        "catalog add a b",
        "catalog list all",
        "action",
        &format!("action run {DEVICE}"),
        &format!("action run {DEVICE} {ID} --minutes 0"),
        &format!("action run {DEVICE} {ID} --minutes 1441"),
        &format!("action run {DEVICE} {ID} --minutes"),
        &format!("action run {DEVICE} {ID} --version 0"),
        &format!("action run {DEVICE} {ID} --version 1 --version 2"),
        &format!("action run {DEVICE} {ID} --now yes"),
        &format!("action run {DEVICE} ERP.Restart"),
        &format!("action run {DEVICE} erp"),
        &format!("action run not-a-uuid {ID}"),
        "action show",
        "action show 1234",
        &format!("action list {DEVICE} {DEVICE}"),
        &format!("action cancel {}", DEVICE.to_uppercase()),
    ] {
        assert!(parsed(line).is_err(), "{line}");
    }
    assert_eq!(MAX_MINUTES, 1440);
}

/// A key goes in only if the whole list still works as `verify` takes it: a weak key, a
/// fifth one, or the same one twice never breaks every `catalog add` after it.
#[tokio::test]
async fn a_key_is_checked_before_it_is_trusted() {
    let store = MemoryStore::new();
    let (logs, _guard) = Logs::capture();

    // The identity point: small order, it verifies signatures it never made.
    let mut weak = [0; 32];
    weak[0] = 1;
    let (result, _) = run_on(
        &store,
        Command::CatalogKeyAdd {
            key: PublicKey::from_bytes(weak),
        },
    )
    .await;
    assert!(result.unwrap_err().contains("weak key"));
    assert_eq!(store.signing_keys().await.unwrap(), []);

    for seed in 1..=4 {
        trust(&store, seed).await;
    }
    let (result, out) = run_on(
        &store,
        Command::CatalogKeyAdd {
            key: manifest_public(2),
        },
    )
    .await;
    result.unwrap();
    assert!(out.contains("already trusted"), "{out}");
    let (result, _) = run_on(
        &store,
        Command::CatalogKeyAdd {
            key: manifest_public(5),
        },
    )
    .await;
    assert!(result.unwrap_err().contains("remove one first"));

    let (_, out) = run_on(&store, Command::CatalogKeyList).await;
    assert_eq!(out.lines().count(), 4, "{out}");
    assert!(out.starts_with(&manifest_public(1).to_string()), "{out}");

    let (result, _) = run_on(
        &store,
        Command::CatalogKeyRemove {
            key: manifest_public(2),
        },
    )
    .await;
    result.unwrap();
    let (result, _) = run_on(
        &store,
        Command::CatalogKeyRemove {
            key: manifest_public(2),
        },
    )
    .await;
    assert_eq!(result.unwrap_err(), "the server does not trust that key");

    let logs = logs.text();
    assert_eq!(logs.matches("signing_key_added").count(), 4, "{logs}");
    assert_eq!(logs.matches("signing_key_removed").count(), 1, "{logs}");
}

/// ADR-0010: `catalog add` verifies against the keys the server trusts, never the key the
/// envelope names, and takes nothing expired, not yet valid or of no valid shape. The file
/// is read bounded, and its text never comes back in an error.
#[tokio::test]
async fn catalog_add_verifies_against_the_keys_of_the_server() {
    let store = MemoryStore::new();
    let good = signed(1, 1, 0);

    assert_eq!(
        add(&store, &good).await.unwrap_err(),
        "the server trusts no key yet: add one with catalog key add"
    );
    trust(&store, 2).await;
    // Signed by a key the server does not trust: the envelope names its own key.
    assert!(
        add(&store, &good)
            .await
            .unwrap_err()
            .contains("not trusted")
    );

    trust(&store, 1).await;
    // Valid 90 days from an hour before `at(-91 days)`: expired at `at(0)`.
    let expired = signed(1, 1, -91 * 24 * 3600);
    assert!(add(&store, &expired).await.unwrap_err().contains("expired"));
    let early = signed(1, 1, 3600 + 3600);
    assert!(add(&store, &early).await.unwrap_err().contains("future"));
    let mut altered = good.clone();
    altered.expires_at += 1;
    assert!(
        add(&store, &altered)
            .await
            .unwrap_err()
            .contains("signature")
    );
    let shapeless = envelope(1, "id = \"SECRET-ID\"\nversion = 1\n", at(-3600));
    let refused = add(&store, &shapeless).await.unwrap_err();
    assert!(refused.contains("not a manifest"), "{refused}");
    assert!(!refused.contains("SECRET"), "{refused}");

    let path = std::env::temp_dir().join(format!("ponte-envelope-{}", Uuid::now_v7()));
    for (bytes, expected) in [
        (
            b"SECRET not json".to_vec(),
            "the file is not an envelope written by ponte-sign",
        ),
        (
            vec![b' '; usize::try_from(MAX_ENVELOPE_FILE_BYTES).unwrap() + 1],
            "the envelope file is larger than 65536 bytes",
        ),
    ] {
        std::fs::write(&path, bytes).unwrap();
        let (result, _) = run_on(&store, Command::CatalogAdd { file: path.clone() }).await;
        assert_eq!(result.unwrap_err(), expected);
    }
    std::fs::remove_file(&path).unwrap();
    let (result, _) = run_on(&store, Command::CatalogAdd { file: path }).await;
    assert!(result.unwrap_err().starts_with("the envelope file: "));
    assert_eq!(store.manifests(None).await.unwrap(), []);

    let (logs, _guard) = Logs::capture();
    add(&store, &good).await.unwrap();
    let file = envelope_file(&good);
    let (result, out) = run_on(&store, Command::CatalogAdd { file: file.clone() }).await;
    std::fs::remove_file(file).unwrap();
    result.unwrap();
    assert!(out.starts_with("already in the catalog"), "{out}");
    assert_eq!(store.manifests(None).await.unwrap().len(), 1);
    let logs = logs.text();
    assert_eq!(logs.matches("manifest_added").count(), 1, "{logs}");
    assert!(!logs.contains("FakeErp"), "{logs}");
}

/// What a listing says about each envelope, and never the text of the manifest.
#[tokio::test]
async fn the_catalog_lists_each_envelope_and_whether_it_can_be_sent() {
    let store = MemoryStore::new();
    trust(&store, 1).await;
    trust(&store, 2).await;
    add(&store, &signed(1, 1, 0)).await.unwrap();
    add(&store, &signed(2, 2, 0)).await.unwrap();
    run_on(
        &store,
        Command::CatalogKeyRemove {
            key: manifest_public(2),
        },
    )
    .await
    .0
    .unwrap();

    let (_, out) = run_on(&store, Command::CatalogList).await;
    let lines: Vec<_> = out.lines().collect();
    assert_eq!(lines.len(), 2, "{out}");
    assert!(lines[0].contains("erp.restart-service v1  Medium"), "{out}");
    assert!(lines[0].ends_with("  valid"), "{out}");
    assert!(lines[1].ends_with("  key not trusted"), "{out}");
    assert!(!out.contains("FakeErp"), "{out}");

    let (_, out) = run_at(&store, Command::CatalogList, at(91 * 24 * 3600)).await;
    assert!(out.lines().next().unwrap().ends_with("  expired"), "{out}");
}

/// ADR-0010: `action run` sends, of the highest version unless one is named, the envelope
/// with the latest `issued_at` that verifies now against a key the server still trusts.
#[tokio::test]
async fn action_run_sends_the_newest_envelope_that_verifies() {
    let store = MemoryStore::new();
    let device = enrolled(&store, 1, 1).await;
    trust(&store, 1).await;
    trust(&store, 2).await;
    let first = signed(1, 1, -100);
    let renewed = signed(1, 1, -50);
    let second = signed(1, 2, -100);
    let untrusted = signed(2, 3, -100);
    for envelope in [&first, &renewed, &second, &untrusted] {
        add(&store, envelope).await.unwrap();
    }
    run_on(
        &store,
        Command::CatalogKeyRemove {
            key: manifest_public(2),
        },
    )
    .await
    .0
    .unwrap();

    let sent = |envelope: &SignedManifest| crate::agents::EnvelopeHash::of(envelope);
    let (result, out) = run_on(&store, ask(device, None)).await;
    result.unwrap();
    let request = last_request(&store).await;
    assert_eq!(request.manifest, sent(&second), "{out}");
    assert!(out.contains("erp.restart-service v2"), "{out}");

    run_on(&store, ask(device, Some(1))).await.0.unwrap();
    assert_eq!(last_request(&store).await.manifest, sent(&renewed));

    // Nothing of a version whose every envelope has expired.
    let later = at(90 * 24 * 3600 - 3650 + 1);
    let (result, _) = run_at(&store, ask(device, Some(1)), later).await;
    assert_eq!(
        result.unwrap_err(),
        "no envelope of that manifest verifies now against the keys the server trusts"
    );
    let (result, _) = run_on(&store, ask(device, Some(3))).await;
    assert!(result.is_err());
}

/// RF-49, RF-04: an action is asked for an active device only, and waits at most the
/// minutes asked.
#[tokio::test]
async fn action_run_asks_for_an_active_device_only() {
    let store = MemoryStore::new();
    let active = enrolled(&store, 1, 1).await;
    let pending = enrolled(&store, 2, 2).await;
    let revoked = enrolled(&store, 3, 1).await;
    store.revoke_device(revoked).await.unwrap();
    trust(&store, 1).await;
    add(&store, &signed(1, 1, 0)).await.unwrap();

    for (device, expected) in [
        (pending, "the device is pending: approve it first"),
        (revoked, "the device is revoked: it is sent nothing"),
        (DeviceId::new(), "no device with that id"),
    ] {
        let (result, _) = run_on(&store, ask(device, None)).await;
        assert_eq!(result.unwrap_err(), expected);
    }
    assert_eq!(store.requests(None, 10).await.unwrap(), []);

    let (logs, _guard) = Logs::capture();
    run_on(&store, ask(active, None)).await.0.unwrap();
    let request = last_request(&store).await;
    assert_eq!(request.device, active);
    assert_eq!(request.expires_at, epoch(at(0)) + 30 * 60);
    assert_eq!(
        request.initiator,
        ponte_protocol::Initiator::Human {
            user_id: "server_cli".parse().unwrap()
        }
    );
    let logs = logs.text();
    assert!(logs.contains("event=\"action_requested\""), "{logs}");
    assert!(logs.contains("outcome=Done"), "{logs}");
}

/// ADR-0012: what reached the agent is the agent's. `show` gives the size of an output,
/// never its text.
#[tokio::test]
async fn requests_are_shown_listed_and_cancelled_while_queued() {
    let store = MemoryStore::new();
    let device = enrolled(&store, 1, 1).await;
    trust(&store, 1).await;
    add(&store, &signed(1, 1, 0)).await.unwrap();
    run_on(&store, ask(device, None)).await.0.unwrap();
    let queued = last_request(&store).await.id;
    run_on(&store, ask(device, None)).await.0.unwrap();
    let sent = last_request(&store).await.id;

    let (logs, _guard) = Logs::capture();
    let (result, out) = run_on(&store, Command::ActionCancel { request: queued }).await;
    result.unwrap();
    assert_eq!(out, format!("request {queued} cancelled\n"));
    let (result, _) = run_on(&store, Command::ActionCancel { request: queued }).await;
    assert!(result.unwrap_err().starts_with("only a queued request"));
    let (result, _) = run_on(
        &store,
        Command::ActionCancel {
            request: RequestId::new(),
        },
    )
    .await;
    assert_eq!(result.unwrap_err(), "no request with that id");
    assert_eq!(logs.text().matches("action_cancelled").count(), 1);

    // Sent, then answered with an output.
    assert_eq!(store.claim_due(&[device], at(1)).await.unwrap().len(), 1);
    let (result, _) = run_on(&store, Command::ActionCancel { request: sent }).await;
    assert!(result.unwrap_err().starts_with("only a queued request"));
    let answer = ActionResult {
        request_id: sent,
        outcome: ActionOutcome::Rejected {
            reason: RejectReason::ServiceNotAllowed,
        },
        output: Some("SECRET-CUSTOMER-RECORD".parse::<Output>().unwrap()),
        duration_ms: 12,
    };
    store.finish(device, &answer, at(2)).await.unwrap();

    let (_, out) = run_on(&store, Command::ActionShow { request: sent }).await;
    assert!(
        out.contains("status    rejected service_not_allowed"),
        "{out}"
    );
    assert!(out.contains("duration  12 ms"), "{out}");
    assert!(out.contains("output    22 bytes, not shown"), "{out}");
    assert!(out.contains("asked by  server_cli"), "{out}");
    assert!(!out.contains("SECRET"), "{out}");

    let (_, out) = run_on(&store, Command::ActionList { device: None }).await;
    let lines: Vec<_> = out.lines().collect();
    assert_eq!(lines.len(), 2, "{out}");
    assert!(lines[0].starts_with(&sent.to_string()), "{out}");
    assert!(lines[1].contains("cancelled"), "{out}");
    let (_, out) = run_on(
        &store,
        Command::ActionList {
            device: Some(DeviceId::new()),
        },
    )
    .await;
    assert_eq!(out, "");
}

/// ADR-0010: the device's clock offset, from its last heartbeat, is in `device list`.
#[tokio::test]
async fn device_list_shows_the_clock_offset_of_each_device() {
    let store = MemoryStore::new();
    let device = enrolled(&store, 1, 1).await;
    // Collected at `at(0)` by the device's clock, stored at `at(3)` by the server's.
    store.heartbeat(device, &telemetry(1), at(3)).await.unwrap();
    let (_, out) = run_on(&store, Command::DeviceList { customer: None }).await;
    assert!(out.contains("clock -3s"), "{out}");
}
