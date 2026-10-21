use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;

use ponte_protocol::{EnrollmentToken, PublicKey};

use super::*;
use crate::agents::testkit::{Logs, about, at, grant, token};
use crate::agents::{
    ActionStore, CancelOutcome, CatalogEntry, DeviceAdmin, DeviceStatus, DeviceStore,
    EnrollOutcome, EnrollRequest, Finish, KeyAdded, MemoryStore, NewRequest, Outgoing,
    RequestOutcome, RequestRecord, SigningKey,
};

fn args(line: &str) -> Vec<OsString> {
    line.split_whitespace().map(OsString::from).collect()
}

fn parsed(line: &str) -> Result<Command, UsageError> {
    parse(args(line))
}

const CUSTOMER: &str = "0190f2c4-8d3a-7b1e-9c4d-5e6f7a8b9c0d";

/// A path in the temporary directory that nothing uses yet.
fn fresh_path() -> PathBuf {
    std::env::temp_dir().join(format!("ponte-token-{}", Uuid::now_v7()))
}

async fn run_on(store: &MemoryStore, command: Command) -> (Result<(), String>, String) {
    let mut out = Vec::new();
    let result = run(store, command, &mut out, at(0))
        .await
        .map_err(|error| error.to_string());
    (result, String::from_utf8(out).unwrap())
}

async fn customer(store: &MemoryStore) -> CustomerId {
    let name = "Acme Software".parse().unwrap();
    store.add_customer(&name).await.unwrap().unwrap()
}

async fn enrolled(store: &MemoryStore, token_seed: u8, key_seed: u8) -> DeviceId {
    let request = EnrollRequest {
        token: TokenHash::of(&token(token_seed)),
        public_key: PublicKey::from_bytes([key_seed; 32]),
        about: about(),
    };
    match store.enroll(request, at(0)).await.unwrap() {
        EnrollOutcome::Enrolled { device_id, .. } => device_id,
        EnrollOutcome::Refused(refusal) => panic!("{refusal:?}"),
    }
}

#[test]
fn every_command_parses() {
    let customer = CustomerId::from_uuid(Uuid::parse_str(CUSTOMER).unwrap());
    let device = DeviceId::from_uuid(Uuid::parse_str(CUSTOMER).unwrap());
    assert_eq!(parse(Vec::new()), Ok(Command::Serve));
    assert_eq!(parsed("--help"), Ok(Command::Help));
    assert_eq!(parsed("migrate"), Ok(Command::Migrate));
    assert_eq!(
        parse([
            OsString::from("customer"),
            OsString::from("create"),
            OsString::from("Padaria São João")
        ]),
        Ok(Command::CustomerCreate {
            name: "Padaria São João".parse().unwrap()
        })
    );
    assert_eq!(parsed("customer list"), Ok(Command::CustomerList));
    assert_eq!(
        parsed(&format!("token create {CUSTOMER} --out t.txt")),
        Ok(Command::TokenCreate {
            customer,
            out: PathBuf::from("t.txt"),
            uses: NonZeroU32::MIN,
            hours: 24,
        })
    );
    assert_eq!(
        parsed(&format!(
            "token create {CUSTOMER} --hours 720 --uses 10000 --out t.txt"
        )),
        Ok(Command::TokenCreate {
            customer,
            out: PathBuf::from("t.txt"),
            uses: NonZeroU32::new(10_000).unwrap(),
            hours: 720,
        })
    );
    assert_eq!(
        parsed("token list"),
        Ok(Command::TokenList { customer: None })
    );
    assert_eq!(
        parsed(&format!("token list {CUSTOMER}")),
        Ok(Command::TokenList {
            customer: Some(customer)
        })
    );
    assert_eq!(
        parsed("token revoke 66687aadf862bd77"),
        Ok(Command::TokenRevoke {
            prefix: [0x66, 0x68, 0x7a, 0xad, 0xf8, 0x62, 0xbd, 0x77]
        })
    );
    assert_eq!(
        parsed(&format!("device list {CUSTOMER}")),
        Ok(Command::DeviceList {
            customer: Some(customer)
        })
    );
    assert_eq!(
        parsed(&format!("device approve {CUSTOMER}")),
        Ok(Command::DeviceApprove { device })
    );
    assert_eq!(
        parsed(&format!("device revoke {CUSTOMER}")),
        Ok(Command::DeviceRevoke { device })
    );
}

/// A command that is not exactly one of the usage does nothing: no guessing, no default
/// that turns a typo into a token for a hundred machines.
#[test]
fn anything_else_is_refused() {
    let upper = CUSTOMER.to_uppercase();
    for line in [
        "serve",
        "customer",
        "customer create",
        "customer delete x",
        "migrate now",
        &format!("token create {CUSTOMER}"),
        &format!("token create {CUSTOMER} --out"),
        &format!("token create {CUSTOMER} --out a --out b"),
        &format!("token create {CUSTOMER} --out a --uses 0"),
        &format!("token create {CUSTOMER} --out a --uses 10001"),
        &format!("token create {CUSTOMER} --out a --uses -1"),
        &format!("token create {CUSTOMER} --out a --hours 0"),
        &format!("token create {CUSTOMER} --out a --hours 721"),
        &format!("token create {CUSTOMER} --out a --force yes"),
        &format!("token create {upper} --out a"),
        "token create not-a-uuid --out a",
        &format!("token list {CUSTOMER} {CUSTOMER}"),
        "token revoke 66687AADF862BD77",
        "token revoke 66687aadf862bd7",
        "token revoke 66687aadf862bd770",
        "token revoke 66687aadf862bd7g",
        "device approve",
        "device approve 1234",
        &format!("device revoke {CUSTOMER} now"),
    ] {
        assert!(parsed(line).is_err(), "{line}");
    }
    let empty_name = [
        OsString::from("customer"),
        OsString::from("create"),
        OsString::from(" "),
    ];
    assert_eq!(parse(empty_name), Err(UsageError::Invalid("customer name")));
}

/// The token goes to its file and nowhere else: not to the output, not to the log. The
/// file holds exactly what the agent reads, and the store holds its hash.
#[tokio::test]
async fn a_token_is_written_to_a_new_file_only() {
    let store = MemoryStore::new();
    let customer = customer(&store).await;
    let path = fresh_path();
    let (logs, _guard) = Logs::capture();

    let command = Command::TokenCreate {
        customer,
        out: path.clone(),
        uses: NonZeroU32::new(3).unwrap(),
        hours: 48,
    };
    let (result, out) = run_on(&store, command).await;
    result.unwrap();

    let written = fs::read_to_string(&path).unwrap();
    fs::remove_file(&path).unwrap();
    let hex = written.strip_suffix('\n').unwrap();
    assert_eq!(hex.len(), 64);
    let token: EnrollmentToken = hex.parse().unwrap();
    let hash = TokenHash::of(&token);

    let info = store.token(&hash).await.unwrap().unwrap();
    assert_eq!(info.grant.customer, customer);
    assert_eq!(info.grant.max_uses.get(), 3);
    assert_eq!(info.grant.expires_at, at(48 * 60 * 60));
    assert_eq!(info.uses, 0);

    let logs = logs.text();
    for shown in [&out, &logs] {
        assert!(!shown.contains(hex), "the token: {shown}");
        assert!(!shown.contains(&hex[..16]), "part of the token: {shown}");
    }
    assert!(out.contains(&hash.short()), "{out}");
    assert!(logs.contains("token_issued"), "{logs}");
    assert!(logs.contains("actor=\"server_cli\""), "{logs}");
    assert!(logs.contains(&hash.short()), "{logs}");

    // Two tokens are never the same.
    let again = Command::TokenCreate {
        customer,
        out: path.clone(),
        uses: NonZeroU32::MIN,
        hours: 1,
    };
    run_on(&store, again).await.0.unwrap();
    let second = fs::read_to_string(&path).unwrap();
    fs::remove_file(&path).unwrap();
    assert_ne!(second, written);
}

#[tokio::test]
async fn an_existing_file_is_never_overwritten() {
    let store = MemoryStore::new();
    let customer = customer(&store).await;
    let path = fresh_path();
    fs::write(&path, "the agent's own file").unwrap();

    let command = Command::TokenCreate {
        customer,
        out: path.clone(),
        uses: NonZeroU32::MIN,
        hours: 1,
    };
    let (result, out) = run_on(&store, command).await;
    assert!(result.unwrap_err().contains("token file"));
    assert_eq!(out, "");
    assert_eq!(fs::read_to_string(&path).unwrap(), "the agent's own file");
    fs::remove_file(&path).unwrap();
    assert!(store.tokens(None).await.unwrap().is_empty());
}

/// A token the store did not take enrolls nobody, and is not left on disk either.
#[tokio::test]
async fn a_token_for_a_customer_that_does_not_exist_leaves_no_file() {
    let store = MemoryStore::new();
    let path = fresh_path();
    let command = Command::TokenCreate {
        customer: CustomerId::new(),
        out: path.clone(),
        uses: NonZeroU32::MIN,
        hours: 1,
    };
    let (result, _) = run_on(&store, command).await;
    assert_eq!(result.unwrap_err(), "no customer with that id");
    assert!(!path.exists());
    assert!(store.tokens(None).await.unwrap().is_empty());
}

#[tokio::test]
async fn a_token_is_revoked_by_the_prefix_of_its_hash() {
    let store = MemoryStore::new();
    store.add_token(&token(1), grant(1));
    store.add_token(&token(2), grant(1));
    let hash = TokenHash::of(&token(1));
    let mut prefix = [0; 8];
    prefix.copy_from_slice(&hash.as_bytes()[..8]);
    let (logs, _guard) = Logs::capture();

    let (result, out) = run_on(&store, Command::TokenRevoke { prefix }).await;
    result.unwrap();
    assert!(out.contains(&hash.short()), "{out}");
    assert!(store.token(&hash).await.unwrap().unwrap().revoked);
    let other = TokenHash::of(&token(2));
    assert!(!store.token(&other).await.unwrap().unwrap().revoked);
    assert!(logs.text().contains("token_revoked"), "{}", logs.text());

    let nobody = Command::TokenRevoke { prefix: [0; 8] };
    assert_eq!(
        run_on(&store, nobody).await.0.unwrap_err(),
        "no token starts with that prefix"
    );
}

#[tokio::test]
async fn devices_are_approved_and_revoked_by_id() {
    let store = MemoryStore::new();
    store.add_token(&token(1), grant(2));
    let device = enrolled(&store, 1, 10).await;
    let (logs, _guard) = Logs::capture();

    let (result, _) = run_on(&store, Command::DeviceApprove { device }).await;
    result.unwrap();
    assert_eq!(store.record(device).unwrap().status, DeviceStatus::Active);
    let (result, _) = run_on(&store, Command::DeviceApprove { device }).await;
    assert_eq!(
        result.unwrap_err(),
        "the device is not pending: only a pending device can be approved"
    );

    let (result, _) = run_on(&store, Command::DeviceRevoke { device }).await;
    result.unwrap();
    assert_eq!(store.record(device).unwrap().status, DeviceStatus::Revoked);

    let unknown = DeviceId::new();
    for command in [
        Command::DeviceApprove { device: unknown },
        Command::DeviceRevoke { device: unknown },
    ] {
        let (result, _) = run_on(&store, command).await;
        assert_eq!(result.unwrap_err(), "no device with that id");
    }

    let logs = logs.text();
    assert_eq!(logs.matches("device_approved").count(), 1, "{logs}");
    assert_eq!(logs.matches("device_revoked").count(), 1, "{logs}");
}

#[tokio::test]
async fn lists_show_one_line_per_item() {
    let store = MemoryStore::new();
    let (result, out) = run_on(
        &store,
        Command::CustomerCreate {
            name: "Acme Software".parse().unwrap(),
        },
    )
    .await;
    result.unwrap();
    let customer = CustomerId::from_uuid(Uuid::parse_str(out.trim()).unwrap());
    let (result, _) = run_on(
        &store,
        Command::CustomerCreate {
            name: "Acme Software".parse().unwrap(),
        },
    )
    .await;
    assert_eq!(
        result.unwrap_err(),
        "a customer with that name already exists"
    );

    let (_, out) = run_on(&store, Command::CustomerList).await;
    assert_eq!(out, format!("{customer}  Acme Software\n"));

    store.add_token(&token(1), grant(2));
    let device = enrolled(&store, 1, 10).await;
    let (_, out) = run_on(&store, Command::DeviceList { customer: None }).await;
    assert_eq!(out.lines().count(), 1, "{out}");
    assert!(out.starts_with(&device.to_string()), "{out}");
    assert!(
        out.contains(
            "pending  offline  last seen never  clock unknown  agent 0.1.0  Windows 11 Pro"
        ),
        "{out}"
    );
    let (_, out) = run_on(&store, Command::TokenList { customer: None }).await;
    assert!(out.contains("1/2 used"), "{out}");
    assert!(out.ends_with("valid\n"), "{out}");
}

/// A store whose every call fails, the way a database does when its answer is lost after
/// it committed: nobody can tell whether the change happened.
struct Down;

#[derive(Debug, thiserror::Error)]
#[error("the store is down")]
struct DownError;

impl DeviceStore for Down {
    type Error = DownError;

    async fn enroll(&self, _: EnrollRequest, _: DateTime<Utc>) -> Result<EnrollOutcome, DownError> {
        Err(DownError)
    }

    async fn device(&self, _: DeviceId) -> Result<Option<crate::agents::Device>, DownError> {
        Err(DownError)
    }

    async fn session_started(
        &self,
        _: DeviceId,
        _: crate::agents::SessionId,
        _: &crate::agents::AgentInfo,
        _: DateTime<Utc>,
    ) -> Result<Option<DeviceStatus>, DownError> {
        Err(DownError)
    }

    async fn heartbeat(
        &self,
        _: DeviceId,
        _: &ponte_protocol::TelemetrySnapshot,
        _: DateTime<Utc>,
    ) -> Result<Option<DeviceStatus>, DownError> {
        Err(DownError)
    }

    async fn session_ended(
        &self,
        _: DeviceId,
        _: crate::agents::SessionId,
        _: DateTime<Utc>,
    ) -> Result<(), DownError> {
        Err(DownError)
    }
}

impl DeviceAdmin for Down {
    async fn add_customer(&self, _: &CustomerName) -> Result<Option<CustomerId>, DownError> {
        Err(DownError)
    }

    async fn customers(&self) -> Result<Vec<crate::agents::Customer>, DownError> {
        Err(DownError)
    }

    async fn issue_token(&self, _: TokenHash, _: TokenGrant) -> Result<bool, DownError> {
        Err(DownError)
    }

    async fn revoke_token(&self, _: &TokenHash) -> Result<bool, DownError> {
        Err(DownError)
    }

    async fn token(&self, _: &TokenHash) -> Result<Option<TokenInfo>, DownError> {
        Err(DownError)
    }

    async fn tokens(&self, _: Option<CustomerId>) -> Result<Vec<TokenInfo>, DownError> {
        Err(DownError)
    }

    async fn approve_device(&self, _: DeviceId) -> Result<bool, DownError> {
        Err(DownError)
    }

    async fn revoke_device(&self, _: DeviceId) -> Result<bool, DownError> {
        Err(DownError)
    }

    async fn device_record(&self, _: DeviceId) -> Result<Option<DeviceRecord>, DownError> {
        Err(DownError)
    }

    async fn devices(&self, _: Option<CustomerId>) -> Result<Vec<DeviceRecord>, DownError> {
        Err(DownError)
    }
}

impl ActionStore for Down {
    async fn claim_due(
        &self,
        _: &[DeviceId],
        _: DateTime<Utc>,
    ) -> Result<Vec<Outgoing>, DownError> {
        Err(DownError)
    }

    async fn release(&self, _: RequestId) -> Result<bool, DownError> {
        Err(DownError)
    }

    async fn unanswered(&self, _: DeviceId, _: DateTime<Utc>) -> Result<Vec<Outgoing>, DownError> {
        Err(DownError)
    }

    async fn finish(
        &self,
        _: DeviceId,
        _: &ponte_protocol::ActionResult,
        _: DateTime<Utc>,
    ) -> Result<Finish, DownError> {
        Err(DownError)
    }

    async fn expire(&self, _: DateTime<Utc>) -> Result<Vec<(RequestId, DeviceId)>, DownError> {
        Err(DownError)
    }
}

impl ActionAdmin for Down {
    async fn add_signing_key(&self, _: PublicKey, _: DateTime<Utc>) -> Result<KeyAdded, DownError> {
        Err(DownError)
    }

    async fn remove_signing_key(&self, _: &PublicKey) -> Result<bool, DownError> {
        Err(DownError)
    }

    async fn signing_keys(&self) -> Result<Vec<SigningKey>, DownError> {
        Err(DownError)
    }

    async fn add_manifest(&self, _: &CatalogEntry, _: DateTime<Utc>) -> Result<bool, DownError> {
        Err(DownError)
    }

    async fn manifests(&self, _: Option<&ManifestId>) -> Result<Vec<CatalogEntry>, DownError> {
        Err(DownError)
    }

    async fn request_action(
        &self,
        _: &NewRequest,
        _: DateTime<Utc>,
    ) -> Result<RequestOutcome, DownError> {
        Err(DownError)
    }

    async fn request(&self, _: RequestId) -> Result<Option<RequestRecord>, DownError> {
        Err(DownError)
    }

    async fn requests(
        &self,
        _: Option<DeviceId>,
        _: usize,
    ) -> Result<Vec<RequestRecord>, DownError> {
        Err(DownError)
    }

    async fn cancel(&self, _: RequestId, _: DateTime<Utc>) -> Result<CancelOutcome, DownError> {
        Err(DownError)
    }
}

/// RF-40: a change that may have happened is audited as one, with its outcome unknown.
/// Otherwise a lost answer leaves an approval, a revocation or a token with no record.
#[tokio::test]
async fn a_change_whose_outcome_is_unknown_is_still_audited() {
    let (logs, _guard) = Logs::capture();
    let device = DeviceId::new();
    let path = fresh_path();
    for command in [
        Command::CustomerCreate {
            name: "Acme Software".parse().unwrap(),
        },
        Command::TokenCreate {
            customer: CustomerId::new(),
            out: path.clone(),
            uses: NonZeroU32::MIN,
            hours: 1,
        },
        Command::DeviceApprove { device },
        Command::DeviceRevoke { device },
        Command::CatalogKeyRemove {
            key: PublicKey::from_bytes([1; 32]),
        },
        Command::ActionCancel {
            request: RequestId::new(),
        },
    ] {
        let mut out = Vec::new();
        let failed = run(&Down, command, &mut out, at(0)).await;
        assert!(failed.is_err());
        assert!(out.is_empty());
    }
    assert!(!path.exists());

    let logs = logs.text();
    for event in [
        "customer_added",
        "token_issued",
        "device_approved",
        "device_revoked",
        "signing_key_removed",
        "action_cancelled",
    ] {
        let line = logs
            .lines()
            .find(|line| line.contains(event))
            .unwrap_or_else(|| panic!("{event} not audited: {logs}"));
        assert!(line.contains("outcome=Unknown"), "{line}");
    }
}
