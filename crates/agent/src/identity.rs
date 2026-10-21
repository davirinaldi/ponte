//! Who this device is: its key, the id the server gave it, and the token that buys both
//! (ADR-0008).
//!
//! Three things rest on disk:
//!
//! | What | Where | When |
//! |---|---|---|
//! | the private key | `device.key`, through `platform::keystore` | before anything is sent |
//! | the record | `identity.toml` | `enrolling` with the key, `enrolled` with the id |
//! | the token | the file the configuration names | written by the installer, removed by the agent |
//!
//! The order of the writes is the point of this module:
//!
//! 1. A new key and its `enrolling` record are on disk **before** the key is shown to the
//!    server. If the answer is lost, the agent enrolls again with the same key and the same
//!    token and the server gives the same device back, as long as the token is still good
//!    on the server. Past its deadline, or once it is revoked, the repeat is refused too and
//!    the machine needs a new token, which means a new key and a new device. A key the server stored and the
//!    agent forgot would be a device nobody can connect as, and a spent token.
//! 2. The `enrolled` record is on disk **before** the token file is removed. Until then the
//!    token is the only way to be told the id again.
//!
//! The record names the public key it belongs to, and the fingerprint of the token it was
//! made with. A key and a record that do not match are no identity at all, whatever order
//! a crash left them in. A token with another fingerprint is another enrollment and gets a
//! new key: the old one may already be stored on the server under the old token, and a key
//! enrolls once.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signer, SigningKey};
use ponte_protocol::{
    DeviceId, EnrollmentToken, Nonce, ProtocolVersion, PublicKey, Signature, enroll_transcript,
    hello_transcript,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use sha2::{Digest, Sha256};
use tracing::{error, info, warn};

use crate::platform::{self, keystore};

/// The device's private key. It signs the two handshake transcripts of `ponte_protocol`
/// and nothing else: there is no method here that takes bytes to sign, so no message from
/// the server can be turned into a signature over something of its choosing.
///
/// The key wipes itself when dropped, and lives behind a `Box` so that moving a
/// `DeviceKey` around does not copy it (ADR-0013). The signing key type implements
/// `Clone`: never clone it.
pub(crate) struct DeviceKey(Box<SigningKey>);

impl DeviceKey {
    fn generate() -> Result<Self, IdentityError> {
        let mut secret = keystore::Secret::default();
        getrandom::fill(secret.as_mut_slice()).map_err(|_| IdentityError::NoRandomBytes)?;
        Ok(Self::from_secret(&secret))
    }

    pub(crate) fn from_secret(secret: &[u8; 32]) -> Self {
        Self(Box::new(SigningKey::from_bytes(secret)))
    }

    /// The private half, to store it, wiped when dropped. Never log it.
    fn expose_secret(&self) -> keystore::Secret {
        keystore::Secret::new(self.0.to_bytes())
    }

    pub(crate) fn public_key(&self) -> PublicKey {
        PublicKey::from_bytes(self.0.verifying_key().to_bytes())
    }

    /// The `signature` of `Hello`, for a connection that negotiated `version`.
    pub(crate) fn sign_hello(
        &self,
        version: ProtocolVersion,
        nonce: &Nonce,
        device_id: DeviceId,
    ) -> Signature {
        let transcript = hello_transcript(version, nonce, device_id);
        Signature::from_bytes(self.0.sign(transcript.expose_bytes()).to_bytes())
    }

    /// The `signature` of `Enroll`, for a connection that negotiated `version`.
    pub(crate) fn sign_enroll(
        &self,
        version: ProtocolVersion,
        nonce: &Nonce,
        token: &EnrollmentToken,
    ) -> Signature {
        let transcript = enroll_transcript(version, nonce, token, &self.public_key());
        Signature::from_bytes(self.0.sign(transcript.expose_bytes()).to_bytes())
    }
}

impl fmt::Debug for DeviceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceKey({})", self.public_key())
    }
}

/// SHA-256 of an enrollment token: enough to tell whether a token file still holds the
/// token an enrollment was started with, and of no use to enroll.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct TokenFingerprint([u8; 32]);

impl TokenFingerprint {
    pub(crate) fn of(token: &EnrollmentToken) -> Self {
        Self(Sha256::digest(token.expose_secret()).into())
    }
}

impl fmt::Debug for TokenFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TokenFingerprint(..)")
    }
}

impl Serialize for TokenFingerprint {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let hex: String = self.0.iter().map(|byte| format!("{byte:02x}")).collect();
        serializer.serialize_str(&hex)
    }
}

impl<'de> Deserialize<'de> for TokenFingerprint {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let hex = String::deserialize(deserializer)?;
        let invalid = || de::Error::custom("expected 64 lowercase hex characters");
        let lowercase_hex = |byte: u8| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte);
        if hex.len() != 64 || !hex.bytes().all(lowercase_hex) {
            return Err(invalid());
        }
        let mut bytes = [0; 32];
        for (byte, pair) in bytes.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
            let pair = std::str::from_utf8(pair).map_err(|_| invalid())?;
            *byte = u8::from_str_radix(pair, 16).map_err(|_| invalid())?;
        }
        Ok(Self(bytes))
    }
}

/// What `identity.toml` holds. Unknown fields and unknown states are refused: a record
/// this build cannot read in full is not an identity it may use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum Record {
    /// The key was generated for the token with this fingerprint. Whether the server has
    /// stored it is not known.
    Enrolling {
        public_key: PublicKey,
        token_sha256: TokenFingerprint,
    },
    Enrolled {
        device_id: DeviceId,
        public_key: PublicKey,
        token_sha256: TokenFingerprint,
    },
}

/// What the agent answers the next challenge with.
#[derive(Debug)]
pub(crate) enum Credentials {
    Enrolled {
        key: DeviceKey,
        device_id: DeviceId,
    },
    /// Not enrolled yet, or not told so. The key and its record are already on disk.
    Enrolling {
        key: DeviceKey,
        token: EnrollmentToken,
    },
}

impl Credentials {
    /// What to keep if the server answers this with `Enrolled`. `None` for a device that
    /// is enrolled already: nothing the server says then changes who it is.
    pub(crate) fn enrollment(&self) -> Option<Enrollment> {
        match self {
            Self::Enrolled { .. } => None,
            Self::Enrolling { key, token } => Some(Enrollment {
                public_key: key.public_key(),
                token: TokenFingerprint::of(token),
            }),
        }
    }
}

/// An enrollment that was sent and not answered yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Enrollment {
    public_key: PublicKey,
    token: TokenFingerprint,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum IdentityError {
    #[error("cannot {0}: {1}")]
    Disk(&'static str, #[source] io::Error),
    #[error("the operating system gave no random bytes for a device key")]
    NoRandomBytes,
    #[error("the identity record cannot be written as text")]
    Encode,
}

/// The files an identity rests on. A trait so that the order of the writes, and what is
/// left after any of them fails, can be tested without a disk.
pub(crate) trait Disk: Send + Sync + 'static {
    /// `None` if there is no key, and `InvalidData` if what is there is not one.
    fn read_key(&self) -> io::Result<Option<keystore::Secret>>;
    fn write_key(&self, secret: &[u8; 32]) -> io::Result<()>;
    /// `None` if there is no record, and `InvalidData` if what is there cannot be one.
    fn read_record(&self) -> io::Result<Option<String>>;
    fn write_record(&self, record: &str) -> io::Result<()>;
    /// `None` if there is no token file, and `InvalidData` if what is there cannot be one.
    fn read_token(&self) -> io::Result<Option<String>>;
    fn remove_token(&self) -> io::Result<()>;
}

/// The identity of this device, on `D`.
pub(crate) struct IdentityStore<D> {
    disk: D,
}

impl<D: Disk> IdentityStore<D> {
    pub(crate) fn new(disk: D) -> Self {
        Self { disk }
    }

    /// What to answer the next challenge with, or `None` if this machine has neither an
    /// identity nor a token to get one. Starting an enrollment writes the new key and its
    /// record before returning, so whatever comes back is already on disk.
    pub(crate) fn credentials(&self) -> Result<Option<Credentials>, IdentityError> {
        let key = match self.disk.read_key() {
            Ok(secret) => secret.map(|secret| DeviceKey::from_secret(&secret)),
            Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                error!("the device key file does not hold a key: it is ignored");
                None
            }
            // A key that is there and cannot be read is still this device's key. Going
            // on would end in enrolling again, on top of it.
            Err(error) => return Err(IdentityError::Disk("read the device key", error)),
        };
        let record = match self.disk.read_record() {
            Ok(Some(text)) => toml::from_str::<Record>(&text)
                // Not the error's text: it quotes the file.
                .inspect_err(|_| error!("the identity record cannot be read: it is ignored"))
                .ok(),
            Ok(None) => None,
            Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                error!("the identity record cannot be read: it is ignored");
                None
            }
            Err(error) => return Err(IdentityError::Disk("read the identity record", error)),
        };

        match (key, record) {
            (
                Some(key),
                Some(Record::Enrolled {
                    device_id,
                    public_key,
                    token_sha256,
                }),
            ) if key.public_key() == public_key => {
                self.leftover_token(token_sha256);
                Ok(Some(Credentials::Enrolled { key, device_id }))
            }
            (
                Some(key),
                Some(Record::Enrolling {
                    public_key,
                    token_sha256,
                }),
            ) if key.public_key() == public_key => match self.token()? {
                Some(token) if TokenFingerprint::of(&token) == token_sha256 => {
                    Ok(Some(Credentials::Enrolling { key, token }))
                }
                // Another token is another enrollment, and that takes another key.
                Some(token) => self.begin(token).map(Some),
                // The key may be stored on the server already. Without its token it
                // cannot be presented, and it is not thrown away either.
                None => Ok(None),
            },
            // No key, no record, or two that are not about each other: not an identity.
            (key, record) => {
                if key.is_some() || record.is_some() {
                    warn!(
                        key = key.is_some(),
                        record = record.is_some(),
                        "the device key and the identity record do not belong together: \
                         this machine has no identity"
                    );
                }
                self.token()?.map(|token| self.begin(token)).transpose()
            }
        }
    }

    /// Keeps the id the server answered `enrollment` with, then removes the token file.
    pub(crate) fn enrolled(
        &self,
        enrollment: &Enrollment,
        device_id: DeviceId,
    ) -> Result<(), IdentityError> {
        self.write_record(&Record::Enrolled {
            device_id,
            public_key: enrollment.public_key,
            token_sha256: enrollment.token,
        })?;
        // Only now: until the id is on disk, the token is the only way to be told it again.
        // And only the token this enrollment was made with. One that arrived in the
        // meantime is somebody else's decision.
        self.leftover_token(enrollment.token);
        Ok(())
    }

    /// Starts an enrollment with `token`: a new key, stored with its record before it is
    /// handed out.
    fn begin(&self, token: EnrollmentToken) -> Result<Credentials, IdentityError> {
        let key = DeviceKey::generate()?;
        let written = self.disk.write_key(&key.expose_secret());
        written.map_err(|error| IdentityError::Disk("write the device key", error))?;
        self.write_record(&Record::Enrolling {
            public_key: key.public_key(),
            token_sha256: TokenFingerprint::of(&token),
        })?;
        info!(public_key = %key.public_key(), "new device key stored for an enrollment");
        Ok(Credentials::Enrolling { key, token })
    }

    fn write_record(&self, record: &Record) -> Result<(), IdentityError> {
        let text = toml::to_string(record).map_err(|_| IdentityError::Encode)?;
        self.disk
            .write_record(&text)
            .map_err(|error| IdentityError::Disk("write the identity record", error))
    }

    /// The token in the token file, if there is a file and it holds one.
    fn token(&self) -> Result<Option<EnrollmentToken>, IdentityError> {
        let text = match self.disk.read_token() {
            Ok(Some(text)) => text,
            Ok(None) => return Ok(None),
            Err(error) if error.kind() == io::ErrorKind::InvalidData => String::new(),
            Err(error) => return Err(IdentityError::Disk("read the enrollment token", error)),
        };
        // One token, and the line ending an editor or `echo` leaves after it. Nothing
        // else is trimmed: a token has one spelling.
        let token = text
            .trim_end_matches(['\r', '\n'])
            .parse()
            // Not the error and not the text: this may be most of a token.
            .inspect_err(|_| {
                error!(
                    "the enrollment token file does not hold a token (64 lowercase hex \
                     characters): it is ignored"
                );
            })
            .ok();
        Ok(token)
    }

    /// An enrolled device has no use for a token. The one it enrolled with is removed,
    /// which is the step a crash right after enrolling left undone. Any other is somebody
    /// else's decision and stays where it is.
    fn leftover_token(&self, enrolled_with: TokenFingerprint) {
        match self.token() {
            Ok(Some(token)) if TokenFingerprint::of(&token) == enrolled_with => {
                self.remove_token();
            }
            Ok(Some(_)) => warn!(
                "an enrollment token is waiting, and this device is already enrolled: the \
                 token is ignored. To enroll as a new device, remove the agent's data \
                 directory"
            ),
            Ok(None) => {}
            Err(error) => warn!(%error, "the enrollment token file could not be looked at"),
        }
    }

    fn remove_token(&self) {
        match self.disk.remove_token() {
            Ok(()) => info!("enrollment token file removed: the device is enrolled"),
            Err(error) => warn!(
                %error,
                "the enrollment token file could not be removed; it is tried again when the \
                 agent next connects"
            ),
        }
    }
}

/// The agent's data directory, and the token file wherever the configuration put it.
pub(crate) struct DataDir {
    key: PathBuf,
    record: PathBuf,
    token: Option<PathBuf>,
}

/// The record is three short lines.
const MAX_RECORD_BYTES: usize = 4 * 1024;
/// A token is 64 characters. The rest is room for the line ending an editor adds.
const MAX_TOKEN_FILE_BYTES: usize = 128;

impl DataDir {
    pub(crate) fn new(dir: &Path, token_file: Option<&Path>) -> Self {
        Self {
            key: dir.join("device.key"),
            record: dir.join("identity.toml"),
            token: token_file.map(Path::to_owned),
        }
    }
}

fn text(bytes: Option<Vec<u8>>) -> io::Result<Option<String>> {
    bytes
        .map(|bytes| String::from_utf8(bytes).map_err(|_| io::ErrorKind::InvalidData.into()))
        .transpose()
}

impl Disk for DataDir {
    fn read_key(&self) -> io::Result<Option<keystore::Secret>> {
        keystore::load(&self.key)
    }

    fn write_key(&self, secret: &[u8; 32]) -> io::Result<()> {
        keystore::save(&self.key, secret)
    }

    fn read_record(&self) -> io::Result<Option<String>> {
        text(platform::read_bounded(&self.record, MAX_RECORD_BYTES)?)
    }

    fn write_record(&self, record: &str) -> io::Result<()> {
        platform::write_private(&self.record, record.as_bytes())
    }

    fn read_token(&self) -> io::Result<Option<String>> {
        let Some(token) = &self.token else {
            return Ok(None);
        };
        text(platform::read_bounded(token, MAX_TOKEN_FILE_BYTES)?)
    }

    fn remove_token(&self) -> io::Result<()> {
        let Some(token) = &self.token else {
            return Ok(());
        };
        platform::remove_file(token)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use ed25519_dalek::VerifyingKey;

    use super::*;
    use crate::testkit::TempDir;

    fn token(seed: u8) -> EnrollmentToken {
        EnrollmentToken::from_bytes([seed; 32])
    }

    fn device_id() -> DeviceId {
        serde_json::from_str("\"00112233-4455-6677-8899-aabbccddeeff\"").unwrap()
    }

    fn version() -> ProtocolVersion {
        ProtocolVersion::supported().next().unwrap()
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Write {
        Key,
        Record,
        RemoveToken,
    }

    #[derive(Default)]
    struct Files {
        key: Option<Vec<u8>>,
        record: Option<String>,
        token: Option<String>,
        /// Every write, in order, whether or not it went through.
        writes: Vec<Write>,
        /// How many more writes go through. After that the disk fails, as if the machine
        /// had lost power there.
        writes_left: Option<usize>,
        key_unreadable: bool,
    }

    /// A disk in memory that remembers the order of what was written to it.
    #[derive(Clone, Default)]
    struct FakeDisk(Arc<Mutex<Files>>);

    impl FakeDisk {
        fn with_token(seed: u8) -> Self {
            let disk = Self::default();
            disk.put_token(&token(seed).expose_hex());
            disk
        }

        fn files(&self) -> std::sync::MutexGuard<'_, Files> {
            self.0.lock().unwrap()
        }

        fn put_token(&self, text: &str) {
            self.files().token = Some(text.to_owned());
        }

        fn fail_after(&self, writes: usize) {
            self.files().writes_left = Some(writes);
        }

        fn works_again(&self) {
            self.files().writes_left = None;
        }

        fn writes(&self) -> Vec<Write> {
            self.files().writes.clone()
        }

        fn record(&self) -> Option<Record> {
            let text = self.files().record.clone()?;
            Some(toml::from_str(&text).unwrap())
        }

        /// The public half of the key on disk.
        fn public_key(&self) -> Option<PublicKey> {
            let key = self.files().key.clone()?;
            let secret = <[u8; 32]>::try_from(key.as_slice()).unwrap();
            Some(DeviceKey::from_secret(&secret).public_key())
        }

        fn write(&self, write: Write, apply: impl FnOnce(&mut Files)) -> io::Result<()> {
            let mut files = self.files();
            files.writes.push(write);
            match &mut files.writes_left {
                Some(0) => return Err(io::Error::other("the disk is gone")),
                Some(left) => *left -= 1,
                None => {}
            }
            apply(&mut files);
            Ok(())
        }
    }

    impl Disk for FakeDisk {
        fn read_key(&self) -> io::Result<Option<keystore::Secret>> {
            let files = self.files();
            if files.key_unreadable {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            files
                .key
                .as_deref()
                .map(|key| {
                    <[u8; 32]>::try_from(key)
                        .map(keystore::Secret::new)
                        .map_err(|_| io::ErrorKind::InvalidData.into())
                })
                .transpose()
        }

        fn write_key(&self, secret: &[u8; 32]) -> io::Result<()> {
            self.write(Write::Key, |files| files.key = Some(secret.to_vec()))
        }

        fn read_record(&self) -> io::Result<Option<String>> {
            Ok(self.files().record.clone())
        }

        fn write_record(&self, record: &str) -> io::Result<()> {
            self.write(Write::Record, |files| {
                files.record = Some(record.to_owned());
            })
        }

        fn read_token(&self) -> io::Result<Option<String>> {
            Ok(self.files().token.clone())
        }

        fn remove_token(&self) -> io::Result<()> {
            self.write(Write::RemoveToken, |files| files.token = None)
        }
    }

    fn store(disk: &FakeDisk) -> IdentityStore<FakeDisk> {
        IdentityStore::new(disk.clone())
    }

    /// The key of credentials that are expected to be an enrollment.
    fn enrolling(credentials: Option<Credentials>) -> (PublicKey, EnrollmentToken) {
        match credentials {
            Some(Credentials::Enrolling { key, token }) => (key.public_key(), token),
            other => panic!("expected an enrollment, got {other:?}"),
        }
    }

    fn enrolled(credentials: Option<Credentials>) -> (PublicKey, DeviceId) {
        match credentials {
            Some(Credentials::Enrolled { key, device_id }) => (key.public_key(), device_id),
            other => panic!("expected an enrolled device, got {other:?}"),
        }
    }

    /// Enrolls on `disk` all the way and returns the key it enrolled with.
    fn enroll(disk: &FakeDisk) -> PublicKey {
        let credentials = store(disk).credentials().unwrap().unwrap();
        let enrollment = credentials.enrollment().unwrap();
        store(disk).enrolled(&enrollment, device_id()).unwrap();
        enrollment.public_key
    }

    // What the key signs.

    fn verifies(key: &PublicKey, bytes: &[u8], signature: &Signature) -> bool {
        let key = VerifyingKey::from_bytes(key.as_bytes()).unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(signature.as_bytes());
        key.verify_strict(bytes, &signature).is_ok()
    }

    #[test]
    fn the_key_signs_the_two_transcripts_of_the_protocol() {
        let key = DeviceKey::from_secret(&[7; 32]);
        let public_key = key.public_key();
        let nonce = Nonce::from_bytes([1; 32]);

        let hello = hello_transcript(version(), &nonce, device_id());
        let enroll = enroll_transcript(version(), &nonce, &token(2), &public_key);

        let signature = key.sign_hello(version(), &nonce, device_id());
        assert!(verifies(&public_key, hello.expose_bytes(), &signature));
        assert!(!verifies(&public_key, enroll.expose_bytes(), &signature));

        let signature = key.sign_enroll(version(), &nonce, &token(2));
        assert!(verifies(&public_key, enroll.expose_bytes(), &signature));
        assert!(!verifies(&public_key, hello.expose_bytes(), &signature));

        // Every input is the one that was given, not a neighbour.
        let other_nonce = Nonce::from_bytes([9; 32]);
        let signature = key.sign_hello(version(), &other_nonce, device_id());
        assert!(!verifies(&public_key, hello.expose_bytes(), &signature));
        let signature = key.sign_enroll(version(), &nonce, &token(3));
        assert!(!verifies(&public_key, enroll.expose_bytes(), &signature));
    }

    #[test]
    fn a_generated_key_is_new_every_time() {
        let first = DeviceKey::generate().unwrap();
        let second = DeviceKey::generate().unwrap();
        assert_ne!(first.public_key(), second.public_key());
        assert_ne!(*first.expose_secret(), [0; 32]);
    }

    /// A key ends up in a `{:?}` sooner or later. Only its public half may show.
    #[test]
    fn debug_of_a_key_and_of_credentials_shows_no_secret() {
        let secret = [0xab; 32];
        let key = DeviceKey::from_secret(&secret);
        let public_key = key.public_key().to_string();
        let credentials = Credentials::Enrolling {
            key,
            token: token(0xcd),
        };

        let debug = format!("{credentials:?}");
        assert!(debug.contains(&public_key), "{debug}");
        assert!(debug.contains("EnrollmentToken(<redacted>)"), "{debug}");
        for secret in ["abab", "171, 171", "cdcd", "205, 205"] {
            assert!(!debug.contains(secret), "{secret}: {debug}");
        }
    }

    // The record on disk.

    const PUBLIC_KEY: &str = "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf";
    const FINGERPRINT: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    fn fingerprint() -> TokenFingerprint {
        TokenFingerprint(std::array::from_fn(|i| u8::try_from(i).unwrap()))
    }

    /// Pins what is on the disk of every enrolled machine. If this test fails, an agent
    /// that updates no longer reads its own identity and the device is gone.
    #[test]
    fn the_record_format_is_stable() {
        let enrolling = Record::Enrolling {
            public_key: PUBLIC_KEY.parse().unwrap(),
            token_sha256: fingerprint(),
        };
        let text = format!(
            "state = \"enrolling\"\npublic_key = \"{PUBLIC_KEY}\"\ntoken_sha256 = \"{FINGERPRINT}\"\n"
        );
        assert_eq!(toml::to_string(&enrolling).unwrap(), text);
        assert_eq!(toml::from_str::<Record>(&text).unwrap(), enrolling);

        let enrolled = Record::Enrolled {
            device_id: device_id(),
            public_key: PUBLIC_KEY.parse().unwrap(),
            token_sha256: fingerprint(),
        };
        let text = format!(
            "state = \"enrolled\"\ndevice_id = \"00112233-4455-6677-8899-aabbccddeeff\"\n\
             public_key = \"{PUBLIC_KEY}\"\ntoken_sha256 = \"{FINGERPRINT}\"\n"
        );
        assert_eq!(toml::to_string(&enrolled).unwrap(), text);
        assert_eq!(toml::from_str::<Record>(&text).unwrap(), enrolled);
    }

    #[test]
    fn a_record_this_build_cannot_read_in_full_is_refused() {
        let valid = format!(
            "state = \"enrolling\"\npublic_key = \"{PUBLIC_KEY}\"\ntoken_sha256 = \"{FINGERPRINT}\"\n"
        );
        assert!(toml::from_str::<Record>(&valid).is_ok());
        for broken in [
            format!("{valid}trusted = true\n"),
            valid.replace("enrolling", "enrolled"),
            valid.replace("enrolling", "approved"),
            valid.replace(FINGERPRINT, &FINGERPRINT.to_uppercase()),
            valid.replace(FINGERPRINT, &FINGERPRINT[2..]),
            valid.replace(FINGERPRINT, &format!("{FINGERPRINT}00")),
            valid.replace(FINGERPRINT, &FINGERPRINT.replacen("00", "+0", 1)),
            valid.replace("state = \"enrolling\"\n", ""),
            String::new(),
            "not toml at all".to_owned(),
        ] {
            assert!(toml::from_str::<Record>(&broken).is_err(), "{broken}");
        }
    }

    #[test]
    fn the_fingerprint_is_the_sha_256_of_the_token() {
        // SHA-256 of 32 zero bytes.
        let expected = "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925";
        let fingerprint = TokenFingerprint::of(&token(0));
        assert_eq!(
            serde_json::to_value(fingerprint).unwrap(),
            serde_json::json!(expected)
        );
        assert_ne!(fingerprint, TokenFingerprint::of(&token(1)));
        assert_eq!(format!("{fingerprint:?}"), "TokenFingerprint(..)");
    }

    // The order of the writes.

    /// Obligation of ADR-0008: by the time there is anything to send, the key and the
    /// record that goes with it are on disk.
    #[test]
    fn a_new_enrollment_is_on_disk_before_there_is_anything_to_send() {
        let disk = FakeDisk::with_token(1);

        let (public_key, presented) = enrolling(store(&disk).credentials().unwrap());

        assert_eq!(disk.writes(), [Write::Key, Write::Record]);
        assert_eq!(disk.public_key(), Some(public_key));
        assert_eq!(
            disk.record(),
            Some(Record::Enrolling {
                public_key,
                token_sha256: TokenFingerprint::of(&token(1)),
            })
        );
        assert_eq!(presented, token(1));
    }

    #[test]
    fn nothing_is_presented_when_the_key_or_its_record_could_not_be_written() {
        for writes in [0, 1] {
            let disk = FakeDisk::with_token(1);
            disk.fail_after(writes);
            assert!(
                matches!(store(&disk).credentials(), Err(IdentityError::Disk(_, _))),
                "{writes}"
            );
        }
    }

    /// If the answer to `Enroll` is lost, the server may have stored the key. Only the
    /// same key gets the same device back.
    #[test]
    fn the_same_token_again_presents_the_same_key() {
        let disk = FakeDisk::with_token(1);
        let (first, _) = enrolling(store(&disk).credentials().unwrap());
        let (second, token_again) = enrolling(store(&disk).credentials().unwrap());

        assert_eq!(first, second);
        assert_eq!(token_again, token(1));
        assert_eq!(disk.writes(), [Write::Key, Write::Record]);
    }

    /// A key enrolls once. If the old token expired after the server stored the key, the
    /// old key is refused under any new token, so a new token always gets a new key.
    #[test]
    fn another_token_gets_a_new_key() {
        let disk = FakeDisk::with_token(1);
        let (first, _) = enrolling(store(&disk).credentials().unwrap());

        disk.put_token(&token(2).expose_hex());
        let (second, presented) = enrolling(store(&disk).credentials().unwrap());

        assert_ne!(first, second);
        assert_eq!(presented, token(2));
        assert_eq!(disk.public_key(), Some(second));
        assert_eq!(
            disk.record(),
            Some(Record::Enrolling {
                public_key: second,
                token_sha256: TokenFingerprint::of(&token(2)),
            })
        );
    }

    #[test]
    fn the_id_is_on_disk_before_the_token_is_removed() {
        let disk = FakeDisk::with_token(1);
        let public_key = enroll(&disk);

        assert_eq!(
            disk.writes(),
            [Write::Key, Write::Record, Write::Record, Write::RemoveToken]
        );
        assert_eq!(
            disk.record(),
            Some(Record::Enrolled {
                device_id: device_id(),
                public_key,
                token_sha256: TokenFingerprint::of(&token(1)),
            })
        );
        assert_eq!(disk.files().token, None);
        assert_eq!(
            enrolled(store(&disk).credentials().unwrap()),
            (public_key, device_id())
        );
    }

    /// The id could not be written: the token must still be there to ask for it again.
    #[test]
    fn the_token_stays_when_the_id_could_not_be_written() {
        let disk = FakeDisk::with_token(1);
        let credentials = store(&disk).credentials().unwrap().unwrap();
        let enrollment = credentials.enrollment().unwrap();

        disk.fail_after(0);
        assert!(store(&disk).enrolled(&enrollment, device_id()).is_err());
        assert_eq!(disk.writes().last(), Some(&Write::Record));
        assert!(disk.files().token.is_some());

        // The next attempt is the same enrollment again.
        disk.works_again();
        let (public_key, _) = enrolling(store(&disk).credentials().unwrap());
        assert_eq!(Some(public_key), disk.public_key());
        assert_eq!(public_key, enrollment.public_key);
    }

    /// A token that arrived while the enrollment was on its way is another enrollment's,
    /// and stays where it is.
    #[test]
    fn enrolling_removes_its_own_token_and_no_other() {
        let disk = FakeDisk::with_token(1);
        let credentials = store(&disk).credentials().unwrap().unwrap();
        let enrollment = credentials.enrollment().unwrap();

        disk.put_token(&token(2).expose_hex());
        store(&disk).enrolled(&enrollment, device_id()).unwrap();

        assert_eq!(disk.files().token, Some(token(2).expose_hex()));
        assert!(!disk.writes().contains(&Write::RemoveToken));
        assert_eq!(enrolled(store(&disk).credentials().unwrap()).1, device_id());
    }

    /// The token file could not be removed: the device is enrolled all the same, and the
    /// file goes the next time the identity is read.
    #[test]
    fn a_token_that_could_not_be_removed_is_removed_later() {
        let disk = FakeDisk::with_token(1);
        let credentials = store(&disk).credentials().unwrap().unwrap();
        let enrollment = credentials.enrollment().unwrap();

        disk.fail_after(1);
        store(&disk).enrolled(&enrollment, device_id()).unwrap();
        assert!(disk.files().token.is_some());

        disk.works_again();
        enrolled(store(&disk).credentials().unwrap());
        assert_eq!(disk.files().token, None);
    }

    /// Whatever write the power goes out at, what is on disk afterwards is an enrollment
    /// that can be repeated or a device that is enrolled. Never a key under another key's
    /// id, and never an identity half gone with the token already removed.
    #[test]
    fn a_crash_at_any_write_leaves_something_to_go_on_with() {
        for writes in 0..=4 {
            let disk = FakeDisk::with_token(1);
            disk.fail_after(writes);
            let sent = store(&disk)
                .credentials()
                .ok()
                .flatten()
                .map(|credentials| {
                    let enrollment = credentials.enrollment().unwrap();
                    let _ = store(&disk).enrolled(&enrollment, device_id());
                    enrollment.public_key
                });

            disk.works_again();
            let after = store(&disk).credentials().unwrap();
            match (writes, after) {
                // The enrollment never reached the point of sending anything.
                (0 | 1, Some(Credentials::Enrolling { .. })) => assert_eq!(sent, None),
                // It was sent and its answer is not on disk: the same key again.
                (2, Some(Credentials::Enrolling { key, .. })) => {
                    assert_eq!(Some(key.public_key()), sent);
                }
                (3 | 4, Some(Credentials::Enrolled { key, device_id: id })) => {
                    assert_eq!(Some(key.public_key()), sent);
                    assert_eq!(id, device_id());
                    assert_eq!(disk.files().token, None);
                }
                (writes, after) => panic!("after {writes} writes: {after:?}"),
            }
            // The key on disk is always the one the record is about.
            match disk.record().unwrap() {
                Record::Enrolling { public_key, .. } | Record::Enrolled { public_key, .. } => {
                    assert_eq!(disk.public_key(), Some(public_key), "{writes}");
                }
            }
        }
    }

    // What is found on disk.

    #[test]
    fn without_an_identity_and_without_a_token_there_is_nothing_to_present() {
        let disk = FakeDisk::default();
        assert!(store(&disk).credentials().unwrap().is_none());
        assert_eq!(disk.writes(), []);
    }

    /// An enrollment that was started, with its token gone: the key cannot be presented
    /// without it, and must not be thrown away either.
    #[test]
    fn an_enrollment_without_its_token_waits() {
        let disk = FakeDisk::with_token(1);
        let (public_key, _) = enrolling(store(&disk).credentials().unwrap());

        disk.files().token = None;
        assert!(store(&disk).credentials().unwrap().is_none());
        assert_eq!(disk.public_key(), Some(public_key));

        disk.put_token(&token(1).expose_hex());
        assert_eq!(enrolling(store(&disk).credentials().unwrap()).0, public_key);
    }

    #[test]
    fn a_token_file_is_one_token_and_at_most_a_line_ending() {
        for ending in ["", "\n", "\r\n"] {
            let disk = FakeDisk::default();
            disk.put_token(&format!("{}{ending}", token(1).expose_hex()));
            let (_, presented) = enrolling(store(&disk).credentials().unwrap());
            assert_eq!(presented, token(1), "{ending:?}");
        }

        // A token with letters in it, so that its upper case is another text.
        let hex = token(0xab).expose_hex();
        for not_a_token in [
            String::new(),
            "\n".to_owned(),
            hex.to_uppercase(),
            hex[1..].to_owned(),
            format!(" {hex}"),
            format!("{hex} "),
            format!("{hex}\n{hex}"),
            format!("token = \"{hex}\""),
        ] {
            let disk = FakeDisk::default();
            disk.put_token(&not_a_token);
            assert!(
                store(&disk).credentials().unwrap().is_none(),
                "{not_a_token:?}"
            );
            assert_eq!(disk.writes(), [], "{not_a_token:?}");
        }
    }

    /// An enrolled device does not enroll again because a token appeared: the token of
    /// its own enrollment is removed, and any other is left where it is.
    #[test]
    fn an_enrolled_device_stays_what_it_is_when_a_token_is_there() {
        let disk = FakeDisk::with_token(1);
        let public_key = enroll(&disk);

        disk.put_token(&token(1).expose_hex());
        assert_eq!(
            enrolled(store(&disk).credentials().unwrap()),
            (public_key, device_id())
        );
        assert_eq!(disk.files().token, None);

        disk.put_token(&token(2).expose_hex());
        assert_eq!(
            enrolled(store(&disk).credentials().unwrap()),
            (public_key, device_id())
        );
        assert_eq!(disk.files().token, Some(token(2).expose_hex()));
        assert_eq!(disk.public_key(), Some(public_key));
    }

    /// A key and a record that are not about each other are no identity. Presenting them
    /// would be a `Hello` under an id with another device's key, refused for ever with no
    /// reason given.
    #[test]
    fn a_key_and_a_record_that_do_not_match_are_not_an_identity() {
        let other_key = DeviceKey::from_secret(&[9; 32]);
        type Breakage = (&'static str, fn(&mut Files));
        let breakages: [Breakage; 6] = [
            ("another key", |files| files.key = Some(vec![9; 32])),
            ("no key", |files| files.key = None),
            ("half a key", |files| files.key = Some(vec![9; 16])),
            ("no record", |files| files.record = None),
            ("a record that is not one", |files| {
                files.record = Some("device_id = 1".to_owned());
            }),
            ("a record with a field too many", |files| {
                let record = files.record.take().unwrap();
                files.record = Some(format!("{record}trusted = true\n"));
            }),
        ];
        for (what, break_it) in breakages {
            // Without a token there is nothing to do but wait.
            let disk = FakeDisk::with_token(1);
            let public_key = enroll(&disk);
            break_it(&mut disk.files());
            let writes = disk.writes().len();
            assert!(store(&disk).credentials().unwrap().is_none(), "{what}");
            assert_eq!(disk.writes().len(), writes, "{what}");

            // With one, the machine enrolls as a new device, with a new key.
            disk.put_token(&token(2).expose_hex());
            let (new_key, presented) = enrolling(store(&disk).credentials().unwrap());
            assert_ne!(new_key, public_key, "{what}");
            assert_ne!(new_key, other_key.public_key(), "{what}");
            assert_eq!(presented, token(2), "{what}");
            assert_eq!(disk.public_key(), Some(new_key), "{what}");
        }
    }

    /// A key that is there and cannot be read is still the device's key. Enrolling again
    /// would write over it.
    #[test]
    fn a_key_that_cannot_be_read_is_not_replaced() {
        let disk = FakeDisk::with_token(1);
        let public_key = enroll(&disk);
        disk.put_token(&token(2).expose_hex());
        disk.files().key_unreadable = true;
        let writes = disk.writes().len();

        assert!(matches!(
            store(&disk).credentials(),
            Err(IdentityError::Disk(_, _))
        ));
        assert_eq!(disk.writes().len(), writes);

        disk.files().key_unreadable = false;
        assert_eq!(disk.public_key(), Some(public_key));
        enrolled(store(&disk).credentials().unwrap());
    }

    // The real disk.

    #[test]
    fn an_identity_survives_on_a_real_disk() {
        let dir = TempDir::new();
        let data = dir.path().join("data");
        // The agent makes it when it starts.
        platform::create_private_dir(&data).unwrap();
        let token_file = dir.path().join("enrollment-token");
        std::fs::write(&token_file, format!("{}\n", token(1).expose_hex())).unwrap();
        let open = || IdentityStore::new(DataDir::new(&data, Some(&token_file)));

        let credentials = open().credentials().unwrap().unwrap();
        let enrollment = credentials.enrollment().unwrap();
        let stored = std::fs::read(data.join("device.key")).unwrap();
        // Under DPAPI on Windows; a plain file elsewhere.
        assert_eq!(stored.len() == 32, !keystore::PROTECTED);
        assert!(token_file.exists());

        // Read again by a store that knows nothing: a restart.
        let (public_key, _) = enrolling(open().credentials().unwrap());
        assert_eq!(public_key, enrollment.public_key);

        open().enrolled(&enrollment, device_id()).unwrap();
        assert!(!token_file.exists());
        assert_eq!(
            enrolled(open().credentials().unwrap()),
            (public_key, device_id())
        );

        let mut names: Vec<_> = std::fs::read_dir(&data)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        assert_eq!(names, ["device.key", "identity.toml"]);
    }

    /// A key under DPAPI that this account cannot open is not "no key": with a new token
    /// waiting, the agent still does not enroll over it (ADR-0013). The plain key of M1 is
    /// another matter: refused as no key, and replaced by the new enrollment.
    #[cfg(windows)]
    #[test]
    fn a_key_this_account_cannot_open_is_never_enrolled_over() {
        let dir = TempDir::new();
        let data = dir.path().join("data");
        platform::create_private_dir(&data).unwrap();
        let token_file = dir.path().join("enrollment-token");
        std::fs::write(&token_file, token(1).expose_hex()).unwrap();
        let open = || IdentityStore::new(DataDir::new(&data, Some(&token_file)));
        open().credentials().unwrap().unwrap();

        let key_file = data.join("device.key");
        let mut foreign = std::fs::read(&key_file).unwrap();
        for byte in &mut foreign[24..40] {
            *byte ^= 0x5a;
        }
        std::fs::write(&key_file, &foreign).unwrap();
        std::fs::write(&token_file, token(2).expose_hex()).unwrap();
        assert!(matches!(
            open().credentials(),
            Err(IdentityError::Disk("read the device key", _))
        ));
        assert_eq!(std::fs::read(&key_file).unwrap(), foreign);

        std::fs::write(&key_file, [7; 32]).unwrap();
        let (_, token) = enrolling(open().credentials().unwrap());
        assert_eq!(token, self::token(2));
        assert_ne!(std::fs::read(&key_file).unwrap().len(), 32);
    }

    #[test]
    fn files_that_cannot_be_what_they_should_are_not_read_in() {
        let dir = TempDir::new();
        let token_file = dir.path().join("enrollment-token");
        let disk = DataDir::new(dir.path(), Some(&token_file));

        std::fs::write(&token_file, "0".repeat(MAX_TOKEN_FILE_BYTES + 1)).unwrap();
        assert_eq!(
            disk.read_token().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        std::fs::write(&token_file, [0xff, 0xfe]).unwrap();
        assert_eq!(
            disk.read_token().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        std::fs::write(
            dir.path().join("identity.toml"),
            vec![b'#'; MAX_RECORD_BYTES + 1],
        )
        .unwrap();
        assert_eq!(
            disk.read_record().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        // No token file configured: nothing to read and nothing to remove.
        let disk = DataDir::new(dir.path(), None);
        assert_eq!(disk.read_token().unwrap(), None);
        disk.remove_token().unwrap();
        assert!(token_file.exists());
    }
}
