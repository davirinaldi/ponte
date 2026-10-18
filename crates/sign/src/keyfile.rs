//! The signing key at rest (ADR-0010): ed25519, encrypted with a key derived from a
//! password by argon2id, under XChaCha20-Poly1305.
//!
//! The file is JSON and records everything needed to open it, the KDF's cost included, so
//! the cost can rise later without breaking old files. What it does not record is never
//! guessed: an unknown field, algorithm or format is refused (invariant 7).

use anyhow::{Context, bail, ensure};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
use ed25519_dalek::SigningKey;
use ponte_protocol::PublicKey;
use serde::{Deserialize, Serialize};

use crate::hex;

/// The label of this layout, in the file and in the associated data of the cipher.
const FORMAT: &str = "ponte.signing-key.v1";
/// The cost new keys get: 64 MiB, 3 passes, one lane (ADR-0010).
const MEMORY_KIB: u32 = 64 * 1024;
const ITERATIONS: u32 = 3;
const PARALLELISM: u32 = 1;
/// What a file may ask for. Below the floor a stolen file is cheaper to attack than the
/// ones this tool writes; above the ceiling, opening it would exhaust the machine.
const MEMORY_KIB_RANGE: std::ops::RangeInclusive<u32> = MEMORY_KIB..=4 * 1024 * 1024;
const ITERATIONS_RANGE: std::ops::RangeInclusive<u32> = ITERATIONS..=64;
const PARALLELISM_RANGE: std::ops::RangeInclusive<u32> = 1..=16;
/// Shortest password `keygen` accepts, in characters.
pub(crate) const MIN_PASSWORD_CHARS: usize = 12;

/// A password, wiped when dropped. It only ever comes from the terminal, or from the
/// scripted console of the tests.
pub(crate) struct Password(Vec<u8>);

impl Password {
    pub(crate) fn new(text: String) -> Self {
        Self(text.into_bytes())
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub(crate) fn chars(&self) -> usize {
        String::from_utf8_lossy(&self.0).chars().count()
    }
}

impl PartialEq for Password {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Drop for Password {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

impl std::fmt::Debug for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Password(<redacted>)")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct KeyFile {
    format: String,
    public_key: PublicKey,
    kdf: Kdf,
    cipher: Cipher,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Kdf {
    algorithm: KdfAlgorithm,
    /// The argon2 version, 19 (0x13).
    version: u32,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    #[serde(with = "hex")]
    salt: [u8; 16],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum KdfAlgorithm {
    #[serde(rename = "argon2id")]
    Argon2id,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cipher {
    algorithm: CipherAlgorithm,
    #[serde(with = "hex")]
    nonce: [u8; 24],
    /// The 32 secret bytes followed by the 16 bytes of the tag.
    #[serde(with = "hex")]
    ciphertext: [u8; 48],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum CipherAlgorithm {
    #[serde(rename = "xchacha20poly1305")]
    XChaCha20Poly1305,
}

impl KeyFile {
    /// Encrypts `key` under `password`, with a fresh salt and nonce.
    pub(crate) fn seal(key: &SigningKey, password: &Password) -> anyhow::Result<Self> {
        let mut salt = [0; 16];
        let mut nonce = [0; 24];
        getrandom::fill(&mut salt).context("the system gave no random bytes")?;
        getrandom::fill(&mut nonce).context("the system gave no random bytes")?;
        let public_key = PublicKey::from_bytes(key.verifying_key().to_bytes());
        let kdf = Kdf {
            algorithm: KdfAlgorithm::Argon2id,
            version: 0x13,
            memory_kib: MEMORY_KIB,
            iterations: ITERATIONS,
            parallelism: PARALLELISM,
            salt,
        };
        let ciphertext = encrypt(&kdf, &nonce, &public_key, key.as_bytes(), password)?;
        Ok(Self {
            format: FORMAT.to_owned(),
            public_key,
            kdf,
            cipher: Cipher {
                algorithm: CipherAlgorithm::XChaCha20Poly1305,
                nonce,
                ciphertext,
            },
        })
    }

    /// The public half, readable without the password.
    pub(crate) const fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Decrypts the key. The file's public key must be the one the private key makes.
    pub(crate) fn unlock(&self, password: &Password) -> anyhow::Result<SigningKey> {
        self.check()?;
        let mut key = derive(&self.kdf, password)?;
        let cipher = XChaCha20Poly1305::new(&Key::from(key));
        key.fill(0);
        let opened = cipher.decrypt(
            &XNonce::from(self.cipher.nonce),
            Payload {
                msg: &self.cipher.ciphertext,
                aad: &associated_data(&self.public_key),
            },
        );
        let Ok(mut plain) = opened else {
            bail!("wrong password, or the key file was changed");
        };
        let secret = <[u8; 32]>::try_from(plain.as_slice());
        plain.fill(0);
        let Ok(mut secret) = secret else {
            bail!("the key file does not hold an ed25519 key");
        };
        let signing = SigningKey::from_bytes(&secret);
        secret.fill(0);
        ensure!(
            signing.verifying_key().to_bytes() == *self.public_key.as_bytes(),
            "the key file's public key is not the one its private key makes"
        );
        Ok(signing)
    }

    /// The parts of the file the types do not already pin down.
    fn check(&self) -> anyhow::Result<()> {
        ensure!(self.format == FORMAT, "not a {FORMAT} key file");
        ensure!(self.kdf.version == 0x13, "unknown argon2 version");
        ensure!(
            MEMORY_KIB_RANGE.contains(&self.kdf.memory_kib)
                && ITERATIONS_RANGE.contains(&self.kdf.iterations)
                && PARALLELISM_RANGE.contains(&self.kdf.parallelism),
            "the key file asks for an argon2 cost outside {} to {} KiB, {} to {} passes and {} \
             to {} lanes",
            MEMORY_KIB_RANGE.start(),
            MEMORY_KIB_RANGE.end(),
            ITERATIONS_RANGE.start(),
            ITERATIONS_RANGE.end(),
            PARALLELISM_RANGE.start(),
            PARALLELISM_RANGE.end(),
        );
        Ok(())
    }
}

/// Binds the ciphertext to this layout and to the public key next to it, so neither can
/// be swapped without the decryption failing.
fn associated_data(public_key: &PublicKey) -> Vec<u8> {
    [FORMAT.as_bytes(), &[0], public_key.as_bytes()].concat()
}

fn derive(kdf: &Kdf, password: &Password) -> anyhow::Result<[u8; 32]> {
    let params = Params::new(kdf.memory_kib, kdf.iterations, kdf.parallelism, Some(32))
        .map_err(|_| anyhow::anyhow!("the key file's argon2 cost is not usable"))?;
    let mut key = [0; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), &kdf.salt, &mut key)
        .map_err(|_| anyhow::anyhow!("argon2 failed"))?;
    Ok(key)
}

fn encrypt(
    kdf: &Kdf,
    nonce: &[u8; 24],
    public_key: &PublicKey,
    secret: &[u8; 32],
    password: &Password,
) -> anyhow::Result<[u8; 48]> {
    let mut key = derive(kdf, password)?;
    let cipher = XChaCha20Poly1305::new(&Key::from(key));
    key.fill(0);
    let sealed = cipher
        .encrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: secret,
                aad: &associated_data(public_key),
            },
        )
        .map_err(|_| anyhow::anyhow!("encryption failed"))?;
    <[u8; 48]>::try_from(sealed.as_slice()).context("unexpected ciphertext length")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn password(text: &str) -> Password {
        Password::new(text.to_owned())
    }

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn sealed() -> KeyFile {
        KeyFile::seal(&key(7), &password("correct horse battery")).unwrap()
    }

    #[test]
    fn a_sealed_key_opens_with_its_password_only() {
        let file = sealed();
        let opened = file.unlock(&password("correct horse battery")).unwrap();
        assert_eq!(opened.to_bytes(), key(7).to_bytes());
        assert_eq!(
            file.public_key().as_bytes(),
            &key(7).verifying_key().to_bytes()
        );

        let error = file.unlock(&password("correct horse batterY")).unwrap_err();
        assert_eq!(
            error.to_string(),
            "wrong password, or the key file was changed"
        );
    }

    /// The file says how it was made, at the cost of ADR-0010, and never holds the secret.
    #[test]
    fn the_file_records_its_cost_and_hides_the_key() {
        let file = sealed();
        let json = serde_json::to_value(&file).unwrap();
        assert_eq!(json["format"], "ponte.signing-key.v1");
        assert_eq!(json["kdf"]["algorithm"], "argon2id");
        assert_eq!(json["kdf"]["version"], 19);
        assert_eq!(json["kdf"]["memory_kib"], 65_536);
        assert_eq!(json["kdf"]["iterations"], 3);
        assert_eq!(json["kdf"]["parallelism"], 1);
        assert_eq!(json["cipher"]["algorithm"], "xchacha20poly1305");
        assert_eq!(json["kdf"]["salt"].as_str().unwrap().len(), 32);
        assert_eq!(json["cipher"]["nonce"].as_str().unwrap().len(), 48);
        let text = json.to_string();
        assert!(!text.contains(&hex::encode(&key(7).to_bytes())));
        assert_eq!(serde_json::from_value::<KeyFile>(json).unwrap(), file);

        // A fresh salt and nonce every time.
        let again = sealed();
        assert_ne!(again.kdf.salt, file.kdf.salt);
        assert_ne!(again.cipher.nonce, file.cipher.nonce);
    }

    #[test]
    fn a_changed_file_does_not_open() {
        let right = password("correct horse battery");
        type Change = fn(&mut KeyFile);
        let changes: [(&str, Change); 6] = [
            ("public key", |f| {
                f.public_key = PublicKey::from_bytes(key(8).verifying_key().to_bytes());
            }),
            ("salt", |f| f.kdf.salt[0] ^= 1),
            ("nonce", |f| f.cipher.nonce[0] ^= 1),
            ("ciphertext", |f| f.cipher.ciphertext[0] ^= 1),
            ("tag", |f| f.cipher.ciphertext[47] ^= 1),
            ("cost", |f| f.kdf.iterations += 1),
        ];
        for (what, change) in changes {
            let mut file = sealed();
            change(&mut file);
            assert!(file.unlock(&right).is_err(), "{what}");
        }
    }

    /// Were the associated data ever dropped, a file could pair someone's private key with
    /// another public key, and `sign` would show one key and sign with another.
    #[test]
    fn the_public_key_must_be_the_private_keys() {
        let right = password("correct horse battery");
        let mut file = sealed();
        let other = PublicKey::from_bytes(key(8).verifying_key().to_bytes());
        file.cipher.ciphertext = encrypt(
            &file.kdf,
            &file.cipher.nonce,
            &other,
            &key(7).to_bytes(),
            &right,
        )
        .unwrap();
        file.public_key = other;
        assert_eq!(
            file.unlock(&right).unwrap_err().to_string(),
            "the key file's public key is not the one its private key makes"
        );
    }

    #[test]
    fn what_the_file_asks_for_is_bounded() {
        let right = password("correct horse battery");
        let changes: [fn(&mut KeyFile); 7] = [
            |f| f.kdf.memory_kib = MEMORY_KIB - 1,
            |f| f.kdf.memory_kib = u32::MAX,
            |f| f.kdf.iterations = 2,
            |f| f.kdf.iterations = 65,
            |f| f.kdf.parallelism = 0,
            |f| f.kdf.parallelism = 17,
            |f| f.kdf.version = 0x10,
        ];
        for change in changes {
            let mut file = sealed();
            change(&mut file);
            let error = file.unlock(&right).unwrap_err().to_string();
            assert!(!error.contains("wrong password"), "{error}");
        }
        let mut file = sealed();
        file.format = "ponte.signing-key.v2".to_owned();
        assert!(file.unlock(&right).is_err());
    }

    #[test]
    fn unknown_fields_and_algorithms_are_refused() {
        let json = serde_json::to_value(sealed()).unwrap();
        let edits: [fn(&mut serde_json::Value); 5] = [
            |j| j["comment"] = "x".into(),
            |j| j["kdf"]["pepper"] = "x".into(),
            |j| j["kdf"]["algorithm"] = "argon2i".into(),
            |j| j["cipher"]["algorithm"] = "aes256gcm".into(),
            |j| j["cipher"]["nonce"] = "00".into(),
        ];
        for edit in edits {
            let mut wrong = json.clone();
            edit(&mut wrong);
            assert!(serde_json::from_value::<KeyFile>(wrong).is_err());
        }
    }

    #[test]
    fn a_password_is_redacted() {
        let secret = password("hunter2hunter2");
        assert_eq!(format!("{secret:?}"), "Password(<redacted>)");
        assert_eq!(secret.chars(), 14);
        assert_eq!(password("çãéíóúâêôàü").chars(), 11);
    }
}
