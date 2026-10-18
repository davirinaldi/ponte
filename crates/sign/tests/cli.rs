//! The real binary, on the commands that need no password: exit codes and what reaches
//! stdout and stderr.

#![allow(clippy::unwrap_used)]

use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey};
use ponte_protocol::{PublicKey, Signature, SignedManifest, manifest_transcript};

const RESTART: &str = include_str!("../../../manifests/examples/erp-restart-service.toml");

fn ponte_sign(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ponte-sign"))
        .args(args)
        // Nothing to read: a command that wanted a password would fail, not hang.
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ponte-sign-cli-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn envelope(key: &SigningKey) -> SignedManifest {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut signed = SignedManifest {
        manifest: RESTART.parse().unwrap(),
        issued_at: now - 3600,
        expires_at: now + 24 * 3600,
        public_key: PublicKey::from_bytes(key.verifying_key().to_bytes()),
        signature: Signature::from_bytes([0; 64]),
    };
    let signature = key.sign(manifest_transcript(&signed).expose_bytes());
    signed.signature = Signature::from_bytes(signature.to_bytes());
    signed
}

#[test]
fn help_and_usage_errors() {
    let help = ponte_sign(&["help"]);
    assert_eq!(help.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&help.stdout).contains("ponte-sign sign --key"));

    for args in [&[][..], &["bogus"], &["sign", "--password", "x", "m.toml"]] {
        let output = ponte_sign(args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(String::from_utf8_lossy(&output.stderr).contains("usage:"));
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn verify_and_show_an_envelope() {
    let dir = scratch("verify");
    let key = SigningKey::from_bytes(&[5; 32]);
    let signed = envelope(&key);
    let path = dir.join("restart.signed.json");
    std::fs::write(&path, serde_json::to_string_pretty(&signed).unwrap()).unwrap();
    let path = path.to_str().unwrap();
    let public = signed.public_key.to_string();

    let verified = ponte_sign(&["verify", "--key", &public, path]);
    assert_eq!(verified.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&verified.stdout).contains("Valid: signed by"));

    let stranger = SigningKey::from_bytes(&[6; 32]).verifying_key().to_bytes();
    let stranger = PublicKey::from_bytes(stranger).to_string();
    let refused = ponte_sign(&["verify", "--key", &stranger, path]);
    assert_eq!(refused.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&refused.stderr).contains("not trusted"));

    let shown = ponte_sign(&["show", path]);
    assert_eq!(shown.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&shown.stdout).contains("restart service FakeErp"));

    let manifest = dir.join("restart.toml");
    std::fs::write(&manifest, RESTART).unwrap();
    let missing = ponte_sign(&["sign", "--key", "no-such.key", manifest.to_str().unwrap()]);
    assert_eq!(missing.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&missing.stderr).contains("no-such.key"));
    let _ = std::fs::remove_dir_all(dir);
}
