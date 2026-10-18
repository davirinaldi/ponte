//! The whole command line, run in the process with a console that types the passwords.

use std::collections::VecDeque;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use ed25519_dalek::SigningKey;
use ponte_protocol::{PublicKey, SignedManifest};

use crate::cli::{Access, Console, FAILED, OK, USAGE_ERROR, run, write_new};
use crate::keyfile::{KeyFile, Password};

const RESTART: &str = include_str!("../../../manifests/examples/erp-restart-service.toml");
const CLEAR_LOCK: &str = include_str!("../../../manifests/examples/erp-clear-stale-lock.toml");
const PASSWORD: &str = "correct horse battery staple";
const DAY: u64 = 24 * 60 * 60;
/// 2026-10-18 12:00 UTC.
const NOW: u64 = 1_792_324_800;

/// Hands out the passwords it was given, in order, and fails the test on one more.
struct Scripted {
    out: Vec<u8>,
    err: Vec<u8>,
    passwords: VecDeque<&'static str>,
}

impl Scripted {
    fn new(passwords: &[&'static str]) -> Self {
        Self {
            out: Vec::new(),
            err: Vec::new(),
            passwords: passwords.iter().copied().collect(),
        }
    }

    fn out(&self) -> String {
        String::from_utf8(self.out.clone()).unwrap()
    }

    fn err(&self) -> String {
        String::from_utf8(self.err.clone()).unwrap()
    }
}

impl Console for Scripted {
    fn out(&mut self) -> &mut dyn Write {
        &mut self.out
    }

    fn err(&mut self) -> &mut dyn Write {
        &mut self.err
    }

    fn password(&mut self, _prompt: &str) -> io::Result<Password> {
        let password = self.passwords.pop_front();
        assert!(
            password.is_some(),
            "asked for a password it should not need"
        );
        password
            .map(|password| Password::new(password.to_owned()))
            .ok_or_else(|| io::ErrorKind::UnexpectedEof.into())
    }
}

/// A directory of its own under the system's temp folder, removed when dropped.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "ponte-sign-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    fn write(&self, name: &str, text: &str) -> PathBuf {
        let path = self.join(name);
        std::fs::write(&path, text).unwrap();
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn command(console: &mut Scripted, args: &[&str], now: u64) -> u8 {
    run(args.iter().map(Into::into), console, now)
}

fn arg(path: &Path) -> &str {
    path.to_str().unwrap()
}

/// A key file made by `keygen`, in `dir`.
fn keygen(dir: &TempDir) -> (PathBuf, PublicKey) {
    let key_file = dir.join("ops.key");
    let mut console = Scripted::new(&[PASSWORD, PASSWORD]);
    assert_eq!(
        command(&mut console, &["keygen", arg(&key_file)], NOW),
        OK,
        "{}",
        console.err()
    );
    let public = std::fs::read_to_string(dir.join("ops.key.pub")).unwrap();
    let public: PublicKey = public.strip_suffix('\n').unwrap().parse().unwrap();
    assert!(console.out().contains(&public.to_string()));
    (key_file, public)
}

fn read_envelope(path: &Path) -> SignedManifest {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn keygen_sign_verify_and_show() {
    let dir = TempDir::new();
    let (key_file, public) = keygen(&dir);
    let manifest = dir.write("erp-restart-service.toml", RESTART);

    let mut console = Scripted::new(&[PASSWORD]);
    let code = command(
        &mut console,
        &["sign", "--key", arg(&key_file), "--yes", arg(&manifest)],
        NOW,
    );
    assert_eq!(code, OK, "{}", console.err());
    let envelope = dir.join("erp-restart-service.signed.json");
    assert!(console.out().contains("Signed. Wrote"));

    // Exactly the reviewed text, an hour back, 90 days by default.
    let signed = read_envelope(&envelope);
    assert_eq!(signed.manifest.as_str(), RESTART);
    assert_eq!(signed.issued_at, NOW - 3600);
    assert_eq!(signed.expires_at, NOW - 3600 + 90 * DAY);
    assert_eq!(signed.public_key, public);

    // By public key, by .pub file, and as `show` sees it.
    let public_hex = public.to_string();
    let pub_file = dir.join("ops.key.pub");
    for key in [public_hex.as_str(), arg(&pub_file)] {
        let mut console = Scripted::new(&[]);
        let code = command(&mut console, &["verify", "--key", key, arg(&envelope)], NOW);
        assert_eq!(code, OK, "{}", console.err());
        assert!(console.out().contains("Valid: signed by"));
    }
    let mut console = Scripted::new(&[]);
    assert_eq!(command(&mut console, &["show", arg(&envelope)], NOW), OK);
    assert!(console.out().contains("Status: signed by the key it names"));
    assert!(console.out().contains("erp.restart-service, version 1"));
}

#[test]
fn without_yes_nothing_is_signed_and_no_password_is_asked() {
    let dir = TempDir::new();
    let (key_file, public) = keygen(&dir);
    let manifest = dir.write("lock.toml", CLEAR_LOCK);

    let mut console = Scripted::new(&[]);
    let code = command(
        &mut console,
        &["sign", "--key", arg(&key_file), arg(&manifest)],
        NOW,
    );
    assert_eq!(code, OK, "{}", console.err());
    let out = console.out();
    for expected in [
        "Risk          medium",
        &format!("Signing key   {public}"),
        "Valid         2026-10-18 11:00 UTC to 2027-01-16 11:00 UTC (90 days)",
        "delete the file C:\\FakeErp\\run\\erp.lock",
        "Services      FakeErp",
        "Paths         C:\\FakeErp\\run\\erp.lock",
        "Nothing was signed",
    ] {
        assert!(out.contains(expected), "missing {expected:?} in\n{out}");
    }
    assert!(!dir.join("lock.signed.json").exists());
}

#[test]
fn the_validity_is_chosen_within_a_year() {
    let dir = TempDir::new();
    let (key_file, _) = keygen(&dir);
    let manifest = dir.write("restart.toml", RESTART);
    let out = dir.join("out.json");

    for days in ["1", "365"] {
        let mut console = Scripted::new(&[PASSWORD]);
        let args = [
            "sign",
            "--key",
            arg(&key_file),
            "--days",
            days,
            "--out",
            arg(&out),
            "--yes",
            arg(&manifest),
        ];
        assert_eq!(command(&mut console, &args, NOW), OK, "{}", console.err());
        let signed = read_envelope(&out);
        let days: u64 = days.parse().unwrap();
        assert_eq!(signed.expires_at - signed.issued_at, days * DAY);
    }
    for days in ["0", "366", "-1", "90.5", "1e2", ""] {
        let mut console = Scripted::new(&[]);
        let args = [
            "sign",
            "--key",
            arg(&key_file),
            "--days",
            days,
            "--yes",
            arg(&manifest),
        ];
        assert_eq!(command(&mut console, &args, NOW), USAGE_ERROR, "{days}");
        assert!(console.err().contains("--days"), "{days}");
    }
}

#[test]
fn keygen_refuses_weak_or_mistyped_passwords_and_never_overwrites() {
    let dir = TempDir::new();
    let key_file = dir.join("k.key");
    let mut console = Scripted::new(&["short pass1"]);
    assert_eq!(
        command(&mut console, &["keygen", arg(&key_file)], NOW),
        FAILED
    );
    assert!(console.err().contains("at least 12 characters"));
    let mut console = Scripted::new(&[PASSWORD, "correct horse battery stapl"]);
    assert_eq!(
        command(&mut console, &["keygen", arg(&key_file)], NOW),
        FAILED
    );
    assert!(console.err().contains("differ"));
    assert!(!key_file.exists());

    let (key_file, _) = keygen(&dir);
    let before = std::fs::read(&key_file).unwrap();
    let mut console = Scripted::new(&[]);
    assert_eq!(
        command(&mut console, &["keygen", arg(&key_file)], NOW),
        FAILED
    );
    assert!(console.err().contains("never overwritten"));
    assert_eq!(std::fs::read(&key_file).unwrap(), before);

    // A leftover .pub alone also stops it, before any password is asked.
    let lone = dir.write("lone.key.pub", "x\n");
    let mut console = Scripted::new(&[]);
    assert_eq!(
        command(&mut console, &["keygen", arg(&dir.join("lone.key"))], NOW),
        FAILED
    );
    assert_eq!(std::fs::read_to_string(lone).unwrap(), "x\n");
}

#[test]
fn the_envelope_replaces_nothing_but_an_envelope() {
    let dir = TempDir::new();
    let (key_file, _) = keygen(&dir);
    let manifest = dir.write("restart.toml", RESTART);
    // A second key kept for rotation is the way out of a lost password.
    let backup = dir.write("backup.key", &std::fs::read_to_string(&key_file).unwrap());
    let public = dir.join("ops.key.pub");
    let notes = dir.write("notes.txt", "keep me");
    let key_before = std::fs::read(&key_file).unwrap();
    for out in [&key_file, &manifest, &backup, &public, &notes, &dir.0] {
        let mut console = Scripted::new(&[]);
        let args = [
            "sign",
            "--key",
            arg(&key_file),
            "--out",
            arg(out),
            "--yes",
            arg(&manifest),
        ];
        assert_eq!(command(&mut console, &args, NOW), FAILED);
        assert!(
            console.err().contains("is not a signed envelope"),
            "{}",
            console.err()
        );
    }
    assert_eq!(std::fs::read(&key_file).unwrap(), key_before);
    assert_eq!(std::fs::read_to_string(&manifest).unwrap(), RESTART);
    assert_eq!(
        std::fs::read_to_string(&backup).unwrap().as_bytes(),
        key_before
    );
    assert_eq!(std::fs::read_to_string(&notes).unwrap(), "keep me");

    // An earlier envelope is replaced: that is how a signature is renewed.
    let envelope = dir.join("restart.signed.json");
    for days in ["30", "60"] {
        let mut console = Scripted::new(&[PASSWORD]);
        let args = [
            "sign",
            "--key",
            arg(&key_file),
            "--days",
            days,
            "--yes",
            arg(&manifest),
        ];
        assert_eq!(command(&mut console, &args, NOW), OK, "{}", console.err());
    }
    let signed = read_envelope(&envelope);
    assert_eq!(signed.expires_at - signed.issued_at, 60 * DAY);
    assert!(!dir.join("restart.signed.json.tmp").exists());
}

/// `keygen` checks first, and the write itself refuses too, should a file appear between
/// the check and the write.
#[test]
fn a_key_is_written_only_where_nothing_is() {
    let dir = TempDir::new();
    let existing = dir.write("k.key", "old");
    assert!(write_new(&existing, "new", Access::Owner).is_err());
    assert_eq!(std::fs::read_to_string(&existing).unwrap(), "old");
    write_new(&dir.join("fresh.key"), "new", Access::Owner).unwrap();
    assert_eq!(
        std::fs::read_to_string(dir.join("fresh.key")).unwrap(),
        "new"
    );
}

/// Where files have modes, only the owner reads the key file.
#[cfg(unix)]
#[test]
fn the_key_file_is_the_owners_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new();
    let (key_file, _) = keygen(&dir);
    let mode = std::fs::metadata(&key_file).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn a_wrong_password_signs_nothing() {
    let dir = TempDir::new();
    let (key_file, _) = keygen(&dir);
    let manifest = dir.write("restart.toml", RESTART);
    let mut console = Scripted::new(&["correct horse battery stapler"]);
    let code = command(
        &mut console,
        &["sign", "--key", arg(&key_file), "--yes", arg(&manifest)],
        NOW,
    );
    assert_eq!(code, FAILED);
    assert!(console.err().contains("wrong password"));
    assert!(!dir.join("restart.signed.json").exists());
}

#[test]
fn text_that_cannot_be_signed_says_how_to_fix_it() {
    let dir = TempDir::new();
    let (key_file, _) = keygen(&dir);
    let cases = [
        (RESTART.replace('\n', "\r\n"), "LF line endings"),
        (format!("\u{feff}{RESTART}"), "byte order mark"),
        (
            RESTART.replace("Restarts", "Reinicia o servic\u{327}o; restarts"),
            "save it in NFC",
        ),
        (
            format!("{RESTART}# {}\n", "x".repeat(16 * 1024)),
            "larger than 16384 bytes",
        ),
    ];
    for (text, expected) in cases {
        let manifest = dir.write("bad.toml", &text);
        let mut console = Scripted::new(&[]);
        let code = command(
            &mut console,
            &["sign", "--key", arg(&key_file), "--yes", arg(&manifest)],
            NOW,
        );
        assert_eq!(code, FAILED, "{expected}");
        assert!(
            console.err().contains(expected),
            "{expected}: {}",
            console.err()
        );
    }

    let manifest = dir.join("bad.toml");
    std::fs::write(&manifest, [0xff, 0xfe, 0x00]).unwrap();
    let mut console = Scripted::new(&[]);
    assert_eq!(
        command(
            &mut console,
            &["sign", "--key", arg(&key_file), arg(&manifest)],
            NOW
        ),
        FAILED
    );
    assert!(console.err().contains("not UTF-8"));
}

#[test]
fn a_manifest_without_a_valid_shape_is_not_signed() {
    let dir = TempDir::new();
    let (key_file, _) = keygen(&dir);
    let cases = [
        (
            format!("{RESTART}\n[[steps]]\nop = \"clear_temp_dir\"\n"),
            "refuses",
        ),
        (RESTART.replace("[[verify]]", "[[preconditions]]"), "verify"),
        (format!("run_as = \"SYSTEM\"\n{RESTART}"), "not a manifest"),
    ];
    for (text, expected) in cases {
        let manifest = dir.write("bad.toml", &text);
        let mut console = Scripted::new(&[]);
        let code = command(
            &mut console,
            &["sign", "--key", arg(&key_file), "--yes", arg(&manifest)],
            NOW,
        );
        assert_eq!(code, FAILED, "{expected}");
        assert!(
            console.err().contains(expected),
            "{expected}: {}",
            console.err()
        );
    }
}

#[test]
fn verify_refuses_what_an_agent_would_refuse() {
    let dir = TempDir::new();
    let (key_file, public) = keygen(&dir);
    let manifest = dir.write("restart.toml", RESTART);
    let envelope = dir.join("restart.signed.json");
    let mut console = Scripted::new(&[PASSWORD]);
    command(
        &mut console,
        &["sign", "--key", arg(&key_file), "--yes", arg(&manifest)],
        NOW,
    );
    let public = public.to_string();

    let verify = |key: &str, envelope: &Path, now: u64| {
        let mut console = Scripted::new(&[]);
        let code = command(&mut console, &["verify", "--key", key, arg(envelope)], now);
        (code, console.err())
    };

    // Another key.
    let other = PublicKey::from_bytes(SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes());
    let (code, err) = verify(&other.to_string(), &envelope, NOW);
    assert_eq!(code, FAILED);
    assert!(err.contains("not trusted"), "{err}");

    // Expired, and from the future.
    let (code, err) = verify(&public, &envelope, NOW + 91 * DAY);
    assert_eq!(code, FAILED);
    assert!(err.contains("expired"), "{err}");
    let (code, err) = verify(&public, &envelope, NOW - 2 * 3600);
    assert_eq!(code, FAILED);
    assert!(err.contains("future"), "{err}");

    // Changed after signing.
    let mut signed = read_envelope(&envelope);
    signed.expires_at += DAY;
    let forged = dir.write("forged.json", &serde_json::to_string(&signed).unwrap());
    let (code, err) = verify(&public, &forged, NOW);
    assert_eq!(code, FAILED);
    assert!(err.contains("signature does not verify"), "{err}");
    let mut console = Scripted::new(&[]);
    assert_eq!(command(&mut console, &["show", arg(&forged)], NOW), OK);
    assert!(
        console
            .out()
            .contains("Status: refused: the signature does not verify")
    );

    // Neither a key nor a file.
    let (code, err) = verify("not-a-key", &envelope, NOW);
    assert_eq!(code, FAILED);
    assert!(err.contains("not-a-key"), "{err}");
}

#[test]
fn a_tampered_key_file_signs_nothing() {
    let dir = TempDir::new();
    let (key_file, _) = keygen(&dir);
    let manifest = dir.write("restart.toml", RESTART);
    let mut json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&key_file).unwrap()).unwrap();
    // Someone else's public key, so `sign` would show one key and sign with another.
    let other = SigningKey::from_bytes(&[9; 32]);
    json["public_key"] = PublicKey::from_bytes(other.verifying_key().to_bytes())
        .to_string()
        .into();
    let tampered = dir.write("tampered.key", &json.to_string());

    let mut console = Scripted::new(&[PASSWORD]);
    let code = command(
        &mut console,
        &["sign", "--key", arg(&tampered), "--yes", arg(&manifest)],
        NOW,
    );
    assert_eq!(code, FAILED);
    assert!(!dir.join("restart.signed.json").exists());

    // The real file still works, and a sealed key round-trips through the file.
    let file: KeyFile = serde_json::from_str(&std::fs::read_to_string(&key_file).unwrap()).unwrap();
    assert!(file.unlock(&Password::new(PASSWORD.to_owned())).is_ok());
}

/// `show` is for envelopes of unknown origin: an escape in the signed TOML must not reach
/// the terminal, hide the steps or fake the status line. `sign` refuses the same text.
#[test]
fn show_never_prints_what_an_escape_decodes_into() {
    use ed25519_dalek::Signer;
    use ponte_protocol::{Signature, manifest_transcript};

    let dir = TempDir::new();
    let text = RESTART.replace(
        "description = \"Restarts the FakeErp Windows service and confirms it is running again.\"",
        "description = \"Harmless.\\e[8m\\rStatus: fine\"",
    );
    assert_ne!(text, RESTART);
    let key = SigningKey::from_bytes(&[4; 32]);
    let mut signed = SignedManifest {
        manifest: text.parse().unwrap(),
        issued_at: NOW - 3600,
        expires_at: NOW + DAY,
        public_key: PublicKey::from_bytes(key.verifying_key().to_bytes()),
        signature: Signature::from_bytes([0; 64]),
    };
    let signature = key.sign(manifest_transcript(&signed).expose_bytes());
    signed.signature = Signature::from_bytes(signature.to_bytes());
    let envelope = dir.write("odd.json", &serde_json::to_string(&signed).unwrap());

    let mut console = Scripted::new(&[]);
    assert_eq!(command(&mut console, &["show", arg(&envelope)], NOW), OK);
    let out = console.out();
    assert!(
        !out.contains(char::from(0x1b)) && !out.contains('\r'),
        "{out:?}"
    );
    assert!(
        out.contains("  | Harmless.<U+001B>[8m<U+000D>Status: fine\n"),
        "{out}"
    );
    assert!(out.contains("Status: refused: the signed manifest has no valid shape"));

    let (key_file, _) = keygen(&dir);
    let manifest = dir.write("odd.toml", &text);
    let mut console = Scripted::new(&[]);
    let code = command(
        &mut console,
        &["sign", "--key", arg(&key_file), arg(&manifest)],
        NOW,
    );
    assert_eq!(code, FAILED);
    assert!(
        console.err().contains("description holds a character"),
        "{}",
        console.err()
    );
}

#[test]
fn usage_errors() {
    for args in [
        &[][..],
        &["bogus"],
        &["sign"],
        &["sign", "m.toml"],
        &["sign", "--key"],
        &["sign", "--key", "k", "--key", "k", "m.toml"],
        &["sign", "--key", "k", "--yes", "--yes", "m.toml"],
        &["sign", "--key", "k", "a.toml", "b.toml"],
        &["sign", "--key", "k", "--password", "x", "m.toml"],
        &["keygen"],
        &["keygen", "--yes", "k"],
        &["verify", "e.json"],
        &["verify", "--key", "k", "--days", "3", "e.json"],
        &["show"],
        &["show", "--key", "k", "e.json"],
        &["help", "x"],
    ] {
        let mut console = Scripted::new(&[]);
        assert_eq!(command(&mut console, args, NOW), USAGE_ERROR, "{args:?}");
        assert!(console.err().contains("usage:"), "{args:?}");
    }
    let mut console = Scripted::new(&[]);
    assert_eq!(command(&mut console, &["help"], NOW), OK);
    assert!(console.out().contains("ponte-sign keygen"));
}
