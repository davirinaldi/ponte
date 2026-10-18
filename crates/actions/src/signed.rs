//! Checking a signed manifest (ADR-0010): the key, the signature, the validity, and only
//! then the TOML.
//!
//! Nothing signed is read before the signature verifies. A server that is not trusted
//! (invariant 2) chooses every byte of the envelope, so the order is the defence: the key
//! is looked up in the agent's own list, the signature is checked over the exact bytes of
//! [`manifest_transcript`], the dates are checked with arithmetic that cannot wrap, and the
//! TOML parser sees the text last.

use std::fmt;

use ed25519_dalek::VerifyingKey;
use ponte_protocol::{PublicKey, RejectReason, SignedManifest, manifest_transcript};

use crate::{Manifest, ManifestError, ValidManifest};

/// Most manifest keys one verifier trusts (ADR-0010). Two allow a rotation; four leave room.
pub const MAX_TRUSTED_KEYS: usize = 4;
/// Longest window a manifest may have, `expires_at - issued_at` (ADR-0010).
pub const MAX_VALIDITY_SECS: u64 = 365 * 24 * 60 * 60;
/// How far ahead of the verifier's clock `issued_at` may be (ADR-0010).
pub const MAX_CLOCK_SKEW_SECS: u64 = 5 * 60;
/// How far behind its high-water mark the clock may be before every action is refused
/// (ADR-0010).
pub const MAX_CLOCK_BACK_SECS: u64 = 60 * 60;
/// Latest date a manifest may carry. Anything later does not fit the `i64` seconds of
/// `chrono` and of the server's database, and no real manifest gets near it.
const MAX_DATE: u64 = i64::MAX.unsigned_abs();

/// The manifest keys a verifier accepts: the agent's `manifest_keys`, or the server's
/// trusted keys. From 1 to [`MAX_TRUSTED_KEYS`], each a point on the curve that is not of
/// small order, none twice.
#[derive(Clone)]
pub struct TrustedKeys(Vec<(PublicKey, VerifyingKey)>);

/// Why a list of keys cannot be trusted. Keys are public, but a list is refused whole, so
/// the error says which entry, counted from 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TrustedKeysError {
    #[error("at least one manifest key is needed")]
    Empty,
    #[error("at most {MAX_TRUSTED_KEYS} manifest keys are allowed")]
    TooMany,
    #[error("manifest key {0} is not an ed25519 public key")]
    NotAKey(usize),
    #[error("manifest key {0} is a weak key, which signs anything")]
    Weak(usize),
    #[error("manifest key {0} is listed twice")]
    Duplicate(usize),
}

impl TrustedKeys {
    /// # Errors
    /// The list is empty or too long, or one entry is not a usable key or repeats another.
    pub fn new(keys: impl IntoIterator<Item = PublicKey>) -> Result<Self, TrustedKeysError> {
        let mut trusted: Vec<(PublicKey, VerifyingKey)> = Vec::new();
        for (index, key) in keys.into_iter().enumerate() {
            if index == MAX_TRUSTED_KEYS {
                return Err(TrustedKeysError::TooMany);
            }
            let verifying = VerifyingKey::from_bytes(key.as_bytes())
                .map_err(|_| TrustedKeysError::NotAKey(index))?;
            if verifying.is_weak() {
                return Err(TrustedKeysError::Weak(index));
            }
            if trusted.iter().any(|(known, _)| *known == key) {
                return Err(TrustedKeysError::Duplicate(index));
            }
            trusted.push((key, verifying));
        }
        if trusted.is_empty() {
            return Err(TrustedKeysError::Empty);
        }
        Ok(Self(trusted))
    }

    /// The keys, in the order they were given.
    pub fn keys(&self) -> impl Iterator<Item = &PublicKey> {
        self.0.iter().map(|(key, _)| key)
    }

    fn find(&self, key: &PublicKey) -> Option<&VerifyingKey> {
        self.0
            .iter()
            .find(|(known, _)| known == key)
            .map(|(_, verifying)| verifying)
    }
}

impl fmt::Debug for TrustedKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.keys()).finish()
    }
}

/// A manifest whose signature verified against a trusted key, inside its validity, with a
/// valid shape. Only [`verify`] makes one, and only a `VerifiedManifest` can go on to the
/// agent's local policy.
#[derive(Clone)]
pub struct VerifiedManifest {
    manifest: ValidManifest,
    public_key: PublicKey,
    issued_at: u64,
    expires_at: u64,
}

impl VerifiedManifest {
    #[must_use]
    pub fn manifest(&self) -> &Manifest {
        self.manifest.manifest()
    }

    /// The trusted key that signed it.
    #[must_use]
    pub const fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Seconds since the Unix epoch, at most `i64::MAX`.
    #[must_use]
    pub const fn issued_at(&self) -> u64 {
        self.issued_at
    }

    /// Seconds since the Unix epoch, at most `i64::MAX`.
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// A manifest taken as verified, for the tests of what comes after verification. Only
    /// this crate's own tests can call it.
    #[cfg(test)]
    pub(crate) fn for_test(manifest: ValidManifest) -> Self {
        Self {
            manifest,
            public_key: PublicKey::from_bytes([0; 32]),
            issued_at: 0,
            expires_at: 1,
        }
    }
}

/// The id and version only: the rest names paths and services, which logs do not.
impl fmt::Debug for VerifiedManifest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let manifest = self.manifest();
        write!(f, "VerifiedManifest({} v{})", manifest.id, manifest.version)
    }
}

/// Why a signed manifest was refused. Says nothing of the manifest's text.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    #[error("the manifest is signed by a key that is not trusted")]
    UnknownKey,
    #[error("the signature does not verify")]
    BadSignature,
    #[error("a date of the manifest is past the year 292 billion")]
    DateOutOfRange,
    #[error("the manifest's validity ends before it starts")]
    EmptyWindow,
    #[error("the manifest's validity is longer than 365 days")]
    WindowTooLong,
    #[error("the clock is more than one hour behind the latest time this verifier saw")]
    ClockWentBack,
    #[error("the manifest was issued more than 5 minutes in the future")]
    NotYetValid,
    #[error("the manifest has expired")]
    Expired,
    #[error("the signed text is not a manifest")]
    Parse,
    #[error("the signed manifest has no valid shape: {0}")]
    Shape(ManifestError),
}

impl VerifyError {
    /// The code the agent answers with (ADR-0012).
    #[must_use]
    pub const fn reject_reason(&self) -> RejectReason {
        match self {
            Self::UnknownKey => RejectReason::UnknownKey,
            Self::BadSignature => RejectReason::BadSignature,
            Self::NotYetValid => RejectReason::ManifestNotYetValid,
            Self::Expired => RejectReason::ManifestExpired,
            Self::WindowTooLong => RejectReason::ValidityTooLong,
            Self::ClockWentBack => RejectReason::ClockWentBack,
            Self::Shape(ManifestError::PrimitiveRefused(_)) => RejectReason::PrimitiveRefused,
            Self::DateOutOfRange | Self::EmptyWindow | Self::Parse | Self::Shape(_) => {
                RejectReason::InvalidManifest
            }
        }
    }
}

/// Checks a signed manifest and returns it parsed, in this order (ADR-0010):
///
/// 1. its key is one of `keys`;
/// 2. `verify_strict` over [`manifest_transcript`], which refuses the second encoding of a
///    signature and signatures made for weak keys;
/// 3. its dates: both at most `i64::MAX`, a window of 1 second to 365 days, a clock no
///    more than one hour behind `high_water`, `issued_at` no more than 5 minutes after
///    `now`, and `expires_at` after both `now` and `high_water`, so setting the clock back
///    revives nothing;
/// 4. only then the TOML, and its shape.
///
/// `now` is the verifier's clock and `high_water` the latest time it ever saw, both in
/// seconds since the Unix epoch. A verifier with no mark passes `now` as both.
///
/// # Errors
/// The first check that fails.
pub fn verify(
    signed: &SignedManifest,
    keys: &TrustedKeys,
    now: u64,
    high_water: u64,
) -> Result<VerifiedManifest, VerifyError> {
    let key = keys
        .find(&signed.public_key)
        .ok_or(VerifyError::UnknownKey)?;
    let signature = ed25519_dalek::Signature::from_bytes(signed.signature.as_bytes());
    key.verify_strict(manifest_transcript(signed).expose_bytes(), &signature)
        .map_err(|_| VerifyError::BadSignature)?;
    check_validity(signed.issued_at, signed.expires_at, now, high_water)?;
    // The parser's error quotes the text, so it stays here.
    let manifest = Manifest::from_toml(signed.manifest.as_str()).map_err(|_| VerifyError::Parse)?;
    let manifest = manifest.validate_shape().map_err(VerifyError::Shape)?;
    Ok(VerifiedManifest {
        manifest,
        public_key: signed.public_key,
        issued_at: signed.issued_at,
        expires_at: signed.expires_at,
    })
}

fn check_validity(
    issued_at: u64,
    expires_at: u64,
    now: u64,
    high_water: u64,
) -> Result<(), VerifyError> {
    if issued_at > MAX_DATE || expires_at > MAX_DATE {
        return Err(VerifyError::DateOutOfRange);
    }
    let window = expires_at
        .checked_sub(issued_at)
        .filter(|&window| window > 0)
        .ok_or(VerifyError::EmptyWindow)?;
    if window > MAX_VALIDITY_SECS {
        return Err(VerifyError::WindowTooLong);
    }
    if now < high_water.saturating_sub(MAX_CLOCK_BACK_SECS) {
        return Err(VerifyError::ClockWentBack);
    }
    // Against the clock, not the mark: the stricter of the two for a date in the future.
    if issued_at > now.saturating_add(MAX_CLOCK_SKEW_SECS) {
        return Err(VerifyError::NotYetValid);
    }
    if expires_at <= now.max(high_water) {
        return Err(VerifyError::Expired);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};
    use ponte_protocol::Signature;

    use super::*;
    use crate::{MAX_STEPS, Primitive};

    const RESTART: &str = include_str!("../../../manifests/examples/erp-restart-service.toml");
    const DAY: u64 = 24 * 60 * 60;
    /// 2026-10-18, give or take: any instant well inside every range works.
    const NOW: u64 = 1_792_300_000;

    fn signer(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn public(key: &SigningKey) -> PublicKey {
        PublicKey::from_bytes(key.verifying_key().to_bytes())
    }

    fn sign_with(key: &SigningKey, text: &str, issued_at: u64, expires_at: u64) -> SignedManifest {
        let mut signed = SignedManifest {
            manifest: text.parse().unwrap(),
            issued_at,
            expires_at,
            public_key: public(key),
            signature: Signature::from_bytes([0; 64]),
        };
        let signature = key.sign(manifest_transcript(&signed).expose_bytes());
        signed.signature = Signature::from_bytes(signature.to_bytes());
        signed
    }

    /// Signed by key 1 an hour ago, valid for 90 days: what `ponte-sign` writes.
    fn signed() -> SignedManifest {
        sign_with(&signer(1), RESTART, NOW - 3600, NOW - 3600 + 90 * DAY)
    }

    fn trusted() -> TrustedKeys {
        TrustedKeys::new([public(&signer(1)), public(&signer(2))]).unwrap()
    }

    fn check(signed: &SignedManifest) -> Result<VerifiedManifest, VerifyError> {
        verify(signed, &trusted(), NOW, NOW)
    }

    fn dates(issued_at: u64, expires_at: u64) -> Result<VerifiedManifest, VerifyError> {
        check(&sign_with(&signer(1), RESTART, issued_at, expires_at))
    }

    #[test]
    fn a_signed_manifest_verifies() {
        let verified = check(&signed()).unwrap();
        assert_eq!(verified.manifest().id, "erp.restart-service");
        assert_eq!(verified.public_key(), &public(&signer(1)));
        assert_eq!(verified.issued_at(), NOW - 3600);
        assert_eq!(verified.expires_at(), NOW - 3600 + 90 * DAY);
        assert_eq!(
            format!("{verified:?}"),
            "VerifiedManifest(erp.restart-service v1)"
        );
        // Either trusted key will do.
        let other = sign_with(&signer(2), RESTART, NOW - 3600, NOW + DAY);
        assert!(check(&other).is_ok());
    }

    /// The limits of ADR-0010, in numbers the tests below cannot move.
    #[test]
    fn limits_are_pinned() {
        assert_eq!(MAX_TRUSTED_KEYS, 4);
        assert_eq!(MAX_VALIDITY_SECS, 31_536_000);
        assert_eq!(MAX_CLOCK_SKEW_SECS, 300);
        assert_eq!(MAX_CLOCK_BACK_SECS, 3_600);
        assert_eq!(MAX_DATE, 9_223_372_036_854_775_807);
    }

    /// Every byte the signature covers, changed after signing.
    #[test]
    fn every_signed_field_is_covered() {
        type Change = fn(&mut SignedManifest);
        let changes: [(&str, Change); 5] = [
            ("text", |s| {
                s.manifest = RESTART.replace("FakeErp", "WinDefend").parse().unwrap();
            }),
            ("one more byte", |s| {
                s.manifest = format!("{RESTART}\n").parse().unwrap();
            }),
            ("issued_at", |s| s.issued_at -= 1),
            ("expires_at", |s| s.expires_at += DAY),
            ("dates swapped", |s| {
                std::mem::swap(&mut s.issued_at, &mut s.expires_at)
            }),
        ];
        for (what, change) in changes {
            let mut forged = signed();
            change(&mut forged);
            assert_eq!(
                check(&forged).unwrap_err(),
                VerifyError::BadSignature,
                "{what}"
            );
        }

        // One bit of the signature.
        for byte in [0, 31, 32, 63] {
            let mut forged = signed();
            let mut bytes = *forged.signature.as_bytes();
            bytes[byte] ^= 0x01;
            forged.signature = Signature::from_bytes(bytes);
            assert_eq!(
                check(&forged).unwrap_err(),
                VerifyError::BadSignature,
                "{byte}"
            );
        }
    }

    #[test]
    fn the_key_must_be_trusted_and_must_have_signed() {
        // Signed by a key the verifier does not list.
        let stranger = sign_with(&signer(9), RESTART, NOW - 3600, NOW + DAY);
        assert_eq!(check(&stranger).unwrap_err(), VerifyError::UnknownKey);

        // A trusted key named on a signature it did not make.
        let mut claimed = signed();
        claimed.public_key = public(&signer(2));
        assert_eq!(check(&claimed).unwrap_err(), VerifyError::BadSignature);

        // A stranger's envelope relabelled with a trusted key.
        let mut relabelled = stranger;
        relabelled.public_key = public(&signer(1));
        assert_eq!(check(&relabelled).unwrap_err(), VerifyError::BadSignature);
    }

    /// `s + L` is the same signature written another way: refused, so an envelope has one
    /// spelling and one id.
    #[test]
    fn a_malleable_signature_is_refused() {
        const L: [u8; 32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x10,
        ];
        let mut forged = signed();
        let mut bytes = *forged.signature.as_bytes();
        let mut carry = 0u16;
        for (s, l) in bytes[32..].iter_mut().zip(L) {
            let sum = u16::from(*s) + u16::from(l) + carry;
            *s = (sum & 0xff) as u8;
            carry = sum >> 8;
        }
        // `s < L < 2^253`, so `s + L` fits in 32 bytes without a carry out.
        assert_eq!(carry, 0);
        forged.signature = Signature::from_bytes(bytes);
        assert_eq!(check(&forged).unwrap_err(), VerifyError::BadSignature);
    }

    /// A key of small order "signs" every message with `R` = identity and `s` = 0, and
    /// plain `verify` accepts that. `TrustedKeys::new` refuses such a key; were one to get
    /// in anyway, `verify_strict` is the second line.
    #[test]
    fn a_weak_key_signs_nothing() {
        const IDENTITY: [u8; 32] = {
            let mut point = [0; 32];
            point[0] = 1;
            point
        };
        let weak = PublicKey::from_bytes(IDENTITY);
        assert_eq!(
            TrustedKeys::new([weak]).unwrap_err(),
            TrustedKeysError::Weak(0)
        );

        let verifying = VerifyingKey::from_bytes(&IDENTITY).unwrap();
        let keys = TrustedKeys(vec![(weak, verifying)]);
        let mut forged = signed();
        forged.public_key = weak;
        let mut bytes = [0; 64];
        bytes[..32].copy_from_slice(&IDENTITY);
        forged.signature = Signature::from_bytes(bytes);
        // The forgery is real: the lenient check takes it.
        let lenient = ed25519_dalek::Signature::from_bytes(&bytes);
        assert!(
            verifying
                .verify_strict(manifest_transcript(&forged).expose_bytes(), &lenient)
                .is_err()
        );
        assert!(
            ed25519_dalek::Verifier::verify(
                &verifying,
                manifest_transcript(&forged).expose_bytes(),
                &lenient
            )
            .is_ok()
        );
        assert_eq!(
            verify(&forged, &keys, NOW, NOW).unwrap_err(),
            VerifyError::BadSignature
        );
    }

    #[test]
    fn trusted_keys_are_few_usable_and_distinct() {
        let key = |seed| public(&signer(seed));
        assert!(TrustedKeys::new([key(1)]).is_ok());
        assert!(TrustedKeys::new((1..=4).map(key)).is_ok());
        assert_eq!(
            TrustedKeys::new((1..=5).map(key)).unwrap_err(),
            TrustedKeysError::TooMany
        );
        assert_eq!(TrustedKeys::new([]).unwrap_err(), TrustedKeysError::Empty);
        assert_eq!(
            TrustedKeys::new([key(1), key(2), key(1)]).unwrap_err(),
            TrustedKeysError::Duplicate(2)
        );
        // Not a point on the curve: about half of all encodings are not.
        let not_a_point = (2..=u8::MAX)
            .map(|y| {
                let mut bytes = [0; 32];
                bytes[0] = y;
                bytes
            })
            .find(|bytes| VerifyingKey::from_bytes(bytes).is_err())
            .map(PublicKey::from_bytes)
            .unwrap();
        assert_eq!(
            TrustedKeys::new([key(1), not_a_point]).unwrap_err(),
            TrustedKeysError::NotAKey(1)
        );
        assert_eq!(
            format!("{:?}", TrustedKeys::new([key(1)]).unwrap()),
            format!("[{:?}]", key(1))
        );
    }

    #[test]
    fn the_window_is_bounded() {
        let issued = NOW - 3600;
        assert!(dates(issued, issued + MAX_VALIDITY_SECS).is_ok());
        assert_eq!(
            dates(issued, issued + MAX_VALIDITY_SECS + 1).unwrap_err(),
            VerifyError::WindowTooLong
        );
        // What a careless signer would compute: 365 days counted from now, not from issue.
        assert_eq!(
            dates(issued, NOW + MAX_VALIDITY_SECS).unwrap_err(),
            VerifyError::WindowTooLong
        );
        assert!(dates(NOW - 1, NOW + 1).is_ok());
        // Ends before or when it starts: no subtraction may wrap into a long window.
        assert_eq!(
            dates(NOW + 60, NOW + 59).unwrap_err(),
            VerifyError::EmptyWindow
        );
        assert_eq!(dates(NOW, NOW).unwrap_err(), VerifyError::EmptyWindow);
        assert_eq!(dates(u64::MAX, 0).unwrap_err(), VerifyError::DateOutOfRange);
        assert_eq!(dates(MAX_DATE, 0).unwrap_err(), VerifyError::EmptyWindow);
    }

    #[test]
    fn dates_past_i64_are_refused_before_any_arithmetic() {
        for (issued_at, expires_at) in [
            (NOW, u64::MAX),
            (NOW, MAX_DATE + 1),
            (u64::MAX, u64::MAX),
            (MAX_DATE + 1, MAX_DATE + 2),
            (u64::MAX - 10, u64::MAX),
        ] {
            assert_eq!(
                dates(issued_at, expires_at).unwrap_err(),
                VerifyError::DateOutOfRange,
                "{issued_at} {expires_at}"
            );
        }
        // At the edge, the window decides.
        assert_eq!(
            dates(MAX_DATE - 10, MAX_DATE).unwrap_err(),
            VerifyError::NotYetValid
        );
    }

    #[test]
    fn a_manifest_from_the_future_is_refused() {
        let at = |issued_at: u64| dates(issued_at, issued_at + DAY);
        assert!(at(NOW + MAX_CLOCK_SKEW_SECS).is_ok());
        assert_eq!(
            at(NOW + MAX_CLOCK_SKEW_SECS + 1).unwrap_err(),
            VerifyError::NotYetValid
        );
        // The mark does not make the future arrive sooner: the clock decides.
        let signed = sign_with(&signer(1), RESTART, NOW + 1800, NOW + DAY);
        assert_eq!(
            verify(&signed, &trusted(), NOW, NOW + 3000).unwrap_err(),
            VerifyError::NotYetValid
        );
    }

    #[test]
    fn an_expired_manifest_is_refused_by_the_clock_or_by_the_mark() {
        assert!(dates(NOW - DAY, NOW + 1).is_ok());
        assert_eq!(dates(NOW - DAY, NOW).unwrap_err(), VerifyError::Expired);
        assert_eq!(dates(NOW - DAY, NOW - 1).unwrap_err(), VerifyError::Expired);

        // Expired an hour ago by the mark. The clock was set back less than the tolerance,
        // so it still reads as valid: the mark wins.
        let signed = sign_with(&signer(1), RESTART, NOW - DAY, NOW - 1800);
        assert_eq!(
            verify(&signed, &trusted(), NOW - 3600, NOW).unwrap_err(),
            VerifyError::Expired
        );
        // Without the setback it would have been fine.
        assert!(verify(&signed, &trusted(), NOW - 3600, NOW - 3600).is_ok());
    }

    #[test]
    fn a_clock_far_behind_its_mark_refuses() {
        let signed = signed();
        let keys = trusted();
        assert!(verify(&signed, &keys, NOW, NOW + MAX_CLOCK_BACK_SECS).is_ok());
        assert_eq!(
            verify(&signed, &keys, NOW, NOW + MAX_CLOCK_BACK_SECS + 1).unwrap_err(),
            VerifyError::ClockWentBack
        );
        // A mark behind the clock is the normal case.
        assert!(verify(&signed, &keys, NOW, 0).is_ok());
        assert!(verify(&signed, &keys, NOW, NOW - DAY).is_ok());
    }

    /// The signature is checked before the dates and the dates before the TOML: what an
    /// untrusted server sends is not read until it is known to be signed.
    #[test]
    fn nothing_is_parsed_before_the_signature() {
        let not_toml = "this is [[ not = toml\n";
        let mut forged = sign_with(&signer(1), not_toml, NOW - 3600, NOW + DAY);
        forged.issued_at -= 1;
        assert_eq!(check(&forged).unwrap_err(), VerifyError::BadSignature);

        let stranger = sign_with(&signer(9), not_toml, NOW - 3600, NOW + DAY);
        assert_eq!(check(&stranger).unwrap_err(), VerifyError::UnknownKey);

        let expired = sign_with(&signer(1), not_toml, NOW - DAY, NOW - 1);
        assert_eq!(check(&expired).unwrap_err(), VerifyError::Expired);

        let fresh = sign_with(&signer(1), not_toml, NOW - 3600, NOW + DAY);
        assert_eq!(check(&fresh).unwrap_err(), VerifyError::Parse);
    }

    #[test]
    fn a_signed_text_must_still_be_a_valid_manifest() {
        let refused =
            |text: &str| check(&sign_with(&signer(1), text, NOW - 3600, NOW + DAY)).unwrap_err();
        // Unknown field and duplicate key: signing them does not make them mean anything.
        assert_eq!(
            refused(&format!("run_as = \"SYSTEM\"\n{RESTART}")),
            VerifyError::Parse
        );
        assert_eq!(
            refused(&RESTART.replace("risk = \"medium\"", "risk = \"medium\"\nrisk = \"read\"")),
            VerifyError::Parse
        );

        let mut many = Manifest::from_toml(RESTART).unwrap();
        many.steps = vec![many.steps[0].clone(); MAX_STEPS + 1];
        let text = toml::to_string(&many).unwrap();
        assert_eq!(
            refused(&text),
            VerifyError::Shape(ManifestError::TooManySteps)
        );

        let mut wiper = Manifest::from_toml(RESTART).unwrap();
        wiper.steps.push(Primitive::ClearTempDir {});
        let error = refused(&toml::to_string(&wiper).unwrap());
        assert_eq!(error.reject_reason(), RejectReason::PrimitiveRefused);
    }

    /// What the protocol refuses before a verifier sees it: text that was not signed as it
    /// reads, and envelopes with more than the signed fields.
    #[test]
    fn an_envelope_carries_only_what_was_signed() {
        let envelope = serde_json::to_value(signed()).unwrap();
        assert!(serde_json::from_value::<SignedManifest>(envelope.clone()).is_ok());

        let crlf = RESTART.replace('\n', "\r\n");
        let bom = format!("\u{feff}{RESTART}");
        let large = format!(
            "{RESTART}{}",
            "#".repeat(ponte_protocol::MAX_MANIFEST_BYTES)
        );
        for text in [crlf.as_str(), bom.as_str(), large.as_str()] {
            let mut wrong = envelope.clone();
            wrong["manifest"] = serde_json::json!(text);
            assert!(serde_json::from_value::<SignedManifest>(wrong).is_err());
        }
        let mut extra = envelope;
        extra["verified"] = serde_json::json!(true);
        assert!(serde_json::from_value::<SignedManifest>(extra).is_err());
    }

    #[test]
    fn errors_map_to_reasons() {
        for (error, reason) in [
            (VerifyError::UnknownKey, RejectReason::UnknownKey),
            (VerifyError::BadSignature, RejectReason::BadSignature),
            (VerifyError::NotYetValid, RejectReason::ManifestNotYetValid),
            (VerifyError::Expired, RejectReason::ManifestExpired),
            (VerifyError::WindowTooLong, RejectReason::ValidityTooLong),
            (VerifyError::ClockWentBack, RejectReason::ClockWentBack),
            (VerifyError::DateOutOfRange, RejectReason::InvalidManifest),
            (VerifyError::EmptyWindow, RejectReason::InvalidManifest),
            (VerifyError::Parse, RejectReason::InvalidManifest),
            (
                VerifyError::Shape(ManifestError::NoSteps),
                RejectReason::InvalidManifest,
            ),
        ] {
            assert_eq!(error.reject_reason(), reason, "{error:?}");
        }
    }
}
