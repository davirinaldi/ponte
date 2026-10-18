//! The exact bytes a device signs to prove it holds its key (ADR-0008), and the bytes a
//! manifest signing key signs (ADR-0010).
//!
//! Both sides build them here, so they cannot disagree about the layout. A transcript is a
//! label followed by fields of fixed size, with nothing optional and nothing to parse:
//!
//! | Transcript | Label | Then |
//! |---|---|---|
//! | hello | `ponte.agent.hello\0` | version (u16, big-endian), nonce (32), device id (16) |
//! | enroll | `ponte.agent.enroll\0` | version (u16, big-endian), nonce (32), token (32), public key (32) |
//! | manifest | `ponte.manifest.v1\0` | issued at (u64, big-endian), expires at (u64, big-endian), text length (u32, big-endian), text |
//!
//! - The label says what the signature is for. A signature made to enroll never verifies
//!   as a `Hello`, nor as anything else this key may sign later.
//! - The version is the one the server selected in the WebSocket upgrade (ADR-0007), so a
//!   signature made under one version never verifies under another.
//! - The nonce is the server's, fresh for each connection, so a recorded answer is useless.
//! - Enrollment covers the token, so a valid proof cannot be moved to another token and
//!   land the device under another customer.
//!
//! What a signature does not show:
//!
//! - That the rest of the message is intact. `agent_version` and `os` are not covered.
//! - That the version is the best the two sides share. Only the selected version is signed,
//!   not the agent's offer, so removing the newer names from the offer goes unnoticed.
//! - That the signer is at the other end of this connection. Nothing ties the transcript to
//!   the TLS session, so a party in the middle can hand the server's challenge to the agent
//!   and pass the answer on.
//!
//! All three take someone who terminates TLS, and that party can already change every
//! message that follows (ADR-0009).

use std::fmt;

use crate::{
    DeviceId, EnrollmentToken, MAX_MANIFEST_BYTES, Nonce, ProtocolVersion, PublicKey,
    SignedManifest,
};

const HELLO_LABEL: &[u8] = b"ponte.agent.hello\0";
const ENROLL_LABEL: &[u8] = b"ponte.agent.enroll\0";
const MANIFEST_LABEL: &[u8] = b"ponte.manifest.v1\0";

/// Bytes to sign or to verify, and nothing else: the enrollment transcript holds the token,
/// so `Debug` is redacted and reading the bytes takes a call that says so.
pub struct Transcript(Vec<u8>);

impl Transcript {
    /// The bytes, for the signer or the verifier. Never log them.
    #[must_use]
    pub fn expose_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Transcript {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Transcript(<{} bytes>)", self.0.len())
    }
}

/// What the `signature` of `Hello` covers. `version` is the one this connection negotiated.
#[must_use]
pub fn hello_transcript(
    version: ProtocolVersion,
    nonce: &Nonce,
    device_id: DeviceId,
) -> Transcript {
    Transcript(
        [
            HELLO_LABEL,
            &version.number().to_be_bytes(),
            nonce.as_bytes(),
            device_id.as_uuid().as_bytes(),
        ]
        .concat(),
    )
}

/// What the `signature` of `Enroll` covers. `version` is the one this connection negotiated.
#[must_use]
pub fn enroll_transcript(
    version: ProtocolVersion,
    nonce: &Nonce,
    token: &EnrollmentToken,
    public_key: &PublicKey,
) -> Transcript {
    Transcript(
        [
            ENROLL_LABEL,
            &version.number().to_be_bytes(),
            nonce.as_bytes(),
            token.expose_secret(),
            public_key.as_bytes(),
        ]
        .concat(),
    )
}

/// What the `signature` of a [`SignedManifest`] covers (ADR-0010). Unlike the two above it
/// carries no protocol version: a manifest is signed offline and must outlive versions.
/// The text is the only field of variable size, and its length comes first.
#[must_use]
pub fn manifest_transcript(signed: &SignedManifest) -> Transcript {
    let text = signed.manifest.as_str().as_bytes();
    // `ManifestText` caps the text at `MAX_MANIFEST_BYTES`, which the assertion below keeps
    // inside a `u32`. Were it ever larger, the length would read `u32::MAX` and the
    // signature would not verify: wrong, but closed.
    let length = u32::try_from(text.len()).unwrap_or(u32::MAX);
    Transcript(
        [
            MANIFEST_LABEL,
            &signed.issued_at.to_be_bytes(),
            &signed.expires_at.to_be_bytes(),
            &length.to_be_bytes(),
            text,
        ]
        .concat(),
    )
}

const _: () = assert!(MAX_MANIFEST_BYTES <= u32::MAX as usize);

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;
    use crate::Signature;

    const V1: ProtocolVersion = ProtocolVersion::for_test(1);
    const V2: ProtocolVersion = ProtocolVersion::for_test(2);

    fn nonce() -> Nonce {
        Nonce::from_bytes([0x11; 32])
    }

    fn device_id() -> DeviceId {
        DeviceId::from_uuid(Uuid::from_u128(0x0011_2233_4455_6677_8899_aabb_ccdd_eeff))
    }

    fn token() -> EnrollmentToken {
        EnrollmentToken::from_bytes([0x44; 32])
    }

    fn public_key() -> PublicKey {
        PublicKey::from_bytes([0x22; 32])
    }

    fn hello(version: ProtocolVersion, nonce: &Nonce, device_id: DeviceId) -> Vec<u8> {
        hello_transcript(version, nonce, device_id)
            .expose_bytes()
            .to_vec()
    }

    fn enroll(
        version: ProtocolVersion,
        nonce: &Nonce,
        token: &EnrollmentToken,
        public_key: &PublicKey,
    ) -> Vec<u8> {
        enroll_transcript(version, nonce, token, public_key)
            .expose_bytes()
            .to_vec()
    }

    /// Pins the signed bytes. If this test fails, every enrolled device stops
    /// authenticating: a new layout needs a new protocol version, with the old one still
    /// built for connections that negotiated the old version.
    #[test]
    fn hello_transcript_is_stable() {
        let mut expected = b"ponte.agent.hello\0".to_vec();
        expected.extend([0x00, 0x01]);
        expected.extend([0x11; 32]);
        expected.extend([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ]);

        assert_eq!(hello(V1, &nonce(), device_id()), expected);
        assert_eq!(expected.len(), 68);
    }

    /// Same pin for enrollment.
    #[test]
    fn enroll_transcript_is_stable() {
        let mut expected = b"ponte.agent.enroll\0".to_vec();
        expected.extend([0x00, 0x01]);
        expected.extend([0x11; 32]);
        expected.extend([0x44; 32]);
        expected.extend([0x22; 32]);

        assert_eq!(enroll(V1, &nonce(), &token(), &public_key()), expected);
        assert_eq!(expected.len(), 117);
    }

    #[test]
    fn version_is_big_endian() {
        let version = ProtocolVersion::for_test(0x0102);
        let transcript = hello(version, &nonce(), device_id());
        assert_eq!(transcript[HELLO_LABEL.len()..][..2], [0x01, 0x02]);
        let transcript = enroll(version, &nonce(), &token(), &public_key());
        assert_eq!(transcript[ENROLL_LABEL.len()..][..2], [0x01, 0x02]);
    }

    /// A signature is only as specific as the bytes under it: every input must change them.
    #[test]
    fn every_input_changes_the_hello_transcript() {
        let base = hello(V1, &nonce(), device_id());
        let other_nonce = Nonce::from_bytes([0x12; 32]);

        assert_ne!(hello(V2, &nonce(), device_id()), base);
        assert_ne!(hello(V1, &other_nonce, device_id()), base);
        assert_ne!(hello(V1, &nonce(), DeviceId::new()), base);
    }

    #[test]
    fn every_input_changes_the_enroll_transcript() {
        let base = enroll(V1, &nonce(), &token(), &public_key());
        let other_nonce = Nonce::from_bytes([0x12; 32]);
        let other_token = EnrollmentToken::from_bytes([0x45; 32]);
        let other_key = PublicKey::from_bytes([0x23; 32]);

        assert_ne!(enroll(V2, &nonce(), &token(), &public_key()), base);
        assert_ne!(enroll(V1, &other_nonce, &token(), &public_key()), base);
        assert_ne!(enroll(V1, &nonce(), &other_token, &public_key()), base);
        assert_ne!(enroll(V1, &nonce(), &token(), &other_key), base);
        // Token and key are both 32 bytes: swapping them must not go unnoticed.
        let swapped_token = EnrollmentToken::from_bytes([0x22; 32]);
        let swapped_key = PublicKey::from_bytes([0x44; 32]);
        assert_ne!(enroll(V1, &nonce(), &swapped_token, &swapped_key), base);
    }

    /// A signature made for one purpose must never pass for another, whatever the inputs.
    /// Each label ends at its first NUL and the labels differ, so no transcript of one kind
    /// can equal, or start with, one of another.
    #[test]
    fn labels_separate_the_transcripts() {
        let labels = [HELLO_LABEL, ENROLL_LABEL, MANIFEST_LABEL];
        for label in labels {
            assert_eq!(
                label.iter().position(|&byte| byte == 0),
                Some(label.len() - 1)
            );
            assert!(label.is_ascii());
        }
        for (i, a) in labels.iter().enumerate() {
            for b in &labels[i + 1..] {
                assert_ne!(a, b);
            }
        }

        let transcripts = [
            hello(V1, &nonce(), device_id()),
            enroll(V1, &nonce(), &token(), &public_key()),
            manifest(&signed()),
        ];
        for (i, a) in transcripts.iter().enumerate() {
            for (j, b) in transcripts.iter().enumerate() {
                assert!(i == j || !a.starts_with(b), "{i} starts with {j}");
            }
        }
    }

    fn signed() -> SignedManifest {
        SignedManifest {
            manifest: "id = \"a.b\"\n".parse().unwrap(),
            issued_at: 0x0102_0304_0506_0708,
            expires_at: 0x1112_1314_1516_1718,
            public_key: public_key(),
            signature: Signature::from_bytes([0x33; 64]),
        }
    }

    fn manifest(signed: &SignedManifest) -> Vec<u8> {
        manifest_transcript(signed).expose_bytes().to_vec()
    }

    /// Pins the bytes a manifest key signs. If this test fails, every manifest signed so
    /// far stops verifying: a new layout needs a new label (ADR-0010).
    #[test]
    fn manifest_transcript_is_stable() {
        let mut expected = b"ponte.manifest.v1\0".to_vec();
        expected.extend([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        expected.extend([0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18]);
        expected.extend([0x00, 0x00, 0x00, 0x0b]);
        expected.extend(b"id = \"a.b\"\n");

        assert_eq!(manifest(&signed()), expected);
        assert_eq!(expected.len(), 49);
    }

    #[test]
    fn every_input_changes_the_manifest_transcript() {
        let base = manifest(&signed());
        let with = |change: fn(&mut SignedManifest)| {
            let mut other = signed();
            change(&mut other);
            manifest(&other)
        };

        assert_ne!(with(|s| s.issued_at += 1), base);
        assert_ne!(with(|s| s.expires_at += 1), base);
        assert_ne!(
            with(|s| s.manifest = "id = \"a.c\"\n".parse().unwrap()),
            base
        );
        // One more byte at the end changes the length in front as well.
        assert_ne!(
            with(|s| s.manifest = "id = \"a.b\"\n\n".parse().unwrap()),
            base
        );
        // Both dates are eight bytes: swapping them must not go unnoticed.
        assert_ne!(
            with(|s| std::mem::swap(&mut s.issued_at, &mut s.expires_at)),
            base
        );
    }

    /// The key and the signature are not in the signed bytes. ed25519 already binds a
    /// signature to its key, and the verifier picks the key from its own list (ADR-0010).
    #[test]
    fn key_and_signature_stay_out_of_the_manifest_transcript() {
        let mut other = signed();
        other.public_key = PublicKey::from_bytes([0x23; 32]);
        other.signature = Signature::from_bytes([0x34; 64]);
        assert_eq!(manifest(&other), manifest(&signed()));
    }

    #[test]
    fn the_largest_manifest_fits_its_length() {
        let mut large = signed();
        large.manifest = "#".repeat(MAX_MANIFEST_BYTES).parse().unwrap();
        let transcript = manifest(&large);
        let at = MANIFEST_LABEL.len() + 16;
        assert_eq!(transcript[at..at + 4], [0x00, 0x00, 0x40, 0x00]);
        assert_eq!(transcript.len(), at + 4 + MAX_MANIFEST_BYTES);
    }

    /// The enrollment transcript holds the token. A stray `{:?}` must not print it, in
    /// hex or as a list of numbers.
    #[test]
    fn debug_is_redacted() {
        let transcript = enroll_transcript(V1, &nonce(), &token(), &public_key());
        assert_eq!(format!("{transcript:?}"), "Transcript(<117 bytes>)");
        assert_eq!(format!("{transcript:#?}"), "Transcript(<117 bytes>)");
    }
}
