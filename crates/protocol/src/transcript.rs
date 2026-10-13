//! The exact bytes a device signs to prove it holds its key (ADR-0008).
//!
//! Both sides build them here, so they cannot disagree about the layout. A transcript is a
//! label followed by fields of fixed size, with nothing optional and nothing to parse:
//!
//! | Transcript | Label | Then |
//! |---|---|---|
//! | hello | `ponte.agent.hello\0` | version (u16, big-endian), nonce (32), device id (16) |
//! | enroll | `ponte.agent.enroll\0` | version (u16, big-endian), nonce (32), token (32), public key (32) |
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

use crate::{DeviceId, EnrollmentToken, Nonce, ProtocolVersion, PublicKey};

const HELLO_LABEL: &[u8] = b"ponte.agent.hello\0";
const ENROLL_LABEL: &[u8] = b"ponte.agent.enroll\0";

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

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;

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

    /// A signature made to enroll must never pass as a `Hello`, whatever the inputs. Each
    /// label ends at its first NUL and the labels differ, so no transcript of one kind can
    /// equal, or start with, one of the other.
    #[test]
    fn labels_separate_the_two_transcripts() {
        for label in [HELLO_LABEL, ENROLL_LABEL] {
            assert_eq!(
                label.iter().position(|&byte| byte == 0),
                Some(label.len() - 1)
            );
            assert!(label.is_ascii());
        }
        assert_ne!(HELLO_LABEL, ENROLL_LABEL);

        let hello = hello(V1, &nonce(), device_id());
        let enroll = enroll(V1, &nonce(), &token(), &public_key());
        assert!(!enroll.starts_with(&hello) && !hello.starts_with(&enroll));
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
