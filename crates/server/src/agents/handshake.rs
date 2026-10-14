//! Decides what the first message of a connection is worth (ADR-0008).
//!
//! No socket here: the session hands over the negotiated version, the nonce it sent and the
//! one message the agent answered with, and gets back who the peer is or why it is nobody.
//!
//! The reason for a refusal is for the server's log. The peer never learns it: every
//! refusal closes the connection the same way, so the answer does not tell an unknown
//! device from a revoked one, or a bad token from a bad signature.

use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;
use ponte_protocol::{
    AgentToServer, DeviceId, Nonce, ProtocolVersion, PublicKey, Signature, Transcript,
    enroll_transcript, hello_transcript,
};
use serde_json::error::Category;
use tracing::error;

use super::store::{
    AgentInfo, CustomerId, Device, DeviceStatus, DeviceStore, EnrollOutcome, EnrollRefusal,
    EnrollRequest, TokenHash,
};

/// What a valid first message earns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Accepted {
    /// The key is stored under `device_id`. This does not authenticate the connection: the
    /// agent connects again and says `Hello`.
    Enrolled {
        device_id: DeviceId,
        customer: CustomerId,
        status: DeviceStatus,
        repeated: bool,
    },
    /// The peer holds the key of `device`, which may still be pending.
    Authenticated { device: Device, about: AgentInfo },
}

/// Why a handshake was refused. Never sent to the peer, and safe to log: no variant holds
/// anything the peer wrote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rejection {
    /// No answer within the deadline.
    TimedOut,
    /// The peer went away, or the connection failed.
    Disconnected,
    /// The first frame was not text.
    NotText,
    /// Longer than `MAX_HANDSHAKE_MESSAGE_BYTES`.
    TooLarge,
    /// Only the kind of error: its text may repeat what the peer sent.
    Unparseable(Category),
    /// A valid message, but neither `Enroll` nor `Hello`.
    NotAHandshake,
    /// The public key is not a point on the curve, or is one of the weak ones.
    UnusableKey,
    BadSignature,
    Enrollment(EnrollRefusal),
    UnknownDevice,
    RevokedDevice,
    /// The server could not make a nonce or reach its store. Nobody gets in on a guess.
    ServerFailure,
}

/// A valid key nobody enrolled with, to spend the time of a verification on when there is
/// no stored key to check (RFC 8032, test 1). Its private half is public knowledge, so a
/// signature that verifies under it proves nothing and is never treated as if it did.
const DECOY_KEY: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];

/// Judges the agent's answer to `Challenge { nonce }` on a connection that negotiated
/// `version`.
pub(crate) async fn answer<D: DeviceStore>(
    store: &D,
    version: ProtocolVersion,
    nonce: &Nonce,
    message: AgentToServer,
    now: DateTime<Utc>,
) -> Result<Accepted, Rejection> {
    match message {
        AgentToServer::Enroll {
            token,
            public_key,
            agent_version,
            os,
            signature,
        } => {
            let key = usable_key(&public_key).ok_or(Rejection::UnusableKey)?;
            let transcript = enroll_transcript(version, nonce, &token, &public_key);
            // Before the store hears of the token: a peer that cannot sign spends nothing.
            verify(&key, &transcript, &signature)?;

            let request = EnrollRequest {
                token: TokenHash::of(&token),
                public_key,
                about: AgentInfo { agent_version, os },
            };
            match store
                .enroll(request, now)
                .await
                .map_err(store_failed::<D>)?
            {
                EnrollOutcome::Enrolled {
                    device_id,
                    customer,
                    status,
                    repeated,
                } => Ok(Accepted::Enrolled {
                    device_id,
                    customer,
                    status,
                    repeated,
                }),
                EnrollOutcome::Refused(refusal) => Err(Rejection::Enrollment(refusal)),
            }
        }
        AgentToServer::Hello {
            device_id,
            agent_version,
            os,
            signature,
        } => {
            let device = store.device(device_id).await.map_err(store_failed::<D>)?;
            let stored_key = device
                .as_ref()
                .and_then(|device| usable_key(&device.public_key));
            let transcript = hello_transcript(version, nonce, device_id);

            // One verification on every path, so the time it takes to refuse does not tell
            // an id nobody has from one whose signature was wrong.
            let verified = match &stored_key {
                Some(key) => verify(key, &transcript, &signature),
                None => {
                    if let Some(decoy) = usable_key(&PublicKey::from_bytes(DECOY_KEY)) {
                        // The result is dropped on purpose: see `DECOY_KEY`.
                        let _ = verify(&decoy, &transcript, &signature);
                    }
                    Err(Rejection::BadSignature)
                }
            };

            let Some(device) = device else {
                return Err(Rejection::UnknownDevice);
            };
            verified?;
            // After the signature: only the device itself gets far enough to be told apart
            // in the log as revoked.
            if device.status == DeviceStatus::Revoked {
                return Err(Rejection::RevokedDevice);
            }
            Ok(Accepted::Authenticated {
                device,
                about: AgentInfo { agent_version, os },
            })
        }
        AgentToServer::Heartbeat { .. } | AgentToServer::ActionResult(_) => {
            Err(Rejection::NotAHandshake)
        }
    }
}

// The key as something to verify with, unless it is malformed or weak. A weak key makes
/// signatures that verify for many messages, so one never becomes an identity.
fn usable_key(key: &PublicKey) -> Option<VerifyingKey> {
    VerifyingKey::from_bytes(key.as_bytes())
        .ok()
        .filter(|key| !key.is_weak())
}

/// `verify_strict`, not `verify`: it also refuses the signatures that have more than one
/// encoding and the ones made for a weak key.
fn verify(
    key: &VerifyingKey,
    transcript: &Transcript,
    signature: &Signature,
) -> Result<(), Rejection> {
    let signature = ed25519_dalek::Signature::from_bytes(signature.as_bytes());
    key.verify_strict(transcript.expose_bytes(), &signature)
        .map_err(|_| Rejection::BadSignature)
}

fn store_failed<D: DeviceStore>(error: D::Error) -> Rejection {
    error!(%error, "the device store failed during a handshake");
    Rejection::ServerFailure
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use ed25519_dalek::SigningKey;
    use ponte_protocol::{ActionOutcome, ActionResult, RequestId, TelemetrySnapshot};

    use super::*;
    use crate::agents::store::{MemoryStore, SessionId};
    use crate::agents::testkit::{
        TestDevice, about, at, store_with_token, telemetry, token, version,
    };

    fn nonce(seed: u8) -> Nonce {
        Nonce::from_bytes([seed; 32])
    }

    async fn judge(
        store: &impl DeviceStore,
        message: AgentToServer,
    ) -> Result<Accepted, Rejection> {
        answer(store, version(), &nonce(1), message, at(0)).await
    }

    /// Enrolls `device` with the token of `token_seed`, signing for `nonce(1)`.
    async fn enroll(store: &MemoryStore, device: &TestDevice, token_seed: u8) -> DeviceId {
        let message = device.enroll(&nonce(1), &token(token_seed));
        match judge(store, message).await {
            Ok(Accepted::Enrolled { device_id, .. }) => device_id,
            other => panic!("not enrolled: {other:?}"),
        }
    }

    fn uses_left(store: &MemoryStore, token_seed: u8) -> Option<u32> {
        store.uses_left(&TokenHash::of(&token(token_seed)))
    }

    #[tokio::test]
    async fn a_signed_enrollment_with_a_good_token_is_accepted() {
        let store = store_with_token(1, 1);
        let device = TestDevice::new(10);

        let accepted = judge(&store, device.enroll(&nonce(1), &token(1))).await;
        let Ok(Accepted::Enrolled {
            device_id,
            status,
            repeated,
            ..
        }) = accepted
        else {
            panic!("{accepted:?}");
        };
        assert_eq!(status, DeviceStatus::Active);
        assert!(!repeated);

        let record = store.record(device_id).unwrap();
        assert_eq!(record.public_key, device.public_key());
        assert_eq!(record.about, about());
        // Enrolling is not connecting.
        assert_eq!(record.online, None);
    }

    #[tokio::test]
    async fn an_enrolled_device_authenticates_with_its_key() {
        let store = store_with_token(1, 1);
        let device = TestDevice::new(10);
        let id = enroll(&store, &device, 1).await;

        let accepted = judge(&store, device.hello(&nonce(1), id)).await.unwrap();
        let Accepted::Authenticated {
            device: found,
            about: said,
        } = accepted
        else {
            panic!("{accepted:?}");
        };
        assert_eq!(found.id, id);
        assert_eq!(found.status, DeviceStatus::Active);
        assert_eq!(found.public_key, device.public_key());
        assert_eq!(said, about());
    }

    #[tokio::test]
    async fn a_bad_token_enrolls_nothing() {
        let device = TestDevice::new(10);
        let message = || device.enroll(&nonce(1), &token(1));

        let store = store_with_token(2, 1);
        assert_eq!(
            judge(&store, message()).await,
            Err(Rejection::Enrollment(EnrollRefusal::UnknownToken))
        );

        let store = store_with_token(1, 1);
        let late = answer(&store, version(), &nonce(1), message(), at(100)).await;
        assert_eq!(
            late,
            Err(Rejection::Enrollment(EnrollRefusal::ExpiredToken))
        );

        store.revoke_token(&TokenHash::of(&token(1)));
        assert_eq!(
            judge(&store, message()).await,
            Err(Rejection::Enrollment(EnrollRefusal::RevokedToken))
        );
        assert_eq!(uses_left(&store, 1), Some(1));

        let store = store_with_token(1, 1);
        enroll(&store, &TestDevice::new(11), 1).await;
        assert_eq!(
            judge(&store, message()).await,
            Err(Rejection::Enrollment(EnrollRefusal::ExhaustedToken))
        );
    }

    /// The signature is checked before the token is looked at, so a peer that cannot sign
    /// spends no use and learns nothing about the token.
    #[tokio::test]
    async fn an_enrollment_with_a_bad_signature_spends_nothing() {
        let store = store_with_token(1, 1);
        let device = TestDevice::new(10);
        let other = TestDevice::new(11);

        let signed_for = |nonce_seed: u8, token_seed: u8, signer: &TestDevice| {
            let transcript = enroll_transcript(
                version(),
                &nonce(nonce_seed),
                &token(token_seed),
                &device.public_key(),
            );
            AgentToServer::Enroll {
                token: token(1),
                public_key: device.public_key(),
                agent_version: about().agent_version,
                os: about().os,
                signature: signer.sign(&transcript),
            }
        };

        for (case, message) in [
            ("another nonce", signed_for(2, 1, &device)),
            ("another token", signed_for(1, 2, &device)),
            ("another key", signed_for(1, 1, &other)),
            (
                "a hello transcript",
                AgentToServer::Enroll {
                    token: token(1),
                    public_key: device.public_key(),
                    agent_version: about().agent_version,
                    os: about().os,
                    signature: device.sign(&hello_transcript(
                        version(),
                        &nonce(1),
                        DeviceId::new(),
                    )),
                },
            ),
            ("no signature at all", {
                let AgentToServer::Enroll {
                    token,
                    public_key,
                    agent_version,
                    os,
                    ..
                } = device.enroll(&nonce(1), &token(1))
                else {
                    unreachable!()
                };
                AgentToServer::Enroll {
                    token,
                    public_key,
                    agent_version,
                    os,
                    signature: Signature::from_bytes([0; 64]),
                }
            }),
        ] {
            assert_eq!(
                judge(&store, message).await,
                Err(Rejection::BadSignature),
                "{case}"
            );
        }
        assert_eq!(uses_left(&store, 1), Some(1));

        // And the same messages with the right signature would have worked.
        assert!(judge(&store, signed_for(1, 1, &device)).await.is_ok());
    }

    /// A weak key would let anyone forge its signatures, and bytes that are no key at all
    /// must not be stored as one.
    #[tokio::test]
    async fn a_weak_or_malformed_key_is_refused() {
        let store = store_with_token(1, 9);
        let signer = TestDevice::new(10);

        // The points of small order, in their usual encodings.
        let weak: [[u8; 32]; 6] = [
            hex("0100000000000000000000000000000000000000000000000000000000000000"),
            hex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
            hex("0000000000000000000000000000000000000000000000000000000000000000"),
            hex("0000000000000000000000000000000000000000000000000000000000000080"),
            hex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
            hex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
        ];
        for bytes in weak {
            assert!(
                VerifyingKey::from_bytes(&bytes).is_ok_and(|key| key.is_weak()),
                "not a weak key: {bytes:02x?}"
            );
        }
        // About half of all byte strings are not a point on the curve. Take the first.
        let malformed = (2..=u8::MAX)
            .map(|first| {
                let mut bytes = [0; 32];
                bytes[0] = first;
                bytes
            })
            .find(|bytes| VerifyingKey::from_bytes(bytes).is_err())
            .unwrap();

        for bytes in weak.into_iter().chain([malformed]) {
            let public_key = PublicKey::from_bytes(bytes);
            let transcript = enroll_transcript(version(), &nonce(1), &token(1), &public_key);
            for signature in [signer.sign(&transcript), Signature::from_bytes([0; 64])] {
                let message = AgentToServer::Enroll {
                    token: token(1),
                    public_key,
                    agent_version: about().agent_version,
                    os: about().os,
                    signature,
                };
                assert_eq!(
                    judge(&store, message).await,
                    Err(Rejection::UnusableKey),
                    "{bytes:02x?}"
                );
            }
        }
        assert_eq!(uses_left(&store, 1), Some(9));
    }

    #[tokio::test]
    async fn repeating_an_enrollment_gives_the_same_device() {
        let store = store_with_token(1, 1);
        let device = TestDevice::new(10);
        let id = enroll(&store, &device, 1).await;

        // A new connection has a new nonce, so the agent signs again.
        let again = answer(
            &store,
            version(),
            &nonce(2),
            device.enroll(&nonce(2), &token(1)),
            at(0),
        )
        .await;
        let Ok(Accepted::Enrolled {
            device_id,
            repeated,
            ..
        }) = again
        else {
            panic!("{again:?}");
        };
        assert_eq!(device_id, id);
        assert!(repeated);
        assert_eq!(uses_left(&store, 1), Some(0));
    }

    /// Replay: the answer to one challenge is worth nothing on another connection.
    #[tokio::test]
    async fn a_recorded_answer_fails_against_another_nonce() {
        let store = store_with_token(1, 2);
        let device = TestDevice::new(10);
        let id = enroll(&store, &device, 1).await;

        let recorded_hello = device.hello(&nonce(1), id);
        let recorded_enroll = TestDevice::new(11).enroll(&nonce(1), &token(1));
        for recorded in [recorded_hello.clone(), recorded_enroll.clone()] {
            let replayed = answer(&store, version(), &nonce(2), recorded, at(0)).await;
            assert_eq!(replayed, Err(Rejection::BadSignature));
        }
        assert_eq!(uses_left(&store, 1), Some(1));

        // Both were good answers to the challenge they were made for.
        assert!(judge(&store, recorded_hello).await.is_ok());
        assert!(judge(&store, recorded_enroll).await.is_ok());
    }

    #[tokio::test]
    async fn a_hello_signed_for_something_else_is_refused() {
        let store = store_with_token(1, 3);
        let device = TestDevice::new(10);
        let other = TestDevice::new(11);
        let id = enroll(&store, &device, 1).await;
        let other_id = enroll(&store, &other, 1).await;

        let hello = |device_id: DeviceId, signature: Signature| AgentToServer::Hello {
            device_id,
            agent_version: about().agent_version,
            os: about().os,
            signature,
        };
        let enroll_signature = {
            let transcript =
                enroll_transcript(version(), &nonce(1), &token(1), &device.public_key());
            device.sign(&transcript)
        };

        for (case, message) in [
            ("another device's key", other.hello(&nonce(1), id)),
            (
                "this key, for another device",
                hello(
                    other_id,
                    device.sign(&hello_transcript(version(), &nonce(1), id)),
                ),
            ),
            ("an enrollment transcript", hello(id, enroll_signature)),
            (
                "no signature at all",
                hello(id, Signature::from_bytes([0; 64])),
            ),
        ] {
            assert_eq!(
                judge(&store, message).await,
                Err(Rejection::BadSignature),
                "{case}"
            );
        }
    }

    #[tokio::test]
    async fn an_unknown_device_is_refused() {
        let store = store_with_token(1, 1);
        let device = TestDevice::new(10);
        enroll(&store, &device, 1).await;

        let message = device.hello(&nonce(1), DeviceId::new());
        assert_eq!(judge(&store, message).await, Err(Rejection::UnknownDevice));
    }

    /// RF-49: a pending device proves who it is like any other. What it may do is decided
    /// after the handshake, from its status.
    #[tokio::test]
    async fn a_pending_device_authenticates_as_pending() {
        let store = store_with_token(1, 2);
        let device = TestDevice::new(10);
        let id = enroll(&store, &device, 1).await;

        let accepted = judge(&store, device.hello(&nonce(1), id)).await;
        let Ok(Accepted::Authenticated { device: found, .. }) = accepted else {
            panic!("{accepted:?}");
        };
        assert_eq!(found.status, DeviceStatus::Pending);
    }

    /// RF-04: revocation holds against the device's own, valid key.
    #[tokio::test]
    async fn a_revoked_device_is_refused() {
        let store = store_with_token(1, 1);
        let device = TestDevice::new(10);
        let id = enroll(&store, &device, 1).await;
        store.revoke_device(id);

        assert_eq!(
            judge(&store, device.hello(&nonce(1), id)).await,
            Err(Rejection::RevokedDevice)
        );
        // A wrong signature is told apart in the log, never on the wire.
        assert_eq!(
            judge(&store, TestDevice::new(11).hello(&nonce(1), id)).await,
            Err(Rejection::BadSignature)
        );
    }

    #[tokio::test]
    async fn anything_but_enroll_or_hello_is_not_a_handshake() {
        let store = store_with_token(1, 1);
        for message in [
            AgentToServer::Heartbeat {
                telemetry: telemetry(1),
            },
            AgentToServer::ActionResult(ActionResult {
                request_id: RequestId::new(),
                outcome: ActionOutcome::Succeeded {},
                output: None,
                duration_ms: 1,
            }),
        ] {
            assert_eq!(judge(&store, message).await, Err(Rejection::NotAHandshake));
        }
    }

    /// A store that answers every lookup with the same device, whatever its key is worth.
    struct OneDevice(Device);

    impl DeviceStore for OneDevice {
        type Error = Infallible;

        async fn enroll(
            &self,
            _: EnrollRequest,
            _: DateTime<Utc>,
        ) -> Result<EnrollOutcome, Infallible> {
            Ok(EnrollOutcome::Refused(EnrollRefusal::UnknownToken))
        }

        async fn device(&self, _: DeviceId) -> Result<Option<Device>, Infallible> {
            Ok(Some(self.0.clone()))
        }

        async fn session_started(
            &self,
            _: DeviceId,
            _: SessionId,
            _: &AgentInfo,
            _: DateTime<Utc>,
        ) -> Result<(), Infallible> {
            Ok(())
        }

        async fn heartbeat(
            &self,
            _: DeviceId,
            _: &TelemetrySnapshot,
            _: DateTime<Utc>,
        ) -> Result<Option<DeviceStatus>, Infallible> {
            Ok(None)
        }

        async fn session_ended(
            &self,
            _: DeviceId,
            _: SessionId,
            _: DateTime<Utc>,
        ) -> Result<(), Infallible> {
            Ok(())
        }
    }

    /// When there is no stored key to check, the signature is checked against a decoy so
    /// that refusing takes as long either way. Anyone can sign with the decoy: that must
    /// never let them in.
    #[tokio::test]
    async fn a_signature_made_with_the_decoy_key_proves_nothing() {
        // RFC 8032, test 1.
        let decoy = TestDevice::from_secret(hex(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        ));
        assert_eq!(decoy.public_key().as_bytes(), &DECOY_KEY);
        assert!(usable_key(&PublicKey::from_bytes(DECOY_KEY)).is_some());

        let id = DeviceId::new();
        let message = || decoy.hello(&nonce(1), id);

        // Nobody has this id.
        let empty = MemoryStore::new();
        assert_eq!(
            judge(&empty, message()).await,
            Err(Rejection::UnknownDevice)
        );

        // Someone has it, but the key in the store is damaged.
        for stored in [[0; 32], [0xff; 32]] {
            let store = OneDevice(Device {
                id,
                customer: CustomerId::new(),
                public_key: PublicKey::from_bytes(stored),
                status: DeviceStatus::Active,
            });
            assert_eq!(judge(&store, message()).await, Err(Rejection::BadSignature));
        }

        // The decoy is a key like any other once it is the one in the store.
        let store = OneDevice(Device {
            id,
            customer: CustomerId::new(),
            public_key: decoy.public_key(),
            status: DeviceStatus::Active,
        });
        assert!(judge(&store, message()).await.is_ok());
    }

    #[test]
    fn test_keys_are_real_keys() {
        let key = SigningKey::from_bytes(&[10; 32]);
        let device = TestDevice::new(10);
        assert_eq!(
            device.public_key().as_bytes(),
            key.verifying_key().as_bytes()
        );
        assert!(usable_key(&device.public_key()).is_some());
    }

    fn hex(text: &str) -> [u8; 32] {
        *text.parse::<PublicKey>().unwrap().as_bytes()
    }
}
