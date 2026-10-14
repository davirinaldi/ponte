//! The agent's side of the handshake (ADR-0008), on a connection that already agreed on a
//! protocol version (ADR-0007).
//!
//! ```text
//! server: Challenge      must be the first message, within its deadline
//! agent:  Enroll         or Hello, signed once
//! server: Enrolled       or Welcome, and nothing else
//! ```
//!
//! The server is not trusted here (invariant 2 in `AGENTS.md`). The device key signs the
//! first challenge and is gone before the answer is even sent: a second challenge finds
//! nothing to sign with. `Enrolled` counts only as the answer to an `Enroll` and `Welcome`
//! only as the answer to a `Hello`, so no message can make an enrolled device take a new
//! id or an unenrolled one believe it has a session.
//!
//! A server that refuses says nothing and closes, the same way for every reason. The agent
//! cannot tell a revoked device from a spent token, and does not try.

use futures_util::{Sink, Stream, StreamExt};
use ponte_protocol::{
    AgentToServer, DeviceId, Label, MAX_HANDSHAKE_MESSAGE_BYTES, ProtocolVersion, ServerToAgent,
};
use tokio::time::timeout;

use crate::Timing;
use crate::identity::{Credentials, Enrollment};
use crate::wire::{self, Message};

/// What the agent says about itself. The signature does not cover it.
#[derive(Debug, Clone)]
pub(crate) struct About {
    pub(crate) agent_version: Label,
    pub(crate) os: Label,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Accepted {
    /// The device is authenticated and the session begins.
    Welcome,
    /// The server stored the key under this id and now closes: the agent keeps the id
    /// and connects again.
    Enrolled {
        device_id: DeviceId,
        enrollment: Enrollment,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum Refused {
    #[error("no challenge came in time")]
    NoChallenge,
    #[error("the first message was not a challenge")]
    NotAChallenge,
    #[error("the answer to the challenge could not be sent")]
    SendFailed,
    #[error("the server closed the connection without an answer")]
    Closed,
    #[error("no answer came in time")]
    NoAnswer,
    #[error("the answer was not the one that belongs to what was sent")]
    UnexpectedAnswer,
}

/// One message of the handshake, or why there is none.
enum Read {
    Message(ServerToAgent),
    Closed,
    /// Not text, too large, or not a message. What it was is of no interest: before the
    /// handshake is over the server has one thing to say at a time.
    Invalid,
}

async fn read<St, E>(stream: &mut St) -> Read
where
    St: Stream<Item = Result<Message, E>> + Unpin,
{
    match stream.next().await {
        Some(Ok(Message::Text(text))) if text.len() <= MAX_HANDSHAKE_MESSAGE_BYTES => {
            serde_json::from_str(text.as_str()).map_or(Read::Invalid, Read::Message)
        }
        Some(Ok(Message::Close(_)) | Err(_)) | None => Read::Closed,
        Some(Ok(_)) => Read::Invalid,
    }
}

/// Answers the server's challenge with `credentials` and waits for its verdict.
pub(crate) async fn run<St, Si, E>(
    stream: &mut St,
    sink: &mut Si,
    version: ProtocolVersion,
    credentials: Credentials,
    about: &About,
    timing: &Timing,
) -> Result<Accepted, Refused>
where
    St: Stream<Item = Result<Message, E>> + Unpin,
    Si: Sink<Message> + Unpin,
{
    let nonce = match timeout(timing.challenge, read(stream)).await {
        Ok(Read::Message(ServerToAgent::Challenge { nonce })) => nonce,
        Ok(Read::Message(_) | Read::Invalid) => return Err(Refused::NotAChallenge),
        Ok(Read::Closed) => return Err(Refused::Closed),
        Err(_) => return Err(Refused::NoChallenge),
    };

    // The one signature of this connection. `credentials` is consumed here, and the key
    // with it.
    let enrollment = credentials.enrollment();
    let answer = match credentials {
        Credentials::Enrolled { key, device_id } => AgentToServer::Hello {
            device_id,
            agent_version: about.agent_version.clone(),
            os: about.os.clone(),
            signature: key.sign_hello(version, &nonce, device_id),
        },
        Credentials::Enrolling { key, token } => AgentToServer::Enroll {
            signature: key.sign_enroll(version, &nonce, &token),
            public_key: key.public_key(),
            token,
            agent_version: about.agent_version.clone(),
            os: about.os.clone(),
        },
    };
    wire::send(sink, &answer, timing.send)
        .await
        .map_err(|wire::SendFailed| Refused::SendFailed)?;
    drop(answer);

    match (timeout(timing.verdict, read(stream)).await, enrollment) {
        (Ok(Read::Message(ServerToAgent::Welcome {})), None) => Ok(Accepted::Welcome),
        (Ok(Read::Message(ServerToAgent::Enrolled { device_id })), Some(enrollment)) => {
            Ok(Accepted::Enrolled {
                device_id,
                enrollment,
            })
        }
        (Ok(Read::Message(_) | Read::Invalid), _) => Err(Refused::UnexpectedAnswer),
        (Ok(Read::Closed), _) => Err(Refused::Closed),
        (Err(_), _) => Err(Refused::NoAnswer),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ed25519_dalek::VerifyingKey;
    use ponte_protocol::{
        ActionRequest, EnrollmentToken, Initiator, Nonce, PublicKey, RequestId, Signature,
        enroll_transcript, hello_transcript,
    };
    use tokio::task::JoinHandle;
    use tokio::time::Instant;

    use super::*;
    use crate::identity::DeviceKey;
    use crate::testkit::{Peer, Sent, about, device_id, pipe, stuck_sink, version};

    fn nonce() -> Nonce {
        Nonce::from_bytes([0x11; 32])
    }

    fn challenge() -> ServerToAgent {
        ServerToAgent::Challenge { nonce: nonce() }
    }

    fn token() -> EnrollmentToken {
        EnrollmentToken::from_bytes([0x44; 32])
    }

    fn key() -> DeviceKey {
        DeviceKey::from_secret(&[0x22; 32])
    }

    fn enrolled() -> Credentials {
        Credentials::Enrolled {
            key: key(),
            device_id: device_id(),
        }
    }

    fn enrolling() -> Credentials {
        Credentials::Enrolling {
            key: key(),
            token: token(),
        }
    }

    fn verifies(key: &PublicKey, bytes: &[u8], signature: &Signature) -> bool {
        let key = VerifyingKey::from_bytes(key.as_bytes()).unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(signature.as_bytes());
        key.verify_strict(bytes, &signature).is_ok()
    }

    /// Runs the agent's side against a peer the test plays.
    fn handshake(credentials: Credentials) -> (Peer, JoinHandle<Result<Accepted, Refused>>) {
        let (peer, mut stream, mut sink) = pipe();
        let task = tokio::spawn(async move {
            run(
                &mut stream,
                &mut sink,
                version(),
                credentials,
                &about(),
                &Timing::default(),
            )
            .await
        });
        (peer, task)
    }

    #[tokio::test(start_paused = true)]
    async fn an_enrolled_device_signs_the_challenge_and_is_welcomed() {
        let (mut peer, task) = handshake(enrolled());
        let start = Instant::now();
        peer.send(&challenge());

        let AgentToServer::Hello {
            device_id: id,
            agent_version,
            os,
            signature,
        } = peer.message().await
        else {
            panic!("not a hello");
        };
        // The key was opened before the connection: the answer takes no time at all,
        // out of the ten seconds the server gives.
        assert_eq!(start.elapsed(), Duration::ZERO);
        assert_eq!(id, device_id());
        assert_eq!((agent_version, os), (about().agent_version, about().os));
        let transcript = hello_transcript(version(), &nonce(), device_id());
        assert!(verifies(
            &key().public_key(),
            transcript.expose_bytes(),
            &signature
        ));

        peer.send(&ServerToAgent::Welcome {});
        assert_eq!(task.await.unwrap(), Ok(Accepted::Welcome));
        assert_eq!(peer.sent_so_far(), []);
    }

    #[tokio::test(start_paused = true)]
    async fn a_new_machine_presents_its_token_and_key_and_is_enrolled() {
        let credentials = enrolling();
        let enrollment = credentials.enrollment().unwrap();
        let (mut peer, task) = handshake(credentials);
        peer.send(&challenge());

        let AgentToServer::Enroll {
            token: presented,
            public_key,
            signature,
            ..
        } = peer.message().await
        else {
            panic!("not an enroll");
        };
        assert_eq!(presented, token());
        assert_eq!(public_key, key().public_key());
        let transcript = enroll_transcript(version(), &nonce(), &token(), &public_key);
        assert!(verifies(&public_key, transcript.expose_bytes(), &signature));

        peer.send(&ServerToAgent::Enrolled {
            device_id: device_id(),
        });
        assert_eq!(
            task.await.unwrap(),
            Ok(Accepted::Enrolled {
                device_id: device_id(),
                enrollment,
            })
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_server_that_sends_no_challenge_is_given_ten_seconds() {
        let (mut peer, task) = handshake(enrolled());
        let start = Instant::now();

        assert_eq!(task.await.unwrap(), Err(Refused::NoChallenge));
        assert_eq!(start.elapsed(), Timing::default().challenge);
        assert_eq!(start.elapsed(), Duration::from_secs(10));
        assert_eq!(peer.sent_so_far(), []);
    }

    /// The key signs a challenge that came first, as text, within the size of a handshake
    /// message. Anything else gets no signature and no answer.
    #[tokio::test(start_paused = true)]
    async fn nothing_is_signed_unless_the_first_message_is_a_challenge() {
        let oversized = format!(
            "{}{}",
            serde_json::to_string(&challenge()).unwrap(),
            " ".repeat(MAX_HANDSHAKE_MESSAGE_BYTES)
        );
        let run_action = ServerToAgent::RunAction(ActionRequest {
            request_id: RequestId::new(),
            manifest_id: "erp.restart-service".to_owned(),
            manifest_version: 1,
            initiator: Initiator::Human {
                user_id: "u1".to_owned(),
            },
        });
        let json = |message: &ServerToAgent| Message::text(serde_json::to_string(message).unwrap());
        let challenge_as_bytes = serde_json::to_vec(&challenge()).unwrap();

        for first in [
            json(&ServerToAgent::Welcome {}),
            json(&ServerToAgent::Enrolled {
                device_id: device_id(),
            }),
            json(&ServerToAgent::CollectNow {}),
            json(&run_action),
            Message::text("not a message"),
            Message::text(r#"{"type":"challenge"}"#),
            Message::text(format!(
                r#"{{"type":"challenge","nonce":"{}","sign_this_too":"x"}}"#,
                "11".repeat(32)
            )),
            Message::text(oversized.clone()),
            Message::Binary(challenge_as_bytes.clone().into()),
            Message::Ping(Vec::new().into()),
            Message::Pong(Vec::new().into()),
        ] {
            for credentials in [enrolled(), enrolling()] {
                let (mut peer, task) = handshake(credentials);
                let start = Instant::now();
                peer.send_frame(first.clone());

                assert_eq!(
                    task.await.unwrap(),
                    Err(Refused::NotAChallenge),
                    "{first:?}"
                );
                assert_eq!(start.elapsed(), Duration::ZERO, "{first:?}");
                assert_eq!(peer.sent_so_far(), [], "{first:?}");
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_connection_closed_before_the_challenge_is_a_failed_attempt() {
        for closing in [Some(Message::Close(None)), None] {
            let (mut peer, task) = handshake(enrolled());
            match closing {
                Some(frame) => peer.send_frame(frame),
                None => peer.hang_up(),
            }
            assert_eq!(task.await.unwrap(), Err(Refused::Closed));
            assert_eq!(peer.sent_so_far(), []);
        }
    }

    /// How the server refuses: no message, just the end of the connection.
    #[tokio::test(start_paused = true)]
    async fn a_connection_closed_after_the_answer_is_a_refusal() {
        for credentials in [enrolled(), enrolling()] {
            let (mut peer, task) = handshake(credentials);
            peer.send(&challenge());
            peer.message().await;
            peer.send_frame(Message::Close(None));

            assert_eq!(task.await.unwrap(), Err(Refused::Closed));
            assert_eq!(peer.sent_so_far(), []);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_server_that_gives_no_verdict_is_given_thirty_seconds() {
        let (mut peer, task) = handshake(enrolled());
        let start = Instant::now();
        peer.send(&challenge());
        peer.message().await;

        assert_eq!(task.await.unwrap(), Err(Refused::NoAnswer));
        assert_eq!(start.elapsed(), Timing::default().verdict);
        assert_eq!(start.elapsed(), Duration::from_secs(30));
    }

    /// An enrolled device that is told it was just enrolled, under an id the server
    /// picked, must not take it: that would replace its identity on the server's word.
    /// A machine that is still enrolling and is welcomed has no session either.
    #[tokio::test(start_paused = true)]
    async fn only_the_answer_that_belongs_to_what_was_sent_counts() {
        let cases = [
            (
                enrolled(),
                ServerToAgent::Enrolled {
                    device_id: device_id(),
                },
            ),
            (enrolling(), ServerToAgent::Welcome {}),
            (enrolled(), ServerToAgent::CollectNow {}),
            (enrolling(), ServerToAgent::CollectNow {}),
        ];
        for (credentials, answer) in cases {
            let (mut peer, task) = handshake(credentials);
            peer.send(&challenge());
            peer.message().await;
            peer.send(&answer);

            assert_eq!(
                task.await.unwrap(),
                Err(Refused::UnexpectedAnswer),
                "{answer:?}"
            );
            assert_eq!(peer.sent_so_far(), [], "{answer:?}");
        }
    }

    /// One challenge, one signature. A server that asks again gets nothing: every extra
    /// signature is one more thing a party in the middle could spend elsewhere.
    #[tokio::test(start_paused = true)]
    async fn a_second_challenge_is_not_signed() {
        for credentials in [enrolled(), enrolling()] {
            let (mut peer, task) = handshake(credentials);
            peer.send(&challenge());
            peer.message().await;

            peer.send(&ServerToAgent::Challenge {
                nonce: Nonce::from_bytes([0x12; 32]),
            });
            assert_eq!(task.await.unwrap(), Err(Refused::UnexpectedAnswer));
            assert_eq!(peer.sent_so_far(), []);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn an_answer_that_cannot_be_sent_is_given_up_after_ten_seconds() {
        let (peer, mut stream, _) = pipe();
        let mut sink = stuck_sink();
        let start = Instant::now();
        peer.send(&challenge());

        let result = run(
            &mut stream,
            &mut sink,
            version(),
            enrolled(),
            &about(),
            &Timing::default(),
        )
        .await;
        assert_eq!(result, Err(Refused::SendFailed));
        assert_eq!(start.elapsed(), Timing::default().send);
        assert_eq!(start.elapsed(), Duration::from_secs(10));
    }

    /// What was sent is exactly one frame of text, and `Sent` would show anything else.
    #[tokio::test(start_paused = true)]
    async fn the_answer_is_one_text_frame() {
        let (mut peer, task) = handshake(enrolling());
        peer.send(&challenge());
        let Sent::Frame(Message::Text(text)) = peer.next().await.unwrap() else {
            panic!("not text");
        };
        assert!(text.len() <= MAX_HANDSHAKE_MESSAGE_BYTES);
        assert!(serde_json::from_str::<AgentToServer>(text.as_str()).is_ok());
        peer.hang_up();
        assert_eq!(task.await.unwrap(), Err(Refused::Closed));
    }
}
