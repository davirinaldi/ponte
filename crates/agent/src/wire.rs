//! Frames in and out, for the handshake and the session.
//!
//! Nothing here, or anywhere else in the agent, logs a frame, a message or a transcript.
//! `Enroll` holds the token, and what the server sends is text somebody else chose. A
//! message that does not parse is logged by the kind of its error only: the text of a
//! `serde_json` error can repeat what was sent.

use std::time::Duration;

use futures_util::{Sink, SinkExt, Stream, StreamExt};
use ponte_protocol::AgentToServer;
use tokio::time::timeout;

pub(crate) use tokio_tungstenite::tungstenite::Message;

/// The frame did not go out, or not in time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SendFailed;

/// Sends one frame, giving up after `limit`: a connection that takes nothing more is
/// dead, and waiting on it would hold the agent for as long as the system's own
/// time limits last.
pub(crate) async fn send_frame<Si>(
    sink: &mut Si,
    frame: Message,
    limit: Duration,
) -> Result<(), SendFailed>
where
    Si: Sink<Message> + Unpin,
{
    match timeout(limit, sink.send(frame)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) | Err(_) => Err(SendFailed),
    }
}

pub(crate) async fn send<Si>(
    sink: &mut Si,
    message: &AgentToServer,
    limit: Duration,
) -> Result<(), SendFailed>
where
    Si: Sink<Message> + Unpin,
{
    let text = serde_json::to_string(message).map_err(|_| SendFailed)?;
    send_frame(sink, Message::text(text), limit).await
}

/// Closes the connection and gives the server a moment to answer, so that it sees a
/// close and not a reset.
pub(crate) async fn close<St, Si, E>(stream: &mut St, sink: &mut Si, limit: Duration)
where
    St: Stream<Item = Result<Message, E>> + Unpin,
    Si: Sink<Message> + Unpin,
{
    let _ = timeout(limit, async {
        if sink.close().await.is_err() {
            return;
        }
        while let Some(Ok(frame)) = stream.next().await {
            if matches!(frame, Message::Close(_)) {
                break;
            }
        }
    })
    .await;
}
