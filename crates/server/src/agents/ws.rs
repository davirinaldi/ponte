//! `GET /agent`: the WebSocket upgrade and the protocol version (ADR-0007).

use std::sync::Arc;

use axum::extract::State;
use axum::extract::ws::WebSocketUpgrade;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use futures_util::StreamExt;
use ponte_protocol::{MAX_MESSAGE_BYTES, ProtocolVersion};
use tracing::debug;

use super::store::DeviceStore;
use super::{Gateway, session};

pub(crate) async fn upgrade<D: DeviceStore>(
    State(gateway): State<Arc<Gateway<D>>>,
    upgrade: WebSocketUpgrade,
) -> Response {
    // Newest first: axum takes the first name of this list that the agent also offered.
    let names = ProtocolVersion::supported().map(ProtocolVersion::subprotocol);
    let upgrade = upgrade.protocols(names);

    // When no name matches, axum selects nothing and would still upgrade. Without a
    // version there is no connection: neither side assumes a default.
    let selected = upgrade
        .selected_protocol()
        .and_then(|name| name.to_str().ok())
        .and_then(ProtocolVersion::from_subprotocol);
    let Some(version) = selected else {
        debug!("upgrade refused: no protocol version in common");
        return StatusCode::BAD_REQUEST.into_response();
    };

    let Some(permit) = gateway.admit() else {
        debug!("upgrade refused: too many unauthenticated connections");
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };

    upgrade
        .max_message_size(MAX_MESSAGE_BYTES)
        .max_frame_size(MAX_MESSAGE_BYTES)
        .on_upgrade(move |socket| async move {
            let (sink, stream) = socket.split();
            session::run(&gateway, version, stream, sink, permit).await;
        })
}
#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::Duration;

    use ponte_protocol::ProtocolVersion;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::time::{sleep, timeout};

    use crate::agents::store::MemoryStore;
    use crate::agents::{Limits, routes_with};

    /// Asks for the upgrade and returns the status of the answer, with the connection
    /// still open.
    async fn ask(addr: SocketAddr) -> (u16, TcpStream) {
        let offer = ProtocolVersion::supported().next().unwrap().subprotocol();
        let request = format!(
            "GET /agent HTTP/1.1\r\n\
             Host: {addr}\r\n\
             Connection: Upgrade\r\n\
             Upgrade: websocket\r\n\
             Sec-WebSocket-Version: 13\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Protocol: {offer}\r\n\r\n"
        );
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();

        let mut head = Vec::new();
        while !head.windows(4).any(|window| window == b"\r\n\r\n") {
            let mut chunk = [0; 512];
            let read = timeout(Duration::from_secs(10), stream.read(&mut chunk))
                .await
                .unwrap()
                .unwrap();
            assert_ne!(read, 0, "closed before answering");
            head.extend(&chunk[..read]);
        }
        let head = String::from_utf8_lossy(&head);
        let status = head.split(' ').nth(1).unwrap().parse().unwrap();
        (status, stream)
    }

    /// A peer that connects and never answers the challenge costs a task and a buffer for
    /// as long as the deadline lasts. There is room for a fixed number of them.
    #[tokio::test]
    async fn ws_loopback_refuses_upgrades_while_too_many_are_unauthenticated() {
        let limits = Limits {
            unauthenticated: 2,
            ..Limits::default()
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, routes_with(MemoryStore::new(), limits))
                .await
                .unwrap();
        });

        let (status, first) = ask(addr).await;
        assert_eq!(status, 101);
        let (status, _second) = ask(addr).await;
        assert_eq!(status, 101);
        let (status, _) = ask(addr).await;
        assert_eq!(status, 503);

        // A place is free again once one of them is gone.
        drop(first);
        for _ in 0..500 {
            let (status, _) = ask(addr).await;
            if status == 101 {
                return;
            }
            assert_eq!(status, 503);
            sleep(Duration::from_millis(10)).await;
        }
        panic!("the place was never given back");
    }
}
