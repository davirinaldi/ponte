//! `GET /agent`: the WebSocket upgrade and the protocol version (ADR-0007).

use std::sync::Arc;

use axum::extract::State;
use axum::extract::ws::WebSocketUpgrade;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use futures_util::StreamExt;
use ponte_protocol::{MAX_MESSAGE_BYTES, ProtocolVersion};
use tracing::debug;

use super::store::DeviceStore;
use super::{Gateway, session};

/// What is written to the socket at once, in bytes. The server's messages are small.
const WRITE_BUFFER_BYTES: usize = 16 * 1024;

/// What may wait to be written, in bytes. The library asks for the write buffer and one
/// message of the largest size; the rest is a margin.
const MAX_WRITE_BUFFER_BYTES: usize = WRITE_BUFFER_BYTES + MAX_MESSAGE_BYTES + 64 * 1024;

/// Limits in both directions. axum leaves what waits to be written unbounded, and every
/// ping read is a pong queued: whoever holds a device key could fill the server's memory
/// by pinging and never reading. With the limit, the pong owed waits in the one place the
/// library keeps for it, and the server's own next frame fails.
fn limited(upgrade: WebSocketUpgrade) -> WebSocketUpgrade {
    upgrade
        .max_message_size(MAX_MESSAGE_BYTES)
        .max_frame_size(MAX_MESSAGE_BYTES)
        .write_buffer_size(WRITE_BUFFER_BYTES)
        .max_write_buffer_size(MAX_WRITE_BUFFER_BYTES)
}

pub(crate) async fn upgrade<D: DeviceStore>(
    State(gateway): State<Arc<Gateway<D>>>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> Response {
    // A browser names the page that opened the socket, and an agent is not a page. Without
    // this, any website could spend its visitors' connections on this endpoint.
    if headers.contains_key(header::ORIGIN) {
        debug!("upgrade refused: the request comes from a browser");
        return StatusCode::FORBIDDEN.into_response();
    }

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

    limited(upgrade).on_upgrade(move |socket| async move {
        let (sink, stream) = socket.split();
        session::run(&gateway, version, stream, sink, permit).await;
    })
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::net::SocketAddr;
    use std::time::Duration;

    use ponte_protocol::{MAX_MESSAGE_BYTES, ProtocolVersion};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::time::{sleep, timeout};
    use tokio_tungstenite::tungstenite;
    use tokio_tungstenite::tungstenite::Error as WsError;
    use tokio_tungstenite::tungstenite::protocol::{
        Role, WebSocket, WebSocketConfig, WebSocketContext,
    };

    use super::{MAX_WRITE_BUFFER_BYTES, WRITE_BUFFER_BYTES};
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

    /// The limits of the server's sockets, as the WebSocket library under axum takes them.
    fn socket_limits() -> WebSocketConfig {
        WebSocketConfig::default()
            .max_message_size(Some(MAX_MESSAGE_BYTES))
            .max_frame_size(Some(MAX_MESSAGE_BYTES))
            .write_buffer_size(WRITE_BUFFER_BYTES)
            .max_write_buffer_size(MAX_WRITE_BUFFER_BYTES)
    }

    /// The library refuses, with a panic, limits where the most that may wait to be written
    /// is not above what it writes at once. That panic would end every connection's task.
    #[test]
    fn the_socket_limits_are_ones_the_library_accepts() {
        let limits = socket_limits();
        // The library's own rule: a message of the largest size fits on top of what it
        // writes at once. Below that, a large message on a slow link would end a session.
        assert!(limits.max_write_buffer_size >= limits.write_buffer_size + MAX_MESSAGE_BYTES);
        let _ = WebSocketContext::new(Role::Server, Some(limits));
    }

    /// A peer that sends nothing but pings, masked as a client must, and takes nothing in.
    struct Flood {
        pings_left: usize,
    }

    impl io::Read for Flood {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            // FIN and ping, then the mask bit with an empty payload, then the mask.
            const PING: [u8; 6] = [0x89, 0x80, 0x3a, 0x51, 0xc4, 0x0e];
            let frames = (buffer.len() / PING.len()).min(self.pings_left);
            if frames == 0 {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            for frame in buffer[..frames * PING.len()].chunks_exact_mut(PING.len()) {
                frame.copy_from_slice(&PING);
            }
            self.pings_left -= frames;
            Ok(frames * PING.len())
        }
    }

    impl io::Write for Flood {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::WouldBlock.into())
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::ErrorKind::WouldBlock.into())
        }
    }

    /// Whoever holds a device key can send pings and never read the pongs. Each ping read
    /// is a pong owed, and without a limit every one of them waits in memory. With it, a
    /// pong that does not fit waits in the one place the library keeps for it, and the
    /// server's own next frame fails at once.
    #[test]
    fn pongs_owed_to_a_peer_that_reads_nothing_do_not_pile_up() {
        // Pongs of two bytes each: almost two times the limit, if all of them waited.
        let pings = 400_000;
        let mut socket = WebSocket::from_raw_socket(
            Flood { pings_left: pings },
            Role::Server,
            Some(socket_limits()),
        );
        let mut read = 0;
        loop {
            match socket.read() {
                Ok(tungstenite::Message::Ping(_)) => read += 1,
                Err(WsError::Io(error)) if error.kind() == io::ErrorKind::WouldBlock => break,
                other => panic!("{other:?}"),
            }
        }
        // Reading went on all the while: the server keeps hearing the device.
        assert_eq!(read, pings);
        let next = socket.write(tungstenite::Message::Text("{}".into()));
        assert!(matches!(next, Err(WsError::WriteBufferFull(_))), "{next:?}");
    }
}
