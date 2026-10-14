//! From a URL to a WebSocket that agreed on a protocol version: TCP, TLS, the upgrade.
//!
//! Everything a server can get wrong here is one outcome, a failed connection, and the
//! agent backs off (RNF-16): an upgrade refused with 503 or 400, an upgrade that selects
//! no version or one that was not offered, a certificate that does not verify, a redirect.
//!
//! - **TLS** is rustls with the `ring` provider, TLS 1.3 only (RNF-01), and the server
//!   certificate checked by the operating system's verifier (ADR-0009). The agent builds
//!   that configuration itself and always hands it to the WebSocket library, which is
//!   built without a root store of its own.
//! - **Plain `ws://`** is for development against this very machine. The configuration
//!   only accepts it for `localhost` and `127.0.0.1`, and this module checks the address
//!   the socket actually connected to: a name can resolve anywhere.
//! - **The protocol version** (ADR-0007) is offered newest first and read back from the
//!   answer. No version, no connection: the agent never assumes one.
//! - **No `Origin` header.** The server refuses requests that carry one.

use std::fmt;
use std::io;
use std::net::IpAddr;
use std::sync::Arc;

use ponte_protocol::{MAX_MESSAGE_BYTES, ProtocolVersion};
use rustls::ClientConfig;
use rustls_platform_verifier::BuilderVerifierExt;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Error as WsError;
use tokio_tungstenite::tungstenite::client::ClientRequestBuilder;
use tokio_tungstenite::tungstenite::error::ProtocolError;
use tokio_tungstenite::tungstenite::http::{HeaderMap, Uri};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::{Connector, MaybeTlsStream, WebSocketStream, client_async_tls_with_config};

use crate::config::{Security, ServerUrl};

pub(crate) type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ConnectError {
    #[error("the server cannot be reached: {0}")]
    Unreachable(io::ErrorKind),
    #[error("ws:// is only for this machine, and the address it resolved to is another one")]
    NotLoopback,
    #[error("TLS could not be set up: {0}")]
    TlsSetup(String),
    #[error("the connection is not encrypted although the URL asks for it")]
    NotEncrypted,
    #[error("the server answered the upgrade with HTTP status {0}")]
    Http(u16),
    #[error(
        "the server selected none of the offered protocol versions (a proxy that removes the \
         Sec-WebSocket-Protocol header causes this too)"
    )]
    NoVersion,
    #[error("the TLS handshake (TLS 1.3 only) or the upgrade failed: {0}")]
    Upgrade(String),
}

/// The TLS configuration, built the first time a connection needs it and kept, so that
/// connections after the first can resume a session.
#[derive(Default)]
pub(crate) struct Tls(Option<Arc<ClientConfig>>);

impl Tls {
    fn config(&mut self) -> Result<Arc<ClientConfig>, ConnectError> {
        if let Some(config) = &self.0 {
            return Ok(Arc::clone(config));
        }
        let config = client_config().map_err(|error| ConnectError::TlsSetup(bounded(&error)))?;
        Ok(Arc::clone(self.0.insert(Arc::new(config))))
    }
}

fn client_config() -> Result<ClientConfig, rustls::Error> {
    // Named here, so that nothing depends on a process-wide default provider.
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    Ok(ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_platform_verifier()?
        .with_no_client_auth())
}

/// Opens the connection and returns it with the version the two sides agreed on.
pub(crate) async fn connect(
    url: &ServerUrl,
    tls: &mut Tls,
) -> Result<(ProtocolVersion, Socket), ConnectError> {
    let tls = match url.security() {
        Security::Tls => Some(tls.config()?),
        Security::PlainLoopback => None,
    };
    let stream = TcpStream::connect((url.host(), url.port()))
        .await
        .map_err(|error| ConnectError::Unreachable(error.kind()))?;
    let encrypted = tls.is_some();
    let connector = match tls {
        Some(config) => Connector::Rustls(config),
        None => {
            let peer = stream
                .peer_addr()
                .map_err(|error| ConnectError::Unreachable(error.kind()))?;
            plain_to(peer.ip())?
        }
    };
    // Messages are small and each one matters now: no waiting to fill a packet.
    let _ = stream.set_nodelay(true);

    let offered: Vec<ProtocolVersion> = ProtocolVersion::supported().collect();
    let request = upgrade_request(url, &offered)?;
    let limits = WebSocketConfig::default()
        .max_message_size(Some(MAX_MESSAGE_BYTES))
        .max_frame_size(Some(MAX_MESSAGE_BYTES));
    // The connector is always given: the library never gets to pick a TLS setup itself.
    let (socket, response) =
        client_async_tls_with_config(request, stream, Some(limits), Some(connector))
            .await
            .map_err(classify)?;

    // The library decides between TLS and plain by the URL's scheme, as this module did.
    // Should the two ever disagree, nothing has been sent yet but the upgrade request.
    if encrypted && !matches!(socket.get_ref(), MaybeTlsStream::Rustls(_)) {
        return Err(ConnectError::NotEncrypted);
    }
    let version =
        negotiated_version(&offered, response.headers()).ok_or(ConnectError::NoVersion)?;
    Ok((version, socket))
}

/// The upgrade request: the URL and the versions on offer, newest first. No `Origin`.
fn upgrade_request(
    url: &ServerUrl,
    offered: &[ProtocolVersion],
) -> Result<ClientRequestBuilder, ConnectError> {
    let uri: Uri = url
        .as_str()
        .parse()
        .map_err(|_| ConnectError::Upgrade("the server URL is not a valid URI".to_owned()))?;
    Ok(offered
        .iter()
        .fold(ClientRequestBuilder::new(uri), |request, version| {
            request.with_sub_protocol(version.subprotocol())
        }))
}

/// The version the server selected, if its answer names exactly one and that one was
/// offered. The WebSocket library checks the header too, but it looks at the first one
/// only, and what counts as a version is not for it to say.
fn negotiated_version(offered: &[ProtocolVersion], answer: &HeaderMap) -> Option<ProtocolVersion> {
    let mut selected = answer.get_all("sec-websocket-protocol").iter();
    let (Some(name), None) = (selected.next(), selected.next()) else {
        return None;
    };
    let version = ProtocolVersion::from_subprotocol(name.to_str().ok()?)?;
    offered.contains(&version).then_some(version)
}

/// The connector for a connection without TLS, which only this machine gets: the name in
/// the URL was `localhost`, and a name can resolve to anything.
fn plain_to(peer: IpAddr) -> Result<Connector, ConnectError> {
    if !is_loopback(peer) {
        return Err(ConnectError::NotLoopback);
    }
    Ok(Connector::Plain)
}

/// Whether `address` is this machine. An IPv4 address written as IPv6 counts as what it is.
fn is_loopback(address: IpAddr) -> bool {
    address.to_canonical().is_loopback()
}

fn classify(error: WsError) -> ConnectError {
    match error {
        // Only the status: the rest of the answer is whatever the other side wrote.
        WsError::Http(response) => ConnectError::Http(response.status().as_u16()),
        WsError::Protocol(ProtocolError::SecWebSocketSubProtocolError(_)) => {
            ConnectError::NoVersion
        }
        other => ConnectError::Upgrade(bounded(&other)),
    }
}

/// An error of a library as one short line. Such a text can repeat what the other side
/// sent, a name out of a certificate for example, and it goes to the log: ADR-0009 wants
/// the certificate problem named there.
fn bounded(error: &dyn fmt::Display) -> String {
    const MAX_CHARS: usize = 200;
    error
        .to_string()
        .chars()
        .take(MAX_CHARS)
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

#[cfg(test)]
mod tests {
    use tokio_tungstenite::tungstenite;
    use tungstenite::client::IntoClientRequest;
    use tungstenite::http::HeaderValue;

    use super::*;

    fn offered() -> Vec<ProtocolVersion> {
        ProtocolVersion::supported().collect()
    }

    fn newest() -> String {
        offered()[0].subprotocol()
    }

    fn answer(selected: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("upgrade", HeaderValue::from_static("websocket"));
        for name in selected {
            headers.append("sec-websocket-protocol", name.parse().unwrap());
        }
        headers
    }

    #[test]
    fn the_selected_version_is_the_one_the_answer_names() {
        assert_eq!(
            negotiated_version(&offered(), &answer(&[&newest()])),
            Some(offered()[0])
        );
        for version in offered() {
            assert_eq!(
                negotiated_version(&offered(), &answer(&[&version.subprotocol()])),
                Some(version)
            );
        }
    }

    /// ADR-0007: an upgrade answered without a selected version is a failed handshake,
    /// and the agent never assumes a default.
    #[test]
    fn an_answer_that_does_not_name_exactly_one_offered_version_selects_nothing() {
        let newest = newest();
        let twice = format!("{newest}, {newest}");
        let cases: [&[&str]; 14] = [
            &[],
            &[""],
            &[&newest, &newest],
            &[&newest, "mqtt"],
            &["mqtt", &newest],
            &[&twice],
            &["ponte.v0"],
            &["ponte.v65535"],
            &["Ponte.v1"],
            &["ponte.V1"],
            &["ponte.v01"],
            &["ponte.v1.0"],
            &["mqtt"],
            &["ponte"],
        ];
        for selected in cases {
            assert_eq!(
                negotiated_version(&offered(), &answer(selected)),
                None,
                "{selected:?}"
            );
        }
        // Bytes that are not text.
        let mut headers = answer(&[]);
        headers.insert(
            "sec-websocket-protocol",
            HeaderValue::from_bytes(b"ponte.v1\xff").unwrap(),
        );
        assert_eq!(negotiated_version(&offered(), &headers), None);
    }

    /// A version this build speaks, and that was not in the offer of this connection.
    #[test]
    fn a_version_that_was_not_offered_is_not_selected() {
        assert_eq!(negotiated_version(&[], &answer(&[&newest()])), None);
    }

    #[test]
    fn the_upgrade_request_offers_every_version_newest_first_and_names_no_origin() {
        let url: ServerUrl = "wss://ponte.example.com/agent".parse().unwrap();
        let request = upgrade_request(&url, &offered())
            .unwrap()
            .into_client_request()
            .unwrap();

        let names: Vec<String> = offered().iter().map(|v| v.subprotocol()).collect();
        let offer: Vec<_> = request
            .headers()
            .get_all("sec-websocket-protocol")
            .iter()
            .collect();
        assert_eq!(offer, [names.join(", ").as_str()]);
        assert!(names[0].ends_with(&ponte_protocol::PROTOCOL_VERSION.to_string()));
        assert!(!request.headers().contains_key("origin"));
        assert_eq!(request.uri().path(), "/agent");
        assert_eq!(request.uri().host(), Some("ponte.example.com"));
    }

    /// Only the machine itself may be talked to without TLS.
    #[test]
    fn only_addresses_of_this_machine_are_loopback() {
        for local in [
            "127.0.0.1",
            "127.0.0.2",
            "127.255.255.254",
            "::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(is_loopback(local.parse().unwrap()), "{local}");
        }
        for remote in [
            "192.0.2.1",
            "10.0.0.1",
            "192.168.1.10",
            "169.254.1.1",
            "0.0.0.0",
            "128.0.0.1",
            "126.255.255.255",
            "::",
            "::2",
            "2001:db8::1",
            "fe80::1",
            "::ffff:192.0.2.1",
            "::ffff:128.0.0.1",
        ] {
            assert!(!is_loopback(remote.parse().unwrap()), "{remote}");
        }
    }

    /// `localhost` is a name, and the answer to a name can be forged or misconfigured. If
    /// it leads anywhere else, nothing is sent: not the upgrade, let alone a token.
    #[test]
    fn a_plain_connection_is_refused_unless_it_reached_this_machine() {
        for local in ["127.0.0.1", "::1"] {
            assert!(matches!(
                plain_to(local.parse().unwrap()),
                Ok(Connector::Plain)
            ));
        }
        for remote in ["192.0.2.1", "10.0.0.1", "2001:db8::1", "::ffff:192.0.2.1"] {
            assert!(
                matches!(
                    plain_to(remote.parse().unwrap()),
                    Err(ConnectError::NotLoopback)
                ),
                "{remote}"
            );
        }
    }

    /// The configuration builds on the machine that runs the tests, with the system's
    /// verifier and without a default provider installed for the process.
    #[test]
    fn the_tls_configuration_builds_and_is_kept() {
        let mut tls = Tls::default();
        let first = tls.config().unwrap();
        let second = tls.config().unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        assert!(first.alpn_protocols.is_empty());
    }

    #[test]
    fn errors_of_libraries_become_one_short_line() {
        let long = format!(
            "certificate for evil\r\n2026-01-01 INFO all good\u{1b}[2J {}",
            "x".repeat(500)
        );
        let line = bounded(&long);
        assert_eq!(line.chars().count(), 200);
        assert!(!line.chars().any(char::is_control));
        assert!(line.starts_with("certificate for evil  2026-01-01 INFO all good"));
    }

    #[test]
    fn an_upgrade_refused_with_a_status_keeps_only_the_status() {
        let response = tungstenite::http::Response::builder()
            .status(503)
            .header("x-reason", "whatever the other side wrote")
            .body(Some(b"whatever the other side wrote".to_vec()))
            .unwrap();
        let error = classify(WsError::Http(Box::new(response)));
        assert_eq!(error, ConnectError::Http(503));
        assert!(!error.to_string().contains("whatever"));
    }
}
