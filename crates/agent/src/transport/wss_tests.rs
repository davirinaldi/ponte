//! The agent's TLS over a real socket: `transport::connect` against a `wss://` server made
//! on the spot, with certificates from an authority made on the spot too.
//!
//! The configuration under test is the agent's own (`base`), with the system's verifier
//! given one more root: the test's authority. Every refusal has a twin that connects, to
//! the same kind of server with only the one thing wrong put right, so that a refusal
//! for any other reason cannot pass for the check.

use std::io;
use std::net::{SocketAddr, TcpListener};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, date_time_ymd,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned, SupportedProtocolVersion};
use tokio_tungstenite::tungstenite;
use tungstenite::handshake::server::{ErrorResponse, Request, Response};

use super::*;

/// An authority of the test's own, which no system trusts.
struct Authority(CertifiedIssuer<'static, KeyPair>);

impl Authority {
    fn new() -> Self {
        Self::named("Ponte test authority")
    }

    fn named(name: &str) -> Self {
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.not_before = date_time_ymd(2020, 1, 1);
        params.not_after = date_time_ymd(2100, 1, 1);
        Self(CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap())
    }

    fn root(&self) -> CertificateDer<'static> {
        self.0.der().clone()
    }

    /// A server certificate for `name` that is good today.
    fn leaf(&self, name: &str) -> Leaf {
        self.leaf_until(name, 2100)
    }

    fn leaf_until(&self, name: &str, year: i32) -> Leaf {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec![name.to_owned()]).unwrap();
        params.distinguished_name.push(DnType::CommonName, name);
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.not_before = date_time_ymd(2020, 1, 1);
        params.not_after = date_time_ymd(year, 1, 1);
        let certificate = params.signed_by(&key, &self.0).unwrap();
        Leaf {
            chain: vec![certificate.der().clone()],
            key: PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        }
    }
}

struct Leaf {
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

/// How the one connection a [`TlsServer`] takes went, on the server's side.
#[derive(Debug, PartialEq, Eq)]
enum Served {
    /// TLS and the upgrade both completed.
    Upgraded,
    /// The TLS handshake did not complete.
    Refused,
}

/// A `wss://` server on this machine that takes one connection: TLS with `leaf`, in the
/// given versions, then the upgrade, selecting the newest version the agent speaks.
struct TlsServer {
    addr: SocketAddr,
    served: mpsc::Receiver<Served>,
}

impl TlsServer {
    fn start(leaf: Leaf, versions: &[&'static SupportedProtocolVersion]) -> Self {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(versions)
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(leaf.chain, leaf.key)
            .unwrap();
        // The address `localhost` names first, which the agent tries first. On Windows, a
        // connection refused on another one costs two seconds.
        let listener = TcpListener::bind("localhost:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (report, served) = mpsc::channel();
        thread::spawn(move || {
            let Ok((stream, _)) = listener.accept() else {
                return;
            };
            // Nothing here should take long: a test that waits this much is stuck.
            let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
            let connection = ServerConnection::new(Arc::new(config)).unwrap();
            let mut tls = StreamOwned::new(connection, stream);
            let outcome = match handshake(&mut tls) {
                // A failure after TLS is no refusal: the thread panics, and `served` with it.
                Ok(()) => match tungstenite::accept_hdr(tls, select_newest) {
                    Ok(_) => Served::Upgraded,
                    Err(error) => panic!("the upgrade failed after TLS: {error}"),
                },
                Err(_) => Served::Refused,
            };
            let _ = report.send(outcome);
        });
        Self { addr, served }
    }

    fn url(&self, name: &str) -> ServerUrl {
        format!("wss://{name}:{}/agent", self.addr.port())
            .parse()
            .unwrap()
    }

    /// How the connection went on the server's side.
    fn served(&self) -> Served {
        self.served.recv_timeout(Duration::from_secs(30)).unwrap()
    }
}

/// Answers the upgrade by selecting the newest version the agent speaks.
// The signature of the callback is the library's: it is the one that makes the error large.
#[allow(clippy::result_large_err)]
fn select_newest(_: &Request, mut response: Response) -> Result<Response, ErrorResponse> {
    let newest = ProtocolVersion::supported().next().unwrap().subprotocol();
    response
        .headers_mut()
        .append("sec-websocket-protocol", newest.parse().unwrap());
    Ok(response)
}

/// Runs the TLS handshake to its end, without waiting for the client to write anything.
fn handshake(tls: &mut StreamOwned<ServerConnection, std::net::TcpStream>) -> io::Result<()> {
    while tls.conn.is_handshaking() {
        tls.conn.complete_io(&mut tls.sock)?;
    }
    Ok(())
}

/// The agent's configuration, trusting `authority` too.
fn agent_trusting(authority: &Authority) -> Arc<ClientConfig> {
    Arc::new(trusting([authority.root()]).unwrap())
}

async fn connect_to(
    url: ServerUrl,
    tls: Arc<ClientConfig>,
) -> Result<(ProtocolVersion, Socket), ConnectError> {
    tokio::time::timeout(Duration::from_secs(30), connect(url, Some(tls)))
        .await
        .expect("timed out")
}

#[tokio::test]
async fn ws_loopback_wss_connects_to_a_server_whose_root_the_test_trusts() {
    let authority = Authority::new();
    let server = TlsServer::start(authority.leaf("localhost"), &[&rustls::version::TLS13]);

    let (version, socket) = connect_to(server.url("localhost"), agent_trusting(&authority))
        .await
        .unwrap();

    assert_eq!(Some(version), ProtocolVersion::supported().next());
    assert!(matches!(socket.get_ref(), MaybeTlsStream::Rustls(_)));
    assert_eq!(server.served(), Served::Upgraded);
}

/// Connects with `tls` to a server that must refuse, and returns what the agent would log.
async fn refused(server: &TlsServer, tls: Arc<ClientConfig>) -> String {
    let error = match connect_to(server.url("localhost"), tls).await {
        Ok(_) => panic!("the agent connected"),
        Err(error) => error,
    };
    // The refusal came from TLS, on both sides: not from the upgrade, not from the socket.
    let ConnectError::Tls(problem) = &error else {
        panic!("not a TLS failure: {error:?}");
    };
    assert_eq!(server.served(), Served::Refused);
    // One short line of printable ASCII, as everything that goes to the log from here.
    assert!(problem.len() <= 200, "{problem}");
    assert!(
        problem.chars().all(|c| c == ' ' || c.is_ascii_graphic()),
        "{problem}"
    );
    problem.clone()
}

#[tokio::test]
async fn ws_loopback_wss_refuses_a_certificate_from_an_authority_it_does_not_trust() {
    let trusted = Authority::new();
    let stranger = Authority::named("Another test authority");
    let server = TlsServer::start(stranger.leaf("localhost"), &[&rustls::version::TLS13]);

    assert_eq!(
        refused(&server, agent_trusting(&trusted)).await,
        "the server's certificate is from an authority this machine does not trust"
    );
}

/// Another key under the trusted authority's very name. A verifier that matched issuers
/// by name alone would take it.
#[tokio::test]
async fn ws_loopback_wss_refuses_a_certificate_from_an_authority_that_copies_a_trusted_name() {
    let trusted = Authority::new();
    let impostor = Authority::new();
    let server = TlsServer::start(impostor.leaf("localhost"), &[&rustls::version::TLS13]);

    let problem = refused(&server, agent_trusting(&trusted)).await;
    // Windows and webpki tell this one in words of their own.
    assert!(problem.starts_with("the "), "{problem}");
    assert!(problem.contains("certificate"), "{problem}");
}

#[tokio::test]
async fn ws_loopback_wss_refuses_a_certificate_for_another_name() {
    let authority = Authority::new();
    let server = TlsServer::start(authority.leaf("other.example"), &[&rustls::version::TLS13]);

    let problem = refused(&server, agent_trusting(&authority)).await;
    // The names in the certificate are the server's to choose, and stay out of the log.
    assert_eq!(problem, "the server's certificate is for another name");
}

#[tokio::test]
async fn ws_loopback_wss_refuses_an_expired_certificate() {
    let authority = Authority::new();
    let server = TlsServer::start(
        authority.leaf_until("localhost", 2021),
        &[&rustls::version::TLS13],
    );

    assert_eq!(
        refused(&server, agent_trusting(&authority)).await,
        "the server's certificate has expired"
    );
}

/// RNF-01. The server's certificate is good: only the version is wrong.
#[tokio::test]
async fn ws_loopback_wss_refuses_a_server_that_only_speaks_tls_1_2() {
    let authority = Authority::new();
    let server = TlsServer::start(authority.leaf("localhost"), &[&rustls::version::TLS12]);

    let problem = refused(&server, agent_trusting(&authority)).await;
    assert_eq!(problem, "the server does not speak TLS 1.3");
}

/// The agent's own configuration, as it connects in production: the test's authority is
/// in no store of this machine.
fn agent() -> Arc<ClientConfig> {
    Tls::default().config().unwrap()
}

#[tokio::test]
async fn ws_loopback_wss_the_agent_trusts_no_authority_of_a_test() {
    let authority = Authority::new();
    let server = TlsServer::start(authority.leaf("localhost"), &[&rustls::version::TLS13]);

    assert_eq!(
        refused(&server, agent()).await,
        "the server's certificate is from an authority this machine does not trust"
    );
}

/// The versions are agreed before the certificate is looked at: a configuration of the
/// agent's that allowed TLS 1.2 would fail on the certificate instead.
#[tokio::test]
async fn ws_loopback_wss_the_agent_refuses_tls_1_2_before_the_certificate() {
    let authority = Authority::new();
    let server = TlsServer::start(authority.leaf("localhost"), &[&rustls::version::TLS12]);

    assert_eq!(
        refused(&server, agent()).await,
        "the server does not speak TLS 1.3"
    );
}
