use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use ponte_actions::PathPolicy;
use serde::Deserialize;

/// Agent configuration, read from a TOML file written by the installer.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    /// Control-plane URL. Must be `wss://`; plain `ws://` is accepted only for localhost.
    pub server_url: ServerUrl,
    /// Directories that file-touching actions may access.
    #[serde(default)]
    pub allowed_roots: Vec<String>,
    /// Where the agent keeps its device key and its identity. Only administrators may
    /// write here: whoever can replace these files decides who the device is. A relative
    /// path is taken from the working directory, which suits development only.
    pub data_dir: PathBuf,
    /// File holding the enrollment token (RF-01), 64 lowercase hex characters. The agent
    /// reads it to enroll and removes it once enrolled. Not needed after that.
    #[serde(default)]
    pub enrollment_token_file: Option<PathBuf>,
    /// Seconds between heartbeats, from 10 to 3600.
    #[serde(default = "default_heartbeat_secs")]
    pub heartbeat_secs: u64,
}

const fn default_heartbeat_secs() -> u64 {
    60
}

/// Why a configuration was refused.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read the file: {0}")]
    Read(#[from] std::io::Error),
    #[error("{0}")]
    Parse(#[from] toml::de::Error),
    #[error("invalid allowed root `{0}`")]
    AllowedRoot(String),
    #[error("data_dir must not be empty")]
    DataDir,
    #[error("enrollment_token_file must not be empty")]
    TokenFile,
    #[error("heartbeat_secs must be between 10 and 3600")]
    Heartbeat,
}

impl AgentConfig {
    /// Reads and validates the file at `path`.
    ///
    /// # Errors
    /// The file cannot be read, is not what [`AgentConfig`] expects, or holds a value
    /// outside its limits. Nothing is repaired: a configuration is taken whole or not at all.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        std::fs::read_to_string(path)?.parse()
    }

    fn validate(&self) -> Result<(), ConfigError> {
        PathPolicy::new(&self.allowed_roots).map_err(ConfigError::AllowedRoot)?;
        if self.data_dir.as_os_str().is_empty() {
            return Err(ConfigError::DataDir);
        }
        if matches!(&self.enrollment_token_file, Some(file) if file.as_os_str().is_empty()) {
            return Err(ConfigError::TokenFile);
        }
        if !(10..=3600).contains(&self.heartbeat_secs) {
            return Err(ConfigError::Heartbeat);
        }
        Ok(())
    }
}

impl FromStr for AgentConfig {
    type Err = ConfigError;

    fn from_str(toml: &str) -> Result<Self, Self::Err> {
        let config: Self = toml::from_str(toml)?;
        config.validate()?;
        Ok(config)
    }
}

/// Whether the connection to the server is encrypted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Security {
    /// `wss://`: TLS, with the certificate checked against the system's store (ADR-0009).
    Tls,
    /// `ws://` to this very machine, for development. The transport checks again that the
    /// address it connected to is a loopback one.
    PlainLoopback,
}

/// Where the server is. It only exists for `wss://`, or for `ws://` to this machine, so
/// nothing that holds one can send a token or a signature in the clear over a network.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct ServerUrl {
    text: String,
    security: Security,
    host: String,
    port: u16,
}

/// The URL is not one the agent connects to. Says which rule it broke, not what it was.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InvalidServerUrl {
    #[error("server_url must use wss:// (ws:// is only allowed for localhost)")]
    Scheme,
    #[error("server_url must name a host, with no user name, and an optional numeric port")]
    Authority,
    #[error("server_url must not have a fragment, spaces or control characters")]
    Path,
}

impl ServerUrl {
    pub(crate) fn security(&self) -> Security {
        self.security
    }

    pub(crate) fn host(&self) -> &str {
        &self.host
    }

    pub(crate) fn port(&self) -> u16 {
        self.port
    }

    /// The whole URL, as the upgrade request names it.
    pub(crate) fn as_str(&self) -> &str {
        &self.text
    }
}

impl FromStr for ServerUrl {
    type Err = InvalidServerUrl;

    fn from_str(url: &str) -> Result<Self, Self::Err> {
        let (security, rest) = if let Some(rest) = url.strip_prefix("wss://") {
            (Security::Tls, rest)
        } else if let Some(rest) = url.strip_prefix("ws://") {
            (Security::PlainLoopback, rest)
        } else {
            return Err(InvalidServerUrl::Scheme);
        };
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, path) = rest.split_at(end);
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        };

        // Letters, digits, dots and hyphens: no user name, no brackets, no backslash. The
        // host checked here is then the only host any library can read out of the URL,
        // which is what stops `localhost:80@evil.example` and its relatives.
        let plain_name = |host: &str| {
            host.bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-')
        };
        if host.is_empty() || !plain_name(host) {
            return Err(InvalidServerUrl::Authority);
        }
        let port = match port {
            None if security == Security::Tls => 443,
            None => 80,
            // Digits only: `str::parse` alone would also take `+443`.
            Some(port) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => port
                .parse()
                .ok()
                .filter(|port| *port != 0)
                .ok_or(InvalidServerUrl::Authority)?,
            Some(_) => return Err(InvalidServerUrl::Authority),
        };
        // The path goes into the request line as it is.
        let plain_path = (path.is_empty() || path.starts_with('/'))
            && path
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && byte != b'#');
        if !plain_path {
            return Err(InvalidServerUrl::Path);
        }
        // The names must match exactly: a prefix test would take `localhost.evil.example`.
        if security == Security::PlainLoopback && !matches!(host, "localhost" | "127.0.0.1") {
            return Err(InvalidServerUrl::Scheme);
        }

        Ok(Self {
            text: url.to_owned(),
            security,
            host: host.to_owned(),
            port,
        })
    }
}

impl TryFrom<String> for ServerUrl {
    type Error = InvalidServerUrl;

    fn try_from(url: String) -> Result<Self, Self::Error> {
        url.parse()
    }
}

impl fmt::Display for ServerUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

impl fmt::Debug for ServerUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ServerUrl({})", self.text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(text: &str) -> Result<ServerUrl, InvalidServerUrl> {
        text.parse()
    }

    fn config(toml: &str) -> Result<AgentConfig, ConfigError> {
        toml.parse()
    }

    /// A configuration with `more` added to the two fields every one needs.
    fn with(more: &str) -> Result<AgentConfig, ConfigError> {
        config(&format!(
            "server_url = \"wss://ponte.example.com/agent\"\ndata_dir = \"data\"\n{more}"
        ))
    }

    #[test]
    fn requires_tls_except_on_localhost() {
        assert!(url("wss://ponte.example.com/agent").is_ok());
        assert!(url("ws://localhost:8080/agent").is_ok());
        assert_eq!(
            url("ws://ponte.example.com/agent"),
            Err(InvalidServerUrl::Scheme)
        );
        for other in [
            "https://ponte.example.com",
            "http://localhost",
            "WSS://ponte.example.com",
            "wss:/ponte.example.com",
            "ponte.example.com",
            "",
        ] {
            assert_eq!(url(other), Err(InvalidServerUrl::Scheme), "{other}");
        }
    }

    #[test]
    fn localhost_exception_matches_the_exact_host() {
        for text in [
            "ws://localhost",
            "ws://localhost/agent",
            "ws://localhost:8080",
            "ws://127.0.0.1:8080/agent?x=1",
        ] {
            assert_eq!(
                url(text).map(|url| url.security()),
                Ok(Security::PlainLoopback),
                "{text}"
            );
        }
        for text in [
            "ws://localhost.evil.example/agent",
            "ws://127.0.0.1.evil.example:8080",
            "ws://localhostevil.example",
            "ws://localhost@evil.example/agent",
            "ws://localhost:8080@evil.example/agent",
            "ws://localhost:8080.evil.example",
            "ws://localhost:",
            r"ws://localhost\@evil.example",
            "ws://",
            "ws://LOCALHOST",
            "ws://127.0.0.2",
            "ws://[::1]:8080",
            "ws://0.0.0.0:8080",
        ] {
            assert!(url(text).is_err(), "{text}");
        }
    }

    #[test]
    fn the_parts_are_what_the_transport_connects_to() {
        let tls = url("wss://ponte.example.com/agent").unwrap();
        assert_eq!(tls.security(), Security::Tls);
        assert_eq!((tls.host(), tls.port()), ("ponte.example.com", 443));
        assert_eq!(tls.as_str(), "wss://ponte.example.com/agent");
        assert_eq!(tls.to_string(), "wss://ponte.example.com/agent");

        let with_port = url("wss://ponte.example.com:8443").unwrap();
        assert_eq!(
            (with_port.host(), with_port.port()),
            ("ponte.example.com", 8443)
        );

        let plain = url("ws://localhost").unwrap();
        assert_eq!((plain.host(), plain.port()), ("localhost", 80));
        let plain = url("ws://127.0.0.1:8080/agent").unwrap();
        assert_eq!((plain.host(), plain.port()), ("127.0.0.1", 8080));
    }

    /// Everything that could make the host the agent checks differ from the host a
    /// library connects to, or put a secret where a proxy logs it.
    #[test]
    fn urls_with_more_than_a_host_a_port_and_a_path_are_refused() {
        for text in [
            "wss://user@ponte.example.com/agent",
            "wss://user:secret@ponte.example.com/agent",
            "wss://ponte.example.com:0/agent",
            "wss://ponte.example.com:65536/agent",
            "wss://ponte.example.com:+443/agent",
            "wss://ponte.example.com:44a/agent",
            "wss://:443/agent",
            "wss:///agent",
            "wss://ponte example.com/agent",
            "wss://ponte.example.com\\agent",
            "wss://ponte_example.com/agent",
            "wss://pont\u{e9}.example.com/agent",
            "wss://[2001:db8::1]/agent",
        ] {
            assert_eq!(url(text), Err(InvalidServerUrl::Authority), "{text}");
        }
        for text in [
            "wss://ponte.example.com/agent#fragment",
            "wss://ponte.example.com/a gent",
            "wss://ponte.example.com/agent\r\nX-Injected: 1",
            "wss://ponte.example.com/agent\t",
            "wss://ponte.example.com/agent\u{e9}",
            "wss://ponte.example.com#fragment",
        ] {
            assert_eq!(url(text), Err(InvalidServerUrl::Path), "{text}");
        }
    }

    #[test]
    fn rejects_invalid_roots() {
        assert!(with(r"allowed_roots = ['C:\FakeErp']").is_ok());
        assert!(matches!(
            with(r"allowed_roots = ['..\FakeErp']"),
            Err(ConfigError::AllowedRoot(_))
        ));
    }

    #[test]
    fn heartbeat_interval_has_limits_and_a_default() {
        assert_eq!(with("").unwrap().heartbeat_secs, 60);
        assert_eq!(with("heartbeat_secs = 10").unwrap().heartbeat_secs, 10);
        assert_eq!(with("heartbeat_secs = 3600").unwrap().heartbeat_secs, 3600);
        for outside in ["0", "9", "3601", "18446744073709551615"] {
            assert!(
                matches!(
                    with(&format!("heartbeat_secs = {outside}")),
                    Err(ConfigError::Heartbeat)
                ),
                "{outside}"
            );
        }
        assert!(matches!(
            with("heartbeat_secs = -1"),
            Err(ConfigError::Parse(_))
        ));
    }

    #[test]
    fn the_data_directory_is_required_and_the_token_file_is_not() {
        assert!(matches!(
            config("server_url = \"wss://ponte.example.com\""),
            Err(ConfigError::Parse(_))
        ));
        assert!(matches!(
            config("server_url = \"wss://ponte.example.com\"\ndata_dir = \"\""),
            Err(ConfigError::DataDir)
        ));
        assert!(matches!(
            with("enrollment_token_file = \"\""),
            Err(ConfigError::TokenFile)
        ));

        let config = with("").unwrap();
        assert_eq!(config.data_dir, PathBuf::from("data"));
        assert_eq!(config.enrollment_token_file, None);
        let config = with("enrollment_token_file = \"data/token\"").unwrap();
        assert_eq!(
            config.enrollment_token_file,
            Some(PathBuf::from("data/token"))
        );
    }

    #[test]
    fn an_invalid_url_or_an_unknown_field_refuses_the_whole_file() {
        assert!(matches!(
            config("server_url = \"ws://ponte.example.com\"\ndata_dir = \"data\""),
            Err(ConfigError::Parse(_))
        ));
        assert!(matches!(
            with("skip_certificate_check = true"),
            Err(ConfigError::Parse(_))
        ));
    }

    #[test]
    fn example_config_parses() {
        let config = config(include_str!("../agent.example.toml")).unwrap();
        assert_eq!(config.server_url.security(), Security::PlainLoopback);
        assert!(config.enrollment_token_file.is_some());
    }
}
