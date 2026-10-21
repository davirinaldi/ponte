use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use ponte_actions::{
    AllowedServices, AllowedServicesError, InvalidRoot, LocalPolicy, PathPolicy, RiskCeiling,
    Roots, TrustedKeys, TrustedKeysError,
};
use ponte_protocol::{PublicKey, ServiceName};
use serde::Deserialize;

/// Agent configuration, read from a TOML file written by the installer.
///
/// It is a root of trust (ADR-0011): `manifest_keys` and the local policy decide what the
/// agent runs as SYSTEM, so only administrators may be able to change the file.
#[derive(Debug)]
pub struct AgentConfig {
    /// Control-plane URL. Must be `wss://`; plain `ws://` is accepted only for localhost.
    /// It is written to the log: never put a secret in it.
    pub server_url: ServerUrl,
    /// Directories that file-touching actions may access. None may be a drive, a system
    /// folder or a folder every user shares, and names hold printable ASCII and Latin
    /// letters only, without dashes or quotes from a word processor (ADR-0011).
    pub allowed_roots: Vec<String>,
    /// Where `delete_file` may act, as written: the machine resolves them when the agent
    /// starts (ADR-0011).
    pub(crate) delete_roots: Vec<String>,
    /// Where the agent keeps its device key, its identity, its journal and its clock
    /// mark. Only administrators may write here: whoever can replace these files decides
    /// who the device is and what it already ran. A relative path is taken from the
    /// working directory, which suits development only.
    pub data_dir: PathBuf,
    /// File holding the enrollment token (RF-01), 64 lowercase hex characters. The agent
    /// reads it to enroll and removes it once enrolled. Not needed after that. Like
    /// `data_dir`, it belongs where only administrators can write: the agent, running as
    /// SYSTEM, deletes whatever is at this path.
    pub enrollment_token_file: Option<PathBuf>,
    /// Seconds between heartbeats, from 10 to 3600.
    pub heartbeat_secs: u64,
    /// What the agent runs, built from the fields of ADR-0010 and ADR-0011.
    pub(crate) actions: ActionSettings,
}

/// The file as written. [`AgentConfig`] is what is left once every rule held.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    server_url: ServerUrl,
    #[serde(default)]
    allowed_roots: Vec<String>,
    data_dir: PathBuf,
    #[serde(default)]
    enrollment_token_file: Option<PathBuf>,
    #[serde(default = "default_heartbeat_secs")]
    heartbeat_secs: u64,
    /// The manifest keys this agent trusts, 1 to 4 (ADR-0010). Without the field no action
    /// runs at all; an empty list is a mistake, not another way of saying so.
    #[serde(default)]
    manifest_keys: Option<Vec<PublicKey>>,
    /// `read`, `low` or `medium`. `high` waits for the consent prompt of M4 and does not
    /// parse (ADR-0011).
    #[serde(default)]
    max_risk: RiskCeiling,
    #[serde(default)]
    allowed_services: Vec<ServiceName>,
    /// Where `delete_file` may act, each inside an allowed root.
    #[serde(default)]
    delete_roots: Vec<String>,
    #[serde(default = "default_max_actions_per_hour")]
    max_actions_per_hour: u32,
    #[serde(default = "default_min_manifest_interval_secs")]
    min_manifest_interval_secs: u64,
    #[serde(default = "default_shutdown_timeout_secs")]
    shutdown_timeout_secs: u64,
}

const fn default_heartbeat_secs() -> u64 {
    60
}

const fn default_max_actions_per_hour() -> u32 {
    20
}

const fn default_min_manifest_interval_secs() -> u64 {
    600
}

const fn default_shutdown_timeout_secs() -> u64 {
    10
}

/// What the agent needs to decide on a request, from the configuration (ADR-0010,
/// ADR-0011, ADR-0013).
#[derive(Debug, Clone)]
pub(crate) struct ActionSettings {
    /// `None` when the configuration names no manifest key: then nothing runs.
    pub(crate) keys: Option<TrustedKeys>,
    pub(crate) policy: LocalPolicy,
    /// Requests marked "started" in the last hour, 1 to 60.
    pub(crate) max_per_hour: u32,
    /// Between two starts of the same manifest id, 60 to 86 400 seconds.
    pub(crate) min_interval_secs: u64,
    /// How long a stop waits for the running action, 1 to 60 seconds.
    pub(crate) shutdown_timeout: Duration,
}

/// Why a configuration was refused.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read the file: {0}")]
    Read(#[from] std::io::Error),
    #[error("{0}")]
    Parse(#[from] toml::de::Error),
    #[error("allowed_roots: {0}")]
    AllowedRoot(InvalidRoot),
    #[error("delete_roots: {0}")]
    DeleteRoot(InvalidRoot),
    #[error("data_dir must not be empty")]
    DataDir,
    #[error("enrollment_token_file must not be empty")]
    TokenFile,
    #[error("heartbeat_secs must be between 10 and 3600")]
    Heartbeat,
    #[error("manifest_keys: {0}")]
    ManifestKeys(TrustedKeysError),
    #[error("allowed_services: {0}")]
    AllowedServices(AllowedServicesError),
    #[error("allowed_services names the agent's own service")]
    OwnService,
    #[error("max_actions_per_hour must be between 1 and 60")]
    MaxActionsPerHour,
    #[error("min_manifest_interval_secs must be between 60 and 86400")]
    ManifestInterval,
    #[error("shutdown_timeout_secs must be between 1 and 60")]
    ShutdownTimeout,
    #[error("{0} must not lie inside an allowed root, nor hold one (ADR-0011)")]
    InsideRoot(&'static str),
    #[error(
        "{0} cannot be compared with allowed_roots: write it as an absolute path with long \
         names (no `~`) in printable ASCII and Latin letters"
    )]
    NotComparable(&'static str),
    #[error("the folder of the agent's own executable cannot be found")]
    NoExecutable,
}

impl ConfigError {
    /// The setting at fault, or the file itself: what the Event Log gets, since the error's
    /// text may quote the file (ADR-0013).
    #[must_use]
    pub fn setting(&self) -> &'static str {
        match self {
            Self::Read(_) | Self::Parse(_) => "the file",
            Self::AllowedRoot(_) => "allowed_roots",
            Self::DeleteRoot(_) => "delete_roots",
            Self::DataDir => "data_dir",
            Self::TokenFile => "enrollment_token_file",
            Self::Heartbeat => "heartbeat_secs",
            Self::ManifestKeys(_) => "manifest_keys",
            Self::AllowedServices(_) | Self::OwnService => "allowed_services",
            Self::MaxActionsPerHour => "max_actions_per_hour",
            Self::ManifestInterval => "min_manifest_interval_secs",
            Self::ShutdownTimeout => "shutdown_timeout_secs",
            Self::InsideRoot(what) | Self::NotComparable(what) => what,
            Self::NoExecutable => "the agent's executable",
        }
    }

    /// The line of `text` where the file stopped parsing, if this is that error. A number,
    /// never the text around it.
    #[must_use]
    pub fn line_in(&self, text: &str) -> Option<usize> {
        let Self::Parse(error) = self else {
            return None;
        };
        let start = error.span()?.start;
        Some(text.get(..start)?.matches('\n').count() + 1)
    }
}

impl AgentConfig {
    /// Reads and validates the file at `path`, for an agent that is not registered as a
    /// service.
    ///
    /// # Errors
    /// As [`AgentConfig::load_as`].
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        Self::load_as(path, None)
    }

    /// Reads and validates the file at `path` for an agent registered with the service
    /// manager as `registered_as`, which `allowed_services` may not name: a manifest must
    /// never stop the agent that runs it. Besides what [`FromStr`] checks, neither the file
    /// nor the folder of the agent's executable may lie inside an allowed root or hold one.
    ///
    /// # Errors
    /// The file cannot be read, is not what [`AgentConfig`] expects, or holds a value
    /// outside its limits. Nothing is repaired: a configuration is taken whole or not at all.
    pub fn load_as(
        path: impl AsRef<Path>,
        registered_as: Option<&ServiceName>,
    ) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        Self::from_file_text(path, &std::fs::read_to_string(path)?, registered_as)
    }

    /// [`AgentConfig::load_as`] for a file already read as `text`.
    pub(crate) fn from_file_text(
        path: &Path,
        text: &str,
        registered_as: Option<&ServiceName>,
    ) -> Result<Self, ConfigError> {
        let config: Self = text.parse()?;
        let executable = std::env::current_exe().map_err(|_| ConfigError::NoExecutable)?;
        let folder = executable.parent().ok_or(ConfigError::NoExecutable)?;
        config.check_place(path, folder, registered_as)?;
        Ok(config)
    }

    /// The rules of [`AgentConfig::load_as`] that need to know where the agent stands.
    fn check_place(
        &self,
        file: &Path,
        executable_folder: &Path,
        registered_as: Option<&ServiceName>,
    ) -> Result<(), ConfigError> {
        let roots = &self.actions.policy.roots;
        outside_roots(roots, file, "the configuration file")?;
        outside_roots(
            roots,
            executable_folder,
            "the folder of the agent's executable",
        )?;
        if registered_as.is_some_and(|name| self.actions.policy.services.contains(name.as_str())) {
            return Err(ConfigError::OwnService);
        }
        Ok(())
    }

    fn from_raw(raw: RawConfig) -> Result<Self, ConfigError> {
        PathPolicy::new(&raw.allowed_roots).map_err(ConfigError::AllowedRoot)?;
        let roots =
            Roots::new(&raw.allowed_roots, &raw.delete_roots).map_err(ConfigError::DeleteRoot)?;
        if raw.data_dir.as_os_str().is_empty() {
            return Err(ConfigError::DataDir);
        }
        if matches!(&raw.enrollment_token_file, Some(file) if file.as_os_str().is_empty()) {
            return Err(ConfigError::TokenFile);
        }
        if !(10..=3600).contains(&raw.heartbeat_secs) {
            return Err(ConfigError::Heartbeat);
        }
        outside_roots(&roots, &raw.data_dir, "data_dir")?;
        if let Some(token) = &raw.enrollment_token_file {
            outside_roots(&roots, token, "enrollment_token_file")?;
        }
        let keys = raw
            .manifest_keys
            .map(TrustedKeys::new)
            .transpose()
            .map_err(ConfigError::ManifestKeys)?;
        let services =
            AllowedServices::new(raw.allowed_services).map_err(ConfigError::AllowedServices)?;
        if !(1..=60).contains(&raw.max_actions_per_hour) {
            return Err(ConfigError::MaxActionsPerHour);
        }
        if !(60..=86_400).contains(&raw.min_manifest_interval_secs) {
            return Err(ConfigError::ManifestInterval);
        }
        if !(1..=60).contains(&raw.shutdown_timeout_secs) {
            return Err(ConfigError::ShutdownTimeout);
        }
        Ok(Self {
            server_url: raw.server_url,
            allowed_roots: raw.allowed_roots,
            delete_roots: raw.delete_roots,
            data_dir: raw.data_dir,
            enrollment_token_file: raw.enrollment_token_file,
            heartbeat_secs: raw.heartbeat_secs,
            actions: ActionSettings {
                keys,
                policy: LocalPolicy {
                    roots,
                    services,
                    max_risk: raw.max_risk,
                },
                max_per_hour: raw.max_actions_per_hour,
                min_interval_secs: raw.min_manifest_interval_secs,
                shutdown_timeout: Duration::from_secs(raw.shutdown_timeout_secs),
            },
        })
    }

    /// Whether the configuration names manifest keys, without which no action runs.
    #[must_use]
    pub fn actions_enabled(&self) -> bool {
        self.actions.keys.is_some()
    }
}

impl FromStr for AgentConfig {
    type Err = ConfigError;

    fn from_str(toml: &str) -> Result<Self, Self::Err> {
        Self::from_raw(toml::from_str(toml)?)
    }
}

/// Refuses `path` if it lies inside a root or holds one (ADR-0011). `what` names the
/// setting, for the error.
///
/// A path written as a Windows path is compared as it is, on every system. On Windows,
/// one that is not is made absolute first, and one that still cannot be compared refuses
/// the configuration. Elsewhere a path of the system cannot lie under a root, which is
/// always a Windows path. The path as it resolves on the disk is the Windows layer's
/// concern (milestone M2, step 5).
fn outside_roots(roots: &Roots, path: &Path, what: &'static str) -> Result<(), ConfigError> {
    let verdict = |overlaps| {
        if overlaps {
            Err(ConfigError::InsideRoot(what))
        } else {
            Ok(())
        }
    };
    match roots.overlaps(&path.to_string_lossy()) {
        Ok(overlaps) => return verdict(overlaps),
        Err(_) if !cfg!(windows) => return Ok(()),
        Err(_) => {}
    }
    let absolute = std::path::absolute(path).map_err(|_| ConfigError::NotComparable(what))?;
    match roots.overlaps(&absolute.to_string_lossy()) {
        Ok(overlaps) => verdict(overlaps),
        Err(_) => Err(ConfigError::NotComparable(what)),
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
    use ponte_actions::RootRule;

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
        for forbidden in [r"C:\", r"C:\Windows", r"C:\ProgramData", r"C:\Users\joana"] {
            assert!(
                matches!(
                    with(&format!("allowed_roots = ['{forbidden}']")),
                    Err(ConfigError::AllowedRoot(_))
                ),
                "{forbidden}"
            );
        }
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

    fn key_hex(seed: u8) -> String {
        let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        PublicKey::from_bytes(key.verifying_key().to_bytes()).to_string()
    }

    fn keys(hex: &[String]) -> String {
        let quoted: Vec<String> = hex.iter().map(|key| format!("\"{key}\"")).collect();
        format!("manifest_keys = [{}]", quoted.join(", "))
    }

    #[test]
    fn the_settings_of_actions_have_defaults() {
        let config = with("").unwrap();
        let actions = &config.actions;
        assert!(actions.keys.is_none());
        assert!(!config.actions_enabled());
        assert_eq!(actions.policy.max_risk, RiskCeiling::Medium);
        assert!(!actions.policy.services.contains("FakeErp"));
        assert!(
            !actions
                .policy
                .roots
                .delete()
                .is_allowed(r"C:\FakeErp\run\erp.lock")
        );
        assert_eq!(actions.max_per_hour, 20);
        assert_eq!(actions.min_interval_secs, 600);
        assert_eq!(actions.shutdown_timeout, Duration::from_secs(10));
    }

    /// Without `manifest_keys` nothing runs. An empty list is a mistake, and so is a key
    /// that signs anything or a list a rotation does not need.
    #[test]
    fn manifest_keys_are_one_to_four_usable_keys() {
        let one = with(&keys(&[key_hex(1)])).unwrap();
        assert!(one.actions_enabled());
        assert_eq!(one.actions.keys.unwrap().keys().count(), 1);
        let four: Vec<String> = (1..=4).map(key_hex).collect();
        assert!(with(&keys(&four)).unwrap().actions_enabled());

        let refused = |toml: &str| match with(toml) {
            Err(ConfigError::ManifestKeys(error)) => error,
            other => panic!("{toml}: {other:?}"),
        };
        assert_eq!(refused("manifest_keys = []"), TrustedKeysError::Empty);
        let five: Vec<String> = (1..=5).map(key_hex).collect();
        assert_eq!(refused(&keys(&five)), TrustedKeysError::TooMany);
        assert_eq!(
            refused(&keys(&[key_hex(1), key_hex(1)])),
            TrustedKeysError::Duplicate(1)
        );
        // The identity point: small order, so it "verifies" forged signatures.
        let weak = format!("01{}", "00".repeat(31));
        assert_eq!(refused(&keys(&[weak])), TrustedKeysError::Weak(0));
        for not_hex in ["\"zz\"", "\"\"", "1"] {
            let toml = format!("manifest_keys = [{not_hex}]");
            assert!(
                matches!(with(&toml), Err(ConfigError::Parse(_))),
                "{not_hex}"
            );
        }
        let upper = key_hex(1).to_ascii_uppercase();
        assert!(matches!(with(&keys(&[upper])), Err(ConfigError::Parse(_))));
    }

    /// `high` waits for the consent prompt of M4 (ADR-0011).
    #[test]
    fn max_risk_stops_at_medium() {
        for (text, ceiling) in [
            ("read", RiskCeiling::Read),
            ("low", RiskCeiling::Low),
            ("medium", RiskCeiling::Medium),
        ] {
            let config = with(&format!("max_risk = \"{text}\"")).unwrap();
            assert_eq!(config.actions.policy.max_risk, ceiling);
        }
        for refused in ["high", "High", "MEDIUM", ""] {
            assert!(
                matches!(
                    with(&format!("max_risk = \"{refused}\"")),
                    Err(ConfigError::Parse(_))
                ),
                "{refused}"
            );
        }
    }

    /// The compiled list of refused services wins over the configuration, whatever the case.
    #[test]
    fn allowed_services_never_name_a_refused_one() {
        let config = with("allowed_services = [\"FakeErp\", \"MSSQL$SQLEXPRESS\"]").unwrap();
        assert!(config.actions.policy.services.contains("fakeerp"));
        assert!(config.actions.policy.services.contains("MSSQL$SQLEXPRESS"));

        for refused in ["WinDefend", "windefend", "PonteAgent", "EventLog"] {
            let toml = format!("allowed_services = [\"FakeErp\", \"{refused}\"]");
            assert!(
                matches!(
                    with(&toml),
                    Err(ConfigError::AllowedServices(AllowedServicesError::Refused(
                        1
                    )))
                ),
                "{refused}"
            );
        }
        assert!(matches!(
            with("allowed_services = [\"FakeErp\", \"FAKEERP\"]"),
            Err(ConfigError::AllowedServices(
                AllowedServicesError::Duplicate(1)
            ))
        ));
        let many: Vec<String> = (0..33).map(|i| format!("\"Erp{i}\"")).collect();
        assert!(matches!(
            with(&format!("allowed_services = [{}]", many.join(","))),
            Err(ConfigError::AllowedServices(AllowedServicesError::TooMany))
        ));
        for not_a_name in ["Fake Erp ", "\u{e9}rp", "a\\b", ""] {
            let toml = format!("allowed_services = [\"{not_a_name}\"]");
            assert!(
                matches!(with(&toml), Err(ConfigError::Parse(_))),
                "{not_a_name}"
            );
        }
    }

    /// A manifest must never stop the agent that runs it, under whatever name the service
    /// manager knows it by.
    #[test]
    fn allowed_services_never_name_the_agent_itself() {
        let config = with(r"allowed_services = ['FakeErp', 'PonteAgentAcme']").unwrap();
        let place = |name: &str| {
            config.check_place(
                Path::new(r"C:\ProgramData\Ponte\agent.toml"),
                Path::new(r"C:\Program Files\Ponte"),
                Some(&name.parse().unwrap()),
            )
        };
        assert!(matches!(
            place("PonteAgentAcme"),
            Err(ConfigError::OwnService)
        ));
        assert!(matches!(
            place("ponteagentacme"),
            Err(ConfigError::OwnService)
        ));
        assert!(place("PonteAgent").is_ok());
        assert!(
            config
                .check_place(
                    Path::new(r"C:\ProgramData\Ponte\agent.toml"),
                    Path::new(r"C:\Program Files\Ponte"),
                    None
                )
                .is_ok()
        );
    }

    #[test]
    fn delete_roots_lie_inside_allowed_roots() {
        let config = with(
            r"allowed_roots = ['C:\FakeErp']
delete_roots = ['C:\FakeErp\run']",
        )
        .unwrap();
        let roots = &config.actions.policy.roots;
        assert!(roots.delete().is_allowed(r"C:\FakeErp\run\erp.lock"));
        assert!(!roots.delete().is_allowed(r"C:\FakeErp\data\erp.db"));
        assert!(roots.allowed().is_allowed(r"C:\FakeErp\data\erp.db"));

        for (toml, rule) in [
            (
                "allowed_roots = ['C:\\FakeErp']\ndelete_roots = ['C:\\Other']",
                RootRule::OutsideAllowedRoots,
            ),
            (
                "delete_roots = ['C:\\FakeErp\\run']",
                RootRule::OutsideAllowedRoots,
            ),
            (
                "allowed_roots = ['C:\\FakeErp']\ndelete_roots = ['C:\\']",
                RootRule::Drive,
            ),
        ] {
            match with(toml) {
                Err(ConfigError::DeleteRoot(error)) => assert_eq!(error.rule, rule, "{toml}"),
                other => panic!("{toml}: {other:?}"),
            }
        }
    }

    #[test]
    fn the_limits_of_actions_have_bounds() {
        for (field, inside, outside) in [
            (
                "max_actions_per_hour",
                &[1_u64, 20, 60][..],
                &[0_u64, 61][..],
            ),
            (
                "min_manifest_interval_secs",
                &[60, 600, 86_400],
                &[0, 59, 86_401],
            ),
            ("shutdown_timeout_secs", &[1, 10, 60], &[0, 61]),
        ] {
            for value in inside {
                assert!(
                    with(&format!("{field} = {value}")).is_ok(),
                    "{field} = {value}"
                );
            }
            for value in outside {
                let refused = with(&format!("{field} = {value}"));
                let right = match field {
                    "max_actions_per_hour" => {
                        matches!(refused, Err(ConfigError::MaxActionsPerHour))
                    }
                    "min_manifest_interval_secs" => {
                        matches!(refused, Err(ConfigError::ManifestInterval))
                    }
                    _ => matches!(refused, Err(ConfigError::ShutdownTimeout)),
                };
                assert!(right, "{field} = {value}: {refused:?}");
            }
            assert!(matches!(
                with(&format!("{field} = -1")),
                Err(ConfigError::Parse(_))
            ));
        }
        let config = with(
            "max_actions_per_hour = 7\nmin_manifest_interval_secs = 120\nshutdown_timeout_secs = 3",
        )
        .unwrap();
        assert_eq!(config.actions.max_per_hour, 7);
        assert_eq!(config.actions.min_interval_secs, 120);
        assert_eq!(config.actions.shutdown_timeout, Duration::from_secs(3));
    }

    /// A manifest that may delete in a root must not be able to delete the journal, the
    /// key, the configuration or the agent (ADR-0011). Neither inside a root nor around one.
    #[test]
    fn the_agents_own_files_lie_outside_every_root() {
        let roots = "allowed_roots = ['C:\\FakeErp']\n";
        let inside = |toml: &str| match config(&format!(
            "server_url = \"wss://ponte.example.com\"\n{roots}{toml}"
        )) {
            Err(ConfigError::InsideRoot(what)) => what,
            other => panic!("{toml}: {other:?}"),
        };
        assert_eq!(inside(r"data_dir = 'C:\FakeErp\ponte'"), "data_dir");
        assert_eq!(inside(r"data_dir = 'c:/fakeerp'"), "data_dir");
        assert_eq!(inside(r"data_dir = 'C:\'"), "data_dir");
        assert_eq!(
            inside(
                "data_dir = 'C:\\ProgramData\\Ponte'\nenrollment_token_file = 'C:\\FakeErp\\token'"
            ),
            "enrollment_token_file"
        );
        assert!(
            config(&format!(
                "server_url = \"wss://ponte.example.com\"\n{roots}data_dir = 'C:\\ProgramData\\Ponte'\nenrollment_token_file = 'C:\\FakeErpX\\token'"
            ))
            .is_ok()
        );

        let config = with(r"allowed_roots = ['C:\FakeErp\data']").unwrap();
        let place = |file: &str, folder: &str| match config.check_place(
            Path::new(file),
            Path::new(folder),
            None,
        ) {
            Ok(()) => None,
            Err(ConfigError::InsideRoot(what)) => Some(what),
            Err(other) => panic!("{other:?}"),
        };
        assert_eq!(
            place(
                r"C:\ProgramData\Ponte\agent.toml",
                r"C:\Program Files\Ponte"
            ),
            None
        );
        assert_eq!(
            place(r"C:\FakeErp\data\agent.toml", r"C:\Program Files\Ponte"),
            Some("the configuration file")
        );
        assert_eq!(
            place(r"C:\ProgramData\Ponte\agent.toml", r"C:\FakeErp"),
            Some("the folder of the agent's executable")
        );
    }

    /// On Windows a path that cannot be compared with the roots refuses the configuration;
    /// a short 8.3 name could be a root under another spelling.
    #[test]
    fn a_place_that_cannot_be_compared_with_the_roots() {
        let toml = "allowed_roots = ['C:\\FakeErp']\ndata_dir = 'C:\\FAKEER~1\\ponte'";
        let refused = config(&format!("server_url = \"wss://ponte.example.com\"\n{toml}"));
        if cfg!(windows) {
            assert!(matches!(
                refused,
                Err(ConfigError::NotComparable("data_dir"))
            ));
        } else {
            assert!(refused.is_ok());
        }
        // Without roots there is nothing to compare with.
        assert!(with("enrollment_token_file = 'C:\\FAKEER~1\\token'").is_ok());
        // A relative path is taken from the working directory.
        assert!(with("allowed_roots = ['C:\\FakeErp']").is_ok());
    }

    /// What the Event Log may say of a refused file: the setting, and for a file that does
    /// not parse, the line. Never the text.
    #[test]
    fn a_refusal_names_the_setting_and_the_line_only() {
        let text = "server_url = \"wss://ponte.example.com\"\ndata_dir = \"data\"\nheartbeat_secs = \"secret-ish\"\n";
        let error = config(text).unwrap_err();
        assert_eq!(error.setting(), "the file");
        assert_eq!(error.line_in(text), Some(3));
        assert_eq!(
            with("heartbeat_secs = 1").unwrap_err().setting(),
            "heartbeat_secs"
        );
        assert_eq!(with("heartbeat_secs = 1").unwrap_err().line_in(""), None);
        let inside = config(
            "server_url = \"wss://ponte.example.com\"\nallowed_roots = ['C:\\FakeErp']\ndata_dir = 'C:\\FakeErp\\x'",
        )
        .unwrap_err();
        assert_eq!(inside.setting(), "data_dir");
    }

    /// `load` reads the file and checks its place and the executable's.
    #[test]
    fn a_configuration_is_loaded_from_its_file() {
        let dir = crate::testkit::TempDir::new();
        let path = dir.path().join("agent.toml");
        std::fs::write(
            &path,
            "server_url = \"wss://ponte.example.com\"\ndata_dir = \"data\"\nallowed_services = ['FakeErp']\n",
        )
        .unwrap();
        assert!(AgentConfig::load(&path).is_ok());
        let own: ServiceName = "FakeErp".parse().unwrap();
        assert!(matches!(
            AgentConfig::load_as(&path, Some(&own)),
            Err(ConfigError::OwnService)
        ));
        assert!(matches!(
            AgentConfig::load(dir.path().join("missing.toml")),
            Err(ConfigError::Read(_))
        ));
    }

    #[test]
    fn example_config_parses() {
        let config = config(include_str!("../agent.example.toml")).unwrap();
        assert_eq!(config.server_url.security(), Security::PlainLoopback);
        assert!(config.enrollment_token_file.is_some());
        // No key: a copy of the example runs nothing until someone names one.
        assert!(!config.actions_enabled());
        assert!(config.actions.policy.services.contains("FakeErp"));
        let roots = &config.actions.policy.roots;
        assert!(roots.delete().is_allowed(r"C:\FakeErp\run\erp.lock"));

        // With the key line filled in, it is a working configuration.
        let filled = include_str!("../agent.example.toml").replace(
            "# manifest_keys = [\"<64 lowercase hex characters>\"]",
            &keys(&[key_hex(1)]),
        );
        assert!(self::config(&filled).unwrap().actions_enabled());
    }
}
