use anyhow::{Context, ensure};
use ponte_actions::PathPolicy;
use serde::Deserialize;

/// Agent configuration, read from a TOML file written by the installer.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    /// Control-plane URL. Must be `wss://`; plain `ws://` is accepted only for localhost.
    pub server_url: String,
    /// Directories that file-touching actions may access.
    #[serde(default)]
    pub allowed_roots: Vec<String>,
}

impl AgentConfig {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&raw)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> anyhow::Result<()> {
        ensure!(
            self.server_url.starts_with("wss://") || is_plain_ws_to_localhost(&self.server_url),
            "server_url must use wss:// (ws:// is only allowed for localhost)"
        );
        PathPolicy::new(&self.allowed_roots)
            .map_err(|root| anyhow::anyhow!("invalid allowed root `{root}`"))
            .context("validating allowed_roots")?;
        Ok(())
    }
}

/// Whether `url` is plain `ws://` to this very machine. The host must match exactly:
/// a prefix test would also accept `ws://localhost.evil.example`.
fn is_plain_ws_to_localhost(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("ws://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    // A port that is not a number is how `localhost:80@evil.example` hides its real host.
    let port_ok = port.is_none_or(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
    port_ok && matches!(host, "localhost" | "127.0.0.1")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(url: &str, roots: &[&str]) -> AgentConfig {
        AgentConfig {
            server_url: url.to_owned(),
            allowed_roots: roots.iter().map(|r| (*r).to_owned()).collect(),
        }
    }

    #[test]
    fn requires_tls_except_on_localhost() {
        assert!(
            config("wss://ponte.example.com/agent", &[])
                .validate()
                .is_ok()
        );
        assert!(config("ws://localhost:8080/agent", &[]).validate().is_ok());
        assert!(
            config("ws://ponte.example.com/agent", &[])
                .validate()
                .is_err()
        );
        assert!(config("https://ponte.example.com", &[]).validate().is_err());
    }

    #[test]
    fn localhost_exception_matches_the_exact_host() {
        for url in [
            "ws://localhost",
            "ws://localhost/agent",
            "ws://localhost:8080",
            "ws://127.0.0.1:8080/agent?x=1",
        ] {
            assert!(config(url, &[]).validate().is_ok(), "{url}");
        }
        for url in [
            "ws://localhost.evil.example/agent",
            "ws://127.0.0.1.evil.example:8080",
            "ws://localhostevil.example",
            "ws://localhost@evil.example/agent",
            "ws://localhost:8080@evil.example/agent",
            "ws://localhost:8080.evil.example",
            "ws://localhost:",
            r"ws://localhost\@evil.example",
            "ws://",
        ] {
            assert!(config(url, &[]).validate().is_err(), "{url}");
        }
    }

    #[test]
    fn rejects_invalid_roots() {
        assert!(config("wss://x", &[r"C:\FakeErp"]).validate().is_ok());
        assert!(config("wss://x", &[r"..\FakeErp"]).validate().is_err());
    }

    #[test]
    fn example_config_parses() {
        let raw = include_str!("../agent.example.toml");
        let config: AgentConfig = toml::from_str(raw).unwrap();
        assert!(config.validate().is_ok());
    }
}
