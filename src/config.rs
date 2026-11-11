//! Configuration, read from environment variables.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Context;

/// Runtime configuration of the gateway.
#[derive(Clone, Debug)]
pub struct Config {
    /// Address to listen on (`OPSLAB_LISTEN`, default `0.0.0.0:8081`).
    pub listen: SocketAddr,
    /// JWKS document of the api (`OPSLAB_JWKS_URL`).
    pub jwks_url: String,
    /// How often keys are refreshed (`OPSLAB_JWKS_REFRESH_SECS`, default 300).
    pub jwks_refresh: Duration,
    /// Log as JSON lines (`OPSLAB_LOG_FORMAT=json`).
    pub log_json: bool,
    /// Terminals without input for this long are closed
    /// (`OPSLAB_TERMINAL_IDLE_SECS`, default 1800).
    pub terminal_idle: Duration,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    fn from_lookup(get: impl Fn(&str) -> Option<String>) -> anyhow::Result<Self> {
        let listen = get("OPSLAB_LISTEN").unwrap_or_else(|| "0.0.0.0:8081".into());
        let refresh = get("OPSLAB_JWKS_REFRESH_SECS").unwrap_or_else(|| "300".into());
        let idle = get("OPSLAB_TERMINAL_IDLE_SECS").unwrap_or_else(|| "1800".into());
        Ok(Self {
            listen: listen
                .parse()
                .with_context(|| format!("OPSLAB_LISTEN: invalid address {listen:?}"))?,
            jwks_url: get("OPSLAB_JWKS_URL")
                .unwrap_or_else(|| "http://opslab-api:8080/.well-known/jwks.json".into()),
            jwks_refresh: Duration::from_secs(refresh.parse().with_context(|| {
                format!("OPSLAB_JWKS_REFRESH_SECS: invalid number {refresh:?}")
            })?),
            log_json: get("OPSLAB_LOG_FORMAT").as_deref() == Some("json"),
            terminal_idle: Duration::from_secs(
                idle.parse().with_context(|| {
                    format!("OPSLAB_TERMINAL_IDLE_SECS: invalid number {idle:?}")
                })?,
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults() {
        let c = Config::from_lookup(|_| None).unwrap();
        assert_eq!(c.listen.port(), 8081);
        assert_eq!(c.jwks_refresh, Duration::from_secs(300));
        assert!(c.jwks_url.ends_with("/.well-known/jwks.json"));
    }

    #[test]
    fn rejects_invalid_refresh() {
        let r = Config::from_lookup(|k| (k == "OPSLAB_JWKS_REFRESH_SECS").then(|| "soon".into()));
        assert!(r.is_err());
    }
}
