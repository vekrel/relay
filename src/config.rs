// Settings come from the environment only (Railway variables in deploys).
use std::net::SocketAddr;

#[derive(Debug)]
pub struct Config {
    pub addr: SocketAddr,
    /// Public origin of the relay, e.g. `https://relay.example.com` (T3's `relayIssuer`).
    pub relay_origin: String,
    /// Postgres URL; `serve` requires it. Never logged.
    pub database_url: Option<String>,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let port: u16 = match get("PORT") {
            Some(p) => p
                .parse()
                .map_err(|_| format!("PORT is not a port number: {p:?}"))?,
            None => 8080,
        };
        let relay_origin =
            get("RELAY_ORIGIN").unwrap_or_else(|| format!("http://localhost:{port}"));
        let relay_origin = relay_origin.trim_end_matches('/').to_owned();
        if !relay_origin.starts_with("https://") && !relay_origin.starts_with("http://") {
            return Err(format!(
                "RELAY_ORIGIN must start with http:// or https://: {relay_origin:?}"
            ));
        }
        Ok(Self {
            addr: SocketAddr::from(([0, 0, 0, 0], port)),
            relay_origin,
            database_url: get("DATABASE_URL").filter(|s| !s.is_empty()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn load(vars: &[(&str, &str)]) -> Result<Config, String> {
        let m: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Config::from_lookup(|k| m.get(k).cloned())
    }

    #[test]
    fn defaults() {
        let c = load(&[]).unwrap();
        assert_eq!(c.addr.port(), 8080);
        assert_eq!(c.relay_origin, "http://localhost:8080");
        assert!(c.database_url.is_none());
    }

    #[test]
    fn reads_env() {
        let c = load(&[
            ("PORT", "9001"),
            ("RELAY_ORIGIN", "https://relay.example.com/"),
            ("DATABASE_URL", "postgres://localhost/relay"),
        ])
        .unwrap();
        assert_eq!(c.addr.port(), 9001);
        assert_eq!(c.relay_origin, "https://relay.example.com");
        assert_eq!(
            c.database_url.as_deref(),
            Some("postgres://localhost/relay")
        );
    }

    #[test]
    fn rejects_bad_values() {
        assert!(load(&[("PORT", "x")]).is_err());
        assert!(load(&[("RELAY_ORIGIN", "relay.example.com")]).is_err());
    }
}
