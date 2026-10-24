// Settings come from the environment only (Railway variables in deploys).
use std::net::SocketAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignupMode {
    /// Only emails in `signup_allowlist` may create an account (launch default).
    Allowlist,
    Open,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub addr: SocketAddr,
    /// Public origin of the relay, e.g. `https://relay.example.com` (T3's `relayIssuer`).
    pub relay_origin: String,
    /// Postgres URL; `serve` requires it. Never logged.
    pub database_url: Option<String>,
    /// `SIGNUP_MODE=allowlist|open`, default `allowlist`.
    pub signup_mode: SignupMode,
    /// `WEB_ORIGINS`: comma-separated origins of the web app (`https://app.<domain>`). Each gets the
    /// `vekrel-web` redirect `<origin>/auth/callback` and is the only CORS origin for `/oauth/token`.
    pub web_origins: Vec<String>,
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
        let signup_mode = match get("SIGNUP_MODE").as_deref() {
            None | Some("allowlist") => SignupMode::Allowlist,
            Some("open") => SignupMode::Open,
            Some(other) => {
                return Err(format!("SIGNUP_MODE must be allowlist or open: {other:?}"));
            }
        };
        let mut web_origins = Vec::new();
        for o in get("WEB_ORIGINS").unwrap_or_default().split(',') {
            let o = o.trim();
            if o.is_empty() {
                continue;
            }
            let rest = o
                .strip_prefix("https://")
                .or_else(|| o.strip_prefix("http://"));
            if !rest.is_some_and(|h| !h.is_empty() && !h.contains(['/', '?', '#', '*'])) {
                return Err(format!(
                    "WEB_ORIGINS entries must be origins like https://app.example.com: {o:?}"
                ));
            }
            web_origins.push(o.to_owned());
        }
        Ok(Self {
            addr: SocketAddr::from(([0, 0, 0, 0], port)),
            relay_origin,
            database_url: get("DATABASE_URL").filter(|s| !s.is_empty()),
            signup_mode,
            web_origins,
        })
    }

    /// Defaults plus `vars`, for tests elsewhere in the crate.
    #[cfg(test)]
    pub fn for_tests(vars: &[(&str, &str)]) -> Self {
        let m: std::collections::HashMap<&str, &str> = vars.iter().copied().collect();
        Self::from_lookup(|k| m.get(k).map(|v| v.to_string())).unwrap()
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
        assert_eq!(c.signup_mode, SignupMode::Allowlist);
        assert!(c.web_origins.is_empty());
    }

    #[test]
    fn reads_env() {
        let c = load(&[
            ("PORT", "9001"),
            ("RELAY_ORIGIN", "https://relay.example.com/"),
            ("DATABASE_URL", "postgres://localhost/relay"),
            ("SIGNUP_MODE", "open"),
            (
                "WEB_ORIGINS",
                "https://app.example.com, http://localhost:5733",
            ),
        ])
        .unwrap();
        assert_eq!(c.addr.port(), 9001);
        assert_eq!(c.relay_origin, "https://relay.example.com");
        assert_eq!(
            c.database_url.as_deref(),
            Some("postgres://localhost/relay")
        );
        assert_eq!(c.signup_mode, SignupMode::Open);
        assert_eq!(
            c.web_origins,
            ["https://app.example.com", "http://localhost:5733"]
        );
    }

    #[test]
    fn rejects_bad_values() {
        assert!(load(&[("PORT", "x")]).is_err());
        assert!(load(&[("RELAY_ORIGIN", "relay.example.com")]).is_err());
        assert!(load(&[("SIGNUP_MODE", "waitlist")]).is_err());
        for bad in [
            "app.example.com",
            "https://app.example.com/",
            "https://app.example.com/auth",
            "https://*.example.com",
            "https://",
        ] {
            assert!(load(&[("WEB_ORIGINS", bad)]).is_err(), "{bad}");
        }
    }
}
