// Settings come from the environment only (Railway variables in deploys).
use std::net::SocketAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignupMode {
    /// Only emails in `signup_allowlist` may create an account (launch default).
    Allowlist,
    Open,
}

/// A secret setting; `Debug` never prints it.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(pub String);

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret([redacted])")
    }
}

/// How magic-link emails leave the relay (`MAGIC_LINK_TRANSPORT`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MagicLinkTransport {
    /// Nothing is sent; the sign-in page shows the link and code. Refused in production.
    Log,
    /// Resend's HTTP API. `base_url` is `https://api.resend.com` unless tests point it elsewhere.
    Resend {
        api_key: Secret,
        from: String,
        base_url: String,
    },
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
    pub magic_link_transport: MagicLinkTransport,
    /// `TRUST_PROXY_IP_HEADER=true|false`, default false: rate limits key on the socket peer.
    /// Set true on Railway only once staging shows the edge overwrites a client-sent `X-Real-IP`
    /// (plan 6A Task 2); then the header is used, falling back to the peer.
    pub trust_proxy_ip_header: bool,
    /// `GITHUB_CLIENT_ID` + `GITHUB_CLIENT_SECRET` (both or neither); endpoints overridable for tests.
    pub github: Option<OAuthApp>,
    /// `GOOGLE_CLIENT_ID` + `GOOGLE_CLIENT_SECRET` (both or neither); endpoints overridable for tests.
    pub google: Option<OAuthApp>,
    /// `RELAY_MINT_PRIVATE_KEY`: Ed25519 PKCS#8 PEM (T3's `CloudMintKeyPair`); signs link challenges,
    /// relay DPoP tokens and relay -> machine requests. `serve` requires it.
    pub mint_private_key: Option<Secret>,
    /// `RELAY_TUNNEL_ZONE_NAME`: zone that holds managed tunnel hostnames (T3
    /// `managedEndpointBaseDomain`); unset means connect refuses managed endpoints.
    pub tunnel_zone: Option<String>,
}

/// An upstream OAuth app (plan 6A Task 6). `Debug` leaves the secret out.
#[derive(Clone)]
pub struct OAuthApp {
    pub client_id: String,
    pub client_secret: String,
    pub authorize_url: String,
    pub token_url: String,
    /// GitHub: the REST API base (`/user`, `/user/emails`). Google: the JWKS URL.
    pub data_url: String,
}

impl std::fmt::Debug for OAuthApp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthApp")
            .field("client_id", &self.client_id)
            .field("authorize_url", &self.authorize_url)
            .field("token_url", &self.token_url)
            .field("data_url", &self.data_url)
            .finish_non_exhaustive()
    }
}

/// `<P>_CLIENT_ID`, `<P>_CLIENT_SECRET`, and `<P>_<url name>` overrides of `urls` (name, default).
fn oauth_app(
    get: &impl Fn(&str) -> Option<String>,
    p: &str,
    urls: [(&str, &str); 3],
) -> Result<Option<OAuthApp>, String> {
    let get = |k: &str| get(&format!("{p}_{k}")).filter(|v| !v.is_empty());
    let (client_id, client_secret) = match (get("CLIENT_ID"), get("CLIENT_SECRET")) {
        (None, None) => return Ok(None),
        (Some(id), Some(secret)) => (id, secret),
        _ => {
            return Err(format!(
                "set both {p}_CLIENT_ID and {p}_CLIENT_SECRET, or neither"
            ));
        }
    };
    let [a, t, d] = urls.map(|(name, default)| get(name).unwrap_or_else(|| default.to_owned()));
    Ok(Some(OAuthApp {
        client_id,
        client_secret,
        authorize_url: a,
        token_url: t,
        data_url: d,
    }))
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
        let magic_link_transport = match get("MAGIC_LINK_TRANSPORT").as_deref() {
            None | Some("log") => {
                // Railway sets RAILWAY_ENVIRONMENT_NAME; production must really send email.
                if get("RAILWAY_ENVIRONMENT_NAME").as_deref() == Some("production") {
                    return Err("MAGIC_LINK_TRANSPORT=log is not allowed in production".into());
                }
                MagicLinkTransport::Log
            }
            Some("resend") => MagicLinkTransport::Resend {
                api_key: Secret(
                    get("RESEND_API_KEY")
                        .filter(|k| !k.is_empty())
                        .ok_or("MAGIC_LINK_TRANSPORT=resend needs RESEND_API_KEY")?,
                ),
                from: get("MAGIC_LINK_FROM")
                    .filter(|f| f.contains('@'))
                    .ok_or("MAGIC_LINK_TRANSPORT=resend needs MAGIC_LINK_FROM, e.g. Vekrel <signin@example.com>")?,
                base_url: get("RESEND_BASE_URL")
                    .unwrap_or_else(|| "https://api.resend.com".into())
                    .trim_end_matches('/')
                    .to_owned(),
            },
            Some(other) => {
                return Err(format!(
                    "MAGIC_LINK_TRANSPORT must be resend or log: {other:?}"
                ));
            }
        };
        let trust_proxy_ip_header = match get("TRUST_PROXY_IP_HEADER").as_deref() {
            None | Some("false") => false,
            Some("true") => true,
            Some(other) => {
                return Err(format!(
                    "TRUST_PROXY_IP_HEADER must be true or false: {other:?}"
                ));
            }
        };
        let github = oauth_app(
            &get,
            "GITHUB",
            [
                ("AUTHORIZE_URL", "https://github.com/login/oauth/authorize"),
                ("TOKEN_URL", "https://github.com/login/oauth/access_token"),
                ("API_URL", "https://api.github.com"),
            ],
        )?;
        let google = oauth_app(
            &get,
            "GOOGLE",
            [
                (
                    "AUTHORIZE_URL",
                    "https://accounts.google.com/o/oauth2/v2/auth",
                ),
                ("TOKEN_URL", "https://oauth2.googleapis.com/token"),
                ("JWKS_URL", "https://www.googleapis.com/oauth2/v3/certs"),
            ],
        )?;
        Ok(Self {
            addr: SocketAddr::from(([0, 0, 0, 0], port)),
            relay_origin,
            database_url: get("DATABASE_URL").filter(|s| !s.is_empty()),
            signup_mode,
            web_origins,
            magic_link_transport,
            trust_proxy_ip_header,
            github,
            google,
            mint_private_key: get("RELAY_MINT_PRIVATE_KEY")
                .filter(|s| !s.trim().is_empty())
                .map(Secret),
            tunnel_zone: get("RELAY_TUNNEL_ZONE_NAME").filter(|s| !s.trim().is_empty()),
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
        assert_eq!(c.magic_link_transport, MagicLinkTransport::Log);
        assert!(!c.trust_proxy_ip_header);
        assert!(
            load(&[("TRUST_PROXY_IP_HEADER", "true")])
                .unwrap()
                .trust_proxy_ip_header
        );
        assert!(
            !load(&[("TRUST_PROXY_IP_HEADER", "false")])
                .unwrap()
                .trust_proxy_ip_header
        );
        assert!(load(&[("TRUST_PROXY_IP_HEADER", "yes")]).is_err());
    }

    #[test]
    fn magic_link_transport() {
        let c = load(&[
            ("MAGIC_LINK_TRANSPORT", "resend"),
            ("RESEND_API_KEY", "re_test_secret"),
            ("MAGIC_LINK_FROM", "Vekrel <signin@example.com>"),
        ])
        .unwrap();
        assert_eq!(
            c.magic_link_transport,
            MagicLinkTransport::Resend {
                api_key: Secret("re_test_secret".into()),
                from: "Vekrel <signin@example.com>".into(),
                base_url: "https://api.resend.com".into(),
            }
        );
        assert!(!format!("{c:?}").contains("re_test_secret"));
        assert!(load(&[("MAGIC_LINK_TRANSPORT", "resend")]).is_err());
        assert!(load(&[("MAGIC_LINK_TRANSPORT", "resend"), ("RESEND_API_KEY", "k")]).is_err());
        assert!(load(&[("MAGIC_LINK_TRANSPORT", "smtp")]).is_err());
        assert!(load(&[("RAILWAY_ENVIRONMENT_NAME", "production")]).is_err());
        assert!(load(&[("RAILWAY_ENVIRONMENT_NAME", "staging")]).is_ok());
        assert!(c.github.is_none() && c.google.is_none());
    }

    #[test]
    fn oauth_apps() {
        let c = load(&[
            ("GITHUB_CLIENT_ID", "gh-id"),
            ("GITHUB_CLIENT_SECRET", "gh-secret"),
            ("GOOGLE_CLIENT_ID", "g-id"),
            ("GOOGLE_CLIENT_SECRET", "g-secret"),
            ("GOOGLE_JWKS_URL", "http://127.0.0.1:9/certs"),
        ])
        .unwrap();
        let gh = c.github.unwrap();
        assert_eq!(gh.client_id, "gh-id");
        assert_eq!(gh.token_url, "https://github.com/login/oauth/access_token");
        assert_eq!(gh.data_url, "https://api.github.com");
        let g = c.google.unwrap();
        assert_eq!(
            g.authorize_url,
            "https://accounts.google.com/o/oauth2/v2/auth"
        );
        assert_eq!(g.data_url, "http://127.0.0.1:9/certs");
        assert!(!format!("{g:?}").contains("g-secret"));
        assert!(load(&[("GITHUB_CLIENT_ID", "x")]).is_err());
        assert!(load(&[("GOOGLE_CLIENT_SECRET", "x")]).is_err());
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
