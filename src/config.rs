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
    pub database_url: Option<Secret>,
    /// `SIGNUP_MODE=allowlist|open`, default `allowlist`.
    pub signup_mode: SignupMode,
    /// `SIGNUP_ALLOWED_DOMAINS` (Vekrel): comma-separated domains whose every address may create an
    /// account in allowlist mode, lowercase, e.g. `vekrel.com`. Exact match, no subdomains.
    pub signup_allowed_domains: Vec<String>,
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
    /// `RELAY_DEV_MACHINE_ENDPOINT`: local conformance runs only. Machine requests (connect, status)
    /// go to this loopback base instead of `https://<tunnel host>/`. Refused unless `RELAY_ORIGIN`
    /// and the value are both loopback, so a deployed relay can never use it.
    pub dev_machine_endpoint: Option<String>,
    /// APNs and FCM (`crate::push::config`).
    pub push: crate::push::PushConfig,
    /// `RELAY_STAGE`: T3's stage, the namespace of tunnel names and hosts (`prod-<digest>`).
    /// Managed tunnels need it and `RELAY_TUNNEL_ZONE_NAME`.
    pub stage: Option<String>,
    /// `CLOUDFLARE_ACCOUNT_ID` + `CLOUDFLARE_TUNNEL_ZONE_ID` + `CLOUDFLARE_API_TOKEN` (all or
    /// none). Unset: the relay provisions no tunnels (managed links answer 503).
    pub cloudflare: Option<CloudflareConfig>,
    /// `RELAY_TUNNEL_CLEANUP_MODE` and `RELAY_LEGACY_TUNNEL_CLEANUP_MODE` (`off|dry-run|enabled`,
    /// default off), `RELAY_LEGACY_TUNNEL_GRACE_MINUTES` (T3 `Config.ts`).
    pub cleanup: CleanupConfig,
}

#[derive(Debug, Clone)]
pub struct CloudflareConfig {
    pub account_id: String,
    pub zone_id: String,
    /// Never logged (`Secret`).
    pub api_token: Secret,
    /// `CLOUDFLARE_API_BASE`, default `https://api.cloudflare.com/client/v4`; tests point it at a fake.
    pub api_base: String,
}

/// `ManagedEndpointCleanupMode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CleanupMode {
    #[default]
    Off,
    DryRun,
    Enabled,
}

impl CleanupMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::DryRun => "dry-run",
            Self::Enabled => "enabled",
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CleanupConfig {
    pub mode: CleanupMode,
    pub legacy_mode: CleanupMode,
    pub legacy_grace_minutes: Option<i64>,
}

/// `cleanupModeConfig`: unset or blank is off.
fn cleanup_mode(get: &impl Fn(&str) -> Option<String>, name: &str) -> Result<CleanupMode, String> {
    match get(name).as_deref().map(str::trim) {
        None | Some("") | Some("off") => Ok(CleanupMode::Off),
        Some("dry-run") => Ok(CleanupMode::DryRun),
        Some("enabled") => Ok(CleanupMode::Enabled),
        Some(other) => Err(format!("{name} must be off, dry-run or enabled: {other:?}")),
    }
}

fn cloudflare(get: &impl Fn(&str) -> Option<String>) -> Result<Option<CloudflareConfig>, String> {
    let get = |k: &str| get(k).filter(|v| !v.trim().is_empty());
    let names = [
        "CLOUDFLARE_ACCOUNT_ID",
        "CLOUDFLARE_TUNNEL_ZONE_ID",
        "CLOUDFLARE_API_TOKEN",
    ];
    match names.map(get) {
        [None, None, None] => Ok(None),
        [Some(account_id), Some(zone_id), Some(token)] => Ok(Some(CloudflareConfig {
            account_id,
            zone_id,
            api_token: Secret(token),
            api_base: get("CLOUDFLARE_API_BASE")
                .unwrap_or_else(|| "https://api.cloudflare.com/client/v4".into())
                .trim_end_matches('/')
                .to_owned(),
        })),
        _ => Err(format!("set all of {}, or none", names.join(", "))),
    }
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
        let mut signup_allowed_domains = Vec::new();
        for d in get("SIGNUP_ALLOWED_DOMAINS").unwrap_or_default().split(',') {
            let d = d.trim().to_ascii_lowercase();
            if d.is_empty() {
                continue;
            }
            if d.contains('@') || !d.contains('.') || d.starts_with('.') || d.ends_with('.') {
                return Err(format!("SIGNUP_ALLOWED_DOMAINS: not a domain: {d:?}"));
            }
            signup_allowed_domains.push(d);
        }
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
            // The log transport puts sign-in links on the page: local dev only.
            Some("log") if is_loopback_origin(&relay_origin) => MagicLinkTransport::Log,
            Some("log") => {
                return Err(format!(
                    "MAGIC_LINK_TRANSPORT=log only works with a loopback RELAY_ORIGIN (localhost, 127.0.0.1, [::1]), not {relay_origin:?}; use resend"
                ));
            }
            None | Some("resend") => MagicLinkTransport::Resend {
                api_key: Secret(
                    get("RESEND_API_KEY")
                        .filter(|k| !k.is_empty())
                        .ok_or("magic links need RESEND_API_KEY (MAGIC_LINK_TRANSPORT defaults to resend; log is for a loopback RELAY_ORIGIN only)")?,
                ),
                from: get("MAGIC_LINK_FROM")
                    .filter(|f| f.contains('@'))
                    .ok_or("magic links need MAGIC_LINK_FROM, e.g. Vekrel <signin@example.com>")?,
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
        let dev_machine_endpoint = match get("RELAY_DEV_MACHINE_ENDPOINT") {
            None => None,
            Some(v) => Some(dev_machine_endpoint(&relay_origin, &v)?),
        };
        Ok(Self {
            addr: SocketAddr::from(([0, 0, 0, 0], port)),
            relay_origin,
            database_url: get("DATABASE_URL").filter(|s| !s.is_empty()).map(Secret),
            signup_mode,
            signup_allowed_domains,
            web_origins,
            magic_link_transport,
            trust_proxy_ip_header,
            github,
            google,
            mint_private_key: get("RELAY_MINT_PRIVATE_KEY")
                .filter(|s| !s.trim().is_empty())
                .map(Secret),
            tunnel_zone: get("RELAY_TUNNEL_ZONE_NAME").filter(|s| !s.trim().is_empty()),
            dev_machine_endpoint,
            push: crate::push::PushConfig::from_lookup(&get)?,
            stage: get("RELAY_STAGE").filter(|s| !s.trim().is_empty()),
            cloudflare: cloudflare(&get)?,
            cleanup: CleanupConfig {
                mode: cleanup_mode(&get, "RELAY_TUNNEL_CLEANUP_MODE")?,
                legacy_mode: cleanup_mode(&get, "RELAY_LEGACY_TUNNEL_CLEANUP_MODE")?,
                legacy_grace_minutes: match get("RELAY_LEGACY_TUNNEL_GRACE_MINUTES") {
                    None => None,
                    Some(v) => Some(v.trim().parse().ok().filter(|m: &i64| *m > 0).ok_or_else(
                        || format!("RELAY_LEGACY_TUNNEL_GRACE_MINUTES must be a positive integer: {v:?}"),
                    )?),
                },
            },
        })
    }

    /// Defaults plus `vars`, for tests elsewhere in the crate. Without `MAGIC_LINK_TRANSPORT`, a
    /// Resend transport pointed at a closed port (tests that send email set their own).
    #[cfg(test)]
    pub fn for_tests(vars: &[(&str, &str)]) -> Self {
        Self::from_lookup(test_lookup(vars)).unwrap()
    }
}

#[cfg(test)]
fn test_lookup(vars: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
    let mut m: std::collections::HashMap<String, String> = vars
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    if !m.contains_key("MAGIC_LINK_TRANSPORT") {
        for (k, v) in [
            ("RESEND_API_KEY", "re_test_unused"),
            ("MAGIC_LINK_FROM", "Vekrel <signin@example.test>"),
            ("RESEND_BASE_URL", "http://127.0.0.1:1"),
        ] {
            m.entry(k.into()).or_insert_with(|| v.into());
        }
    }
    move |k| m.get(k).cloned()
}

/// A loopback `http(s)://host:port` base with no path, and only next to a loopback `RELAY_ORIGIN`.
fn dev_machine_endpoint(relay_origin: &str, value: &str) -> Result<String, String> {
    let url = url::Url::parse(value.trim()).ok().filter(|u| {
        matches!(u.scheme(), "http" | "https")
            && u.path() == "/"
            && u.query().is_none()
            && u.username().is_empty()
    });
    match url {
        Some(u) if is_loopback_origin(relay_origin) && is_loopback_origin(u.as_str()) => {
            Ok(u.to_string())
        }
        _ => Err(format!(
            "RELAY_DEV_MACHINE_ENDPOINT must be a loopback http(s) origin and needs a loopback RELAY_ORIGIN, got {value:?} with {relay_origin:?}"
        )),
    }
}

/// `http(s)://localhost`, `127.0.0.1` (any 127/8) or `[::1]`, any port.
fn is_loopback_origin(origin: &str) -> bool {
    match url::Url::parse(origin)
        .ok()
        .as_ref()
        .and_then(url::Url::host)
    {
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// With a test Resend key unless the test sets `MAGIC_LINK_TRANSPORT`.
    fn load(vars: &[(&str, &str)]) -> Result<Config, String> {
        Config::from_lookup(test_lookup(vars))
    }

    /// Exactly `vars`, nothing filled in.
    fn load_raw(vars: &[(&str, &str)]) -> Result<Config, String> {
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
        assert!(c.signup_allowed_domains.is_empty());
        assert!(c.web_origins.is_empty());
        assert!(matches!(
            c.magic_link_transport,
            MagicLinkTransport::Resend { .. }
        ));
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
    fn cloudflare_and_cleanup() {
        let c = load(&[]).unwrap();
        assert!(c.cloudflare.is_none());
        assert_eq!(c.cleanup.mode, CleanupMode::Off);
        assert_eq!(c.cleanup.legacy_mode, CleanupMode::Off);
        let all = [
            ("CLOUDFLARE_ACCOUNT_ID", "acct"),
            ("CLOUDFLARE_TUNNEL_ZONE_ID", "zone"),
            ("CLOUDFLARE_API_TOKEN", "cf-secret-token"),
        ];
        let cf = load(&all).unwrap().cloudflare.unwrap();
        assert_eq!(cf.api_base, "https://api.cloudflare.com/client/v4");
        assert!(!format!("{cf:?}").contains("cf-secret-token"));
        assert!(load(&all[..2]).is_err());
        let c = load(&[
            ("RELAY_TUNNEL_CLEANUP_MODE", "dry-run"),
            ("RELAY_LEGACY_TUNNEL_CLEANUP_MODE", " "),
            ("RELAY_LEGACY_TUNNEL_GRACE_MINUTES", "30"),
        ])
        .unwrap();
        assert_eq!(c.cleanup.mode, CleanupMode::DryRun);
        assert_eq!(c.cleanup.legacy_mode, CleanupMode::Off);
        assert_eq!(c.cleanup.legacy_grace_minutes, Some(30));
        assert!(load(&[("RELAY_TUNNEL_CLEANUP_MODE", "on")]).is_err());
        assert!(load(&[("RELAY_LEGACY_TUNNEL_GRACE_MINUTES", "0")]).is_err());
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
    fn signup_allowed_domains_are_lowercased_and_validated() {
        let c = load(&[("SIGNUP_ALLOWED_DOMAINS", " Vekrel.com, ,b.example ")]).unwrap();
        assert_eq!(c.signup_allowed_domains, ["vekrel.com", "b.example"]);
        for bad in [
            "@vekrel.com",
            "x@vekrel.com",
            "localhost",
            ".vekrel.com",
            "vekrel.com.",
        ] {
            assert!(load(&[("SIGNUP_ALLOWED_DOMAINS", bad)]).is_err(), "{bad}");
        }
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
            c.database_url,
            Some(Secret("postgres://localhost/relay".into()))
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

    /// `{:?}` of a full Config carries no secret value (it reaches logs via `?config` easily).
    #[test]
    fn debug_redacts_every_secret() {
        let secrets = [
            (
                "DATABASE_URL",
                "postgres://relay:db-pass-SECRET@db.internal/relay",
            ),
            ("RESEND_API_KEY", "re_resend_SECRET"),
            ("GITHUB_CLIENT_SECRET", "gh_client_SECRET"),
            ("GOOGLE_CLIENT_SECRET", "g_client_SECRET"),
            (
                "RELAY_MINT_PRIVATE_KEY",
                "-----BEGIN PRIVATE KEY-----mint_SECRET",
            ),
        ];
        let mut vars = vec![
            ("MAGIC_LINK_TRANSPORT", "resend"),
            ("MAGIC_LINK_FROM", "Vekrel <signin@example.com>"),
            ("GITHUB_CLIENT_ID", "gh-id"),
            ("GOOGLE_CLIENT_ID", "g-id"),
        ];
        vars.extend(secrets);
        let debug = format!("{:?}", load(&vars).unwrap());
        for (name, value) in secrets {
            assert!(!debug.contains(value), "{name} in Debug: {debug}");
        }
        assert!(!debug.contains("SECRET"), "{debug}");
        assert!(debug.contains("gh-id"), "non-secrets still print: {debug}");
    }

    /// Unset transport means Resend: a deploy without a key fails at boot, never echoes links.
    #[test]
    fn unset_transport_is_resend_and_needs_a_key() {
        let err = load_raw(&[("RELAY_ORIGIN", "https://relay.example.com")]).unwrap_err();
        assert!(err.contains("RESEND_API_KEY"), "{err}");
        assert!(
            load_raw(&[]).is_err(),
            "localhost too: log must be asked for"
        );
        let c = load_raw(&[
            ("RELAY_ORIGIN", "https://relay.example.com"),
            ("RESEND_API_KEY", "k"),
            ("MAGIC_LINK_FROM", "a@example.com"),
        ])
        .unwrap();
        assert!(matches!(
            c.magic_link_transport,
            MagicLinkTransport::Resend { .. }
        ));
    }

    #[test]
    fn log_transport_only_with_a_loopback_origin() {
        for origin in [
            "https://relay.example.com",
            "https://relay-staging.example.com",
            "http://10.0.0.5:8080",
            "http://localhost.example.com",
            "http://127.0.0.1.nip.io",
            "http://[::2]:8080",
        ] {
            let err =
                load_raw(&[("RELAY_ORIGIN", origin), ("MAGIC_LINK_TRANSPORT", "log")]).unwrap_err();
            assert!(err.contains("loopback"), "{origin}: {err}");
        }
        for origin in [
            "http://localhost:8080",
            "http://LOCALHOST",
            "http://127.0.0.1:18777",
            "http://127.3.4.5",
            "http://[::1]:8080",
        ] {
            let c = load_raw(&[("RELAY_ORIGIN", origin), ("MAGIC_LINK_TRANSPORT", "log")])
                .unwrap_or_else(|e| panic!("{origin}: {e}"));
            assert_eq!(c.magic_link_transport, MagicLinkTransport::Log);
        }
        // The default origin is loopback.
        assert!(load_raw(&[("MAGIC_LINK_TRANSPORT", "log")]).is_ok());
    }

    #[test]
    fn dev_machine_endpoint_only_on_loopback() {
        let load = |origin: &str, endpoint: Option<&str>| {
            let mut v = vec![
                ("RELAY_ORIGIN", origin),
                ("RESEND_API_KEY", "k"),
                ("MAGIC_LINK_FROM", "a@example.com"),
            ];
            v.extend(endpoint.map(|e| ("RELAY_DEV_MACHINE_ENDPOINT", e)));
            load_raw(&v)
        };
        assert_eq!(
            load("https://localhost:1", None)
                .unwrap()
                .dev_machine_endpoint,
            None
        );
        let c = load("https://localhost:18613", Some("http://127.0.0.1:18614")).unwrap();
        assert_eq!(
            c.dev_machine_endpoint.as_deref(),
            Some("http://127.0.0.1:18614/")
        );
        for (origin, endpoint) in [
            ("https://relay.example.com", "http://127.0.0.1:18614"),
            ("http://10.0.0.5:8080", "http://127.0.0.1:18614"),
            ("http://localhost:8080", "http://10.0.0.5:18614"),
            ("http://localhost:8080", "https://machine.example.com"),
            ("http://localhost:8080", "ftp://127.0.0.1:18614"),
            ("http://localhost:8080", "http://127.0.0.1:18614/api"),
        ] {
            let err = load(origin, Some(endpoint)).unwrap_err();
            assert!(
                err.contains("RELAY_DEV_MACHINE_ENDPOINT"),
                "{origin} {endpoint}: {err}"
            );
        }
    }
}
