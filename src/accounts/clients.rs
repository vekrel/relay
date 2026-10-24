// Public OAuth clients and their exact redirect URIs (plan 6A Task 5, research §3). Matching is
// whole-string equality: no prefix, no wildcard, no loopback port relaxation.

/// The client that gets the refresh token as an HttpOnly cookie instead of in the body.
pub const WEB: &str = "vekrel-web";
const DESKTOP_REDIRECTS: [&str; 2] = ["vekrel://auth/callback", "vekrel-dev://auth/callback"];
/// Mobile also has a preview build variant with its own scheme (`apps/mobile/app.config.ts`).
const MOBILE_REDIRECTS: [&str; 3] = [
    "vekrel://auth/callback",
    "vekrel-dev://auth/callback",
    "vekrel-preview://auth/callback",
];
/// Engine `CliTokenManager` loopback port 34338.
const CLI_REDIRECT: &str = "http://127.0.0.1:34338/callback";

pub struct Clients {
    web: Vec<String>,
}

impl Clients {
    /// `web_origins` from `WEB_ORIGINS` (validated by `Config`).
    pub fn new(web_origins: &[String]) -> Self {
        Self {
            web: web_origins
                .iter()
                .map(|o| format!("{o}/auth/callback"))
                .collect(),
        }
    }

    pub fn is_known(&self, client_id: &str) -> bool {
        matches!(
            client_id,
            WEB | "vekrel-desktop" | "vekrel-mobile" | "vekrel-cli"
        )
    }

    pub fn redirect_allowed(&self, client_id: &str, redirect_uri: &str) -> bool {
        match client_id {
            WEB => self.web.iter().any(|u| u == redirect_uri),
            "vekrel-desktop" => DESKTOP_REDIRECTS.contains(&redirect_uri),
            "vekrel-mobile" => MOBILE_REDIRECTS.contains(&redirect_uri),
            "vekrel-cli" => redirect_uri == CLI_REDIRECT,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirects_match_exactly() {
        let c = Clients::new(&["https://app.example.com".into()]);
        assert!(c.redirect_allowed(WEB, "https://app.example.com/auth/callback"));
        assert!(c.redirect_allowed("vekrel-mobile", "vekrel://auth/callback"));
        assert!(c.redirect_allowed("vekrel-desktop", "vekrel-dev://auth/callback"));
        assert!(c.redirect_allowed("vekrel-mobile", "vekrel-preview://auth/callback"));
        assert!(c.redirect_allowed("vekrel-cli", "http://127.0.0.1:34338/callback"));
        for (client, uri) in [
            (WEB, "https://app.example.com/auth/callback/x"),
            (WEB, "https://app.example.com/auth/callback?x=1"),
            (WEB, "https://app.example.com/auth/callbac"),
            (WEB, "https://app.example.com.evil.test/auth/callback"),
            (WEB, "HTTPS://app.example.com/auth/callback"),
            (WEB, "vekrel://auth/callback"),
            ("vekrel-cli", "http://127.0.0.1:34339/callback"),
            ("vekrel-cli", "http://localhost:34338/callback"),
            ("vekrel-mobile", "https://app.example.com/auth/callback"),
            ("vekrel-mobile", "vekrel-preview://auth/callback/"),
            ("vekrel-desktop", "vekrel-preview://auth/callback"),
            ("vekrel-other", "vekrel://auth/callback"),
        ] {
            assert!(!c.redirect_allowed(client, uri), "{client} {uri}");
        }
        assert!(!c.is_known("vekrel-other"));
    }
}
