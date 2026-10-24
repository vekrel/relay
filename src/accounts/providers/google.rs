// Google OIDC (plan 6A Task 6): code + PKCE exchange, then the ID token is verified against
// Google's JWKS (RS256, `iss`, `aud` = our client id, `exp`, our `nonce`) and must carry
// `email_verified: true` (Review Focus 1). Google's documented issuers are both accepted.
// Google is authoritative for an address only if it is Gmail or `hd` (Workspace domain) equals the
// email's domain; any other address may sign up or sign back in, never link to an existing user.
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;

use super::{Failure, upstream};
use crate::accounts::signup::VerifiedIdentity;
use crate::config::OAuthApp;

const ISSUERS: [&str; 2] = ["https://accounts.google.com", "accounts.google.com"];

#[derive(Deserialize)]
struct TokenResponse {
    id_token: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct Claims {
    sub: String,
    email: Option<String>,
    #[serde(default)]
    email_verified: bool,
    nonce: Option<String>,
    hd: Option<String>,
}

/// Gmail, or a Workspace account whose `hd` is the email's domain.
fn authoritative(email: &str, hd: Option<&str>) -> bool {
    let domain = email.rsplit_once('@').map_or("", |(_, d)| d);
    domain.eq_ignore_ascii_case("gmail.com")
        || domain.eq_ignore_ascii_case("googlemail.com")
        || hd.is_some_and(|hd| !hd.is_empty() && hd.eq_ignore_ascii_case(domain))
}

pub(super) async fn identity(
    http: &reqwest::Client,
    app: &OAuthApp,
    code: &str,
    verifier: &str,
    redirect_uri: &str,
    nonce: &str,
) -> Result<(VerifiedIdentity, bool), Failure> {
    let res = http
        .post(&app.token_url)
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", app.client_id.as_str()),
            ("client_secret", app.client_secret.as_str()),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("code_verifier", verifier),
        ])
        .send()
        .await
        .map_err(upstream)?;
    let status = res.status();
    let t: TokenResponse = res.json().await.map_err(upstream)?;
    let Some(id_token) = t.id_token.filter(|_| status.is_success()) else {
        let e = t.error.unwrap_or_default();
        return Err(Failure::Upstream(format!(
            "token exchange refused ({status}): {e}"
        )));
    };
    let bad = |why: &str| Failure::Upstream(format!("ID token refused: {why}"));
    let header = jsonwebtoken::decode_header(&id_token).map_err(|_| bad("malformed"))?;
    if header.alg != Algorithm::RS256 {
        return Err(bad("alg is not RS256"));
    }
    // shortcut: JWKS fetched on every sign-in (no cache); cache by Cache-Control if sign-ins get frequent.
    let jwks: JwkSet = http
        .get(&app.data_url)
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(upstream)?
        .json()
        .await
        .map_err(upstream)?;
    let jwk = header
        .kid
        .as_deref()
        .and_then(|kid| jwks.find(kid))
        .ok_or_else(|| bad("unknown kid"))?;
    let key = DecodingKey::from_jwk(jwk).map_err(|_| bad("unusable JWK"))?;
    let mut v = Validation::new(Algorithm::RS256);
    v.set_audience(&[&app.client_id]);
    v.set_issuer(&ISSUERS);
    v.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    let c = jsonwebtoken::decode::<Claims>(&id_token, &key, &v)
        .map_err(|e| bad(&format!("{:?}", e.kind())))?
        .claims;
    if c.nonce.as_deref() != Some(nonce) {
        return Err(bad("nonce mismatch"));
    }
    match c.email {
        Some(email) if c.email_verified => {
            let may_link = authoritative(&email, c.hd.as_deref());
            let id = VerifiedIdentity {
                provider: "google",
                subject: c.sub,
                email,
            };
            Ok((id, may_link))
        }
        _ => Err(Failure::NoVerifiedEmail),
    }
}
