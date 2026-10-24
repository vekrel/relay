// GitHub OAuth app (plan 6A Task 6): code + PKCE exchange, then `/user` for the stable id and
// `/user/emails` for the one email that is both primary and verified. Anything else is refused,
// because the email links the identity to an existing account (Review Focus 1).
use serde::Deserialize;

use super::{Failure, upstream};
use crate::accounts::signup::VerifiedIdentity;
use crate::config::OAuthApp;

#[derive(Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct User {
    id: u64,
}

#[derive(Deserialize)]
struct Email {
    email: String,
    primary: bool,
    verified: bool,
}

pub(super) async fn identity(
    http: &reqwest::Client,
    app: &OAuthApp,
    code: &str,
    verifier: &str,
    redirect_uri: &str,
) -> Result<VerifiedIdentity, Failure> {
    // GitHub answers token errors with 200 and an `error` field.
    let t: TokenResponse = http
        .post(&app.token_url)
        .header(reqwest::header::ACCEPT, "application/json")
        .form(&[
            ("client_id", app.client_id.as_str()),
            ("client_secret", app.client_secret.as_str()),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("code_verifier", verifier),
        ])
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(upstream)?
        .json()
        .await
        .map_err(upstream)?;
    let Some(token) = t.access_token else {
        let e = t.error.unwrap_or_default();
        return Err(Failure::Upstream(format!("token exchange refused: {e}")));
    };
    let api = app.data_url.trim_end_matches('/');
    let get = |path: &str| {
        http.get(format!("{api}{path}"))
            .bearer_auth(&token)
            .header(reqwest::header::ACCEPT, "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .send()
    };
    let user: User = get("/user")
        .await
        .and_then(|r| r.error_for_status())
        .map_err(upstream)?
        .json()
        .await
        .map_err(upstream)?;
    let emails: Vec<Email> = get("/user/emails")
        .await
        .and_then(|r| r.error_for_status())
        .map_err(upstream)?
        .json()
        .await
        .map_err(upstream)?;
    let email = emails
        .into_iter()
        .find(|e| e.primary && e.verified)
        .ok_or(Failure::NoVerifiedEmail)?
        .email;
    Ok(VerifiedIdentity {
        provider: "github",
        subject: user.id.to_string(),
        email,
    })
}
