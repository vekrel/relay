// Upstream sign-in providers (plan 6A Task 6): `GET /auth/{github,google}` sends the browser to
// the provider, `GET /auth/{github,google}/callback` turns the provider's code into a
// `VerifiedIdentity` and ends in `oauth::complete_sign_in`. Our own layer: T3 used Clerk here.
//
// Provider `state`, PKCE verifier and (Google) `nonce` are derived from the pending auth-request
// id, a secret only the browser's HttpOnly cookie holds. So a callback is accepted only in the
// browser that opened `/oauth/authorize` (no login CSRF or session swap), with no extra storage.
//
// Sign in with Apple (owner decision 6) slots in here as `apple.rs`, one more route pair and one
// more button on the sign-in page; no client change. Required before the iOS App Store release.
use std::sync::Arc;

use axum::Router;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::oauth::{self, AUTH_REQUEST_COOKIE, AccountsState, hash, message};
use crate::config::{Config, OAuthApp};

mod github;
mod google;
#[cfg(test)]
mod tests;

#[derive(Clone, Copy)]
enum Provider {
    GitHub,
    Google,
}

impl Provider {
    fn name(self) -> &'static str {
        match self {
            Self::GitHub => "github",
            Self::Google => "google",
        }
    }
    fn label(self) -> &'static str {
        match self {
            Self::GitHub => "GitHub",
            Self::Google => "Google",
        }
    }
}

pub struct Providers {
    accounts: Arc<AccountsState>,
    http: reqwest::Client,
    relay_origin: String,
    github: Option<OAuthApp>,
    google: Option<OAuthApp>,
}

impl Providers {
    fn app(&self, p: Provider) -> Option<&OAuthApp> {
        match p {
            Provider::GitHub => self.github.as_ref(),
            Provider::Google => self.google.as_ref(),
        }
    }
    fn redirect_uri(&self, p: Provider) -> String {
        format!("{}/auth/{}/callback", self.relay_origin, p.name())
    }
}

pub fn router(accounts: Arc<AccountsState>, config: &Config) -> Router {
    let http = reqwest::Client::builder()
        .user_agent("vekrel-relay")
        .timeout(std::time::Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("HTTP client builds");
    let s = Arc::new(Providers {
        accounts,
        http,
        relay_origin: config.relay_origin.clone(),
        github: config.github.clone(),
        google: config.google.clone(),
    });
    type S = State<Arc<Providers>>;
    type Q = Result<Query<CallbackParams>, QueryRejection>;
    Router::new()
        .route(
            "/auth/github",
            get(|s: S, h: HeaderMap| start(s, h, Provider::GitHub)),
        )
        .route(
            "/auth/github/callback",
            get(|s: S, h: HeaderMap, q: Q| callback(s, h, q, Provider::GitHub)),
        )
        .route(
            "/auth/google",
            get(|s: S, h: HeaderMap| start(s, h, Provider::Google)),
        )
        .route(
            "/auth/google/callback",
            get(|s: S, h: HeaderMap, q: Q| callback(s, h, q, Provider::Google)),
        )
        .with_state(s)
}

/// A per-sign-in value bound to the auth-request id (`label` separates state, verifier, nonce).
fn derive(label: &str, request_id: &str) -> String {
    hash(&format!("{label}:{request_id}"))
}

fn not_configured(p: Provider) -> Response {
    message(
        StatusCode::SERVICE_UNAVAILABLE,
        "Sign-in unavailable",
        &format!("{} sign-in is not set up on this server.", p.label()),
    )
}

async fn start(State(s): State<Arc<Providers>>, headers: HeaderMap, p: Provider) -> Response {
    let Some(app) = s.app(p) else {
        return not_configured(p);
    };
    let request_id = match live_request(&s, &headers).await {
        Ok(id) => id,
        Err(res) => return *res,
    };
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(derive("pkce", &request_id)));
    let mut q = form_urlencoded::Serializer::new(String::new());
    q.append_pair("client_id", &app.client_id)
        .append_pair("redirect_uri", &s.redirect_uri(p))
        .append_pair("response_type", "code")
        .append_pair("state", &derive("state", &request_id))
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256");
    match p {
        Provider::GitHub => q.append_pair("scope", "read:user user:email"),
        Provider::Google => q
            .append_pair("scope", "openid email profile")
            .append_pair("nonce", &derive("nonce", &request_id)),
    };
    Redirect::to(&format!("{}?{}", app.authorize_url, q.finish())).into_response()
}

#[derive(Deserialize)]
struct CallbackParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

/// Why a provider gave no usable identity. Messages never carry tokens or response bodies.
enum Failure {
    /// The provider has no verified email for this account.
    NoVerifiedEmail,
    /// Upstream call failed or returned something we refuse (bad ID token, error JSON).
    Upstream(String),
}

async fn callback(
    State(s): State<Arc<Providers>>,
    headers: HeaderMap,
    q: Result<Query<CallbackParams>, QueryRejection>,
    p: Provider,
) -> Response {
    let Some(app) = s.app(p) else {
        return not_configured(p);
    };
    let request_id = match live_request(&s, &headers).await {
        Ok(id) => id,
        Err(res) => return *res,
    };
    let q = q.ok().map(|Query(q)| q);
    let state = q.as_ref().and_then(|q| q.state.as_deref()).unwrap_or("");
    // Compare hashes so the comparison time says nothing about the expected state.
    if hash(state) != hash(&derive("state", &request_id)) {
        tracing::warn!(provider = p.name(), "provider callback: state mismatch");
        return message(
            StatusCode::BAD_REQUEST,
            "Sign-in link is not valid",
            "This sign-in did not start in this browser. Go back to the app and start again.",
        );
    }
    let q = q.expect("state matched, so the query parsed");
    let Some(code) = q.code.filter(|_| q.error.is_none()) else {
        return message(
            StatusCode::BAD_REQUEST,
            "Sign-in cancelled",
            &format!(
                "{} did not sign you in. Go back to the app and try again.",
                p.label()
            ),
        );
    };
    let verifier = derive("pkce", &request_id);
    let redirect_uri = s.redirect_uri(p);
    let identity = match p {
        // GitHub's primary verified email is trusted for linking (plan 6A Task 6).
        Provider::GitHub => github::identity(&s.http, app, &code, &verifier, &redirect_uri)
            .await
            .map(|id| (id, true)),
        Provider::Google => {
            let nonce = derive("nonce", &request_id);
            google::identity(&s.http, app, &code, &verifier, &redirect_uri, &nonce).await
        }
    };
    match identity {
        Ok((id, may_link)) => {
            oauth::complete_sign_in_linking(&s.accounts, &headers, id, may_link).await
        }
        Err(Failure::NoVerifiedEmail) => {
            tracing::info!(provider = p.name(), "sign-in refused: no verified email");
            message(
                StatusCode::FORBIDDEN,
                "Email not verified",
                &format!(
                    "Your {} account has no verified email. Verify it with {}, then sign in again.",
                    p.label(),
                    p.label()
                ),
            )
        }
        Err(Failure::Upstream(why)) => {
            tracing::warn!(provider = p.name(), error = %why, "provider sign-in failed");
            message(
                StatusCode::BAD_GATEWAY,
                "Sign-in failed",
                &format!("{} sign-in did not complete. Try again.", p.label()),
            )
        }
    }
}

/// Upstream error kind and status only: reqwest's text can quote response fragments (decode
/// errors), and bodies carry tokens.
fn upstream(e: reqwest::Error) -> Failure {
    let kind = if e.is_timeout() {
        "timeout"
    } else if e.is_connect() {
        "connect"
    } else if e.is_status() {
        "status"
    } else if e.is_decode() {
        "decode"
    } else if e.is_body() {
        "body"
    } else if e.is_request() {
        "request"
    } else {
        "other"
    };
    Failure::Upstream(match e.status() {
        Some(st) => format!("{kind} ({})", st.as_u16()),
        None => kind.to_owned(),
    })
}

/// A provider's OAuth `error` field, logged only when shaped like an RFC 6749 code.
fn error_code(e: Option<String>) -> String {
    match e {
        None => "none".into(),
        Some(e) if e.len() <= 64 && e.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') => e,
        Some(_) => "other".into(),
    }
}

/// The browser's auth-request id, if that request exists and is unexpired. Checked before any
/// upstream call, so a stale or forged cookie costs the provider nothing.
async fn live_request(s: &Providers, headers: &HeaderMap) -> Result<String, Box<Response>> {
    let Some(id) = oauth::cookie(headers, AUTH_REQUEST_COOKIE) else {
        return Err(Box::new(oauth::expired_page()));
    };
    match sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM auth_requests WHERE id = $1 AND expires_at > now())",
    )
    .bind(&id)
    .fetch_one(&s.accounts.pool)
    .await
    {
        Ok(true) => Ok(id),
        Ok(false) => Err(Box::new(oauth::expired_page())),
        Err(e) => Err(Box::new(oauth::internal(e))),
    }
}
