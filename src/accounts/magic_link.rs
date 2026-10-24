// Email sign-in (plan 6A Task 7, research §3 and R6). Our own layer: T3 used Clerk here.
//
// `POST /auth/email` (from the sign-in page) sends a link and a 6-character code for the pending
// `/oauth/authorize` request of this browser (its `vekrel_auth_request` cookie). The reply is the
// same whatever the email: whether it may sign up is decided by `signup.rs`, after the link proves
// the address. `GET /auth/email/verify?t=` signs in only the browser that asked; any other browser
// (Mail on a phone) is shown the code to type into the waiting page, `POST /auth/email/code`.
// Link: 32 random bytes, stored hashed, 15 min, single use. Code: derived from the token, stored
// hashed, 5 wrong tries kill the link. Neither is ever logged.
use std::sync::Arc;

use askama::Template;
use axum::extract::rejection::{FormRejection, QueryRejection};
use axum::extract::{Query, State};
use axum::http::{Extensions, HeaderMap, StatusCode};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Form, Router};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::oauth::{
    AUTH_REQUEST_COOKIE, AccountsState, complete_sign_in, cookie, expired_page, hash, html,
    internal, message, random_secret,
};
use super::signup::VerifiedIdentity;
use crate::config::{Config, MagicLinkTransport};
use crate::email::{self, Email, Mailer};
use crate::rate_limit::{self, client_ip, ip_bucket};

const LINK_TTL_SECS: i64 = 900;
const MAX_CODE_ATTEMPTS: i32 = 5;
/// `(max, window seconds)`. Research R6: 3 sends per email per 15 min, 20 per IP per hour.
const EMAIL_LIMIT: (i64, i64) = (3, 900);
const IP_LIMIT: (i64, i64) = (20, 3600);
/// Ours, a backstop against many IPs at once: all sends together, per hour.
const GLOBAL_LIMIT: (i64, i64) = (200, 3600);
/// No 0/O or 1/I. 32 symbols, so `byte % 32` is unbiased.
const CODE_ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

pub struct MagicLinks {
    accounts: Arc<AccountsState>,
    mailer: Box<dyn Mailer>,
    /// Log transport (never production, see config): the page shows the link and code.
    echo: bool,
    trust_ip_header: bool,
}

pub fn router(accounts: Arc<AccountsState>, config: &Config) -> Router {
    let transport = &config.magic_link_transport;
    let state = Arc::new(MagicLinks {
        accounts,
        mailer: email::from_transport(transport),
        echo: *transport == MagicLinkTransport::Log,
        trust_ip_header: config.trust_proxy_ip_header,
    });
    Router::new()
        .route("/auth/email", post(request_link))
        .route("/auth/email/verify", get(verify))
        .route("/auth/email/code", post(enter_code))
        .with_state(state)
}

#[derive(Template)]
#[template(path = "email_sent.html")]
struct EmailSentPage<'a> {
    error: Option<&'a str>,
    dev: Option<(&'a str, &'a str)>,
}

fn email_sent(status: StatusCode, error: Option<&str>, dev: Option<(&str, &str)>) -> Response {
    html(
        status,
        EmailSentPage { error, dev }
            .render()
            .expect("template renders"),
    )
}

/// The 6-character code for a link token. Derived, so the verify page can show it without storing it.
fn code_for(token: &str) -> String {
    Sha256::digest(format!("vekrel-magic-code:{token}").as_bytes())[..6]
        .iter()
        .map(|b| CODE_ALPHABET[(b % 32) as usize] as char)
        .collect()
}

/// Typed codes: case and spaces or dashes do not matter.
fn normalize_code(typed: &str) -> String {
    typed
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect::<String>()
        .to_ascii_uppercase()
}

/// A plain `local@domain`: no spaces, angle brackets, commas or a second `@`.
fn valid_email(e: &str) -> bool {
    let Some((local, domain)) = e.split_once('@') else {
        return false;
    };
    e.len() <= 254
        && !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !domain.contains('@')
        && !e
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || "<>,;\"()[]\\".contains(c))
}

fn too_many() -> Response {
    message(
        StatusCode::TOO_MANY_REQUESTS,
        "Too many sign-in emails",
        "Wait a few minutes, then try again.",
    )
}

#[derive(Deserialize)]
struct EmailForm {
    email: Option<String>,
}

async fn request_link(
    State(m): State<Arc<MagicLinks>>,
    headers: HeaderMap,
    extensions: Extensions,
    form: Result<Form<EmailForm>, FormRejection>,
) -> Response {
    let pool = &m.accounts.pool;
    let Some(request_id) = cookie(&headers, AUTH_REQUEST_COOKIE) else {
        return expired_page();
    };
    let live: bool = match sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM auth_requests WHERE id = $1 AND expires_at > now())",
    )
    .bind(&request_id)
    .fetch_one(pool)
    .await
    {
        Ok(l) => l,
        Err(e) => return internal(e),
    };
    if !live {
        return expired_page();
    }
    let email = form
        .ok()
        .and_then(|Form(f)| f.email)
        .map(|e| e.trim().to_lowercase())
        .unwrap_or_default();
    if !valid_email(&email) {
        return message(
            StatusCode::BAD_REQUEST,
            "Check the email address",
            "Enter an address like name@example.com, then try again.",
        );
    }
    let ip = match client_ip(&headers, &extensions, m.trust_ip_header) {
        Ok(Some(ip)) => ip_bucket(ip),
        Ok(None) => return internal("no client address (serve attaches ConnectInfo)"),
        Err(_) => {
            return message(
                StatusCode::BAD_REQUEST,
                "Bad request",
                "The request could not be read.",
            );
        }
    };
    // Fixed key order (rate_limit::allow_all locks in this order).
    let limits = [
        ("magic_link:global".to_owned(), GLOBAL_LIMIT),
        (format!("magic_link:ip:{ip}"), IP_LIMIT),
        (format!("magic_link:email:{}", hash(&email)), EMAIL_LIMIT),
    ]
    .map(|(k, (max, secs))| (k, max, secs));
    match rate_limit::allow_all(pool, &limits).await {
        Ok(true) => {}
        Ok(false) => return too_many(),
        Err(e) => return internal(e),
    }
    let token = random_secret();
    let code = code_for(&token);
    let inserted = sqlx::query(
        "INSERT INTO magic_links (token_hash, email, auth_request_id, code_hash, expires_at)
         VALUES ($1, $2, $3, $4, now() + make_interval(secs => $5))",
    )
    .bind(hash(&token))
    .bind(&email)
    .bind(&request_id)
    .bind(hash(&code))
    .bind(LINK_TTL_SECS as f64)
    .execute(pool)
    .await;
    if let Err(e) = inserted {
        return internal(e);
    }
    let link = format!("{}/auth/email/verify?t={token}", m.accounts.issuer);
    let mail = Email {
        to: email,
        subject: "Sign in to Vekrel".into(),
        text: format!(
            "Open this link to sign in to Vekrel:\n\n{link}\n\nOr type this code in the window that asked for it: {code}\n\nThe link and code work once, for 15 minutes. If you did not ask to sign in, ignore this email.\n"
        ),
        html: format!(
            "<p>Open this link to sign in to Vekrel:</p><p><a href=\"{link}\">Sign in to Vekrel</a></p><p>Or type this code in the window that asked for it: <strong>{code}</strong></p><p>The link and code work once, for 15 minutes. If you did not ask to sign in, ignore this email.</p>"
        ),
    };
    if let Err(e) = m.mailer.send(&mail).await {
        tracing::error!(error = %e, "magic link email failed");
        return message(
            StatusCode::SERVICE_UNAVAILABLE,
            "Email not sent",
            "We could not send the sign-in email. Please try again in a minute.",
        );
    }
    tracing::info!("magic link sent");
    email_sent(
        StatusCode::OK,
        None,
        m.echo.then_some((link.as_str(), code.as_str())),
    )
}

#[derive(Deserialize)]
struct VerifyParams {
    t: String,
}

async fn verify(
    State(m): State<Arc<MagicLinks>>,
    headers: HeaderMap,
    q: Result<Query<VerifyParams>, QueryRejection>,
) -> Response {
    let Ok(Query(VerifyParams { t: token })) = q else {
        return expired_page();
    };
    let pool = &m.accounts.pool;
    let row: Option<(Option<String>,)> = match sqlx::query_as(
        "SELECT auth_request_id FROM magic_links
         WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now() AND code_attempts < $2",
    )
    .bind(hash(&token))
    .bind(MAX_CODE_ATTEMPTS)
    .fetch_optional(pool)
    .await
    {
        Ok(r) => r,
        Err(e) => return internal(e),
    };
    let Some((Some(request_id),)) = row else {
        return expired_page();
    };
    if cookie(&headers, AUTH_REQUEST_COOKIE).as_deref() != Some(request_id.as_str()) {
        // Not the browser that asked: show the code, sign nothing in, leave the link alive.
        let code = code_for(&token);
        return message(
            StatusCode::OK,
            "Your sign-in code",
            &format!(
                "Type {code} into the Vekrel window that asked for it. Only enter it in a window you opened yourself."
            ),
        );
    }
    let consumed: Option<String> = match sqlx::query_scalar(
        "UPDATE magic_links SET used_at = now()
         WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now() AND code_attempts < $2
         RETURNING email::text",
    )
    .bind(hash(&token))
    .bind(MAX_CODE_ATTEMPTS)
    .fetch_optional(pool)
    .await
    {
        Ok(r) => r,
        Err(e) => return internal(e),
    };
    match consumed {
        Some(email) => sign_in(&m, &headers, email).await,
        None => expired_page(),
    }
}

#[derive(Deserialize)]
struct CodeForm {
    code: Option<String>,
}

async fn enter_code(
    State(m): State<Arc<MagicLinks>>,
    headers: HeaderMap,
    form: Result<Form<CodeForm>, FormRejection>,
) -> Response {
    let Some(request_id) = cookie(&headers, AUTH_REQUEST_COOKIE) else {
        return expired_page();
    };
    let code = normalize_code(&form.ok().and_then(|Form(f)| f.code).unwrap_or_default());
    let pool = &m.accounts.pool;
    // One statement compares the code and counts the try, under the row locks, so parallel
    // guesses cannot see the counter before the others bump it. A wrong code costs every live
    // link of this sign-in a try; the fifth wrong try kills it.
    let rows: Vec<(bool, String, bool)> = match sqlx::query_as(
        "UPDATE magic_links SET
                code_attempts = code_attempts + CASE WHEN code_hash = $2 THEN 0 ELSE 1 END,
                used_at = CASE WHEN code_hash = $2 OR code_attempts + 1 >= $3 THEN now() END
         WHERE auth_request_id = $1 AND used_at IS NULL AND expires_at > now() AND code_attempts < $3
         RETURNING code_hash = $2, email::text, used_at IS NULL",
    )
    .bind(&request_id)
    .bind(hash(&code))
    .bind(MAX_CODE_ATTEMPTS)
    .fetch_all(pool)
    .await
    {
        Ok(r) => r,
        Err(e) => return internal(e),
    };
    if let Some((_, email, _)) = rows.iter().find(|r| r.0) {
        return sign_in(&m, &headers, email.clone()).await;
    }
    if rows.iter().any(|r| r.2) {
        email_sent(
            StatusCode::BAD_REQUEST,
            Some("That code is not right. Check the email and try again."),
            None,
        )
    } else {
        message(
            StatusCode::BAD_REQUEST,
            "Code no longer valid",
            "The code expired or was mistyped too often. Go back to the app and start again.",
        )
    }
}

/// The link or code proved the address: hand it to the sign-up rules as a verified email.
async fn sign_in(m: &MagicLinks, headers: &HeaderMap, email: String) -> Response {
    let identity = VerifiedIdentity {
        provider: "email",
        subject: email.clone(),
        email,
    };
    complete_sign_in(&m.accounts, headers, identity).await
}

#[cfg(test)]
mod tests;
