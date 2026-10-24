// Account OAuth (plan 6A Task 5, research §3): `GET /oauth/authorize` (sign-in page),
// `POST /oauth/token` (`authorization_code` + PKCE S256, `refresh_token` with rotation and family
// revoke on reuse), `POST /oauth/revoke`. Our own layer: T3 used Clerk here. The token response
// keeps the shape Engine `cloud/CliTokenManager.ts` reads.
//
// Providers (Tasks 6-8, `providers/`) plug in by calling `complete_sign_in` with a `VerifiedIdentity` from the
// browser that opened `/oauth/authorize`: the pending request is bound to that browser by an
// HttpOnly cookie. Secrets (codes, refresh tokens) are stored as SHA-256 hashes and never logged.
use std::sync::Arc;

use askama::Template;
use axum::extract::rejection::{FormRejection, QueryRejection};
use axum::extract::{FromRef, FromRequestParts, Query, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tower_http::cors::{AllowOrigin, CorsLayer};
use uuid::Uuid;

use super::clients::{self, Clients};
use super::device;
use super::keys::{PublicKeys, SigningKeys};
use super::signup::{self, Refusal, VerifiedIdentity};
use super::tokens::{self, ACCESS_TOKEN_TTL_SECS, AccessClaims};
use crate::config::{Config, SignupMode};

/// Owner decision 4 / research §3: codes 60 s, refresh 30 days sliding.
const CODE_TTL_SECS: i64 = 60;
const REFRESH_TTL_DAYS: i64 = 30;
/// A pending sign-in must outlive a magic link (15 min, Task 7) requested late in it.
const AUTH_REQUEST_TTL_SECS: i64 = 1800;
pub(crate) const AUTH_REQUEST_COOKIE: &str = "vekrel_auth_request";
pub const REFRESH_COOKIE: &str = "vekrel_refresh";
const MAX_STATE_LEN: usize = 512;
const PAGE_CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

pub struct AccountsState {
    pub pool: PgPool,
    pub keys: Arc<SigningKeys>,
    pub public_keys: PublicKeys,
    pub issuer: String,
    pub signup_mode: SignupMode,
    pub clients: Clients,
    pub web_origins: Vec<String>,
}

impl AccountsState {
    pub fn new(pool: PgPool, keys: Arc<SigningKeys>, config: &Config) -> Arc<Self> {
        let public_keys = PublicKeys::from_jwks(&keys.jwks()).expect("own JWKS parses");
        Arc::new(Self {
            pool,
            keys,
            public_keys,
            issuer: config.relay_origin.clone(),
            signup_mode: config.signup_mode,
            clients: Clients::new(&config.web_origins),
            web_origins: config.web_origins.clone(),
        })
    }
}

pub fn router(state: Arc<AccountsState>) -> Router {
    let origins: Vec<HeaderValue> = state
        .web_origins
        .iter()
        .map(|o| HeaderValue::from_str(o).expect("validated origin"))
        .collect();
    // Only the web app reads these responses cross-origin, with its refresh cookie.
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_credentials(true)
        .allow_methods([Method::POST])
        .allow_headers([header::CONTENT_TYPE]);
    let api = Router::new()
        .route("/oauth/token", post(token))
        .route("/oauth/revoke", post(revoke))
        .layer(cors);
    let r = Router::new()
        .route("/oauth/authorize", get(authorize))
        .merge(api);
    #[cfg(test)]
    let r = r.route("/auth/test", get(tests::fake_provider));
    r.with_state(state)
}

pub fn hash(secret: &str) -> String {
    Sha256::digest(secret.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// 32 random bytes, base64url.
pub fn random_secret() -> String {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).expect("OS random source");
    URL_SAFE_NO_PAD.encode(b)
}

pub(super) fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|c| c.trim().strip_prefix(name)?.strip_prefix('='))
        .map(str::to_owned)
}

pub(super) fn set_cookie(
    name: &str,
    value: &str,
    path: &str,
    max_age: i64,
) -> (header::HeaderName, String) {
    (
        header::SET_COOKIE,
        format!("{name}={value}; HttpOnly; Secure; SameSite=Lax; Path={path}; Max-Age={max_age}"),
    )
}

#[derive(Template)]
#[template(path = "signin.html")]
struct SignInPage;

#[derive(Template)]
#[template(path = "message.html")]
struct MessagePage<'a> {
    title: &'a str,
    body: &'a str,
}

pub(super) fn html(status: StatusCode, body: String) -> Response {
    (
        status,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
            (header::CONTENT_SECURITY_POLICY, PAGE_CSP),
            (header::X_FRAME_OPTIONS, "DENY"),
            (header::REFERRER_POLICY, "no-referrer"),
        ],
        body,
    )
        .into_response()
}

pub fn message(status: StatusCode, title: &str, body: &str) -> Response {
    html(
        status,
        MessagePage { title, body }
            .render()
            .expect("template renders"),
    )
}

pub(super) fn expired_page() -> Response {
    message(
        StatusCode::BAD_REQUEST,
        "Sign-in expired",
        "This sign-in is no longer valid. Go back to the app and start again.",
    )
}

pub(super) fn internal(e: impl std::fmt::Display) -> Response {
    tracing::error!(error = %e, "accounts: database error");
    StatusCode::INTERNAL_SERVER_ERROR.into_response()
}

#[derive(Deserialize)]
struct AuthorizeParams {
    response_type: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    state: Option<String>,
}

fn is_b64url(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

async fn authorize(
    State(s): State<Arc<AccountsState>>,
    q: Result<Query<AuthorizeParams>, QueryRejection>,
) -> Response {
    let bad = |body| message(StatusCode::BAD_REQUEST, "Sign-in link is not valid", body);
    let Ok(Query(q)) = q else {
        return bad("The sign-in request is malformed.");
    };
    let (Some(client_id), Some(redirect_uri)) = (q.client_id, q.redirect_uri) else {
        return bad("The sign-in request has no app or return address.");
    };
    // Nothing redirects until the client and its exact redirect URI are known (RFC 6749 §4.1.2.1).
    if !s.clients.redirect_allowed(&client_id, &redirect_uri) {
        return bad("This app or return address is not registered with Vekrel.");
    }
    // Postgres `text` cannot hold NUL: refuse it here rather than fail the insert with a 500.
    if q.state
        .as_ref()
        .is_some_and(|st| st.len() > MAX_STATE_LEN || st.contains('\0'))
    {
        return bad("The sign-in request is malformed.");
    }
    let fail = |error: &str, description: &str| {
        let mut query = form_urlencoded::Serializer::new(String::new());
        query.append_pair("error", error);
        query.append_pair("error_description", description);
        if let Some(st) = &q.state {
            query.append_pair("state", st);
        }
        Redirect::to(&format!("{redirect_uri}?{}", query.finish())).into_response()
    };
    if q.response_type.as_deref() != Some("code") {
        return fail("unsupported_response_type", "response_type must be code");
    }
    // PKCE S256 only: `plain` and a missing method (which RFC 7636 reads as plain) are refused.
    if q.code_challenge_method.as_deref() != Some("S256") {
        return fail("invalid_request", "code_challenge_method must be S256");
    }
    let challenge = q.code_challenge.unwrap_or_default();
    if challenge.len() != 43 || !is_b64url(&challenge) {
        return fail(
            "invalid_request",
            "code_challenge must be a base64url SHA-256",
        );
    }
    start_sign_in(
        &s,
        &client_id,
        &redirect_uri,
        &challenge,
        q.state.as_deref(),
    )
    .await
}

/// Stores a pending sign-in bound to this browser by a cookie and shows the sign-in page. A
/// provider then ends it with `complete_sign_in`. Callers have checked client and redirect.
pub(super) async fn start_sign_in(
    s: &AccountsState,
    client_id: &str,
    redirect_uri: &str,
    challenge: &str,
    state: Option<&str>,
) -> Response {
    let id = random_secret();
    let inserted = sqlx::query(
        "INSERT INTO auth_requests (id, client_id, redirect_uri, code_challenge, state, expires_at)
         VALUES ($1, $2, $3, $4, $5, now() + make_interval(secs => $6))",
    )
    .bind(&id)
    .bind(client_id)
    .bind(redirect_uri)
    .bind(challenge)
    .bind(state)
    .bind(AUTH_REQUEST_TTL_SECS as f64)
    .execute(&s.pool)
    .await;
    if let Err(e) = inserted {
        return internal(e);
    }
    let mut res = html(
        StatusCode::OK,
        SignInPage.render().expect("template renders"),
    );
    let (k, v) = set_cookie(AUTH_REQUEST_COOKIE, &id, "/", AUTH_REQUEST_TTL_SECS);
    res.headers_mut()
        .insert(k, v.parse().expect("cookie header"));
    res
}

/// Ends a sign-in: called by a provider once it has a verified identity for the browser that
/// opened `/oauth/authorize`. Consumes the pending request, applies the sign-up rules, and
/// redirects to the client with a 60 s single-use code and the client's `state`.
pub async fn complete_sign_in(
    s: &AccountsState,
    headers: &HeaderMap,
    identity: VerifiedIdentity,
) -> Response {
    complete_sign_in_linking(s, headers, identity, true).await
}

/// `complete_sign_in`; with `link_by_email` false a new identity may not attach to an existing
/// user by email (the provider is not authoritative for that address).
pub(super) async fn complete_sign_in_linking(
    s: &AccountsState,
    headers: &HeaderMap,
    identity: VerifiedIdentity,
    link_by_email: bool,
) -> Response {
    let Some(request_id) = cookie(headers, AUTH_REQUEST_COOKIE) else {
        return expired_page();
    };
    let pending: Option<(String, String, String, Option<String>, bool)> = match sqlx::query_as(
        "DELETE FROM auth_requests WHERE id = $1
         RETURNING client_id, redirect_uri, code_challenge, state, expires_at > now()",
    )
    .bind(&request_id)
    .fetch_optional(&s.pool)
    .await
    {
        Ok(p) => p,
        Err(e) => return internal(e),
    };
    let Some((client_id, redirect_uri, challenge, state, true)) = pending else {
        return expired_page();
    };
    let resolved = signup::resolve_user(&s.pool, s.signup_mode, &identity, link_by_email).await;
    let user_id = match resolved {
        Err(e) => return internal(e),
        Ok(Err(Refusal::NotAllowed)) => {
            tracing::info!(
                provider = identity.provider,
                "sign-up refused: not on the allowlist"
            );
            return message(
                StatusCode::FORBIDDEN,
                "Vekrel is invite-only for now",
                "This email is not on the list yet. Ask for an invite, then sign in again.",
            );
        }
        Ok(Err(Refusal::Disabled)) => {
            tracing::info!(
                provider = identity.provider,
                "sign-in refused: account disabled"
            );
            return message(
                StatusCode::FORBIDDEN,
                "Account disabled",
                "This Vekrel account is disabled.",
            );
        }
        Ok(Err(Refusal::EmailTaken)) => {
            tracing::info!(
                provider = identity.provider,
                "sign-in refused: email belongs to an account this provider may not link"
            );
            return message(
                StatusCode::FORBIDDEN,
                "Use your usual sign-in",
                "This email already has a Vekrel account. Sign in with your usual method.",
            );
        }
        Ok(Ok(id)) => id,
    };
    let code = random_secret();
    let inserted = sqlx::query(
        "INSERT INTO auth_codes (code_hash, user_id, client_id, redirect_uri, code_challenge, expires_at)
         VALUES ($1, $2, $3, $4, $5, now() + make_interval(secs => $6))",
    )
    .bind(hash(&code))
    .bind(user_id)
    .bind(&client_id)
    .bind(&redirect_uri)
    .bind(&challenge)
    .bind(CODE_TTL_SECS as f64)
    .execute(&s.pool)
    .await;
    if let Err(e) = inserted {
        return internal(e);
    }
    tracing::info!(%user_id, client_id, provider = identity.provider, "sign-in completed");
    let mut query = form_urlencoded::Serializer::new(String::new());
    query.append_pair("code", &code);
    if let Some(st) = &state {
        query.append_pair("state", st);
    }
    let mut res = Redirect::to(&format!("{redirect_uri}?{}", query.finish())).into_response();
    let (k, v) = set_cookie(AUTH_REQUEST_COOKIE, "", "/", 0);
    res.headers_mut()
        .insert(k, v.parse().expect("cookie header"));
    res
}

/// The browser request comes from the web app (cookie-only requests are accepted from it alone).
fn from_web_origin(s: &AccountsState, headers: &HeaderMap) -> bool {
    headers
        .get(header::ORIGIN)
        .and_then(|o| o.to_str().ok())
        .is_some_and(|o| s.web_origins.iter().any(|w| w == o))
}

pub(super) fn oauth_error(error: &str, description: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        [(header::CACHE_CONTROL, "no-store")],
        Json(serde_json::json!({ "error": error, "error_description": description })),
    )
        .into_response()
}

#[derive(Deserialize)]
struct TokenForm {
    grant_type: Option<String>,
    client_id: Option<String>,
    code: Option<String>,
    redirect_uri: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
    device_code: Option<String>,
}

/// `CliTokenManager` `TokenResponse` (snake_case). `refresh_token` is omitted for the web client,
/// which gets it only as an HttpOnly cookie.
#[derive(Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
    id_token: String,
}

/// `id_token`: same key, `typ JWT`. The Engine only decodes it to show who is signed in.
#[derive(Serialize)]
struct IdClaims<'a> {
    iss: &'a str,
    aud: &'a str,
    sub: &'a str,
    iat: u64,
    exp: u64,
    email: &'a str,
}

async fn token(
    State(s): State<Arc<AccountsState>>,
    headers: HeaderMap,
    form: Result<Form<TokenForm>, FormRejection>,
) -> Response {
    let Ok(Form(f)) = form else {
        return oauth_error("invalid_request", "malformed form body");
    };
    let Some(client_id) = f.client_id.filter(|c| s.clients.is_known(c)) else {
        return oauth_error("invalid_client", "unknown client_id");
    };
    let issued = match f.grant_type.as_deref() {
        Some("authorization_code") => {
            let (Some(code), Some(redirect_uri), Some(verifier)) =
                (f.code, f.redirect_uri, f.code_verifier)
            else {
                return oauth_error(
                    "invalid_request",
                    "code, redirect_uri and code_verifier are required",
                );
            };
            redeem_code(&s, &client_id, &code, &redirect_uri, &verifier).await
        }
        Some("refresh_token") => {
            let presented = match f.refresh_token {
                Some(t) => Some(t),
                // The web app sends only its cookie; accept it from the web origins only.
                None if client_id == clients::WEB && from_web_origin(&s, &headers) => {
                    cookie(&headers, REFRESH_COOKIE)
                }
                None => None,
            };
            let Some(presented) = presented else {
                return oauth_error("invalid_request", "refresh_token is required");
            };
            rotate_refresh(&s, &client_id, &presented).await
        }
        Some(device::GRANT_TYPE) => {
            let Some(code) = f.device_code else {
                return oauth_error("invalid_request", "device_code is required");
            };
            match device::redeem(&s, &client_id, &code).await {
                Ok(Err((error, description))) => return oauth_error(error, description),
                Ok(Ok(issued)) => Ok(Ok(issued)),
                Err(e) => Err(e),
            }
        }
        _ => {
            return oauth_error(
                "unsupported_grant_type",
                "grant_type must be authorization_code, refresh_token or device_code",
            );
        }
    };
    let issued = match issued {
        Ok(Ok(t)) => t,
        Ok(Err(description)) => return oauth_error("invalid_grant", description),
        Err(e) => return internal(e),
    };
    let web = client_id == clients::WEB;
    let mut res = (
        [(header::CACHE_CONTROL, "no-store")],
        Json(TokenResponse {
            access_token: issued.access_token,
            token_type: "Bearer",
            expires_in: ACCESS_TOKEN_TTL_SECS,
            refresh_token: (!web).then(|| issued.refresh_token.clone()),
            id_token: issued.id_token,
        }),
    )
        .into_response();
    if web {
        let (k, v) = set_cookie(
            REFRESH_COOKIE,
            &issued.refresh_token,
            "/oauth",
            REFRESH_TTL_DAYS * 86_400,
        );
        res.headers_mut()
            .insert(k, v.parse().expect("cookie header"));
    }
    res
}

pub(super) struct Issued {
    access_token: String,
    refresh_token: String,
    id_token: String,
}

type Grant = Result<Result<Issued, &'static str>, sqlx::Error>;

async fn redeem_code(
    s: &AccountsState,
    client_id: &str,
    code: &str,
    redirect_uri: &str,
    verifier: &str,
) -> Grant {
    let family = Uuid::new_v4();
    // Marks the code used in the same statement that reads it, so it redeems at most once.
    let row: Option<(Uuid, String, String, String, bool, String, bool)> = sqlx::query_as(
        "UPDATE auth_codes c SET used_at = now(), family_id = $2
         FROM users u
         WHERE c.code_hash = $1 AND c.used_at IS NULL AND u.id = c.user_id
         RETURNING c.user_id, c.client_id, c.redirect_uri, c.code_challenge,
                   c.expires_at > now(), u.email::text, u.disabled_at IS NOT NULL",
    )
    .bind(hash(code))
    .bind(family)
    .fetch_optional(&s.pool)
    .await?;
    let Some((user_id, code_client, code_redirect, challenge, live, email, disabled)) = row else {
        // A replayed code revokes whatever it was redeemed into (RFC 6749 §4.1.2).
        let revoked = sqlx::query(
            "UPDATE refresh_tokens SET revoked_at = now()
             WHERE revoked_at IS NULL
               AND family_id = (SELECT family_id FROM auth_codes WHERE code_hash = $1)",
        )
        .bind(hash(code))
        .execute(&s.pool)
        .await?
        .rows_affected();
        if revoked > 0 {
            tracing::warn!("authorization code replayed; its refresh family is revoked");
        }
        return Ok(Err("code is invalid or already used"));
    };
    let pkce = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let verifier_ok = (43..=128).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b));
    if !live || code_client != client_id || code_redirect != redirect_uri {
        return Ok(Err("code is invalid, expired or issued to another client"));
    }
    if !verifier_ok || pkce != challenge {
        return Ok(Err("code_verifier does not match code_challenge"));
    }
    if disabled {
        return Ok(Err("account disabled"));
    }
    let mut tx = s.pool.begin().await?;
    let issued = issue(s, &mut tx, user_id, &email, client_id, family).await?;
    tx.commit().await?;
    Ok(Ok(issued))
}

/// family, user, client, rotated, family revoked, live, email, disabled.
type RefreshRow = (Uuid, Uuid, String, bool, bool, bool, String, bool);

async fn rotate_refresh(s: &AccountsState, client_id: &str, presented: &str) -> Grant {
    let mut tx = s.pool.begin().await?;
    // Row lock: two refreshes with one token run one after the other, and the second is reuse.
    let row: Option<RefreshRow> = sqlx::query_as(
        "SELECT r.family_id, r.user_id, r.client_id, r.rotated_at IS NOT NULL,
                EXISTS (SELECT 1 FROM refresh_tokens f
                        WHERE f.family_id = r.family_id AND f.revoked_at IS NOT NULL),
                r.expires_at > now(), u.email::text, u.disabled_at IS NOT NULL
         FROM refresh_tokens r JOIN users u ON u.id = r.user_id
         WHERE r.hash = $1 FOR UPDATE OF r",
    )
    .bind(hash(presented))
    .fetch_optional(&mut *tx)
    .await?;
    let Some((family, user_id, token_client, rotated, revoked, live, email, disabled)) = row else {
        return Ok(Err("refresh token is invalid"));
    };
    // Any revoked token ends the family: a revoke racing a rotation can miss the new head (its
    // snapshot predates it), so the head is refused here and the family finished off below.
    if revoked || rotated {
        sqlx::query(
            "UPDATE refresh_tokens SET revoked_at = now() WHERE family_id = $1 AND revoked_at IS NULL",
        )
        .bind(family)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        if revoked {
            return Ok(Err("refresh token is revoked"));
        }
        tracing::warn!(family_id = %family, %user_id, "refresh token reused; family revoked");
        return Ok(Err("refresh token was already used"));
    }
    if !live || token_client != client_id || disabled {
        return Ok(Err("refresh token is expired or not valid for this client"));
    }
    sqlx::query("UPDATE refresh_tokens SET rotated_at = now() WHERE hash = $1")
        .bind(hash(presented))
        .execute(&mut *tx)
        .await?;
    let issued = issue(s, &mut tx, user_id, &email, client_id, family).await?;
    tx.commit().await?;
    Ok(Ok(issued))
}

pub(super) async fn issue(
    s: &AccountsState,
    tx: &mut sqlx::PgConnection,
    user_id: Uuid,
    email: &str,
    client_id: &str,
    family: Uuid,
) -> Result<Issued, sqlx::Error> {
    let refresh_token = random_secret();
    sqlx::query(
        "INSERT INTO refresh_tokens (hash, family_id, user_id, client_id, expires_at)
         VALUES ($1, $2, $3, $4, now() + make_interval(days => $5))",
    )
    .bind(hash(&refresh_token))
    .bind(family)
    .bind(user_id)
    .bind(client_id)
    .bind(REFRESH_TTL_DAYS as i32)
    .execute(&mut *tx)
    .await?;
    let claims = AccessClaims::new(
        &s.issuer,
        user_id,
        family,
        client_id,
        email,
        tokens::now_secs(),
    );
    let id_token = tokens::sign(
        &s.keys,
        "JWT",
        &IdClaims {
            iss: &s.issuer,
            aud: client_id,
            sub: &claims.sub,
            iat: claims.iat,
            exp: claims.exp,
            email,
        },
    );
    Ok(Issued {
        access_token: tokens::sign_access_token(&s.keys, &claims),
        refresh_token,
        id_token,
    })
}

#[derive(Deserialize)]
struct RevokeForm {
    token: Option<String>,
}

/// RFC 7009: answers 200 for unknown tokens too. Revokes the whole family of a refresh token.
async fn revoke(
    State(s): State<Arc<AccountsState>>,
    headers: HeaderMap,
    form: Result<Form<RevokeForm>, FormRejection>,
) -> Response {
    let Ok(Form(f)) = form else {
        return oauth_error("invalid_request", "malformed form body");
    };
    // The cookie only from the web app, so a cross-site form post cannot sign the user out.
    let from_cookie = || {
        from_web_origin(&s, &headers)
            .then(|| cookie(&headers, REFRESH_COOKIE))
            .flatten()
    };
    if let Some(t) = f.token.or_else(from_cookie) {
        let done = sqlx::query(
            "UPDATE refresh_tokens SET revoked_at = now()
             WHERE revoked_at IS NULL
               AND family_id = (SELECT family_id FROM refresh_tokens WHERE hash = $1)",
        )
        .bind(hash(&t))
        .execute(&s.pool)
        .await;
        if let Err(e) = done {
            return internal(e);
        }
    }
    if !from_web_origin(&s, &headers) {
        return StatusCode::OK.into_response();
    }
    let (k, v) = set_cookie(REFRESH_COOKIE, "", "/oauth", 0);
    (StatusCode::OK, [(k, v)]).into_response()
}

/// A request with a valid account access token whose user is enabled and whose refresh family is
/// not revoked (so `disable-user` and sign-out take effect on the next request, not in 10 min).
/// Rejection: 401 with an empty body (T3 `HttpApiError.Unauthorized`).
pub struct AccountUser {
    pub user_id: Uuid,
    #[allow(dead_code)] // for routes that show or check them (Tasks 6-8)
    pub email: String,
    #[allow(dead_code)]
    pub client_id: String,
}

impl<S> FromRequestParts<S> for AccountUser
where
    Arc<AccountsState>: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let s = Arc::<AccountsState>::from_ref(state);
        let unauthorized = || StatusCode::UNAUTHORIZED.into_response();
        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or_else(unauthorized)?;
        match account_user(&s, token).await {
            Ok(Some(user)) => Ok(user),
            Ok(None) => Err(unauthorized()),
            Err(e) => Err(internal(e)),
        }
    }
}

/// `AccountUser` for a bearer token: `None` unless the token verifies and is still live.
pub async fn account_user(
    s: &AccountsState,
    token: &str,
) -> Result<Option<AccountUser>, sqlx::Error> {
    let Ok(claims) = tokens::verify_access_token(&s.public_keys, &s.issuer, token) else {
        return Ok(None);
    };
    let (Some(user_id), Ok(family)) = (claims.user_id(), claims.sid.parse::<Uuid>()) else {
        return Ok(None);
    };
    let live: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM users WHERE id = $1 AND disabled_at IS NULL)
            AND NOT EXISTS (SELECT 1 FROM refresh_tokens WHERE family_id = $2 AND revoked_at IS NOT NULL)",
    )
    .bind(user_id)
    .bind(family)
    .fetch_one(&s.pool)
    .await?;
    Ok(live.then_some(AccountUser {
        user_id,
        email: claims.email,
        client_id: claims.client_id,
    }))
}

#[cfg(test)]
pub(crate) mod tests;
