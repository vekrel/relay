// RFC 8628 device authorization grant (plan 6A Task 8) for `vekrel-engine connect --headless`.
// Our own layer: T3 used Clerk's device endpoint. The wire is RFC 8628 as Engine
// `cloud/CliTokenManager.ts` reads it (`DeviceAuthorizationResponse`, `pollDeviceToken`).
//
// `POST /oauth/device_authorization` gives the CLI a device code (stored only as a SHA-256 hash)
// and a short user code. `GET /device` signs the browser in through the normal sign-in page: an
// internal `vekrel-device` authorize request whose PKCE verifier sits in a cookie, so every
// provider and the sign-up rules (`signup::resolve_user`) apply. `/device/callback` then asks for
// an explicit approval, posted back with a signed 5 min token (`/device/confirm`). The CLI polls
// `/oauth/token` with the device_code grant (`redeem`). The prompt heading uses only trusted data
// (client name); the CLI-reported User-Agent is shown below it, labelled unverified.
use std::sync::Arc;

use askama::Template;
use axum::extract::rejection::{FormRejection, QueryRejection};
use axum::extract::{Query, State};
use axum::http::{Extensions, HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::oauth::{
    self, AccountsState, Issued, cookie, expired_page, hash, html, internal, message, oauth_error,
    random_secret, set_cookie,
};
use super::tokens;

pub const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";
/// The one client allowed to use the grant.
const CLIENT: &str = "vekrel-cli";
/// Plan 6A Task 8: codes live 10 min, poll every 5 s; RFC 8628 §3.5 `slow_down` adds 5 s.
const DEVICE_CODE_TTL_SECS: i64 = 600;
const INTERVAL_SECS: i32 = 5;
const SLOW_DOWN_SECS: i32 = 5;
/// RFC 8628 §6.1: 20 consonants (no vowels, so no words; no digits, so no 0/O or 1/I).
/// 8 of them is 20^8, about 2^34.6 codes.
const ALPHABET: &[u8; 20] = b"BCDFGHJKLMNPQRSTVWXZ";
const USER_CODE_LEN: usize = 8;
/// Code lookups per signed-in user per 15 min. With 20^8 codes and a 10 min TTL this keeps a
/// guess at someone else's pending code out of reach.
const LOOKUPS_PER_WINDOW: i32 = 10;
const LOOKUP_WINDOW_SECS: f64 = 900.0;
/// Per client IP, `(max, window seconds)`; ours (T3 used Clerk's device endpoint): device code
/// requests, and user-code lookups next to the per-user limit above.
const DEVICE_START_IP_LIMIT: (i64, i64) = (10, 900);
const LOOKUP_IP_LIMIT: (i64, i64) = (20, 900);
const APPROVAL_TTL_SECS: u64 = 300;
const APPROVAL_TYP: &str = "vekrel-device-approval+jwt";
/// The browser leg's client. Not in `Clients`, so `/oauth/authorize` and `/oauth/token` refuse it.
const BROWSER_CLIENT: &str = "vekrel-device";
const VERIFIER_COOKIE: &str = "vekrel_device_verifier";
const MAX_USER_AGENT_CHARS: usize = 200;
const SHOWN_USER_AGENT_CHARS: usize = 64;

type Refused = (&'static str, &'static str);

pub fn router(state: Arc<AccountsState>) -> Router {
    Router::new()
        .route("/oauth/device_authorization", post(device_authorization))
        .route("/device", get(device_page))
        .route("/device/callback", get(callback))
        .route("/device/confirm", post(confirm))
        .with_state(state)
}

fn new_user_code() -> String {
    let mut out = String::with_capacity(USER_CODE_LEN);
    while out.len() < USER_CODE_LEN {
        let mut b = [0u8; 16];
        getrandom::fill(&mut b).expect("OS random source");
        // 240 = 12 * 20: dropping larger bytes keeps every letter equally likely.
        let need = USER_CODE_LEN - out.len();
        out.extend(
            b.iter()
                .filter(|&&x| x < 240)
                .map(|&x| ALPHABET[usize::from(x % 20)] as char)
                .take(need),
        );
    }
    out
}

/// `BCDF-GHJK`, as people see it. Stored without the dash.
fn display(code: &str) -> String {
    format!("{}-{}", &code[..4], &code[4..])
}

/// Accepts what people type (any case, dashes, spaces); `None` unless 8 alphabet letters.
fn normalize(input: &str) -> Option<String> {
    let c: String = input
        .chars()
        .filter(|c| *c != '-' && !c.is_whitespace())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    (c.len() == USER_CODE_LEN && c.bytes().all(|b| ALPHABET.contains(&b))).then_some(c)
}

fn callback_uri(s: &AccountsState) -> String {
    format!("{}/device/callback", s.issuer)
}

#[derive(Deserialize)]
struct AuthorizationForm {
    // `scope` is accepted and ignored: tokens carry no scopes.
    client_id: Option<String>,
}

/// RFC 8628 §3.2, in the order Engine's schema lists the fields.
#[derive(Serialize)]
struct DeviceAuthorization {
    device_code: String,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: String,
    expires_in: i64,
    interval: i32,
}

async fn device_authorization(
    State(s): State<Arc<AccountsState>>,
    headers: HeaderMap,
    extensions: Extensions,
    form: Result<Form<AuthorizationForm>, FormRejection>,
) -> Response {
    if let Some(res) = oauth::ip_limited(
        &s,
        &headers,
        &extensions,
        "device_authorization",
        DEVICE_START_IP_LIMIT,
        oauth::too_many_oauth,
    )
    .await
    {
        return res;
    }
    let Ok(Form(f)) = form else {
        return oauth_error("invalid_request", "malformed form body");
    };
    match f.client_id.as_deref() {
        Some(CLIENT) => {}
        Some(c) if s.clients.is_known(c) => {
            return oauth_error("unauthorized_client", "only the CLI uses the device grant");
        }
        _ => return oauth_error("invalid_client", "unknown client_id"),
    }
    let user_agent: Option<String> = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|ua| ua.chars().take(MAX_USER_AGENT_CHARS).collect());
    let device_code = random_secret();
    let mut user_code = None;
    // `user_code` is unique: a clash with a stored code just draws again.
    for _ in 0..3 {
        let candidate = new_user_code();
        let inserted = sqlx::query(
            "INSERT INTO device_codes (device_code_hash, user_code, client_id, user_agent, interval_seconds, expires_at)
             VALUES ($1, $2, $3, $4, $5, now() + make_interval(secs => $6))
             ON CONFLICT (user_code) DO NOTHING",
        )
        .bind(hash(&device_code))
        .bind(&candidate)
        .bind(CLIENT)
        .bind(&user_agent)
        .bind(INTERVAL_SECS)
        .bind(DEVICE_CODE_TTL_SECS as f64)
        .execute(&s.pool)
        .await;
        match inserted {
            Err(e) => return internal(e),
            Ok(r) if r.rows_affected() == 1 => {
                user_code = Some(candidate);
                break;
            }
            Ok(_) => {}
        }
    }
    let Some(user_code) = user_code else {
        return internal("device grant: no free user code");
    };
    let shown = display(&user_code);
    let uri = format!("{}/device", s.issuer);
    (
        [(header::CACHE_CONTROL, "no-store")],
        Json(DeviceAuthorization {
            device_code,
            verification_uri_complete: format!("{uri}?user_code={shown}"),
            user_code: shown,
            verification_uri: uri,
            expires_in: DEVICE_CODE_TTL_SECS,
            interval: INTERVAL_SECS,
        }),
    )
        .into_response()
}

#[derive(Template)]
#[template(path = "device.html")]
struct EntryPage<'a> {
    error: Option<&'a str>,
}

#[derive(Template)]
#[template(path = "device_confirm.html")]
struct ConfirmPage<'a> {
    client: &'a str,
    user_agent: Option<String>,
    email: &'a str,
    requested: &'a str,
    user_code: &'a str,
    approval: &'a str,
}

#[derive(Deserialize)]
struct PageParams {
    user_code: Option<String>,
}

/// The code entry form; with a well-formed `user_code`, the sign-in page for this browser.
/// The code is not looked up before sign-in, so guessing costs a sign-in per try (see `callback`).
async fn device_page(
    State(s): State<Arc<AccountsState>>,
    headers: HeaderMap,
    extensions: Extensions,
    q: Result<Query<PageParams>, QueryRejection>,
) -> Response {
    let input = q.ok().and_then(|Query(q)| q.user_code).unwrap_or_default();
    if input.is_empty() {
        let page = EntryPage { error: None };
        return html(StatusCode::OK, page.render().expect("template renders"));
    }
    let Some(code) = normalize(&input) else {
        let page = EntryPage {
            error: Some("That code is not valid. Check it and try again."),
        };
        return html(
            StatusCode::BAD_REQUEST,
            page.render().expect("template renders"),
        );
    };
    if let Some(res) = oauth::ip_limited(
        &s,
        &headers,
        &extensions,
        "authorize",
        oauth::SIGN_IN_START_IP_LIMIT,
        oauth::too_many_pages,
    )
    .await
    {
        return res;
    }
    // The user code rides in the verifier, so the auth request's challenge commits to it and
    // `callback` can tell the `state` it gets back was not swapped.
    let verifier = format!("{}.{code}", random_secret());
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let mut res = oauth::start_sign_in(
        &s,
        BROWSER_CLIENT,
        &callback_uri(&s),
        &challenge,
        Some(&code),
    )
    .await;
    if res.status().is_success() {
        let (k, v) = set_cookie(VERIFIER_COOKIE, &verifier, "/device", DEVICE_CODE_TTL_SECS);
        res.headers_mut()
            .append(k, v.parse().expect("cookie header"));
    }
    res
}

#[derive(Deserialize)]
struct CallbackParams {
    code: Option<String>,
    state: Option<String>,
}

/// Approval token claims: who signed in, for which user code.
#[derive(Serialize, Deserialize)]
struct Approval {
    iss: String,
    aud: String,
    sub: String,
    user_code: String,
    iat: u64,
    exp: u64,
}

fn too_many_lookups() -> Response {
    message(
        StatusCode::TOO_MANY_REQUESTS,
        "Too many attempts",
        "Wait 15 minutes, then run the sign-in command again.",
    )
}

fn invalid_code_page() -> Response {
    message(
        StatusCode::BAD_REQUEST,
        "Code not valid",
        "This code is wrong, expired or already used. Run the sign-in command again for a new code.",
    )
}

/// Back from the sign-in page: redeems the browser leg's code with this browser's verifier,
/// finds the pending device code and asks the signed-in user to approve or deny it.
async fn callback(
    State(s): State<Arc<AccountsState>>,
    headers: HeaderMap,
    extensions: Extensions,
    q: Result<Query<CallbackParams>, QueryRejection>,
) -> Response {
    let (
        Some(verifier),
        Ok(Query(CallbackParams {
            code: Some(code),
            state: Some(state),
        })),
    ) = (cookie(&headers, VERIFIER_COOKIE), q)
    else {
        return expired_page();
    };
    let Some(user_code) = verifier
        .rsplit_once('.')
        .and_then(|(_, bound)| normalize(&state).filter(|c| c == bound))
    else {
        return expired_page();
    };
    // Before the code is spent, so a refused browser can retry once the window passes.
    if let Some(res) = oauth::ip_limited(
        &s,
        &headers,
        &extensions,
        "device_lookup",
        LOOKUP_IP_LIMIT,
        too_many_lookups,
    )
    .await
    {
        return res;
    }
    let redeemed: Option<(Uuid, String, bool)> = match sqlx::query_as(
        "UPDATE auth_codes SET used_at = now()
         WHERE code_hash = $1 AND used_at IS NULL AND client_id = $2 AND redirect_uri = $3
         RETURNING user_id, code_challenge, expires_at > now()",
    )
    .bind(hash(&code))
    .bind(BROWSER_CLIENT)
    .bind(callback_uri(&s))
    .fetch_optional(&s.pool)
    .await
    {
        Ok(r) => r,
        Err(e) => return internal(e),
    };
    let Some((user_id, challenge, true)) = redeemed else {
        return expired_page();
    };
    if URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())) != challenge {
        return expired_page();
    }
    // Every lookup counts, hit or miss, so one account cannot walk the code space.
    let lookups: Result<i32, _> = sqlx::query_scalar(
        "INSERT INTO relay_rate_limits (key, window_start, count)
         VALUES ($1, to_timestamp(floor(extract(epoch FROM now()) / $2) * $2), 1)
         ON CONFLICT (key, window_start) DO UPDATE SET count = relay_rate_limits.count + 1
         RETURNING count",
    )
    .bind(format!("device-lookup:{user_id}"))
    .bind(LOOKUP_WINDOW_SECS)
    .fetch_one(&s.pool)
    .await;
    match lookups {
        Err(e) => return internal(e),
        Ok(n) if n > LOOKUPS_PER_WINDOW => {
            tracing::warn!(%user_id, "device code lookups over the limit");
            return too_many_lookups();
        }
        Ok(_) => {}
    }
    let found: Option<(Option<String>, String, String)> = match sqlx::query_as(
        "SELECT d.user_agent, u.email::text,
                to_char(d.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI')
         FROM device_codes d JOIN users u ON u.id = $2
         WHERE d.user_code = $1 AND d.status = 'pending' AND d.expires_at > now()",
    )
    .bind(&user_code)
    .bind(user_id)
    .fetch_optional(&s.pool)
    .await
    {
        Ok(f) => f,
        Err(e) => return internal(e),
    };
    let Some((user_agent, email, requested)) = found else {
        return invalid_code_page();
    };
    let now = tokens::now_secs();
    let approval = tokens::sign(
        &s.keys,
        APPROVAL_TYP,
        &Approval {
            iss: s.issuer.clone(),
            aud: BROWSER_CLIENT.to_owned(),
            sub: user_id.to_string(),
            user_code: user_code.clone(),
            iat: now,
            exp: now + APPROVAL_TTL_SECS,
        },
    );
    let page = ConfirmPage {
        client: "Vekrel CLI",
        // Self-reported by the CLI: shown small and labelled, never in the heading.
        user_agent: user_agent.map(|ua| ua.chars().take(SHOWN_USER_AGENT_CHARS).collect()),
        email: &email,
        requested: &requested,
        user_code: &display(&user_code),
        approval: &approval,
    };
    let mut res = html(StatusCode::OK, page.render().expect("template renders"));
    let (k, v) = set_cookie(VERIFIER_COOKIE, "", "/device", 0);
    res.headers_mut()
        .append(k, v.parse().expect("cookie header"));
    res
}

fn verify_approval(s: &AccountsState, token: &str) -> Option<Approval> {
    let header = jsonwebtoken::decode_header(token).ok()?;
    if header.alg != Algorithm::EdDSA || header.typ.as_deref() != Some(APPROVAL_TYP) {
        return None;
    }
    let key = s.public_keys.get(header.kid.as_deref()?)?;
    let mut v = Validation::new(Algorithm::EdDSA);
    v.leeway = 0;
    v.set_audience(&[BROWSER_CLIENT]);
    v.set_issuer(&[&s.issuer]);
    v.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    jsonwebtoken::decode::<Approval>(token, key, &v)
        .ok()
        .map(|d| d.claims)
}

#[derive(Deserialize)]
struct ConfirmForm {
    approval: Option<String>,
    action: Option<String>,
}

/// The explicit answer. Only a page this relay rendered for a signed-in user carries a valid
/// `approval`, which a cross-site form cannot read, so this is CSRF-safe without a cookie.
async fn confirm(
    State(s): State<Arc<AccountsState>>,
    form: Result<Form<ConfirmForm>, FormRejection>,
) -> Response {
    let Ok(Form(f)) = form else {
        return expired_page();
    };
    let Some(approval) = f.approval.as_deref().and_then(|t| verify_approval(&s, t)) else {
        return expired_page();
    };
    let Ok(user_id) = approval.sub.parse::<Uuid>() else {
        return expired_page();
    };
    let status = match f.action.as_deref() {
        Some("approve") => "approved",
        Some("deny") => "denied",
        _ => return expired_page(),
    };
    // Re-checked here: the account may have been disabled since the prompt was shown.
    let disabled: Option<bool> =
        match sqlx::query_scalar("SELECT disabled_at IS NOT NULL FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(&s.pool)
            .await
        {
            Ok(d) => d,
            Err(e) => return internal(e),
        };
    match disabled {
        Some(false) => {}
        Some(true) => {
            tracing::info!(%user_id, "device sign-in refused: account disabled");
            return message(
                StatusCode::FORBIDDEN,
                "Account disabled",
                "This Vekrel account is disabled.",
            );
        }
        None => return expired_page(),
    }
    let answered = sqlx::query(
        "UPDATE device_codes SET status = $3, user_id = $2
         WHERE user_code = $1 AND status = 'pending' AND expires_at > now()",
    )
    .bind(&approval.user_code)
    .bind(user_id)
    .bind(status)
    .execute(&s.pool)
    .await;
    match answered {
        Err(e) => internal(e),
        Ok(r) if r.rows_affected() == 0 => invalid_code_page(),
        Ok(_) if status == "approved" => {
            tracing::info!(%user_id, "device sign-in approved");
            message(
                StatusCode::OK,
                "Sign-in approved",
                "You can close this page and go back to your terminal.",
            )
        }
        Ok(_) => {
            tracing::info!(%user_id, "device sign-in denied");
            message(
                StatusCode::OK,
                "Sign-in denied",
                "The terminal will not be signed in.",
            )
        }
    }
}

/// client, status, live, polled too soon, approving user, their email, disabled.
type PollRow = (
    String,
    String,
    bool,
    bool,
    Option<Uuid>,
    Option<String>,
    bool,
);

/// The device_code grant (RFC 8628 §3.4-3.5). Locks the row so a code issues tokens once.
pub(super) async fn redeem(
    s: &AccountsState,
    client_id: &str,
    device_code: &str,
) -> Result<Result<Issued, Refused>, sqlx::Error> {
    let mut tx = s.pool.begin().await?;
    let row: Option<PollRow> = sqlx::query_as(
        "SELECT d.client_id, d.status, d.expires_at > now(),
                d.last_polled_at IS NOT NULL
                    AND now() - d.last_polled_at < make_interval(secs => d.interval_seconds),
                d.user_id, u.email::text, coalesce(u.disabled_at IS NOT NULL, false)
         FROM device_codes d LEFT JOIN users u ON u.id = d.user_id
         WHERE d.device_code_hash = $1 FOR UPDATE OF d",
    )
    .bind(hash(device_code))
    .fetch_optional(&mut *tx)
    .await?;
    let Some((code_client, status, live, too_soon, user_id, email, disabled)) = row else {
        return Ok(Err(("invalid_grant", "device_code is invalid")));
    };
    if code_client != client_id || status == "consumed" {
        return Ok(Err((
            "invalid_grant",
            "device_code is invalid or already used",
        )));
    }
    if !live {
        return Ok(Err(("expired_token", "device_code has expired")));
    }
    if too_soon {
        sqlx::query(
            "UPDATE device_codes SET interval_seconds = interval_seconds + $2, last_polled_at = now()
             WHERE device_code_hash = $1",
        )
        .bind(hash(device_code))
        .bind(SLOW_DOWN_SECS)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        return Ok(Err(("slow_down", "polling too often; add 5 seconds")));
    }
    let next = if status == "approved" {
        "consumed"
    } else {
        status.as_str()
    };
    sqlx::query(
        "UPDATE device_codes SET last_polled_at = now(), status = $2 WHERE device_code_hash = $1",
    )
    .bind(hash(device_code))
    .bind(next)
    .execute(&mut *tx)
    .await?;
    let result = match (status.as_str(), user_id, email) {
        ("approved", Some(user_id), Some(email)) if !disabled => {
            let issued =
                oauth::issue(s, &mut tx, user_id, &email, client_id, Uuid::new_v4()).await?;
            tracing::info!(%user_id, client_id, "device sign-in completed");
            Ok(issued)
        }
        ("approved", ..) => Err(("invalid_grant", "account disabled")),
        ("denied", ..) => Err(("access_denied", "the user denied the sign-in")),
        _ => Err(("authorization_pending", "waiting for the user to approve")),
    };
    tx.commit().await?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_codes_use_the_whole_unambiguous_alphabet() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            let c = new_user_code();
            assert_eq!(c.len(), USER_CODE_LEN);
            assert!(c.bytes().all(|b| ALPHABET.contains(&b)), "{c}");
            seen.extend(c.bytes());
        }
        assert_eq!(seen.len(), ALPHABET.len());
        for b in b"AEIOUY01" {
            assert!(!ALPHABET.contains(b));
        }
    }

    #[test]
    fn typed_codes_normalize() {
        assert_eq!(normalize("bcdf-ghjk").as_deref(), Some("BCDFGHJK"));
        assert_eq!(normalize(" BCDF GHJK ").as_deref(), Some("BCDFGHJK"));
        assert_eq!(display("BCDFGHJK"), "BCDF-GHJK");
        for bad in [
            "BCDF-GHJ",
            "BCDF-GHJKL",
            "BCDF-GHJA",
            "BCDF-GHJ0",
            "BCDF_GHJK",
            "ВCDF-GHJK",
        ] {
            assert_eq!(normalize(bad), None, "{bad}");
        }
    }
}
