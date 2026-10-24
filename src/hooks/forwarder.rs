// `GET/POST/PUT/PATCH /v1/hooks/:endpointKey/:hookId/:token`. Port of T3 Code's
// `infra/relay/src/hooks/HookForwarder.ts` (MIT, Copyright (c) T3 Tools Inc.; see NOTICE).
// Hook paths get no CORS (T3 `layerCors` skips them). The token, the headers and the body never
// reach a log: only the endpoint key, the hook id, outcomes and statuses are logged.
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use http_body_util::BodyExt;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::held::{HookEndpoint, resolve_endpoint};
use super::inbox;
use super::upstream::{self, DELIVERY_PROOF_HEADER, Hook, TUNNEL_OFFLINE_STATUS};
use crate::jws;
use crate::machines::{Relay, now_iso, now_ms};
use crate::rate_limit::allow_all;

/// `RELAY_HOOK_MAX_BODY_BYTES`.
pub const MAX_BODY_BYTES: usize = 1_048_576;
/// `RELAY_HOOK_RATE_LIMIT`: per URL.
pub const HOOK_RATE_LIMIT: (i64, i64) = (60, 60);
/// `RELAY_HOOK_ENDPOINT_RATE_LIMIT`: a sender who knows an endpoint key can mint new URLs for free,
/// so every endpoint also has one overall budget.
pub const ENDPOINT_RATE_LIMIT: (i64, i64) = (600, 60);
/// `DELIVERY_PROOF_LIFETIME_SECONDS`: longer than the inbox holds a request.
const DELIVERY_PROOF_LIFETIME_SECONDS: i64 = 25 * 60 * 60;

/// `DROPPED_REQUEST_HEADERS`, renamed relay headers included.
const DROPPED_HEADERS: [&str; 15] = [
    "host",
    "connection",
    "keep-alive",
    "transfer-encoding",
    "te",
    "upgrade",
    "content-length",
    "cookie",
    "x-real-ip",
    // Only the relay may set these; a sender could otherwise collide delivery ids.
    upstream::DELIVERY_ID_HEADER,
    upstream::RECEIVED_AT_HEADER,
    DELIVERY_PROOF_HEADER,
    // The machine trusts trace context only from the relay.
    "traceparent",
    "tracestate",
    "b3",
];
const DROPPED_HEADER_PREFIXES: [&str; 4] = ["proxy-", "cf-", "x-forwarded-", "x-b3-"];

pub fn router(relay: Arc<Relay>) -> Router {
    Router::new()
        .route("/v1/hooks/{endpoint_key}/{hook_id}/{token}", any(forward))
        .with_state(relay)
}

/// Marks the forwarder's own 405, which the global wrong-method rewrite must keep.
#[derive(Clone, Copy)]
pub struct Own405;

fn error(status: u16, error: &str) -> Response {
    (
        StatusCode::from_u16(status).expect("valid status"),
        axum::Json(json!({ "error": error })),
    )
        .into_response()
}

fn hook_not_found() -> Response {
    error(404, "hook_not_found")
}

struct HookPath {
    endpoint_key: String,
    hook_id: String,
    token: String,
    raw_hook_id: String,
    raw_token: String,
    query: String,
}

/// `decodeURIComponent`: `None` on a malformed escape or invalid UTF-8.
fn decode_uri_component(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            if i + 2 >= b.len() || !(b[i + 1].is_ascii_hexdigit() && b[i + 2].is_ascii_hexdigit()) {
                return None;
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    percent_encoding::percent_decode_str(s)
        .decode_utf8()
        .ok()
        .map(|c| c.into_owned())
}

/// `parseHookPath`.
fn parse_hook_path(path: &str, query: Option<&str>) -> Option<HookPath> {
    let segments: Vec<&str> = path.split('/').collect();
    let [_, _, _, endpoint_key, raw_hook_id, raw_token] = segments[..] else {
        return None;
    };
    if !super::is_endpoint_key(endpoint_key) || raw_hook_id.is_empty() || raw_token.is_empty() {
        return None;
    }
    Some(HookPath {
        endpoint_key: endpoint_key.to_owned(),
        hook_id: decode_uri_component(raw_hook_id)?,
        token: decode_uri_component(raw_token)?,
        raw_hook_id: raw_hook_id.to_owned(),
        raw_token: raw_token.to_owned(),
        query: query.unwrap_or("").to_owned(),
    })
}

/// `hookBudgetKey`: requests with a wrong token get their own budget, so they cannot use up a real
/// sender's. Over decoded segments, so two spellings of one token share it; length-prefixed (in
/// UTF-16 units, as JS counts) so no contents can make two keys collide.
pub fn hook_budget_key(endpoint_key: &str, hook_id: &str, token: &str) -> String {
    let joined: String = [endpoint_key, hook_id, token]
        .iter()
        .map(|p| format!("{}:{p}", p.encode_utf16().count()))
        .collect();
    Sha256::digest(joined.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// One limiter hit; fails open, as T3's: a limiter outage must not drop webhooks.
async fn allow(relay: &Relay, key: String, (max, secs): (i64, i64)) -> bool {
    allow_all(&relay.pool, &[(key, max, secs)])
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, "hook rate limiter unavailable");
            true
        })
}

/// `forwardedHeaders`: lower-case names; repeated headers joined as `fetch` joins them.
fn forwarded_headers(headers: &HeaderMap) -> Map<String, Value> {
    let nominated: Vec<String> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|n| n.trim().to_ascii_lowercase())
        .filter(|n| !n.is_empty())
        .collect();
    let mut out = Map::new();
    for name in headers.keys() {
        let n = name.as_str();
        if DROPPED_HEADERS.contains(&n)
            || nominated.iter().any(|x| x == n)
            || DROPPED_HEADER_PREFIXES.iter().any(|p| n.starts_with(p))
        {
            continue;
        }
        // shortcut: non-UTF-8 header values are dropped (fetch would decode them as Latin-1);
        // webhook signatures are ASCII. Upgrade if a sender ever needs other bytes.
        let values: Option<Vec<&str>> = headers
            .get_all(name)
            .iter()
            .map(|v| v.to_str().ok())
            .collect();
        if let Some(values) = values {
            out.insert(n.to_owned(), Value::String(values.join(", ")));
        }
    }
    out
}

enum BodyError {
    TooLarge,
    Invalid,
}

/// `readCappedBody`.
async fn read_capped(body: Body) -> Result<Vec<u8>, BodyError> {
    let mut body = body;
    let mut out = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| BodyError::Invalid)?;
        if let Some(data) = frame.data_ref() {
            out.extend_from_slice(data);
            if out.len() > MAX_BODY_BYTES {
                return Err(BodyError::TooLarge);
            }
        }
    }
    Ok(out)
}

/// `signDeliveryProof`: proves the delivery id, receive time and hook id came from the relay.
/// Signed once and stored with a held request.
fn delivery_proof(relay: &Relay, machine_id: &str, hook: &Hook) -> String {
    let now = now_ms() / 1000;
    let claims = json!({
        "iss": relay.normalized_issuer(),
        "aud": jws::machine_principal(machine_id),
        "sub": machine_id,
        "jti": uuid::Uuid::new_v4().to_string(),
        "iat": now,
        "exp": now + DELIVERY_PROOF_LIFETIME_SECONDS,
        "machineId": machine_id,
        "deliveryId": hook.id,
        "receivedAt": hook.received_at,
        "hookId": hook.hook_key,
    });
    jws::sign(&relay.mint_key, jws::RELAY_HOOK_DELIVERY_TYP, &claims)
}

/// Whatever the machine answers is served from the relay's own origin, so it must never render
/// or run there.
fn sandboxed(status: u16, content_type: Option<String>, body: Vec<u8>) -> Response {
    let mut r = Response::new(Body::from(body));
    *r.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
    let h = r.headers_mut();
    h.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        "content-security-policy",
        HeaderValue::from_static("sandbox; default-src 'none'"),
    );
    if let Some(ct) = content_type.and_then(|c| HeaderValue::from_str(&c).ok()) {
        h.insert(header::CONTENT_TYPE, ct);
    }
    r
}

async fn forward(State(relay): State<Arc<Relay>>, request: Request) -> Response {
    let (outcome, response) = handle(&relay, request).await;
    tracing::info!(
        outcome,
        status = response.status().as_u16(),
        "relay.hooks.forward"
    );
    response
}

/// `HookForwarder.handle`: the outcome T3 annotates, and the response.
async fn handle(relay: &Relay, request: Request) -> (&'static str, Response) {
    let method = request.method().clone();
    if method == Method::HEAD {
        let mut r = error(405, "method_not_allowed");
        r.headers_mut().insert(
            header::ALLOW,
            HeaderValue::from_static("GET, POST, PUT, PATCH"),
        );
        r.extensions_mut().insert(Own405);
        return ("method_not_allowed", r);
    }
    if ![Method::GET, Method::POST, Method::PUT, Method::PATCH].contains(&method) {
        // T3 has no route for other methods: its catch-all answers an empty 404.
        return ("no_route", StatusCode::NOT_FOUND.into_response());
    }
    let received_at = now_iso();
    let Some(p) = parse_hook_path(request.uri().path(), request.uri().query()) else {
        return ("invalid_path", hook_not_found());
    };
    let endpoint_allowed = allow(
        relay,
        format!("hook-endpoint:{}", p.endpoint_key),
        ENDPOINT_RATE_LIMIT,
    )
    .await;
    let hook_allowed = endpoint_allowed
        && allow(
            relay,
            format!(
                "hook:{}",
                hook_budget_key(&p.endpoint_key, &p.hook_id, &p.token)
            ),
            HOOK_RATE_LIMIT,
        )
        .await;
    if !hook_allowed {
        tracing::info!(
            endpoint_key = %p.endpoint_key,
            limit = if endpoint_allowed { "hook" } else { "endpoint" },
            "hook rate limited"
        );
        let mut r = error(429, "rate_limited");
        r.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from(HOOK_RATE_LIMIT.1));
        return ("rate_limited", r);
    }
    // `Number(content-length ?? "0")`: a non-number skips the check; the reader is capped anyway.
    let declared = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<f64>().ok());
    if declared.is_some_and(|n| n > MAX_BODY_BYTES as f64) {
        return ("payload_too_large", error(413, "payload_too_large"));
    }
    let endpoint = match resolve_endpoint(relay, &p.endpoint_key).await {
        Ok(Some(e)) => e,
        Ok(None) => return ("not_found", hook_not_found()),
        Err(e) => {
            tracing::warn!(endpoint_key = %p.endpoint_key, error = %e, "failed to resolve hook endpoint");
            return ("not_found", hook_not_found());
        }
    };
    let (parts, body) = request.into_parts();
    let body = if method == Method::GET {
        Vec::new()
    } else {
        match read_capped(body).await {
            Ok(b) => b,
            Err(BodyError::TooLarge) => {
                return ("payload_too_large", error(413, "payload_too_large"));
            }
            Err(BodyError::Invalid) => return ("invalid_body", error(400, "invalid_body")),
        }
    };
    tracing::info!(
        endpoint_key = %p.endpoint_key,
        hook_id = %p.hook_id,
        machine_id = %endpoint.machine_id,
        body_bytes = body.len(),
        "relay.hooks.received"
    );
    // One id per request, so a request that reached the machine before a timeout and is later
    // delivered from the inbox runs only once.
    let mut hook = Hook {
        id: uuid::Uuid::new_v4().to_string(),
        received_at,
        method: method.as_str().to_owned(),
        raw_hook_id: p.raw_hook_id,
        raw_token: p.raw_token,
        hook_key: p.hook_id,
        query: p.query,
        headers: forwarded_headers(&parts.headers),
        body,
    };
    let proof = delivery_proof(relay, &endpoint.machine_id, &hook);
    hook.headers
        .insert(DELIVERY_PROOF_HEADER.to_owned(), Value::String(proof));

    let offline = match upstream::send(relay, &endpoint.http_base_url, &hook).await {
        Err(_) => (503, "environment_unavailable"),
        Ok(None) => (504, "environment_timeout"),
        Ok(Some(r)) if matches!(r.status, 502 | 503 | 504 | TUNNEL_OFFLINE_STATUS) => {
            (503, "environment_unavailable")
        }
        Ok(Some(r)) => {
            tracing::info!(
                endpoint_key = %p.endpoint_key,
                upstream_status = r.status,
                upstream_outcome = r.outcome.as_deref(),
                "relay.hooks.forwarded"
            );
            return ("forwarded", sandboxed(r.status, r.content_type, r.body));
        }
    };
    hold_or_fail(relay, &p.endpoint_key, &endpoint, &hook, offline).await
}

/// `holdOrFail`.
async fn hold_or_fail(
    relay: &Relay,
    endpoint_key: &str,
    endpoint: &HookEndpoint,
    hook: &Hook,
    (status, err): (u16, &'static str),
) -> (&'static str, Response) {
    if !endpoint.hold_while_offline {
        return (err, error(status, err));
    }
    match inbox::hold(&relay.pool, endpoint_key, &endpoint.http_base_url, hook).await {
        Ok(true) => (
            "held",
            (StatusCode::ACCEPTED, axum::Json(json!({ "queued": true }))).into_response(),
        ),
        Ok(false) => ("inbox_full", error(503, "inbox_full")),
        Err(e) => {
            tracing::warn!(machine_id = %endpoint.machine_id, error = %e, "could not hold webhook request");
            (err, error(status, err))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_parse_as_t3_parses_them() {
        let p = parse_hook_path("/v1/hooks/0123456789abcdef/hook-1/tok%2Fen", Some("a=1")).unwrap();
        assert_eq!((p.hook_id.as_str(), p.token.as_str()), ("hook-1", "tok/en"));
        assert_eq!(
            (p.raw_token.as_str(), p.query.as_str()),
            ("tok%2Fen", "a=1")
        );
        for bad in [
            "/v1/hooks/0123456789ABCDEF/h/t",
            "/v1/hooks/0123456789abcdef/h",
            "/v1/hooks/0123456789abcdef/h/t/",
            "/v1/hooks/0123456789abcdef/h/%zz",
            "/v1/hooks/0123456789abcdef/h/%e",
            "/v1/hooks/0123456789abcdef/h/%",
            "/v1/hooks/0123456789abcdef/h/%ff",
        ] {
            assert!(parse_hook_path(bad, None).is_none(), "{bad}");
        }
    }

    #[test]
    fn budgets_key_on_decoded_length_prefixed_segments() {
        let k = |a, b, c| hook_budget_key(a, b, c);
        assert_eq!(k("e", "h", "t").len(), 64);
        assert_ne!(k("e", "h", "t:1"), k("e", "h:1", "t"));
        assert_ne!(k("e", "h", "right"), k("e", "h", "wrong"));
        // `"1:e1:h2:ab"` is what JS hashes for these; UTF-16 counts a non-BMP char as 2.
        let expected: String = Sha256::digest(b"1:e1:h2:ab")
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(k("e", "h", "ab"), expected);
        let astral: String = Sha256::digest("1:e1:h2:\u{1F600}".as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(k("e", "h", "\u{1F600}"), astral);
    }
}
