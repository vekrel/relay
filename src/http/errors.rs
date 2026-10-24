// Relay error bodies and request decoding as T3's Effect HttpApi produces them
// (`infra/relay/src/http/Api.ts` `mapRelayCommonApiErrors`, Vekrel-Shared `contracts/src/relay.ts`
// error classes; effect 4.0.5 `http-api/HttpApiBuilder.ts`). A tagged error is JSON with `_tag`
// first, then its fields in schema order; schema failures are an empty 400.
// Handlers return early with the response T3 sends; boxing it buys nothing on this path.
#![allow(clippy::result_large_err)]
use axum::body::Bytes;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};

/// A random 32-hex trace id (T3 returns its span's trace id).
pub fn trace_id() -> String {
    let mut id = [0u8; 16];
    getrandom::fill(&mut id).expect("OS random source");
    id.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Debug)]
pub struct RelayError {
    pub status: StatusCode,
    pub tag: &'static str,
    pub fields: Vec<(&'static str, Value)>,
}

impl RelayError {
    pub fn new(status: u16, tag: &'static str, fields: Vec<(&'static str, Value)>) -> Self {
        Self {
            status: StatusCode::from_u16(status).expect("valid status"),
            tag,
            fields,
        }
    }

    /// `RelayAuthInvalidError` (401).
    pub fn auth(reason: &'static str) -> Self {
        Self::new(
            401,
            "RelayAuthInvalidError",
            vec![("code", "auth_invalid".into()), ("reason", reason.into())],
        )
    }

    /// `RelayAuthInvalidError` with reason `invalid_dpop` and a `dpopFailureReason`.
    pub fn invalid_dpop(failure: &'static str) -> Self {
        let mut e = Self::auth("invalid_dpop");
        e.fields.push(("dpopFailureReason", failure.into()));
        e
    }

    /// `HttpApiError.Unauthorized` after `mapRelayCommonApiErrors(authReason)`.
    pub fn unauthorized(auth_reason: &'static str) -> Self {
        if auth_reason == "invalid_dpop" {
            Self::invalid_dpop("invalid_proof")
        } else {
            Self::auth(auth_reason)
        }
    }

    /// `RelayInternalError` (500).
    pub fn internal(reason: &'static str) -> Self {
        Self::new(
            500,
            "RelayInternalError",
            vec![("code", "internal_error".into()), ("reason", reason.into())],
        )
    }

    pub fn body(&self) -> Value {
        let mut m = Map::new();
        m.insert("_tag".into(), self.tag.into());
        for (k, v) in &self.fields {
            m.insert((*k).into(), v.clone());
        }
        m.insert("traceId".into(), trace_id().into());
        Value::Object(m)
    }
}

impl IntoResponse for RelayError {
    fn into_response(self) -> Response {
        (self.status, axum::Json(self.body())).into_response()
    }
}

/// A database error T3 maps to `RelayInternalError persistence_failed`; the cause is logged.
pub fn persistence(e: sqlx::Error) -> RelayError {
    tracing::error!(error = %e, "relay persistence failed");
    RelayError::internal("persistence_failed")
}

/// `appendRelayCredentialResponseHeaders`.
pub fn no_store(mut r: Response) -> Response {
    let h = r.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    r
}

pub fn bad_request() -> Response {
    StatusCode::BAD_REQUEST.into_response()
}

/// Effect `getAuthorizationCredential` (+ T3's `trimStart`): the credential after a
/// case-insensitive `<scheme> ` and any further spaces, `""` when absent.
pub fn credential(headers: &HeaderMap, scheme: &str) -> String {
    let Some(v) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    else {
        return String::new();
    };
    let n = scheme.len();
    if v.len() <= n
        || v.as_bytes()[n] != b' '
        || !v.is_char_boundary(n)
        || !v[..n].eq_ignore_ascii_case(scheme)
    {
        return String::new();
    }
    v[n..].trim_start_matches(' ').trim_start().to_owned()
}

/// A `TrimmedNonEmptyString` header (`RelayDpopRequestHeaders.dpop`); absent or blank is a 400.
pub fn required_header<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str, Response> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(bad_request)
}

fn content_type(headers: &HeaderMap) -> String {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
}

fn unsupported(ct: &str) -> Response {
    (
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        format!("Unsupported content-type: {ct}"),
    )
        .into_response()
}

/// A JSON payload: other content types are 415, an empty or invalid body or a schema mismatch
/// is an empty 400. Unknown keys are ignored (Effect's default `onExcessProperty`).
pub fn json_payload<T: DeserializeOwned>(headers: &HeaderMap, body: &Bytes) -> Result<T, Response> {
    let ct = content_type(headers);
    if ct != "application/json" {
        return Err(unsupported(&ct));
    }
    serde_json::from_slice(body).map_err(|_| bad_request())
}

/// A form payload (`HttpApiSchema.asFormUrlEncoded`): a repeated key becomes an array, which no
/// string field accepts.
pub fn form_payload<T: DeserializeOwned>(headers: &HeaderMap, body: &Bytes) -> Result<T, Response> {
    let ct = content_type(headers);
    if ct != "application/x-www-form-urlencoded" {
        return Err(unsupported(&ct));
    }
    let mut m = Map::new();
    for (k, v) in form_urlencoded::parse(body) {
        match m.get_mut(k.as_ref()) {
            None => {
                m.insert(k.into_owned(), Value::String(v.into_owned()));
            }
            Some(Value::Array(a)) => a.push(Value::String(v.into_owned())),
            Some(prev) => *prev = Value::Array(vec![prev.take(), Value::String(v.into_owned())]),
        }
    }
    serde_json::from_value(Value::Object(m)).map_err(|_| bad_request())
}

/// `TrimmedNonEmptyString`: trimmed on decode, blank refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tns(pub String);

impl<'de> Deserialize<'de> for Tns {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        let t = s.trim();
        if t.is_empty() {
            return Err(serde::de::Error::custom("blank string"));
        }
        Ok(Self(t.to_owned()))
    }
}

/// `Schema.optional(TrimmedNonEmptyString)`: the key may be absent, but `null` is refused.
pub fn optional_tns<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    Tns::deserialize(d).map(|t| Some(t.0))
}

/// `Schema.Int`: a safe integer (`1.0` counts).
pub fn int(v: &Value) -> Option<i64> {
    if let Some(i) = v.as_i64() {
        return (i.unsigned_abs() <= 9_007_199_254_740_991).then_some(i);
    }
    let f = v.as_f64()?;
    (f.fract() == 0.0 && f.abs() <= 9_007_199_254_740_991.0).then_some(f as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth(v: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::AUTHORIZATION, v.parse().unwrap());
        h
    }

    #[test]
    fn credentials_follow_effect() {
        assert_eq!(credential(&auth("Bearer abc"), "Bearer"), "abc");
        assert_eq!(credential(&auth("bearer   abc"), "Bearer"), "abc");
        assert_eq!(credential(&auth("Bearer"), "Bearer"), "");
        assert_eq!(credential(&auth("Bearer "), "Bearer"), "");
        assert_eq!(credential(&auth("Basic abc"), "Bearer"), "");
        assert_eq!(credential(&auth("Bearerabc"), "Bearer"), "");
        assert_eq!(credential(&auth("DPoP xyz"), "DPoP"), "xyz");
        assert_eq!(credential(&HeaderMap::new(), "Bearer"), "");
    }

    #[test]
    fn error_bodies_put_tag_first_and_trace_last() {
        let b = RelayError::invalid_dpop("replay").body().to_string();
        assert!(b.starts_with(
            r#"{"_tag":"RelayAuthInvalidError","code":"auth_invalid","reason":"invalid_dpop","dpopFailureReason":"replay","traceId":""#
        ));
    }

    #[test]
    fn forms_refuse_repeated_keys() {
        #[derive(Debug, Deserialize)]
        struct F {
            #[allow(dead_code)]
            a: Tns,
        }
        let mut h = HeaderMap::new();
        h.insert(
            header::CONTENT_TYPE,
            "application/x-www-form-urlencoded; charset=utf-8"
                .parse()
                .unwrap(),
        );
        assert!(form_payload::<F>(&h, &Bytes::from_static(b"a=+x+")).is_ok());
        assert!(form_payload::<F>(&h, &Bytes::from_static(b"a=x&a=y")).is_err());
        assert!(form_payload::<F>(&h, &Bytes::from_static(b"a=+")).is_err());
        let r = form_payload::<F>(&HeaderMap::new(), &Bytes::from_static(b"a=x")).unwrap_err();
        assert_eq!(r.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
}
