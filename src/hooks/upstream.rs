// Sends a webhook request through a machine's tunnel. Port of T3 Code's
// `infra/relay/src/hooks/upstream.ts` (MIT, Copyright (c) T3 Tools Inc.; see NOTICE). Header names
// are the renamed ones the Engine reads (`scheduledTasks/RelayDeliveryProof.ts`, `webhookRoute.ts`).
// The URL, its token and the request never reach a log: reqwest errors are reported by kind only.
use std::time::Duration;

use serde_json::{Map, Value};

use crate::machines::Relay;

pub const DELIVERY_ID_HEADER: &str = "x-vekrel-relay-delivery-id";
pub const RECEIVED_AT_HEADER: &str = "x-vekrel-relay-received-at";
/// `RELAY_HOOK_DELIVERY_HEADER` (Vekrel-Shared `relayJwt.ts:15`).
pub const DELIVERY_PROOF_HEADER: &str = "x-vekrel-relay-delivery";
/// The machine names what it did with the request (`webhookRoute.ts` `WEBHOOK_OUTCOME_HEADER`).
const OUTCOME_HEADER: &str = "x-vekrel-hook-outcome";
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
/// `RELAY_HOOK_UPSTREAM_TIMEOUT_MS`.
pub const UPSTREAM_TIMEOUT: Duration = Duration::from_millis(8_000);
/// Cloudflare answers 530 when the tunnel for a hostname has no connected origin.
pub const TUNNEL_OFFLINE_STATUS: u16 = 530;

/// `UpstreamHook` / `HeldHook`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hook {
    pub id: String,
    pub received_at: String,
    pub method: String,
    /// Path segments exactly as the sender sent them; the machine decodes them.
    pub raw_hook_id: String,
    pub raw_token: String,
    /// The decoded hook id, so every spelling of one hook shares its cap.
    pub hook_key: String,
    /// Without the leading `?`.
    pub query: String,
    /// Lower-case names in arrival order, as T3's header record.
    pub headers: Map<String, Value>,
    pub body: Vec<u8>,
}

/// `UpstreamResponse`.
#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub content_type: Option<String>,
    pub outcome: Option<String>,
    pub body: Vec<u8>,
}

/// Why a send failed (the `_tag` T3 annotates); never the error text, which carries the URL.
pub type Failure = &'static str;

/// The machine URL of a hook: `<base>/api/hooks/<rawHookId>/<rawToken>[?query]`. The base is the
/// managed endpoint of the link (never anything from the request), so the host is fixed.
pub fn hook_url(base_url: &str, hook: &Hook) -> String {
    let base = if base_url.ends_with('/') {
        base_url.to_owned()
    } else {
        format!("{base_url}/")
    };
    let query = if hook.query.is_empty() {
        String::new()
    } else {
        format!("?{}", hook.query)
    };
    format!(
        "{base}api/hooks/{}/{}{query}",
        hook.raw_hook_id, hook.raw_token
    )
}

/// `sendUpstream`: `Err` when the machine cannot be reached, `Ok(None)` on timeout.
pub async fn send(relay: &Relay, base_url: &str, hook: &Hook) -> Result<Option<Response>, Failure> {
    #[cfg(test)]
    let base_url = relay.endpoint_override.as_deref().unwrap_or(base_url);
    let url = reqwest::Url::parse(&hook_url(base_url, hook)).map_err(|_| "InvalidUrl")?;
    let method = reqwest::Method::from_bytes(hook.method.as_bytes()).map_err(|_| "InvalidUrl")?;
    let mut headers = reqwest::header::HeaderMap::new();
    for (name, value) in &hook.headers {
        if let (Ok(n), Some(Ok(v))) = (
            reqwest::header::HeaderName::from_bytes(name.as_bytes()),
            value.as_str().map(reqwest::header::HeaderValue::from_str),
        ) {
            headers.insert(n, v);
        }
    }
    for (name, value) in [
        (DELIVERY_ID_HEADER, &hook.id),
        (RECEIVED_AT_HEADER, &hook.received_at),
    ] {
        if let Ok(v) = reqwest::header::HeaderValue::from_str(value) {
            headers.insert(name, v);
        }
    }
    let mut request = relay.http.request(method.clone(), url);
    if method != reqwest::Method::GET {
        // Effect `bodyUint8Array` defaults the content type when the sender sent none.
        if !headers.contains_key(reqwest::header::CONTENT_TYPE) {
            headers.insert(
                reqwest::header::CONTENT_TYPE,
                reqwest::header::HeaderValue::from_static("application/octet-stream"),
            );
        }
        request = request.body(hook.body.clone());
    }
    let call = async {
        let mut res = request
            .headers(headers)
            .send()
            .await
            .map_err(|_| "RequestError")?;
        let mut body = Vec::new();
        while let Some(chunk) = res.chunk().await.map_err(|_| "ResponseError")? {
            body.extend_from_slice(&chunk);
            if body.len() > MAX_RESPONSE_BYTES {
                return Err("ResponseTooLarge");
            }
        }
        let header = |n| {
            res.headers()
                .get(n)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        };
        let outcome = header(OUTCOME_HEADER).filter(|o| {
            (1..=32).contains(&o.len()) && o.bytes().all(|c| c.is_ascii_lowercase() || c == b'_')
        });
        Ok(Response {
            status: res.status().as_u16(),
            content_type: header(reqwest::header::CONTENT_TYPE.as_str()),
            outcome,
            body,
        })
    };
    match tokio::time::timeout(UPSTREAM_TIMEOUT, call).await {
        Ok(r) => r.map(Some),
        Err(_) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_machine_url_keeps_the_base_host_and_raw_segments() {
        let hook = Hook {
            id: "d".into(),
            received_at: "t".into(),
            method: "POST".into(),
            raw_hook_id: "hook-1".into(),
            raw_token: "tok%2Fen".into(),
            hook_key: "hook-1".into(),
            query: "a=1&b=two%20words".into(),
            headers: Map::new(),
            body: vec![],
        };
        assert_eq!(
            hook_url("https://m.example.test/", &hook),
            "https://m.example.test/api/hooks/hook-1/tok%2Fen?a=1&b=two%20words"
        );
        let mut tricky = hook.clone();
        tricky.raw_hook_id = "@evil.example".into();
        tricky.raw_token = "..".into();
        tricky.query = String::new();
        let url = reqwest::Url::parse(&hook_url("https://m.example.test", &tricky)).unwrap();
        assert_eq!(url.host_str(), Some("m.example.test"));
    }
}
