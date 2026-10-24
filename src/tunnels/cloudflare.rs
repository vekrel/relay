// The Cloudflare API calls T3 Code's relay makes through Alchemy's tunnel and DNS bindings
// (`infra/relay/src/environments/ManagedEndpointProvider.ts` `layerCloudflareBindings` and
// `makeCloudflareApiGate`; MIT, Copyright (c) T3 Tools Inc.; see NOTICE), as plain REST calls:
// `/accounts/<id>/cfd_tunnel...` and `/zones/<id>/dns_records...`. Every call passes the gate: a
// shared pause after any 429 refuses calls without a request, so the account can recover instead
// of extending the limit. The API token is only ever a request header; it is never logged.
use std::sync::Mutex;
use std::time::Duration;

use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::PgPool;

use super::api_pause;
use crate::config::CloudflareConfig;
use crate::machines::connector::normalize_zone;
use crate::machines::now_ms;

/// `CLOUDFLARE_DEFAULT_RATE_LIMIT_PAUSE` and `CLOUDFLARE_MAX_RATE_LIMIT_PAUSE`.
const DEFAULT_RATE_LIMIT_PAUSE_MS: i64 = 30_000;
const MAX_RATE_LIMIT_PAUSE_MS: i64 = 120_000;
/// `CLOUDFLARE_PAUSE_REFRESH_MILLIS`: every replica rereads the shared pause at most this often.
const PAUSE_REFRESH_MS: i64 = 5_000;
/// The gate's `Effect.timeout("8 seconds")`.
const CALL_TIMEOUT: Duration = Duration::from_secs(8);

/// `ManagedEndpointTunnel`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Tunnel {
    pub id: Option<String>,
    pub name: Option<String>,
    pub status: Option<String>,
    pub created_at: Option<String>,
    pub conns_inactive_at: Option<String>,
    pub deleted_at: Option<String>,
}

/// `ManagedEndpointTunnelListRequest` (`isDeleted` is always false).
#[derive(Debug, Default)]
pub struct ListRequest<'a> {
    pub name: Option<&'a str>,
    pub include_prefix: Option<&'a str>,
    pub status: Option<&'a str>,
    pub existed_at: Option<&'a str>,
    pub was_inactive_at: Option<&'a str>,
    pub page: Option<u32>,
    pub per_page: Option<u32>,
}

pub struct ListPage {
    pub result: Vec<Tunnel>,
    pub total_count: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// Cloudflare answered with an error status (or `success: false`).
    Status {
        status: u16,
        /// `Retry-After` of a 429, in ms.
        retry_after_ms: Option<i64>,
        messages: Vec<String>,
    },
    /// `CloudflareApiPaused`: refused locally during the pause after a 429.
    Paused { retry_after_ms: i64 },
    /// No answer (connect error, timeout) or one that does not decode.
    Transport(&'static str),
}

/// `ManagedEndpointTunnelClientError` / `ManagedEndpointDnsClientError`.
#[derive(Debug, Clone)]
pub struct ApiError {
    pub operation: &'static str,
    pub failure: Failure,
}

impl ApiError {
    /// `isManagedEndpointNotFound`.
    pub fn is_not_found(&self) -> bool {
        matches!(self.failure, Failure::Status { status: 404, .. })
    }

    /// `cloudflareRetryAfterMillis`; `Some` exactly when the cause is a rate limit or the pause
    /// after one (`isCloudflareRateLimited`).
    pub fn retry_after_ms(&self) -> Option<i64> {
        match &self.failure {
            Failure::Paused { retry_after_ms } => Some(*retry_after_ms),
            Failure::Status {
                status: 429,
                retry_after_ms,
                ..
            } => Some(pause_ms(*retry_after_ms)),
            _ => None,
        }
    }

    /// `isManagedEndpointTunnelInUse`: Cloudflare refuses to delete a tunnel with a connector.
    pub fn is_tunnel_in_use(&self) -> bool {
        matches!(&self.failure, Failure::Status { messages, .. }
            if messages.iter().any(|m| m.contains("has active connections")))
    }
}

/// `cloudflareRateLimitPauseMillis`.
fn pause_ms(retry_after_ms: Option<i64>) -> i64 {
    retry_after_ms
        .unwrap_or(DEFAULT_RATE_LIMIT_PAUSE_MS)
        .min(MAX_RATE_LIMIT_PAUSE_MS)
}

/// `{ type: "CNAME", name, content: "<tunnel>.cfargotunnel.com", ttl: 1, proxied: true }`.
pub fn cname_record(hostname: &str, tunnel_id: &str) -> Value {
    json!({
        "type": "CNAME",
        "name": hostname,
        "content": format!("{tunnel_id}.cfargotunnel.com"),
        "ttl": 1,
        "proxied": true,
    })
}

pub struct Cloudflare {
    config: CloudflareConfig,
    http: reqwest::Client,
    pool: PgPool,
    /// `(pausedUntilMillis, checkedAtMillis)` cached by this replica.
    gate: Mutex<(i64, i64)>,
}

impl Cloudflare {
    pub fn new(config: CloudflareConfig, pool: PgPool) -> Self {
        Self {
            config,
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(CALL_TIMEOUT)
                .build()
                .expect("HTTP client builds"),
            pool,
            gate: Mutex::new((0, i64::MIN)),
        }
    }

    fn url(&self, segments: &[&str]) -> url::Url {
        let mut u = url::Url::parse(&self.config.api_base).expect("CLOUDFLARE_API_BASE is a URL");
        u.path_segments_mut()
            .expect("CLOUDFLARE_API_BASE has a path")
            .pop_if_empty()
            .extend(segments);
        u
    }

    fn tunnel_url(&self, rest: &[&str]) -> url::Url {
        let mut s = vec!["accounts", self.config.account_id.as_str(), "cfd_tunnel"];
        s.extend(rest);
        self.url(&s)
    }

    fn dns_url(&self, rest: &[&str]) -> url::Url {
        let mut s = vec!["zones", self.config.zone_id.as_str(), "dns_records"];
        s.extend(rest);
        self.url(&s)
    }

    /// The gate plus one request; returns the envelope (`result`, `result_info`).
    async fn call(
        &self,
        operation: &'static str,
        method: reqwest::Method,
        url: url::Url,
        body: Option<Value>,
    ) -> Result<Value, ApiError> {
        let err = |failure| ApiError { operation, failure };
        let now = now_ms();
        let refresh = {
            let mut g = self.gate.lock().unwrap();
            let due = now >= g.0 && now.saturating_sub(g.1) >= PAUSE_REFRESH_MS;
            if due {
                g.1 = now;
            }
            due
        };
        if refresh {
            // Read first: a 429 recorded while the read is in flight must win.
            let shared = api_pause::paused_until_ms(&self.pool).await;
            let mut g = self.gate.lock().unwrap();
            g.0 = g.0.max(shared);
        }
        let paused_until = self.gate.lock().unwrap().0;
        if now < paused_until {
            tracing::info!(operation, "cloudflare call refused during the API pause");
            return Err(err(Failure::Paused {
                retry_after_ms: paused_until - now,
            }));
        }
        let mut req = self
            .http
            .request(method, url)
            .bearer_auth(&self.config.api_token.0);
        if let Some(b) = body {
            req = req.json(&b);
        }
        let res = req.send().await.map_err(|e| {
            err(Failure::Transport(if e.is_timeout() {
                "timeout"
            } else {
                "request"
            }))
        })?;
        let status = res.status().as_u16();
        let retry_after_ms = res
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<i64>().ok())
            .map(|s| s.saturating_mul(1000));
        let envelope: Option<Value> = res.json().await.ok();
        let success = envelope
            .as_ref()
            .and_then(|e| e.get("success"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if (200..300).contains(&status) && success {
            return Ok(envelope.unwrap_or(Value::Null));
        }
        if (200..300).contains(&status) && envelope.is_none() {
            return Err(err(Failure::Transport("decode")));
        }
        let messages = envelope
            .as_ref()
            .and_then(|e| e.get("errors"))
            .and_then(Value::as_array)
            .map(|errors| {
                errors
                    .iter()
                    .filter_map(|e| e.get("message").and_then(Value::as_str).map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        let e = err(Failure::Status {
            status,
            retry_after_ms,
            messages,
        });
        if status == 429 {
            let pause = pause_ms(retry_after_ms);
            let until = now_ms() + pause;
            {
                let mut g = self.gate.lock().unwrap();
                g.0 = g.0.max(until);
            }
            tracing::warn!(operation, pause_ms = pause, "cloudflare rate limited");
            api_pause::pause_until(&self.pool, until).await;
        }
        Err(e)
    }

    fn decode<T: serde::de::DeserializeOwned>(
        operation: &'static str,
        v: Value,
    ) -> Result<T, ApiError> {
        serde_json::from_value(v.get("result").cloned().unwrap_or(Value::Null)).map_err(|_| {
            ApiError {
                operation,
                failure: Failure::Transport("decode"),
            }
        })
    }

    pub async fn get_tunnel(&self, tunnel_id: &str) -> Result<Tunnel, ApiError> {
        let v = self
            .call(
                "get",
                reqwest::Method::GET,
                self.tunnel_url(&[tunnel_id]),
                None,
            )
            .await?;
        Self::decode("get", v)
    }

    pub async fn list_tunnels(&self, r: &ListRequest<'_>) -> Result<ListPage, ApiError> {
        let mut url = self.tunnel_url(&[]);
        {
            let mut q = url.query_pairs_mut();
            q.append_pair("is_deleted", "false");
            for (k, v) in [
                ("name", r.name),
                ("include_prefix", r.include_prefix),
                ("status", r.status),
                ("existed_at", r.existed_at),
                ("was_inactive_at", r.was_inactive_at),
            ] {
                if let Some(v) = v {
                    q.append_pair(k, v);
                }
            }
            for (k, v) in [("page", r.page), ("per_page", r.per_page)] {
                if let Some(v) = v {
                    q.append_pair(k, &v.to_string());
                }
            }
        }
        let v = self.call("list", reqwest::Method::GET, url, None).await?;
        let total_count = v
            .get("result_info")
            .and_then(|i| i.get("total_count"))
            .and_then(Value::as_i64);
        Ok(ListPage {
            result: Self::decode("list", v)?,
            total_count,
        })
    }

    pub async fn create_tunnel(&self, name: &str) -> Result<Tunnel, ApiError> {
        let v = self
            .call(
                "create",
                reqwest::Method::POST,
                self.tunnel_url(&[]),
                Some(json!({ "name": name, "config_src": "cloudflare" })),
            )
            .await?;
        Self::decode("create", v)
    }

    /// Ingress `hostname -> service`, then `http_status:404`.
    pub async fn put_configuration(
        &self,
        tunnel_id: &str,
        hostname: &str,
        service: &str,
    ) -> Result<(), ApiError> {
        self.call(
            "put-configuration",
            reqwest::Method::PUT,
            self.tunnel_url(&[tunnel_id, "configurations"]),
            Some(json!({ "config": { "ingress": [
                { "hostname": hostname, "service": service },
                { "service": "http_status:404" },
            ]}})),
        )
        .await
        .map(drop)
    }

    pub async fn get_token(&self, tunnel_id: &str) -> Result<String, ApiError> {
        let v = self
            .call(
                "get-token",
                reqwest::Method::GET,
                self.tunnel_url(&[tunnel_id, "token"]),
                None,
            )
            .await?;
        Self::decode("get-token", v)
    }

    pub async fn delete_tunnel(&self, tunnel_id: &str) -> Result<(), ApiError> {
        self.call(
            "delete",
            reqwest::Method::DELETE,
            self.tunnel_url(&[tunnel_id]),
            None,
        )
        .await
        .map(drop)
    }

    /// `listRecords`: records whose name is exactly `hostname`.
    pub async fn list_records(&self, hostname: &str) -> Result<Vec<String>, ApiError> {
        let mut url = self.dns_url(&[]);
        url.query_pairs_mut().append_pair("search", hostname);
        let v = self
            .call("list-records", reqwest::Method::GET, url, None)
            .await?;
        let records: Vec<Value> = Self::decode("list-records", v)?;
        let want = host_key(hostname);
        Ok(records
            .iter()
            .filter(|r| {
                r.get("name")
                    .and_then(Value::as_str)
                    .is_some_and(|n| host_key(n) == want)
            })
            .filter_map(|r| r.get("id").and_then(Value::as_str).map(str::to_owned))
            .collect())
    }

    pub async fn create_record(&self, record: &Value) -> Result<String, ApiError> {
        let v = self
            .call(
                "create-record",
                reqwest::Method::POST,
                self.dns_url(&[]),
                Some(record.clone()),
            )
            .await?;
        let r: Value = Self::decode("create-record", v)?;
        r.get("id")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or(ApiError {
                operation: "create-record",
                failure: Failure::Transport("decode"),
            })
    }

    pub async fn update_record(&self, id: &str, record: &Value) -> Result<(), ApiError> {
        self.call(
            "update-record",
            reqwest::Method::PUT,
            self.dns_url(&[id]),
            Some(record.clone()),
        )
        .await
        .map(drop)
    }

    pub async fn delete_record(&self, id: &str) -> Result<(), ApiError> {
        self.call(
            "delete-record",
            reqwest::Method::DELETE,
            self.dns_url(&[id]),
            None,
        )
        .await
        .map(drop)
    }
}

/// `normalizeHostname`.
fn host_key(h: &str) -> String {
    let h = normalize_zone(h);
    h.strip_prefix('[')
        .and_then(|x| x.strip_suffix(']'))
        .map(str::to_owned)
        .unwrap_or(h)
}

/// Epoch ms of a Cloudflare timestamp (`DateTime.make`): RFC 3339 UTC with up to nanosecond
/// fractions (`2026-10-24T00:00:00.123456Z`), or `+00:00` for `Z`.
pub fn parse_time(s: &str) -> Option<i64> {
    let s = s
        .strip_suffix("+00:00")
        .map_or(s.to_owned(), |b| format!("{b}Z"));
    let body = s.strip_suffix('Z')?;
    let (whole, frac) = body.split_once('.').unwrap_or((body, ""));
    if !frac.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let ms = &frac[..frac.len().min(3)];
    let iso = if ms.is_empty() {
        format!("{whole}Z")
    } else {
        format!("{whole}.{ms}Z")
    };
    crate::machines::parse_iso_ms(&iso)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloudflare_times_parse() {
        assert_eq!(parse_time("1970-01-01T00:00:01.123456Z"), Some(1_123));
        assert_eq!(parse_time("1970-01-01T00:00:01Z"), Some(1_000));
        assert_eq!(parse_time("1970-01-01T00:00:01+00:00"), Some(1_000));
        assert_eq!(parse_time("1970-01-01T00:00:01.5+01:00"), None);
        assert_eq!(parse_time("soon"), None);
    }

    #[test]
    fn rate_limit_pause_is_bounded() {
        let e = |status, retry_after_ms| ApiError {
            operation: "get",
            failure: Failure::Status {
                status,
                retry_after_ms,
                messages: vec![],
            },
        };
        assert_eq!(e(429, None).retry_after_ms(), Some(30_000));
        assert_eq!(e(429, Some(5_000)).retry_after_ms(), Some(5_000));
        assert_eq!(e(429, Some(600_000)).retry_after_ms(), Some(120_000));
        assert_eq!(e(500, Some(5_000)).retry_after_ms(), None);
        assert!(e(404, None).is_not_found());
    }
}
