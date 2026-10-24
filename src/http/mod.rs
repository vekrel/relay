// Router. `/health` follows T3's relay `infra/relay/src/http/Api.ts` (layerHealthApi) and
// Vekrel-Shared `packages/contracts/src/relay.ts` (RelayHealthResponse).
// T3 runs `SELECT 1` and answers RelayInternalError `database_unavailable` (500) on failure.
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Json, Router, routing::get};
use serde_json::{Value, json};
use sqlx::PgPool;

use crate::accounts::device;
use crate::accounts::keys::SigningKeys;
use crate::accounts::magic_link;
use crate::accounts::oauth::{self, AccountsState};
use crate::accounts::providers;
use crate::config::Config;
use crate::hooks;
use crate::machines::Relay;
use crate::machines::provider::NoTunnels;

pub mod client;
pub mod errors;
pub mod push;
pub mod server;
pub mod token_exchange;
pub mod wellknown;

/// The relay. Machine routes need `RELAY_MINT_PRIVATE_KEY` (`serve` requires it).
#[cfg(test)]
pub fn router(pool: PgPool, keys: Arc<SigningKeys>, config: &Config) -> Router {
    build(pool, keys, config).0
}

/// The router, and the push service whose workers `serve` starts (none without a mint key).
pub fn build(
    pool: PgPool,
    keys: Arc<SigningKeys>,
    config: &Config,
) -> (Router, Option<Arc<crate::push::Push>>) {
    let accounts = AccountsState::new(pool.clone(), keys.clone(), config);
    let r = Router::new()
        .route("/health", get(health))
        .with_state(pool.clone())
        .merge(wellknown::router(&keys, &config.relay_origin))
        .merge(oauth::router(accounts.clone()))
        .merge(device::router(accounts.clone()))
        .merge(magic_link::router(accounts.clone(), config))
        .merge(providers::router(accounts.clone(), config));
    let Some(pem) = &config.mint_private_key else {
        return (global(r), None);
    };
    let mint_key =
        crate::jws::signing_key_from_pem(&pem.0).expect("serve validated RELAY_MINT_PRIVATE_KEY");
    let push = Arc::new(crate::push::Push::new(pool.clone(), config.push.clone()));
    let pool_for_tunnels = pool.clone();
    let relay = Arc::new(Relay::new(
        pool,
        mint_key,
        &config.relay_origin,
        config.tunnel_zone.clone(),
        match crate::tunnels::from_config(&pool_for_tunnels, config) {
            Some(t) => t,
            None => Arc::new(NoTunnels),
        },
    ));
    // Held webhooks are delivered in the background (T3: the inbox objects' alarms).
    tokio::spawn(hooks::inbox::worker(relay.clone()));
    let machines = client::MachineState { relay, accounts };
    let r = r
        .merge(hooks::forwarder::router(machines.relay.clone()))
        .merge(client::router(machines.clone()))
        .merge(push::router(push::PushState {
            machines,
            push: push.clone(),
        }));
    (global(r), Some(push))
}

async fn health(State(pool): State<PgPool>) -> (StatusCode, Json<Value>) {
    match sqlx::query("SELECT 1").execute(&pool).await {
        Ok(_) => (
            StatusCode::OK,
            Json(json!({ "ok": true, "service": "relay" })),
        ),
        Err(e) => {
            tracing::error!(error = %e, "health: database unavailable");
            internal_error("database_unavailable")
        }
    }
}

/// T3 `RelayInternalError` body (Vekrel-Shared `contracts/src/relay.ts`), `traceId` a 32-hex id.
fn internal_error(reason: &str) -> (StatusCode, Json<Value>) {
    let trace_id = errors::trace_id();
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({
            "_tag": "RelayInternalError",
            "code": "internal_error",
            "reason": reason,
            "traceId": trace_id,
        })),
    )
}

/// T3 `Api.ts` `RELAY_REQUEST_DEADLINE_MS` / `RELAY_HOOK_REQUEST_DEADLINE_MS`.
pub(crate) const REQUEST_DEADLINE_MS: u64 = 9_000;
const HOOK_REQUEST_DEADLINE_MS: u64 = 25_000;
/// T3 `HookForwarder.ts` `RELAY_HOOK_PATH_PREFIX`.
const HOOK_PATH_PREFIX: &str = "/v1/hooks/";

/// What every route gets, applied once all routes are in: T3's catch-all 404 (`Api.ts`
/// layerNotFoundRoute, so no 405) and its request deadline.
fn global(r: Router) -> Router {
    // Outside `r`: `Router::layer` wraps each route inside the method router, which adds `Allow`
    // after the layer has run.
    Router::new()
        .fallback_service(r)
        .layer(axum::middleware::map_response(|res: Response| async move {
            // axum answers a known path with another method 405 + `Allow`; the only handler 405
            // (the hook forwarder's, as T3's) is marked.
            if res.status() == StatusCode::METHOD_NOT_ALLOWED
                && res.extensions().get::<hooks::forwarder::Own405>().is_none()
            {
                StatusCode::NOT_FOUND.into_response()
            } else {
                res
            }
        }))
        .layer(axum::middleware::from_fn(deadline))
}

async fn deadline(req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let path = req.uri().path();
    let hook = path.starts_with(HOOK_PATH_PREFIX);
    let ms = if hook {
        HOOK_REQUEST_DEADLINE_MS
    } else {
        REQUEST_DEADLINE_MS
    };
    // Hook URLs carry a secret token in segment 5 (T3 `redactRelayHookUrl`); never log a query.
    let logged: String = if hook {
        path.split('/')
            .enumerate()
            .map(|(i, seg)| if i == 5 { "redacted" } else { seg })
            .collect::<Vec<_>>()
            .join("/")
    } else {
        path.to_owned()
    };
    let method = req.method().clone();
    match tokio::time::timeout(std::time::Duration::from_millis(ms), next.run(req)).await {
        Ok(res) => res,
        Err(_) => {
            tracing::error!(%method, path = %logged, deadline_ms = ms, "relay request exceeded deadline");
            (
                StatusCode::GATEWAY_TIMEOUT,
                Json(json!({ "error": "relay_request_deadline_exceeded" })),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn router(pool: PgPool) -> Router {
        let (a, _) = crate::accounts::keys::tests::entry("a", "active");
        let keys = SigningKeys::from_json(&json!([a]).to_string()).unwrap();
        super::router(pool, Arc::new(keys), &Config::for_tests(&[]))
    }

    #[sqlx::test]
    async fn health_returns_ok(pool: PgPool) {
        let res = router(pool)
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(res.headers()[header::CONTENT_TYPE], "application/json");
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], br#"{"ok":true,"service":"relay"}"#);
    }

    #[sqlx::test]
    async fn unknown_route_is_404(pool: PgPool) {
        let res = router(pool)
            .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }

    /// T3 has one catch-all `* /*` 404 route (`Api.ts` layerNotFoundRoute): a known path with
    /// another method is an empty 404, never axum's 405 with `Allow`.
    #[sqlx::test]
    async fn unknown_method_on_a_known_route_is_404(pool: PgPool) {
        let r = router(pool);
        for (method, uri) in [
            ("POST", "/health"),
            ("DELETE", "/oauth/token"),
            ("PUT", "/oauth/authorize"),
            ("GET", "/oauth/device_authorization"),
        ] {
            let res = r
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(uri)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::NOT_FOUND, "{method} {uri}");
            assert!(res.headers().get(header::ALLOW).is_none(), "{method} {uri}");
            let body = res.into_body().collect().await.unwrap().to_bytes();
            assert!(body.is_empty(), "{method} {uri}");
        }
    }

    async fn slow_status(path: &str, secs: f64) -> (StatusCode, String, Option<String>) {
        let d = std::time::Duration::from_secs_f64(secs);
        let r = global(Router::new().route(
            "/{*rest}",
            get(move || async move {
                tokio::time::sleep(d).await;
                "done"
            }),
        ));
        let res = r
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let ct = res
            .headers()
            .get(header::CONTENT_TYPE)
            .map(|v| v.to_str().unwrap().to_owned());
        let status = res.status();
        let body = res.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8(body.to_vec()).unwrap(), ct)
    }

    /// T3 `Api.ts` relayRequestDeadline: 9 s per request (hooks 25 s), then 504 with its body.
    #[tokio::test(start_paused = true)]
    async fn requests_past_the_deadline_answer_504() {
        let (status, body, ct) = slow_status("/v1/machines/x", 9.5).await;
        assert_eq!(status, StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(body, r#"{"error":"relay_request_deadline_exceeded"}"#);
        assert_eq!(ct.as_deref(), Some("application/json"));
        assert_eq!(slow_status("/v1/machines/x", 8.9).await.0, StatusCode::OK);
        assert_eq!(slow_status("/v1/hooks/k/h/t", 24.0).await.0, StatusCode::OK);
        assert_eq!(
            slow_status("/v1/hooks/k/h/t", 25.5).await.0,
            StatusCode::GATEWAY_TIMEOUT
        );
    }

    #[tokio::test]
    async fn health_is_500_when_database_is_down() {
        // Port 1 refuses connections; a short acquire timeout keeps the test fast.
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_secs(2))
            .connect_lazy("postgres://nobody@127.0.0.1:1/none")
            .unwrap();
        let res = router(pool)
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body: Value =
            serde_json::from_slice(&res.into_body().collect().await.unwrap().to_bytes()).unwrap();
        assert_eq!(body["_tag"], "RelayInternalError");
        assert_eq!(body["code"], "internal_error");
        assert_eq!(body["reason"], "database_unavailable");
        assert_eq!(body["traceId"].as_str().unwrap().len(), 32);
    }
}
