// Router. `/health` follows T3's relay `infra/relay/src/http/Api.ts` (layerHealthApi) and
// Vekrel-Shared `packages/contracts/src/relay.ts` (RelayHealthResponse).
// T3 runs `SELECT 1` and answers RelayInternalError `database_unavailable` (500) on failure.
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::{Json, Router, routing::get};
use serde_json::{Value, json};
use sqlx::PgPool;

use crate::accounts::device;
use crate::accounts::keys::SigningKeys;
use crate::accounts::oauth::{self, AccountsState};
use crate::config::Config;

pub mod wellknown;

pub fn router(pool: PgPool, keys: Arc<SigningKeys>, config: &Config) -> Router {
    let accounts = AccountsState::new(pool.clone(), keys.clone(), config);
    Router::new()
        .route("/health", get(health))
        .with_state(pool)
        .merge(wellknown::router(&keys, &config.relay_origin))
        .merge(oauth::router(accounts.clone()))
        .merge(device::router(accounts))
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
    let mut id = [0u8; 16];
    getrandom::fill(&mut id).expect("OS random source");
    let trace_id: String = id.iter().map(|b| format!("{b:02x}")).collect();
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
