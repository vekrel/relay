// Router. `/health` follows T3's relay `infra/relay/src/http/Api.ts` (layerHealthApi) and
// Vekrel-Shared `packages/contracts/src/relay.ts` (RelayHealthResponse).
use axum::{Json, Router, routing::get};
use serde_json::{Value, json};

pub fn router() -> Router {
    Router::new().route("/health", get(health))
}

// shortcut: T3 also runs `SELECT 1` and answers 500 `database_unavailable` on failure; the DB arrives in Task 2.
async fn health() -> Json<Value> {
    Json(json!({ "ok": true, "service": "relay" }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    #[tokio::test]
    async fn health_returns_ok() {
        let res = router()
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(res.headers()[header::CONTENT_TYPE], "application/json");
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], br#"{"ok":true,"service":"relay"}"#);
    }

    #[tokio::test]
    async fn unknown_route_is_404() {
        let res = router()
            .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }
}
