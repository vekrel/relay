// Discovery documents. `/.well-known/oauth-authorization-server` and `/oauth-protected-resource`
// follow T3's `infra/relay/src/http/Api.ts` layerMetadataApi (schemas `RelayAuthorizationServerMetadata`,
// `RelayProtectedResourceMetadata` in Vekrel-Shared `contracts/src/relay.ts`), with Vekrel's scope
// names. `/.well-known/jwks.json` and `/openid-configuration` describe our account tokens (plan 6A Task 4).
use axum::{Json, Router, routing::get};
use serde_json::{Value, json};

use crate::accounts::keys::SigningKeys;

const SCOPES: [&str; 3] = ["machine:connect", "machine:status", "mobile:registration"];

/// `issuer` is the relay origin without a trailing `/` (T3 `normalizeRelayIssuer`).
pub fn router(keys: &SigningKeys, issuer: &str) -> Router {
    let doc = |v: Value| get(move || std::future::ready(Json(v)));
    Router::new()
        .route("/.well-known/jwks.json", doc(keys.jwks()))
        .route(
            "/.well-known/openid-configuration",
            doc(openid_configuration(issuer)),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            doc(json!({
                "issuer": issuer,
                "token_endpoint": format!("{issuer}/v1/client/dpop-token"),
                "grant_types_supported": ["urn:ietf:params:oauth:grant-type:token-exchange"],
                "token_endpoint_auth_methods_supported": ["none"],
                "dpop_signing_alg_values_supported": ["ES256"],
                "scopes_supported": SCOPES,
            })),
        )
        .route(
            "/.well-known/oauth-protected-resource",
            doc(json!({
                "resource": issuer,
                "authorization_servers": [issuer],
                "scopes_supported": SCOPES,
                "dpop_bound_access_tokens_required": true,
                "dpop_signing_alg_values_supported": ["ES256"],
            })),
        )
}

/// Endpoints for the account flows (Tasks 5 and 8 serve them).
fn openid_configuration(issuer: &str) -> Value {
    json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/oauth/authorize"),
        "token_endpoint": format!("{issuer}/oauth/token"),
        "revocation_endpoint": format!("{issuer}/oauth/revoke"),
        "device_authorization_endpoint": format!("{issuer}/oauth/device_authorization"),
        "jwks_uri": format!("{issuer}/.well-known/jwks.json"),
        "response_types_supported": ["code"],
        "grant_types_supported": [
            "authorization_code",
            "refresh_token",
            "urn:ietf:params:oauth:grant-type:device_code",
        ],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["EdDSA"],
        "scopes_supported": ["openid", "profile", "email", "offline_access"],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::keys::{PublicKeys, tests::entry};
    use crate::accounts::tokens::{AccessClaims, now_secs, sign_access_token, verify_access_token};
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    const ISS: &str = "https://relay.example.test";

    async fn get_json(app: &Router, path: &str) -> (Value, String) {
        let res = app
            .clone()
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK, "{path}");
        assert_eq!(res.headers()[header::CONTENT_TYPE], "application/json");
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8(bytes.to_vec()).unwrap();
        (serde_json::from_str(&text).unwrap(), text)
    }

    #[tokio::test]
    async fn token_verifies_against_the_served_jwks() {
        let (n, dn) = entry("n", "next");
        let (a, da) = entry("a", "active");
        let (r, dr) = entry("r", "retired");
        let keys = SigningKeys::from_json(&json!([n, a, r]).to_string()).unwrap();
        let app = router(&keys, ISS);
        let (jwks, text) = get_json(&app, "/.well-known/jwks.json").await;
        for d in [dn, da, dr] {
            assert!(!text.contains(&d));
        }
        assert_eq!(jwks["keys"].as_array().unwrap().len(), 3);
        let claims = AccessClaims::new(
            ISS,
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
            "vekrel-cli",
            "a@example.test",
            now_secs(),
        );
        let token = sign_access_token(&keys, &claims);
        let served = PublicKeys::from_jwks(&jwks).unwrap();
        assert_eq!(verify_access_token(&served, ISS, &token), Ok(claims));
    }

    #[tokio::test]
    async fn metadata_documents_match_t3_shapes() {
        let keys = SigningKeys::from_json(&json!([entry("a", "active").0]).to_string()).unwrap();
        let app = router(&keys, ISS);
        let (_, as_text) = get_json(&app, "/.well-known/oauth-authorization-server").await;
        assert_eq!(
            as_text,
            r#"{"issuer":"https://relay.example.test","token_endpoint":"https://relay.example.test/v1/client/dpop-token","grant_types_supported":["urn:ietf:params:oauth:grant-type:token-exchange"],"token_endpoint_auth_methods_supported":["none"],"dpop_signing_alg_values_supported":["ES256"],"scopes_supported":["machine:connect","machine:status","mobile:registration"]}"#
        );
        let (_, pr_text) = get_json(&app, "/.well-known/oauth-protected-resource").await;
        assert_eq!(
            pr_text,
            r#"{"resource":"https://relay.example.test","authorization_servers":["https://relay.example.test"],"scopes_supported":["machine:connect","machine:status","mobile:registration"],"dpop_bound_access_tokens_required":true,"dpop_signing_alg_values_supported":["ES256"]}"#
        );
        let (oidc, _) = get_json(&app, "/.well-known/openid-configuration").await;
        assert_eq!(oidc["issuer"], ISS);
        assert_eq!(oidc["jwks_uri"], format!("{ISS}/.well-known/jwks.json"));
        assert_eq!(oidc["code_challenge_methods_supported"], json!(["S256"]));
    }
}
