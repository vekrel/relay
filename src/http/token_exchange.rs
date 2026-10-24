// `POST /v1/client/dpop-token`: T3 Code's relay `token` group (`infra/relay/src/http/Api.ts`
// `layerTokenApi`; MIT, Copyright (c) T3 Tools Inc.; see NOTICE). An RFC 8693 exchange of our
// account access token plus a DPoP proof for a 30-minute relay DPoP access token bound to the
// proof key. T3 took a Clerk token here; the checks around it are T3's.
use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, Uri};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use super::client::{MachineState, dpop_rejected, public_url};
use super::errors::{RelayError, Tns, form_payload, no_store, persistence, required_header};
use crate::accounts::oauth::account_user;
use crate::auth::dpop::Request as DpopRequest;
use crate::auth::dpop_proofs;
use crate::auth::relay_tokens::{
    RELAY_DPOP_ACCESS_TOKEN_TTL_SECONDS, resolve_dpop_access_token_scopes,
};
use crate::machines::{now_ms, wire_user_id};

const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

fn literal<'de, D: serde::Deserializer<'de>>(d: D, want: &str) -> Result<(), D::Error> {
    let s = String::deserialize(d)?;
    if s == want {
        Ok(())
    } else {
        Err(serde::de::Error::custom("unexpected literal"))
    }
}

/// `RelayDpopAccessTokenRequest`.
#[derive(Deserialize)]
struct ExchangeBody {
    #[serde(deserialize_with = "grant_type")]
    #[allow(dead_code)]
    grant_type: (),
    subject_token: Tns,
    #[serde(deserialize_with = "subject_token_type")]
    #[allow(dead_code)]
    subject_token_type: (),
    #[serde(deserialize_with = "requested_token_type")]
    #[allow(dead_code)]
    requested_token_type: (),
    resource: Tns,
    scope: Tns,
    #[serde(deserialize_with = "client_id")]
    client_id: String,
}

fn grant_type<'de, D: serde::Deserializer<'de>>(d: D) -> Result<(), D::Error> {
    literal(d, "urn:ietf:params:oauth:grant-type:token-exchange")
}
fn subject_token_type<'de, D: serde::Deserializer<'de>>(d: D) -> Result<(), D::Error> {
    literal(d, "urn:ietf:params:oauth:token-type:jwt")
}
fn requested_token_type<'de, D: serde::Deserializer<'de>>(d: D) -> Result<(), D::Error> {
    literal(d, ACCESS_TOKEN_TYPE)
}
fn client_id<'de, D: serde::Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    let s = String::deserialize(d)?;
    if matches!(s.as_str(), "vekrel-mobile" | "vekrel-web") {
        Ok(s)
    } else {
        Err(serde::de::Error::custom("unknown client"))
    }
}

pub async fn exchange(
    State(s): State<MachineState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let proof = match required_header(&headers, "dpop") {
        Ok(p) => p.to_owned(),
        Err(r) => return r,
    };
    let b: ExchangeBody = match form_payload(&headers, &body) {
        Ok(b) => b,
        Err(r) => return r,
    };
    no_store(
        async {
            let scopes = resolve_dpop_access_token_scopes(&b.client_id, &b.scope.0);
            let Some(scopes) = scopes.filter(|_| b.resource.0 == s.relay.normalized_issuer())
            else {
                return Err(RelayError::unauthorized("invalid_dpop"));
            };
            let user: Uuid = account_user(&s.accounts, &b.subject_token.0)
                .await
                .map_err(persistence)?
                .ok_or_else(|| RelayError::auth("invalid_bearer"))?
                .user_id;
            let url = public_url(&s.relay, &uri);
            let thumbprint = dpop_proofs::verify_and_consume(
                &s.relay.pool,
                &DpopRequest {
                    proof: Some(&proof),
                    method: method.as_str(),
                    url: &url,
                    now_epoch_seconds: 0,
                    expected_thumbprint: None,
                    expected_access_token: None,
                },
                now_ms(),
            )
            .await
            .map_err(|r| dpop_rejected(r, "invalid_dpop"))?;
            let now = now_ms().div_euclid(1000);
            let access_token = s.relay.tokens.issue_dpop_access_token(
                &wire_user_id(user),
                &thumbprint,
                &Uuid::new_v4().to_string(),
                now,
                now + RELAY_DPOP_ACCESS_TOKEN_TTL_SECONDS,
                &b.client_id,
                &scopes,
            );
            Ok(Json(json!({
                "access_token": access_token,
                "issued_token_type": ACCESS_TOKEN_TYPE,
                "token_type": "DPoP",
                "expires_in": RELAY_DPOP_ACCESS_TOKEN_TTL_SECONDS,
                "scope": scopes.join(" "),
            })))
        }
        .await
        .map_or_else(IntoResponse::into_response, IntoResponse::into_response),
    )
}
