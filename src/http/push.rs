// Push routes: T3 Code's relay `mobile` group and the server group's `publishAgentActivity`
// (`infra/relay/src/http/Api.ts` `layerMobileApi`, `layerServerApi`; MIT, Copyright (c) T3 Tools
// Inc.; see NOTICE), on Vekrel-Shared's paths (`contracts/src/relay.ts`).
// Handlers return early with the response T3 sends; boxing it buys nothing on this path.
#![allow(clippy::result_large_err)]
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, Method, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Deserializer};
use serde_json::json;

use super::client::{MachineState, dpop_challenge, dpop_principal, machine_param, require_dpop};
use super::errors::{RelayError, Tns, credential, json_payload, persistence, required_header};
use crate::auth::relay_tokens::RELAY_MOBILE_REGISTRATION_SCOPE;
use crate::machines::credentials;
use crate::push::Push;
use crate::push::agent_activity::{self, ProofError};
use crate::push::devices::{self, Registration};
use crate::push::payloads::ActivityState;

#[derive(Clone)]
pub struct PushState {
    pub machines: MachineState,
    pub push: Arc<Push>,
}

pub fn router(state: PushState) -> Router {
    Router::new()
        .route("/v1/mobile/devices", post(register_device))
        .route("/v1/mobile/devices/{device_id}", delete(unregister_device))
        .route("/v1/mobile/live-activities", post(register_live_activity))
        .route("/v1/mobile/agent-activity", get(snapshot))
        .route(
            "/v1/machines/{machine_id}/threads/{thread_id}/agent-activity",
            post(publish),
        )
        .layer(super::client::cors())
        .with_state(state)
}

/// DPoP auth, then the `dpop` header and the payload (`decode`), then `mobile:registration` and a
/// fresh proof, then `f`: the order T3's middleware, schema and handler check in.
async fn mobile<T, F, Fut>(
    s: &PushState,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    decode: impl FnOnce() -> Result<T, Response>,
    f: F,
) -> Response
where
    F: FnOnce(uuid::Uuid, T) -> Fut,
    Fut: std::future::Future<Output = Result<Response, RelayError>>,
{
    let m = &s.machines;
    let p = match dpop_principal(m, headers).await {
        Ok(p) => p,
        Err(e) => return dpop_challenge(e.into_response()),
    };
    let proof = match required_header(headers, "dpop") {
        Ok(p) => p,
        Err(r) => return r,
    };
    let input = match decode() {
        Ok(v) => v,
        Err(r) => return r,
    };
    let res = async {
        require_dpop(m, &p, RELAY_MOBILE_REGISTRATION_SCOPE, proof, method, uri).await?;
        f(p.user, input).await
    }
    .await;
    dpop_challenge(res.unwrap_or_else(IntoResponse::into_response))
}

fn ok() -> Response {
    Json(json!({ "ok": true })).into_response()
}

async fn register_device(
    State(s): State<PushState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let decode = || match json_payload::<Registration>(&headers, &body).map(Registration::check) {
        Ok(Some(d)) => Ok(d),
        Ok(None) => Err(super::errors::bad_request()),
        Err(r) => Err(r),
    };
    let push = s.push.clone();
    mobile(
        &s,
        &method,
        &uri,
        &headers,
        decode,
        |user, device| async move {
            let mut conn = push.pool.acquire().await.map_err(persistence)?;
            devices::register(&mut conn, user, &device)
                .await
                .map_err(persistence)?;
            drop(conn);
            replay(
                &push,
                user,
                &device.r.device_id,
                "device registration activity replay failed",
            )
            .await;
            Ok(ok())
        },
    )
    .await
}

async fn replay(push: &Push, user: uuid::Uuid, device: &str, what: &str) {
    if let Err(e) = agent_activity::replay_for_registration(push, user, device).await {
        tracing::warn!(error = %e, "{what}");
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LiveActivityBody {
    device_id: Tns,
    activity_push_token: Tns,
}

async fn register_live_activity(
    State(s): State<PushState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let decode = || json_payload::<LiveActivityBody>(&headers, &body);
    let push = s.push.clone();
    mobile(&s, &method, &uri, &headers, decode, |user, b| async move {
        let mut conn = push.pool.acquire().await.map_err(persistence)?;
        devices::register_live_activity(&mut conn, user, &b.device_id.0, &b.activity_push_token.0)
            .await
            .map_err(persistence)?;
        drop(conn);
        replay(
            &push,
            user,
            &b.device_id.0,
            "live activity registration replay failed",
        )
        .await;
        Ok(ok())
    })
    .await
}

async fn snapshot(
    State(s): State<PushState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let push = s.push.clone();
    mobile(
        &s,
        &method,
        &uri,
        &headers,
        || Ok(()),
        |user, ()| async move {
            let aggregate = agent_activity::snapshot(&push, user)
                .await
                .map_err(persistence)?;
            Ok(Json(json!({ "aggregate": aggregate })).into_response())
        },
    )
    .await
}

async fn unregister_device(
    State(s): State<PushState>,
    Path(device_id): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let decode = || machine_param(&device_id);
    let push = s.push.clone();
    mobile(
        &s,
        &method,
        &uri,
        &headers,
        decode,
        |user, device| async move {
            let mut tx = push.pool.begin().await.map_err(persistence)?;
            devices::unregister(&mut tx, user, &device)
                .await
                .map_err(persistence)?;
            tx.commit().await.map_err(persistence)?;
            Ok(ok())
        },
    )
    .await
}

/// `Schema.NullOr(X)`: the key is required, `null` allowed.
fn nullable<'de, D: Deserializer<'de>>(d: D) -> Result<Option<ActivityState>, D::Error> {
    Option::deserialize(d)
}

/// `RelayAgentActivityPublishRequest`.
#[derive(Deserialize)]
struct PublishBody {
    #[serde(deserialize_with = "nullable")]
    state: Option<ActivityState>,
    proof: Tns,
}

async fn publish(
    State(s): State<PushState>,
    Path((machine_id, thread_id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let relay = &s.machines.relay;
    let p = match credentials::authenticate(&relay.pool, &credential(&headers, "Bearer")).await {
        Ok(Some(p)) => p,
        Ok(None) => return RelayError::auth("not_authorized").into_response(),
        Err(e) => return persistence(e).into_response(),
    };
    let (machine_id, thread_id) = match (machine_param(&machine_id), machine_param(&thread_id)) {
        (Ok(m), Ok(t)) => (m, t),
        (Err(r), _) | (_, Err(r)) => return r,
    };
    let b: PublishBody = match json_payload(&headers, &body) {
        Ok(b) => b,
        Err(r) => return r,
    };
    if p.machine_id != machine_id {
        return RelayError::auth("not_authorized").into_response();
    }
    let verified = agent_activity::verify_publish_proof(
        &s.push,
        &relay.issuer,
        &machine_id,
        &p.machine_public_key,
        &thread_id,
        b.state.as_ref(),
        &b.proof.0,
    )
    .await;
    if let Err(e) = verified {
        return match e {
            ProofError::Expired => RelayError::new(
                401,
                "RelayAgentActivityPublishProofExpiredError",
                vec![("code", "agent_activity_publish_proof_expired".into())],
            ),
            ProofError::Invalid(reason) => RelayError::new(
                401,
                "RelayAgentActivityPublishProofInvalidError",
                vec![
                    ("code", "agent_activity_publish_proof_invalid".into()),
                    ("reason", reason.into()),
                ],
            ),
            ProofError::Persistence(e) => persistence(e),
        }
        .into_response();
    }
    match agent_activity::publish(
        &s.push,
        &machine_id,
        &p.machine_public_key,
        &thread_id,
        b.state.as_ref(),
    )
    .await
    {
        Ok(deliveries) => Json(json!({ "ok": true, "deliveries": deliveries })).into_response(),
        Err(e) => persistence(e).into_response(),
    }
}
