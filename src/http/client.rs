// Client routes: T3 Code's relay `client` and `dpopClient` groups (`infra/relay/src/http/Api.ts`
// `layerClientAuth`, `layerDpopClientAuth`, `layerClientApi`, `layerDpopClientApi`; MIT, Copyright
// (c) T3 Tools Inc.; see NOTICE), on Vekrel-Shared's paths (`contracts/src/relay.ts`). The client
// group takes our account access token as a bearer; the dpopClient group takes the relay's DPoP
// access token from `/v1/client/dpop-token` plus a proof.
// Handlers return early with the response T3 sends; boxing it buys nothing on this path.
#![allow(clippy::result_large_err)]
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::Row;
use tower_http::cors::{Any, CorsLayer};
use uuid::Uuid;

use super::errors::{
    RelayError, Tns, bad_request, credential, json_payload, no_store, optional_tns, persistence,
    required_header,
};
use crate::accounts::oauth::{AccountsState, account_user};
use crate::auth::dpop::Request as DpopRequest;
use crate::auth::dpop_proofs::{self, Rejected};
use crate::auth::relay_tokens::{
    LinkChallengeRequest, RELAY_MACHINE_CONNECT_SCOPE, RELAY_MACHINE_STATUS_SCOPE,
};
use crate::hooks::{held, inbox};
use crate::machines::connector::{self, ConnectError};
use crate::machines::linker::{self, LinkError, LinkRequest};
use crate::machines::provider::ProviderError;
use crate::machines::{Relay, credentials, links, now_ms, wire_user_id};

#[derive(Clone)]
pub struct MachineState {
    pub relay: Arc<Relay>,
    pub accounts: Arc<AccountsState>,
}

/// T3's `relayCorsMiddleware` (Effect `HttpMiddleware.cors`, any origin).
pub fn cors() -> CorsLayer {
    CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
        .allow_headers([
            header::AUTHORIZATION,
            "b3".parse().unwrap(),
            "traceparent".parse().unwrap(),
            header::CONTENT_TYPE,
            "dpop".parse().unwrap(),
        ])
        .expose_headers(["traceparent".parse().unwrap(), header::WWW_AUTHENTICATE])
        .max_age(std::time::Duration::from_secs(86_400))
}

pub fn router(state: MachineState) -> Router {
    Router::new()
        .route("/v1/machines", get(list_machines))
        .route("/v1/client/devices", get(list_devices_v1))
        .route("/v2/client/devices", get(list_devices_v2))
        .route("/v1/client/machine-links", post(link_machine))
        .route("/v1/client/machine-link-challenges", post(create_challenge))
        .route(
            "/v1/client/machine-links/{machine_id}",
            delete(unlink_machine),
        )
        .route(
            "/v1/client/machine-links/{machine_id}/tunnel",
            delete(release_tunnel),
        )
        .route("/v1/machines/{machine_id}/connect", post(connect))
        .route("/v1/machines/{machine_id}/status", post(status))
        .route(
            "/v1/client/dpop-token",
            post(super::token_exchange::exchange),
        )
        .merge(super::server::routes())
        .layer(cors())
        .with_state(state)
}

/// A `MachineId` path parameter (`TrimmedNonEmptyString`).
pub fn machine_param(raw: &str) -> Result<String, Response> {
    let t = raw.trim();
    if t.is_empty() {
        Err(bad_request())
    } else {
        Ok(t.to_owned())
    }
}

/// `layerClientAuth`: our account access token; any failure is `invalid_bearer`.
async fn client_user(s: &MachineState, headers: &HeaderMap) -> Result<Uuid, Response> {
    let token = credential(headers, "Bearer");
    match account_user(&s.accounts, &token).await {
        Ok(Some(u)) => Ok(u.user_id),
        Ok(None) => Err(RelayError::auth("invalid_bearer").into_response()),
        Err(e) => Err(persistence(e).into_response()),
    }
}

/// The URL a DPoP proof's `htu` must match: the relay's public origin plus the request target
/// (TLS ends at the edge, so the socket's own scheme and host are not the public ones).
pub fn public_url(relay: &Relay, uri: &Uri) -> String {
    let target = uri.path_and_query().map_or("/", |p| p.as_str());
    format!("{}{target}", relay.issuer)
}

/// `relayDpopFailureReason`.
pub fn dpop_failure_reason(code: &str) -> &'static str {
    match code {
        "time_window" => "time_window",
        "key_mismatch" => "key_mismatch",
        "method_mismatch" | "url_mismatch" => "request_mismatch",
        "access_token_hash_mismatch" => "token_mismatch",
        "replayed" => "replay",
        _ => "invalid_proof",
    }
}

/// `DpopProofRejected` / its persistence error, through `mapRelayCommonApiErrors(authReason)`.
pub fn dpop_rejected(r: Rejected, auth_reason: &'static str) -> RelayError {
    match r {
        Rejected::Persistence(e) => persistence(e),
        r if auth_reason == "invalid_dpop" => {
            RelayError::invalid_dpop(dpop_failure_reason(r.code().unwrap_or("invalid_proof")))
        }
        _ => RelayError::auth(auth_reason),
    }
}

pub struct DpopPrincipal {
    pub user: Uuid,
    pub token: String,
    pub thumbprint: String,
    pub scopes: Vec<&'static str>,
}

/// `layerDpopClientAuth`. Vekrel also refuses tokens of disabled users, so `disable-user` cuts
/// off the 30-minute token at once.
async fn dpop_principal(
    s: &MachineState,
    headers: &HeaderMap,
) -> Result<DpopPrincipal, RelayError> {
    let invalid = || RelayError::auth("invalid_bearer");
    let scheme_ok = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            let rest = v.get(..4).filter(|p| p.eq_ignore_ascii_case("dpop"));
            rest.is_some() && v[4..].starts_with(' ')
        });
    if !scheme_ok {
        return Err(invalid());
    }
    let token = credential(headers, "DPoP");
    let v = s
        .relay
        .tokens
        .verify_dpop_access_token(&token, now_ms() / 1000)
        .ok_or_else(invalid)?;
    let user = crate::machines::parse_wire_user_id(&v.claims.sub).ok_or_else(invalid)?;
    let enabled: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM users WHERE id = $1 AND disabled_at IS NULL)",
    )
    .bind(user)
    .fetch_one(&s.relay.pool)
    .await
    .map_err(persistence)?;
    if !enabled {
        return Err(invalid());
    }
    Ok(DpopPrincipal {
        user,
        token,
        thumbprint: v.claims.cnf.jkt,
        scopes: v.scopes,
    })
}

/// `appendRelayDpopChallengeHeader`: every 401 after the DPoP middleware starts says `DPoP`.
fn dpop_challenge(mut r: Response) -> Response {
    if r.status() == StatusCode::UNAUTHORIZED {
        r.headers_mut()
            .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("DPoP"));
    }
    r
}

async fn list_machines(State(s): State<MachineState>, headers: HeaderMap) -> Response {
    let user = match client_user(&s, &headers).await {
        Ok(u) => u,
        Err(r) => return r,
    };
    match links::list_for_user(&s.relay.pool, user).await {
        Ok(machines) => Json(json!({ "machines": machines })).into_response(),
        Err(e) => persistence(e).into_response(),
    }
}

/// `Devices.listForUser`, in `RelayClientDeviceRecord` key order.
async fn devices(s: &MachineState, user: Uuid) -> Result<Vec<Value>, RelayError> {
    let rows = sqlx::query(
        "SELECT device_id, label, platform, ios_major_version, android_api_level, app_version,
                preferences_json, updated_at
         FROM relay_mobile_devices WHERE user_id = $1 ORDER BY created_at, device_id",
    )
    .bind(user)
    .fetch_all(&s.relay.pool)
    .await
    .map_err(persistence)?;
    Ok(rows
        .iter()
        .map(|r| {
            let p: Value = r.get("preferences_json");
            json!({
                "deviceId": r.get::<String, _>("device_id"),
                "label": r.get::<String, _>("label"),
                "platform": r.get::<String, _>("platform"),
                "iosMajorVersion": r.get::<Option<i32>, _>("ios_major_version"),
                "androidApiLevel": r.get::<Option<i32>, _>("android_api_level"),
                "appVersion": r.get::<Option<String>, _>("app_version"),
                "notifications": {
                    "enabled": p["notificationsEnabled"],
                    "notifyOnApproval": p["notifyOnApproval"],
                    "notifyOnInput": p["notifyOnInput"],
                    "notifyOnCompletion": p["notifyOnCompletion"],
                    "notifyOnFailure": p["notifyOnFailure"],
                },
                "liveActivities": { "enabled": p["liveActivitiesEnabled"] },
                "updatedAt": r.get::<String, _>("updated_at"),
            })
        })
        .collect())
}

async fn list_devices(s: MachineState, headers: HeaderMap, v1: bool) -> Response {
    let user = match client_user(&s, &headers).await {
        Ok(u) => u,
        Err(r) => return r,
    };
    no_store(match devices(&s, user).await {
        // Installed clients decode v1 as iOS-only.
        Ok(mut d) => {
            if v1 {
                d.retain(|d| d["platform"] == "ios" && !d["iosMajorVersion"].is_null());
            }
            Json(json!({ "devices": d })).into_response()
        }
        Err(e) => e.into_response(),
    })
}

async fn list_devices_v1(State(s): State<MachineState>, headers: HeaderMap) -> Response {
    list_devices(s, headers, true).await
}

async fn list_devices_v2(State(s): State<MachineState>, headers: HeaderMap) -> Response {
    list_devices(s, headers, false).await
}

/// `RelayMachineLinkRequest`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LinkBody {
    #[serde(default, deserialize_with = "optional_tns")]
    device_id: Option<String>,
    proof: Tns,
    notifications_enabled: bool,
    live_activities_enabled: bool,
    managed_tunnels_enabled: bool,
}

fn link_error(e: LinkError) -> RelayError {
    let reason = |r: &'static str| ("reason", Value::from(r));
    let failed = |r| {
        RelayError::new(
            500,
            "RelayMachineLinkFailedError",
            vec![("code", "machine_link_failed".into()), reason(r)],
        )
    };
    let unavailable = |r| {
        RelayError::new(
            503,
            "RelayMachineLinkUnavailableError",
            vec![("code", "machine_link_unavailable".into()), reason(r)],
        )
    };
    let invalid = |r| {
        RelayError::new(
            400,
            "RelayMachineLinkProofInvalidError",
            vec![("code", "machine_link_proof_invalid".into()), reason(r)],
        )
    };
    match e {
        LinkError::Expired => RelayError::new(
            401,
            "RelayMachineLinkProofExpiredError",
            vec![("code", "machine_link_proof_expired".into())],
        ),
        LinkError::Invalid(r) => invalid(r),
        LinkError::Provider(ProviderError::NotConfigured) => {
            unavailable("managed_endpoint_not_configured")
        }
        LinkError::Provider(ProviderError::Failed { stage }) => {
            let mut e = unavailable("managed_endpoint_provisioning_failed");
            e.fields.push(("provisioningStage", stage.into()));
            e
        }
        LinkError::Provider(ProviderError::OriginNotAllowed) => invalid("origin_not_allowed"),
        LinkError::Provider(ProviderError::LimitExceeded { max_tunnels }) => RelayError::new(
            403,
            "RelayMachineLinkLimitExceededError",
            vec![
                ("code", "machine_link_limit_exceeded".into()),
                ("maxTunnels", max_tunnels.into()),
            ],
        ),
        LinkError::LinkPersistence(e) => {
            tracing::error!(error = %e, "machine link persistence failed");
            failed("link_persistence_failed")
        }
        LinkError::CredentialPersistence(e) => {
            tracing::error!(error = %e, "machine credential persistence failed");
            failed("credential_persistence_failed")
        }
        LinkError::ReplayPersistence(e) => {
            tracing::error!(error = %e, "link proof replay persistence failed");
            failed("replay_persistence_failed")
        }
    }
}

async fn link_machine(State(s): State<MachineState>, headers: HeaderMap, body: Bytes) -> Response {
    let user = match client_user(&s, &headers).await {
        Ok(u) => u,
        Err(r) => return r,
    };
    let b: LinkBody = match json_payload(&headers, &body) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let req = LinkRequest {
        proof: b.proof.0,
        device_id: b.device_id,
        caps: LinkChallengeRequest {
            notifications_enabled: b.notifications_enabled,
            live_activities_enabled: b.live_activities_enabled,
            managed_tunnels_enabled: b.managed_tunnels_enabled,
        },
    };
    no_store(match linker::link(&s.relay, user, &req).await {
        Ok(l) => Json(json!({
            "ok": true,
            "cloudUserId": wire_user_id(user),
            "machineId": l.machine_id,
            "endpoint": l.endpoint,
            "endpointRuntime": l.runtime,
            "relayIssuer": s.relay.issuer,
            "machineCredential": l.machine_credential,
            "cloudMintPublicKey": s.relay.mint_public_key_pem,
        }))
        .into_response(),
        Err(e) => link_error(e).into_response(),
    })
}

async fn create_challenge(
    State(s): State<MachineState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let user = match client_user(&s, &headers).await {
        Ok(u) => u,
        Err(r) => return r,
    };
    let req: LinkChallengeRequest = match json_payload(&headers, &body) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let now = now_ms();
    let expires_ms = now + 5 * 60_000;
    let challenge = s.relay.tokens.issue_link_challenge(
        &wire_user_id(user),
        req,
        &Uuid::new_v4().to_string(),
        now.div_euclid(1000),
        expires_ms.div_euclid(1000),
    );
    no_store(
        Json(json!({
            "challenge": challenge,
            "expiresAt": dpop_proofs::iso_millis(expires_ms),
        }))
        .into_response(),
    )
}

/// `unlinkEnvironmentRecord`: revoke in one transaction, then tear the tunnel down; teardown runs
/// even when the link is already revoked, so a retry finishes an earlier failed cleanup.
async fn unlink(s: &MachineState, user: Uuid, machine_id: &str) -> Result<bool, RelayError> {
    let upstream = |_| RelayError::internal("upstream_unavailable");
    let provider = &s.relay.provider;
    let target = provider
        .prepare_deprovision(user, machine_id)
        .await
        .map_err(upstream)?;
    let endpoint_key = held::endpoint_key_of(&s.relay.pool, user, machine_id)
        .await
        .map_err(persistence)?;
    let mut conn = s.relay.pool.acquire().await.map_err(persistence)?;
    let link = links::get_for_user(&mut conn, user, machine_id)
        .await
        .map_err(persistence)?;
    drop(conn);
    let unlinked = match link {
        None => false,
        Some(link) => {
            let tx_failed = |e: sqlx::Error| {
                tracing::error!(error = %e, "unlink transaction failed");
                RelayError::internal("internal_error")
            };
            let mut tx = s.relay.pool.begin().await.map_err(tx_failed)?;
            let revoked = links::revoke_for_user(&mut tx, user, machine_id)
                .await
                .map_err(persistence)?;
            if revoked {
                credentials::revoke_for_machine_public_key(
                    &mut tx,
                    machine_id,
                    &link.machine_public_key,
                )
                .await
                .map_err(persistence)?;
            }
            tx.commit().await.map_err(tx_failed)?;
            revoked
        }
    };
    let deprovisioned = provider
        .deprovision(user, machine_id, Some(target))
        .await
        .map_err(upstream)?;
    // Nobody links the endpoint now, so its held webhooks go (`HookInbox.clear`).
    if let Some(key) = endpoint_key {
        let cleared = async {
            let mut tx = s.relay.pool.begin().await?;
            inbox::clear(&mut tx, &key).await?;
            tx.commit().await
        }
        .await;
        if let Err(e) = cleared {
            tracing::warn!(machine_id, error = %e, "could not clear held webhook requests");
        }
    }
    if !deprovisioned {
        let retry = provider
            .prepare_deprovision(user, machine_id)
            .await
            .map_err(upstream)?;
        if retry.is_some() {
            let mut conn = s.relay.pool.acquire().await.map_err(persistence)?;
            let still_linked = links::get_for_user(&mut conn, user, machine_id)
                .await
                .map_err(persistence)?;
            if still_linked.is_none() {
                provider
                    .deprovision(user, machine_id, Some(retry))
                    .await
                    .map_err(upstream)?;
            }
        }
    }
    Ok(unlinked)
}

async fn unlink_machine(
    State(s): State<MachineState>,
    Path(machine_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let user = match client_user(&s, &headers).await {
        Ok(u) => u,
        Err(r) => return r,
    };
    let machine_id = match machine_param(&machine_id) {
        Ok(m) => m,
        Err(r) => return r,
    };
    match unlink(&s, user, &machine_id).await {
        Ok(ok) => Json(json!({ "ok": ok })).into_response(),
        Err(e) => e.into_response(),
    }
}

async fn release_tunnel(
    State(s): State<MachineState>,
    Path(machine_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let user = match client_user(&s, &headers).await {
        Ok(u) => u,
        Err(r) => return r,
    };
    let machine_id = match machine_param(&machine_id) {
        Ok(m) => m,
        Err(r) => return r,
    };
    // `ok` is whether the connector token is now dead.
    match s.relay.provider.release(user, &machine_id, None).await {
        Ok(ok) => Json(json!({ "ok": ok })).into_response(),
        Err(_) => RelayError::internal("upstream_unavailable").into_response(),
    }
}

/// `RelayMachineConnectRequest`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConnectBody {
    #[serde(default, deserialize_with = "optional_tns")]
    device_id: Option<String>,
    #[serde(default, deserialize_with = "optional_tns")]
    client_key_thumbprint: Option<String>,
    #[serde(default, deserialize_with = "optional_tns")]
    client_proof_key_thumbprint: Option<String>,
}

/// `resolveConnectClientKeyThumbprint`.
fn requested_thumbprint(b: &ConnectBody) -> Option<&str> {
    let t = b
        .client_key_thumbprint
        .as_deref()
        .or(b.client_proof_key_thumbprint.as_deref())?;
    if let (Some(a), Some(c)) = (&b.client_key_thumbprint, &b.client_proof_key_thumbprint)
        && a != c
    {
        return None;
    }
    Some(t)
}

fn connect_error(e: ConnectError) -> RelayError {
    let unavailable = |reason: &'static str| {
        RelayError::new(
            502,
            "RelayMachineEndpointUnavailableError",
            vec![
                ("code", "machine_endpoint_unavailable".into()),
                ("reason", reason.into()),
            ],
        )
    };
    match e {
        ConnectError::NotAuthorized(reason) => RelayError::new(
            403,
            "RelayMachineConnectNotAuthorizedError",
            vec![
                ("code", "machine_connect_not_authorized".into()),
                ("reason", reason.into()),
            ],
        ),
        ConnectError::RequestFailed {
            endpoint_failure,
            endpoint_status,
        } => {
            let mut e = unavailable("endpoint_request_failed");
            if let Some(f) = endpoint_failure {
                e.fields.push(("endpointFailure", f.into()));
            }
            if let Some(s) = endpoint_status.filter(|s| *s != 0) {
                e.fields.push(("endpointStatus", s.into()));
            }
            e
        }
        ConnectError::TimedOut => RelayError::new(
            504,
            "RelayMachineEndpointTimedOutError",
            vec![("code", "machine_endpoint_timed_out".into())],
        ),
        ConnectError::ResponseInvalid => unavailable("endpoint_response_invalid"),
        ConnectError::Persistence(e) => persistence(e),
    }
}

/// `requireDpopPrincipalScope` + `requireDpopThumbprint`.
async fn require_dpop(
    s: &MachineState,
    p: &DpopPrincipal,
    scope: &str,
    proof: &str,
    method: &Method,
    uri: &Uri,
) -> Result<String, RelayError> {
    if !p.scopes.contains(&scope) {
        return Err(RelayError::unauthorized("invalid_dpop"));
    }
    let url = public_url(&s.relay, uri);
    dpop_proofs::verify_and_consume(
        &s.relay.pool,
        &DpopRequest {
            proof: Some(proof),
            method: method.as_str(),
            url: &url,
            now_epoch_seconds: 0,
            expected_thumbprint: Some(&p.thumbprint),
            expected_access_token: Some(&p.token),
        },
        now_ms(),
    )
    .await
    .map_err(|r| dpop_rejected(r, "invalid_dpop"))
}

async fn connect(
    State(s): State<MachineState>,
    Path(machine_id): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    dpop_challenge(connect_inner(s, machine_id, method, uri, headers, body).await)
}

async fn connect_inner(
    s: MachineState,
    machine_id: String,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let p = match dpop_principal(&s, &headers).await {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let machine_id = match machine_param(&machine_id) {
        Ok(m) => m,
        Err(r) => return r,
    };
    let proof = match required_header(&headers, "dpop") {
        Ok(p) => p,
        Err(r) => return r,
    };
    let b: ConnectBody = match json_payload(&headers, &body) {
        Ok(b) => b,
        Err(r) => return r,
    };
    no_store(
        async {
            if !p.scopes.contains(&RELAY_MACHINE_CONNECT_SCOPE) {
                return Err(RelayError::unauthorized("invalid_dpop"));
            }
            if requested_thumbprint(&b) != Some(p.thumbprint.as_str()) {
                return Err(RelayError::unauthorized("invalid_dpop"));
            }
            let jkt =
                require_dpop(&s, &p, RELAY_MACHINE_CONNECT_SCOPE, proof, &method, &uri).await?;
            connector::connect(&s.relay, p.user, &machine_id, &jkt, b.device_id.as_deref())
                .await
                .map_err(connect_error)
        }
        .await
        .map_or_else(IntoResponse::into_response, |r| Json(r).into_response()),
    )
}

async fn status(
    State(s): State<MachineState>,
    Path(machine_id): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    dpop_challenge(
        async {
            let p = match dpop_principal(&s, &headers).await {
                Ok(p) => p,
                Err(e) => return e.into_response(),
            };
            let machine_id = match machine_param(&machine_id) {
                Ok(m) => m,
                Err(r) => return r,
            };
            let proof = match required_header(&headers, "dpop") {
                Ok(p) => p,
                Err(r) => return r,
            };
            let res = async {
                require_dpop(&s, &p, RELAY_MACHINE_STATUS_SCOPE, proof, &method, &uri).await?;
                connector::status(&s.relay, p.user, &machine_id)
                    .await
                    .map_err(connect_error)
            }
            .await;
            res.map_or_else(IntoResponse::into_response, |r| Json(r).into_response())
        }
        .await,
    )
}
