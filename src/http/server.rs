// Machine routes: T3 Code's relay `server` group (`infra/relay/src/http/Api.ts`
// `layerEnvironmentAuth`, `layerServerApi`, `verifyEnvironmentTunnelRecoveryProof`,
// `registerEnvironmentTunnelRecovery`, `recoverEnvironmentTunnelRecord`; MIT, Copyright (c) T3
// Tools Inc.; see NOTICE). The bearer is the machine credential from linking, looked up by hash.
// Held-hook wake and the hold opt-out follow `HeldHooks.ts` (`src/hooks/held.rs`); agent activity
// (Task 12) joins this group later.
// Handlers return early with the response T3 sends; boxing it buys nothing on this path.
#![allow(clippy::result_large_err)]
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::client::{MachineState, machine_param};
use super::errors::{RelayError, Tns, credential, json_payload, no_store, persistence};
use crate::hooks::held;
use crate::jws;
use crate::machines::credentials::{self, Principal};
use crate::machines::linker::{decode_origin, registered_claims_ok, tns};
use crate::machines::provider::{OriginSync, ProviderError, is_loopback_origin};
use crate::machines::{Origin, links, now_ms, parse_wire_user_id};

pub fn routes() -> Router<MachineState> {
    Router::new()
        .route(
            "/v1/machines/{machine_id}/tunnel/recovery",
            post(register_recovery),
        )
        .route("/v1/machines/{machine_id}/tunnel", post(recover))
        .route(
            "/v1/machines/{machine_id}/link-preferences",
            post(link_preferences),
        )
        .route(
            "/v1/machines/{machine_id}/hooks/wake",
            post(wake_held_hooks),
        )
}

/// `layerEnvironmentAuth`.
async fn machine(s: &MachineState, headers: &HeaderMap) -> Result<Principal, Response> {
    match credentials::authenticate(&s.relay.pool, &credential(headers, "Bearer")).await {
        Ok(Some(p)) => Ok(p),
        Ok(None) => Err(RelayError::auth("not_authorized").into_response()),
        Err(e) => Err(persistence(e).into_response()),
    }
}

/// The principal, the path's machine id (it must be the principal's) and the payload.
async fn prelude<T: serde::de::DeserializeOwned>(
    s: &MachineState,
    raw_machine_id: &str,
    headers: &HeaderMap,
    body: &Bytes,
) -> Result<(Principal, String, T), Response> {
    let p = machine(s, headers).await?;
    let machine_id = machine_param(raw_machine_id)?;
    let payload = json_payload(headers, body)?;
    if p.machine_id != machine_id {
        return Err(not_authorized().into_response());
    }
    Ok((p, machine_id, payload))
}

fn not_authorized() -> RelayError {
    RelayError::unauthorized("not_authorized")
}

/// A `RelayManagedEndpointOrigin` body field.
fn origin_de<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Origin, D::Error> {
    decode_origin(&Value::deserialize(d)?).ok_or_else(|| serde::de::Error::custom("bad origin"))
}

/// `verifyEnvironmentTunnelRecoveryProof`.
fn verify_recovery_proof(
    s: &MachineState,
    p: &Principal,
    proof: &str,
    cloud_user_id: &str,
    action: &str,
    tunnel_id: Option<&str>,
    origin: &Origin,
) -> Result<(), RelayError> {
    let key = jws::verifying_key_from_pem(&p.machine_public_key).map_err(|_| not_authorized())?;
    let issuer = jws::machine_principal(&p.machine_id);
    let c = jws::verify(
        &key,
        proof,
        &jws::Expect {
            typ: jws::RELAY_MANAGED_TUNNEL_RECOVERY_TYP,
            issuer: &issuer,
            audience: s.relay.normalized_issuer(),
            now_epoch_seconds: now_ms() / 1000,
            max_age_seconds: jws::DEFAULT_MAX_AGE_SECONDS,
        },
    )
    .map_err(|_| not_authorized())?;
    // `RelayManagedEndpointRecoveryProofPayload` (register | recover).
    let signed_action = c.get("action").and_then(Value::as_str);
    let signed_origin = c.get("origin").and_then(decode_origin);
    let signed_tunnel = tns(c.get("tunnelId"));
    let decodes = registered_claims_ok(&c)
        && tns(c.get("machineId")).is_some()
        && tns(c.get("cloudUserId")).is_some()
        && signed_origin.is_some()
        && match signed_action {
            Some("register") => signed_tunnel.is_some(),
            Some("recover") => true,
            _ => false,
        };
    let ok = decodes
        && tns(c.get("machineId")).as_deref() == Some(&p.machine_id)
        && tns(c.get("sub")).as_deref() == Some(&p.machine_id)
        && tns(c.get("cloudUserId")).as_deref() == Some(cloud_user_id)
        && signed_action == Some(action)
        && (action != "register" || signed_tunnel.as_deref() == tunnel_id)
        && signed_origin.as_ref().is_some_and(|o| {
            o.local_http_host == origin.local_http_host
                && o.local_http_port == origin.local_http_port
        });
    // Vekrel: only loopback origins, checked before any provider call (T3 leaves it to the
    // provider, `ManagedEndpointOriginNotAllowed` -> 401).
    if ok && is_loopback_origin(origin) {
        Ok(())
    } else {
        Err(not_authorized())
    }
}

/// Recovery errors: `catchTags` then `mapRelayCommonApiErrors("not_authorized")`.
fn provider_error(e: ProviderError) -> RelayError {
    let retry = e.retry_after_ms();
    match e {
        ProviderError::OriginNotAllowed => not_authorized(),
        _ => RelayError::internal("upstream_unavailable"),
    }
    .with_retry_after_ms(retry)
}

/// The active managed link this machine key proved for that user.
async fn managed_link(
    s: &MachineState,
    user: Option<Uuid>,
    p: &Principal,
) -> Result<(Uuid, links::LinkedMachine), RelayError> {
    let user = user.ok_or_else(not_authorized)?;
    let mut conn = s.relay.pool.acquire().await.map_err(persistence)?;
    let link = links::get_for_user(&mut conn, user, &p.machine_id)
        .await
        .map_err(persistence)?
        .filter(|l| {
            l.machine_public_key == p.machine_public_key
                && l.endpoint.provider_kind == "cloudflare_tunnel"
                && l.managed_tunnels_enabled
        })
        .ok_or_else(not_authorized)?;
    Ok((user, link))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegistrationBody {
    cloud_user_id: Tns,
    tunnel_id: Tns,
    #[serde(deserialize_with = "origin_de")]
    origin: Origin,
    proof: Tns,
}

async fn register_recovery(
    State(s): State<MachineState>,
    Path(machine_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let (p, _, b): (_, _, RegistrationBody) = match prelude(&s, &machine_id, &headers, &body).await
    {
        Ok(v) => v,
        Err(r) => return r,
    };
    let origin = b.origin.clone();
    let checked = verify_recovery_proof(
        &s,
        &p,
        &b.proof.0,
        &b.cloud_user_id.0,
        "register",
        Some(&b.tunnel_id.0),
        &origin,
    );
    if let Err(e) = checked {
        return e.into_response();
    }
    no_store(
        async {
            let (user, link) = managed_link(&s, parse_wire_user_id(&b.cloud_user_id.0), &p).await?;
            let status = s
                .relay
                .provider
                .reconcile_origin(user, &p.machine_id, &b.tunnel_id.0, &origin, &link.endpoint)
                .await
                .map_err(provider_error)?;
            if status == OriginSync::Ready
                && !s
                    .relay
                    .provider
                    .enable_recovery(
                        user,
                        &p.machine_id,
                        &b.tunnel_id.0,
                        &p.machine_public_key,
                        &origin,
                    )
                    .await
                    .map_err(persistence)?
            {
                return Err(not_authorized());
            }
            Ok(Json(json!({ "status": status.as_str() })))
        }
        .await
        .map_or_else(IntoResponse::into_response, IntoResponse::into_response),
    )
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RecoveryBody {
    cloud_user_id: Tns,
    #[serde(deserialize_with = "origin_de")]
    origin: Origin,
    proof: Tns,
}

async fn recover(
    State(s): State<MachineState>,
    Path(machine_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let (p, _, b): (_, _, RecoveryBody) = match prelude(&s, &machine_id, &headers, &body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let origin = b.origin.clone();
    if let Err(e) = verify_recovery_proof(
        &s,
        &p,
        &b.proof.0,
        &b.cloud_user_id.0,
        "recover",
        None,
        &origin,
    ) {
        return e.into_response();
    }
    no_store(
        async {
            let provider = &s.relay.provider;
            let (user, link) = managed_link(&s, parse_wire_user_id(&b.cloud_user_id.0), &p).await?;
            let recovered = provider
                .provision(user, &p.machine_id, &origin, true)
                .await
                .map_err(provider_error)?;
            let tunnel_id = recovered.runtime.tunnel_id.clone();
            let Some(tunnel_id) = tunnel_id.filter(|_| {
                recovered.endpoint.http_base_url == link.endpoint.http_base_url
                    && recovered.endpoint.ws_base_url == link.endpoint.ws_base_url
            }) else {
                if let Some(t) = recovered.runtime.tunnel_id.as_deref()
                    && let Err(e) = provider.release(user, &p.machine_id, Some(t)).await
                {
                    tracing::warn!(
                        stage = e.stage,
                        "failed to clean up a tunnel with a mismatched endpoint"
                    );
                }
                return Err(not_authorized());
            };
            let enabled = provider
                .enable_recovery(
                    user,
                    &p.machine_id,
                    &tunnel_id,
                    &p.machine_public_key,
                    &origin,
                )
                .await
                .map_err(persistence)?;
            if !enabled {
                let target = provider
                    .prepare_deprovision(user, &p.machine_id)
                    .await
                    .map_err(|e| {
                        RelayError::internal("upstream_unavailable")
                            .with_retry_after_ms(e.retry_after_ms)
                    })?;
                if target.is_some() {
                    let mut conn = s.relay.pool.acquire().await.map_err(persistence)?;
                    let current = links::get_for_user(&mut conn, user, &p.machine_id)
                        .await
                        .map_err(persistence)?;
                    if current.is_none_or(|l| l.endpoint.provider_kind != "cloudflare_tunnel")
                        && let Err(e) = provider
                            .deprovision(user, &p.machine_id, Some(target))
                            .await
                    {
                        tracing::warn!(
                            stage = e.stage,
                            "failed to clean up a tunnel after its managed link was removed"
                        );
                    }
                }
                return Err(not_authorized());
            }
            Ok(Json(json!({
                "endpoint": recovered.endpoint,
                "endpointRuntime": recovered.runtime,
            })))
        }
        .await
        .map_or_else(IntoResponse::into_response, IntoResponse::into_response),
    )
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PreferencesBody {
    hold_webhooks_while_offline: bool,
}

async fn link_preferences(
    State(s): State<MachineState>,
    Path(machine_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let (p, machine_id, b): (_, _, PreferencesBody) =
        match prelude(&s, &machine_id, &headers, &body).await {
            Ok(v) => v,
            Err(r) => return r,
        };
    // Turning the hold off also clears held webhooks (`HeldHooks.setHoldWhileOffline`).
    match held::set_hold_while_offline(
        &s.relay.pool,
        &machine_id,
        &p.machine_public_key,
        b.hold_webhooks_while_offline,
    )
    .await
    {
        Ok(()) => Json(json!({ "holdWebhooksWhileOffline": b.hold_webhooks_while_offline }))
            .into_response(),
        Err(e) => persistence(e).into_response(),
    }
}

/// `wakeHeldHooks`: the machine's tunnel is back; deliver what is held for it now.
async fn wake_held_hooks(
    State(s): State<MachineState>,
    Path(machine_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let p = match machine(&s, &headers).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    let machine_id = match machine_param(&machine_id) {
        Ok(m) => m,
        Err(r) => return r,
    };
    if p.machine_id != machine_id {
        return not_authorized().into_response();
    }
    match held::wake(&s.relay, &machine_id, &p.machine_public_key).await {
        Ok(pending) => Json(json!({ "pending": pending })).into_response(),
        Err(e) => persistence(e).into_response(),
    }
}
