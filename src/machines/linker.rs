// Linking a machine to a user: a port of T3 Code's `infra/relay/src/environments/EnvironmentLinker.ts`
// (MIT, Copyright (c) T3 Tools Inc.; see NOTICE). Same checks in the same order; the proof is a
// `RelayMachineLinkProofPayload` signed by the machine key it names.
use serde_json::{Map, Value};
use uuid::Uuid;

use super::links::{self, UpsertInput};
use super::provider::{ProviderError, Provisioned, RuntimeConfig, is_loopback_origin};
use super::{Endpoint, Origin, PROVIDER_KINDS, Relay, credentials, now_ms};
use crate::auth::dpop::Proof;
use crate::auth::dpop_proofs;
use crate::auth::relay_tokens::LinkChallengeRequest;
use crate::http::errors::int;
use crate::jws;

/// Replay-table key for spent link challenges (T3 `relay-environment-link-challenge`).
const CHALLENGE_REPLAY_KEY: &str = "relay-machine-link-challenge";

/// `RelayMachineLinkRequest` (the capability flags; `proof` and `deviceId` alongside).
pub struct LinkRequest {
    pub proof: String,
    pub device_id: Option<String>,
    pub caps: LinkChallengeRequest,
}

#[derive(Debug)]
pub enum LinkError {
    /// `EnvironmentLinkProofExpired`.
    Expired,
    /// `EnvironmentLinkProofInvalid` with a `RelayMachineLinkProofInvalidReason`.
    Invalid(&'static str),
    Provider(ProviderError),
    /// `EnvironmentLinkUpsertPersistenceError`.
    LinkPersistence(sqlx::Error),
    /// `EnvironmentCredentialCreatePersistenceError`.
    CredentialPersistence(sqlx::Error),
    /// `DpopProofReplayPersistenceError`.
    ReplayPersistence(sqlx::Error),
}

pub struct Linked {
    pub machine_id: String,
    pub endpoint: Endpoint,
    pub runtime: Option<RuntimeConfig>,
    pub machine_credential: String,
}

/// A decoded `RelayMachineLinkProofPayload`; strings trimmed as `TrimmedNonEmptyString` decodes.
#[derive(Debug, Clone)]
pub struct LinkProof {
    pub sub: String,
    pub jti: String,
    pub iat: i64,
    pub exp: i64,
    pub challenge: String,
    pub descriptor: Value,
    pub machine_id: String,
    pub machine_public_key: String,
    pub endpoint: Endpoint,
    pub origin: Origin,
    pub scopes: Vec<String>,
}

pub fn tns(v: Option<&Value>) -> Option<String> {
    let t = v?.as_str()?.trim();
    (!t.is_empty()).then(|| t.to_owned())
}

pub fn decode_endpoint(v: &Value) -> Option<Endpoint> {
    let kind = v.get("providerKind")?.as_str()?;
    PROVIDER_KINDS.contains(&kind).then_some(())?;
    Some(Endpoint {
        http_base_url: tns(v.get("httpBaseUrl"))?,
        ws_base_url: tns(v.get("wsBaseUrl"))?,
        provider_kind: kind.to_owned(),
    })
}

pub fn decode_origin(v: &Value) -> Option<Origin> {
    let port = int(v.get("localHttpPort")?)?;
    (1..=65_535).contains(&port).then_some(())?;
    Some(Origin {
        local_http_host: tns(v.get("localHttpHost"))?,
        local_http_port: port,
    })
}

/// `ExecutionMachineDescriptor`, checked shallowly.
// shortcut: checks the required keys and their kinds, not every capability field; the descriptor
// is stored only as its label and echoed in status. Port the full schema if a client relies on it.
pub fn valid_descriptor(v: &Value) -> bool {
    tns(v.get("machineId")).is_some()
        && tns(v.get("label")).is_some()
        && tns(v.get("serverVersion")).is_some()
        && v.get("platform").is_some_and(Value::is_object)
        && v.get("capabilities").is_some_and(Value::is_object)
        && v.get("orchestrationProtocolVersion")
            .is_none_or(|p| int(p).is_some())
}

/// The registered claims every relay-signed payload carries (`RelaySignedJwtRegisteredClaims`).
pub fn registered_claims_ok(c: &Map<String, Value>) -> bool {
    ["iss", "aud", "sub", "jti"]
        .iter()
        .all(|k| tns(c.get(*k)).is_some())
        && c.get("iat").and_then(int).is_some()
        && c.get("exp").and_then(int).is_some()
}

pub fn decode_proof(c: &Map<String, Value>) -> Option<LinkProof> {
    if !registered_claims_ok(c) {
        return None;
    }
    let descriptor = c.get("descriptor")?.clone();
    if !valid_descriptor(&descriptor) {
        return None;
    }
    let scopes = c
        .get("scopes")?
        .as_array()?
        .iter()
        .map(|s| {
            s.as_str()
                .filter(|s| matches!(*s, "agent_activity_notifications" | "managed_tunnels"))
                .map(str::to_owned)
        })
        .collect::<Option<Vec<_>>>()?;
    Some(LinkProof {
        sub: tns(c.get("sub"))?,
        jti: tns(c.get("jti"))?,
        iat: int(c.get("iat")?)?,
        exp: int(c.get("exp")?)?,
        challenge: tns(c.get("challenge"))?,
        descriptor,
        machine_id: tns(c.get("machineId"))?,
        machine_public_key: tns(c.get("machinePublicKey"))?,
        endpoint: decode_endpoint(c.get("endpoint")?)?,
        origin: decode_origin(c.get("origin")?)?,
        scopes,
    })
}

fn authorizes(proof: &LinkProof, caps: &LinkChallengeRequest) -> bool {
    let has = |s: &str| proof.scopes.iter().any(|p| p == s);
    if caps.managed_tunnels_enabled && !has("managed_tunnels") {
        return false;
    }
    !((caps.notifications_enabled || caps.live_activities_enabled)
        && !has("agent_activity_notifications"))
}

fn is_secure(endpoint: &Endpoint) -> bool {
    let scheme = |u: &str| url::Url::parse(u).map(|u| u.scheme().to_owned()).ok();
    scheme(&endpoint.http_base_url).as_deref() == Some("https")
        && scheme(&endpoint.ws_base_url).as_deref() == Some("wss")
}

/// `link`. `user` is the account (`usr_<uuid>` on the wire).
pub async fn link(relay: &Relay, user: Uuid, req: &LinkRequest) -> Result<Linked, LinkError> {
    let user_wire = super::wire_user_id(user);
    let now = now_ms() / 1000;
    let invalid = LinkError::Invalid("invalid_signature_or_scope");
    let unverified = jws::decode_unverified(&req.proof)
        .ok_or(LinkError::Invalid("invalid_signature_or_scope"))?;
    let candidate = decode_proof(&unverified).ok_or(invalid)?;
    if candidate.exp <= now {
        return Err(LinkError::Expired);
    }
    let invalid = || LinkError::Invalid("invalid_signature_or_scope");
    let key = jws::verifying_key_from_pem(&candidate.machine_public_key).map_err(|_| invalid())?;
    let issuer = jws::machine_principal(&candidate.machine_id);
    let claims = jws::verify(
        &key,
        &req.proof,
        &jws::Expect {
            typ: jws::RELAY_LINK_PROOF_TYP,
            issuer: &issuer,
            audience: relay.normalized_issuer(),
            now_epoch_seconds: now,
            max_age_seconds: jws::DEFAULT_MAX_AGE_SECONDS,
        },
    )
    .map_err(|_| invalid())?;
    let verified = decode_proof(&claims).ok_or_else(invalid)?;
    if verified.sub != verified.machine_id || !authorizes(&verified, &req.caps) {
        return Err(invalid());
    }
    if tns(verified.descriptor.get("machineId")).as_deref() != Some(&verified.machine_id) {
        return Err(LinkError::Invalid("descriptor_mismatch"));
    }
    let challenge = relay
        .tokens
        .verify_link_challenge(&verified.challenge, &user_wire, req.caps, now)
        .ok_or(LinkError::Invalid("challenge_invalid"))?;
    let expires_at_ms = verified.exp * 1000;
    let spent = |thumbprint: &str, jti: &str, iat: i64| Proof {
        thumbprint: thumbprint.to_owned(),
        jti: jti.to_owned(),
        iat,
    };
    let fresh = dpop_proofs::consume(
        &relay.pool,
        &spent(&verified.machine_public_key, &verified.jti, verified.iat),
        expires_at_ms,
        now_ms(),
    )
    .await
    .map_err(LinkError::ReplayPersistence)?;
    if !fresh {
        return Err(LinkError::Invalid("replayed_nonce"));
    }
    let fresh = dpop_proofs::consume(
        &relay.pool,
        &spent(CHALLENGE_REPLAY_KEY, &challenge.jti, challenge.iat),
        expires_at_ms,
        now_ms(),
    )
    .await
    .map_err(LinkError::ReplayPersistence)?;
    if !fresh {
        return Err(LinkError::Invalid("challenge_invalid"));
    }
    let managed = req.caps.managed_tunnels_enabled;
    // Vekrel, not T3: a publish-only link may not claim a relay-managed endpoint kind, or connect
    // and webhooks would treat a machine-chosen URL as a tunnel the relay vouches for.
    if !managed && verified.endpoint.provider_kind != "manual" {
        return Err(invalid());
    }
    if managed && !is_loopback_origin(&verified.origin) {
        return Err(LinkError::Invalid("origin_not_allowed"));
    }
    // Downgrading a managed link to publish-only releases its tunnel and DNS; best effort.
    if !managed
        && let Err(e) = relay
            .provider
            .deprovision(user, &verified.machine_id, None)
            .await
    {
        tracing::warn!(
            machine_id = %verified.machine_id,
            stage = e.stage,
            "managed endpoint deprovision on publish-only link failed"
        );
    }
    // Whether this is the machine's first live link, read before provisioning so the cleanup
    // below never needs the database after a failure.
    let first_link = managed && {
        let mut conn = relay
            .pool
            .acquire()
            .await
            .map_err(LinkError::LinkPersistence)?;
        links::get_for_user(&mut conn, user, &verified.machine_id)
            .await
            .map_err(LinkError::LinkPersistence)?
            .is_none()
    };
    let provisioned: Option<Provisioned> = if managed {
        Some(
            relay
                .provider
                .provision(user, &verified.machine_id, &verified.origin, false)
                .await
                .map_err(LinkError::Provider)?,
        )
    } else {
        None
    };
    let finished = finish(relay, user, req, &verified, provisioned.as_ref(), managed).await;
    if finished.is_err() && provisioned.is_some() && first_link {
        // Vekrel, not T3 (which leaves it): a first link that failed after provisioning frees its
        // tunnel, so it neither lingers nor holds a slot of the tunnel cap. A relink keeps it; the
        // machine's live link still uses it. Best effort, and the link's own error is returned: a
        // cancelled request skips this, and the cap stops counting an unlinked allocation after
        // 10 minutes.
        if let Err(e) = relay
            .provider
            .deprovision(user, &verified.machine_id, None)
            .await
        {
            tracing::warn!(
                machine_id = %verified.machine_id,
                stage = e.stage,
                "managed endpoint cleanup after a failed link failed"
            );
        }
    }
    let (endpoint, machine_credential) = finished?;
    Ok(Linked {
        machine_id: verified.machine_id,
        endpoint,
        runtime: provisioned.map(|p| p.runtime),
        machine_credential,
    })
}

/// After provisioning: the endpoint check, then link and credential in one transaction.
async fn finish(
    relay: &Relay,
    user: Uuid,
    req: &LinkRequest,
    verified: &LinkProof,
    provisioned: Option<&Provisioned>,
    managed: bool,
) -> Result<(Endpoint, String), LinkError> {
    let endpoint = provisioned.map_or_else(|| verified.endpoint.clone(), |p| p.endpoint.clone());
    // Publish-only links are reached out of band; their nominal endpoint is never routed to.
    if managed && !is_secure(&endpoint) {
        return Err(LinkError::Invalid("endpoint_not_secure"));
    }
    let label = tns(verified.descriptor.get("label")).unwrap_or_default();
    // Link and credential commit together: a cancel (request deadline) or a failure between
    // them leaves neither. Proof and challenge consumes stay before provisioning, outside it.
    let mut tx = relay
        .pool
        .begin()
        .await
        .map_err(LinkError::LinkPersistence)?;
    links::upsert(
        &mut tx,
        &UpsertInput {
            user_id: user,
            machine_id: &verified.machine_id,
            label: &label,
            machine_public_key: &verified.machine_public_key,
            endpoint: &endpoint,
            notifications_enabled: req.caps.notifications_enabled,
            live_activities_enabled: req.caps.live_activities_enabled,
            managed_tunnels_enabled: managed,
            device_id: req.device_id.as_deref(),
        },
    )
    .await
    .map_err(LinkError::LinkPersistence)?;
    let machine_credential =
        credentials::create(&mut tx, &verified.machine_id, &verified.machine_public_key)
            .await
            .map_err(LinkError::CredentialPersistence)?;
    tx.commit()
        .await
        .map_err(LinkError::CredentialPersistence)?;
    Ok((endpoint, machine_credential))
}
