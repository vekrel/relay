// Connect and status: a port of T3 Code's `infra/relay/src/environments/EnvironmentConnector.ts`
// and `endpointFailure.ts`, with `deploymentConfig.ts`'s hostname rules (MIT, Copyright (c) T3
// Tools Inc.; see NOTICE). The relay signs a one-shot request with its mint key, POSTs it to the
// machine's managed endpoint (redirects off, 10 s), and accepts only an answer signed by the key
// the link was proven with that echoes this request's nonce.
use std::time::Duration;

use serde::Serialize;
use serde_json::{Map, Value, json};
use uuid::Uuid;

use super::linker::{registered_claims_ok, tns, valid_descriptor};
use super::provider::{self, Allocation};
use super::{Endpoint, Relay, links, now_ms, parse_iso_ms};
use crate::auth::dpop_proofs::iso_millis;
use crate::http::errors::int;
use crate::jws;

/// `ENVIRONMENT_MINT_REQUEST_TIMEOUT_MS`.
pub const MINT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// `ENVIRONMENT_HEALTH_CLOCK_SKEW_MILLIS`.
const HEALTH_CLOCK_SKEW_MS: i64 = 60_000;
/// Mint and health requests live 2 minutes.
const REQUEST_TTL_SECONDS: i64 = 120;
const MINT_PATH: &str = "/api/vekrel-connect/mint-credential";
const HEALTH_PATH: &str = "/api/vekrel-connect/health";

#[derive(Debug)]
pub enum ConnectError {
    /// `EnvironmentConnectNotAuthorized` with a `RelayMachineConnectNotAuthorizedReason`.
    NotAuthorized(&'static str),
    /// `EnvironmentMintRequestFailed` with its diagnosis.
    RequestFailed {
        endpoint_failure: Option<&'static str>,
        endpoint_status: Option<u16>,
    },
    /// `EnvironmentMintRequestTimedOut`.
    TimedOut,
    /// `EnvironmentMintResponseInvalid`.
    ResponseInvalid,
    Persistence(sqlx::Error),
}

/// `RelayMachineConnectResponse`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectResponse {
    pub machine_id: String,
    pub endpoint: Endpoint,
    pub credential: String,
    pub expires_at: String,
}

/// `RelayMachineStatusResponse`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusResponse {
    pub machine_id: String,
    pub endpoint: Endpoint,
    pub status: &'static str,
    pub checked_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub descriptor: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_failure: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offline_reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
}

fn normalize_zone(name: &str) -> String {
    name.trim().to_lowercase().trim_matches('.').to_owned()
}

fn is_dns_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|l| {
            let b = l.as_bytes();
            !b.is_empty()
                && b.len() <= 63
                && b.iter()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
                && b[0] != b'-'
                && b[b.len() - 1] != b'-'
        })
}

/// `isManagedEndpointHostname`.
pub fn is_managed_endpoint_hostname(hostname: &str, base_domain: &str) -> bool {
    let host = normalize_zone(hostname);
    let base = normalize_zone(base_domain);
    hostname == host
        && is_dns_name(&host)
        && is_dns_name(&base)
        && host.ends_with(&format!(".{base}"))
}

/// `managedEndpointForHostname`.
pub fn endpoint_for_hostname(hostname: &str) -> Endpoint {
    Endpoint {
        http_base_url: format!("https://{hostname}/"),
        ws_base_url: format!("wss://{hostname}/ws"),
        provider_kind: "cloudflare_tunnel".into(),
    }
}

/// `validateManagedEndpoint`.
pub fn validate_managed_endpoint(
    link: &links::LinkedMachine,
    allocation: Option<&Allocation>,
    base_domain: Option<&str>,
) -> Result<Endpoint, &'static str> {
    if link.endpoint.provider_kind != "cloudflare_tunnel" {
        return Err("endpoint_provider_not_managed");
    }
    let a = allocation.ok_or("managed_endpoint_allocation_not_found")?;
    let base = base_domain
        .filter(|b| !b.is_empty())
        .ok_or("managed_endpoint_base_domain_not_configured")?;
    if a.ready_at.is_none() || a.tunnel_id.is_none() || a.dns_record_id.is_none() {
        return Err("managed_endpoint_allocation_not_ready");
    }
    if !is_managed_endpoint_hostname(&a.hostname, base) {
        return Err("managed_endpoint_hostname_invalid");
    }
    let endpoint = endpoint_for_hostname(&a.hostname);
    if endpoint.http_base_url != link.endpoint.http_base_url
        || endpoint.ws_base_url != link.endpoint.ws_base_url
    {
        return Err("managed_endpoint_mismatch");
    }
    Ok(endpoint)
}

/// `classifyEndpointResponse`: Cloudflare answers what it cannot route with `error code: NNNN`.
pub fn classify_endpoint_response(status: u16, body: &str) -> &'static str {
    let lower = body.to_ascii_lowercase();
    let code = lower.find("error code:").and_then(|i| {
        let rest = lower[i + "error code:".len()..].trim_start();
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        (digits.len() >= 4).then(|| digits[..4].to_owned())
    });
    match code.as_deref() {
        Some("1016") => return "dns",
        Some("1033") => return "tunnel_down",
        _ => {}
    }
    match status {
        530 if code.is_none() => "tunnel_down",
        530 => "unknown",
        502 | 503 => "origin_unreachable",
        521 => "refused",
        504 | 522 | 524 => "timeout",
        525 | 526 => "tls",
        _ => "invalid_response",
    }
}

/// `classifyTransportFailure`, over the error's source chain.
fn classify_transport(e: &reqwest::Error) -> &'static str {
    let mut text = String::new();
    let mut cur: Option<&dyn std::error::Error> = Some(e);
    let mut depth = 0;
    while let Some(c) = cur {
        if depth == 6 {
            break;
        }
        text.push_str(&format!("{c} {c:?} "));
        cur = c.source();
        depth += 1;
    }
    let t = text.to_lowercase();
    let has = |n: &[&str]| n.iter().any(|w| t.contains(w));
    if has(&[
        "enotfound",
        "eai_again",
        "getaddrinfo",
        "dns",
        "failed to lookup",
        "nodename nor servname",
    ]) {
        "dns"
    } else if has(&["econnrefused", "refused"]) {
        "refused"
    } else if has(&["cert", "tls", "ssl"]) {
        "tls"
    } else if has(&["etimedout", "timeout", "timed out"]) {
        "timeout"
    } else {
        "unknown"
    }
}

/// Typed machine errors (`MachineHttpCloudErrors`) decode on the client, so T3 sees no HTTP
/// status for them, only `invalid_response`.
fn is_machine_error(status: u16, body: &Value) -> bool {
    let tag = body.get("_tag").and_then(Value::as_str);
    let message = body.get("message").is_some_and(Value::is_string);
    match (status, tag) {
        (400, Some("MachineHttpBadRequestError"))
        | (401, Some("MachineHttpUnauthorizedError"))
        | (403, Some("MachineHttpForbiddenError"))
        | (409, Some("MachineHttpConflictError"))
        | (500, Some("MachineHttpInternalServerError")) => message,
        (403, Some("MachineScopeRequiredError")) => {
            body.get("code").and_then(Value::as_str) == Some("insufficient_scope")
        }
        _ => false,
    }
}

enum Outcome {
    Ok(Value),
    /// The request failed; `message` is set for a typed machine error.
    Failed {
        failure: &'static str,
        status: Option<u16>,
        message: Option<String>,
    },
    TimedOut,
}

async fn post(relay: &Relay, endpoint: &Endpoint, path: &str, proof: &str) -> Outcome {
    #[cfg(test)]
    let base = relay
        .endpoint_override
        .clone()
        .unwrap_or_else(|| endpoint.http_base_url.clone());
    #[cfg(not(test))]
    let base = endpoint.http_base_url.clone();
    let url = match url::Url::parse(&base).and_then(|u| u.join(path)) {
        Ok(u) => u,
        Err(_) => {
            return Outcome::Failed {
                failure: "unknown",
                status: None,
                message: None,
            };
        }
    };
    let call = async {
        let res = match relay
            .http
            .post(url)
            .json(&json!({ "proof": proof }))
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                return Outcome::Failed {
                    failure: classify_transport(&e),
                    status: None,
                    message: None,
                };
            }
        };
        let status = res.status().as_u16();
        let body = res.text().await.unwrap_or_default();
        let json: Option<Value> = serde_json::from_str(&body).ok();
        if (200..300).contains(&status) {
            return match json {
                Some(v) => Outcome::Ok(v),
                None => Outcome::Failed {
                    failure: "invalid_response",
                    status: None,
                    message: None,
                },
            };
        }
        if let Some(v) = json.as_ref().filter(|v| is_machine_error(status, v)) {
            return Outcome::Failed {
                failure: "invalid_response",
                status: None,
                message: Some(
                    v.get("message")
                        .and_then(Value::as_str)
                        .map_or_else(|| "Insufficient scope".to_owned(), str::to_owned),
                ),
            };
        }
        // Only Cloudflare's 530 needs the body to tell a dead tunnel from a DNS error.
        let body = if status == 530 { body.as_str() } else { "" };
        Outcome::Failed {
            failure: classify_endpoint_response(status, body),
            status: Some(status),
            message: None,
        }
    };
    tokio::time::timeout(MINT_REQUEST_TIMEOUT, call)
        .await
        .unwrap_or(Outcome::TimedOut)
}

async fn load(
    relay: &Relay,
    user: Uuid,
    machine_id: &str,
) -> Result<(links::LinkedMachine, Option<Allocation>), ConnectError> {
    let mut conn = relay
        .pool
        .acquire()
        .await
        .map_err(ConnectError::Persistence)?;
    let link = links::get_for_user(&mut conn, user, machine_id)
        .await
        .map_err(ConnectError::Persistence)?;
    drop(conn);
    let allocation = provider::allocation(&relay.pool, user, machine_id)
        .await
        .map_err(ConnectError::Persistence)?;
    let link = link.ok_or(ConnectError::NotAuthorized("machine_link_not_found"))?;
    Ok((link, allocation))
}

fn verify_machine_signed(
    relay: &Relay,
    link: &links::LinkedMachine,
    token: &str,
    typ: &str,
    now: i64,
) -> Option<Map<String, Value>> {
    // A linked machine has one key here; T3 loops over `[link.environmentPublicKey]`.
    let key = jws::verifying_key_from_pem(&link.machine_public_key).ok()?;
    let issuer = jws::machine_principal(&link.machine_id);
    let claims = jws::verify(
        &key,
        token,
        &jws::Expect {
            typ,
            issuer: &issuer,
            audience: relay.normalized_issuer(),
            now_epoch_seconds: now,
            max_age_seconds: jws::DEFAULT_MAX_AGE_SECONDS,
        },
    )
    .ok()?;
    registered_claims_ok(&claims).then_some(claims)
}

pub struct MachineRequest<'a> {
    pub issuer: &'a str,
    pub machine_id: &'a str,
    pub user: &'a str,
    pub jti: &'a str,
    pub iat: i64,
    pub nonce: &'a str,
}

fn registered(r: &MachineRequest) -> Map<String, Value> {
    let v = json!({
        "iss": r.issuer,
        "aud": jws::machine_principal(r.machine_id),
        "sub": r.user,
        "jti": r.jti,
        "iat": r.iat,
        "exp": r.iat + REQUEST_TTL_SECONDS,
        "machineId": r.machine_id,
    });
    match v {
        Value::Object(m) => m,
        _ => unreachable!(),
    }
}

/// `RelayCloudMintCredentialProofPayload`, in the order T3 writes it.
pub fn mint_request(r: &MachineRequest, thumbprint: &str, device_id: Option<&str>) -> Value {
    let mut p = registered(r);
    p.insert("clientProofKeyThumbprint".into(), thumbprint.into());
    p.insert("cnf".into(), json!({ "jkt": thumbprint }));
    if let Some(d) = device_id.filter(|d| !d.is_empty()) {
        p.insert("deviceId".into(), d.into());
    }
    p.insert("nonce".into(), r.nonce.into());
    p.insert("scope".into(), json!(["machine:connect"]));
    Value::Object(p)
}

/// `RelayCloudMachineHealthProofPayload`.
pub fn health_request(r: &MachineRequest) -> Value {
    let mut p = registered(r);
    p.insert("nonce".into(), r.nonce.into());
    p.insert("scope".into(), json!(["machine:status"]));
    Value::Object(p)
}

/// `connect`.
pub async fn connect(
    relay: &Relay,
    user: Uuid,
    machine_id: &str,
    client_proof_key_thumbprint: &str,
    device_id: Option<&str>,
) -> Result<ConnectResponse, ConnectError> {
    if client_proof_key_thumbprint.trim().is_empty() {
        return Err(ConnectError::NotAuthorized(
            "client_proof_key_thumbprint_missing",
        ));
    }
    let (link, allocation) = load(relay, user, machine_id).await?;
    let endpoint =
        validate_managed_endpoint(&link, allocation.as_ref(), relay.tunnel_zone.as_deref())
            .map_err(ConnectError::NotAuthorized)?;
    let now = now_ms() / 1000;
    let nonce = Uuid::new_v4().to_string();
    let payload = mint_request(
        &MachineRequest {
            issuer: relay.normalized_issuer(),
            machine_id: &link.machine_id,
            user: &super::wire_user_id(user),
            jti: &Uuid::new_v4().to_string(),
            iat: now,
            nonce: &nonce,
        },
        client_proof_key_thumbprint,
        device_id,
    );
    let proof = jws::sign(&relay.mint_key, jws::RELAY_MINT_REQUEST_TYP, &payload);
    let response = match post(relay, &endpoint, MINT_PATH, &proof).await {
        Outcome::Ok(v) => v,
        Outcome::TimedOut => return Err(ConnectError::TimedOut),
        Outcome::Failed {
            failure, status, ..
        } => {
            return Err(ConnectError::RequestFailed {
                endpoint_failure: Some(failure),
                endpoint_status: status,
            });
        }
    };
    // `RelayMachineMintResponse` must decode before it is checked.
    let (Some(credential), Some(expires_at), Some(response_proof)) = (
        tns(response.get("credential")),
        tns(response.get("expiresAt")),
        tns(response.get("proof")),
    ) else {
        return Err(ConnectError::RequestFailed {
            endpoint_failure: Some("invalid_response"),
            endpoint_status: None,
        });
    };
    let verified = verify_machine_signed(
        relay,
        &link,
        &response_proof,
        jws::RELAY_MINT_RESPONSE_TYP,
        now,
    )
    .is_some_and(|c| {
        tns(c.get("machineId")).as_deref() == Some(machine_id)
            && tns(c.get("requestNonce")).as_deref() == Some(&nonce)
            && tns(c.get("clientProofKeyThumbprint")).as_deref()
                == Some(client_proof_key_thumbprint)
            && tns(c.get("credential")).as_deref() == Some(&credential)
            && parse_iso_ms(&expires_at)
                .is_some_and(|ms| Some(ms.div_euclid(1000)) == c.get("exp").and_then(int))
    });
    if !verified {
        return Err(ConnectError::ResponseInvalid);
    }
    Ok(ConnectResponse {
        machine_id: link.machine_id,
        endpoint,
        credential,
        expires_at,
    })
}

/// `status`: an unreachable machine is `offline` with a diagnosis, not an error.
pub async fn status(
    relay: &Relay,
    user: Uuid,
    machine_id: &str,
) -> Result<StatusResponse, ConnectError> {
    let (link, allocation) = load(relay, user, machine_id).await?;
    let endpoint =
        validate_managed_endpoint(&link, allocation.as_ref(), relay.tunnel_zone.as_deref())
            .map_err(ConnectError::NotAuthorized)?;
    let now_millis = now_ms();
    let now = now_millis / 1000;
    let nonce = Uuid::new_v4().to_string();
    let payload = health_request(&MachineRequest {
        issuer: relay.normalized_issuer(),
        machine_id: &link.machine_id,
        user: &super::wire_user_id(user),
        jti: &Uuid::new_v4().to_string(),
        iat: now,
        nonce: &nonce,
    });
    let proof = jws::sign(&relay.mint_key, jws::RELAY_HEALTH_REQUEST_TYP, &payload);
    let checked_at = iso_millis(now_millis);
    let offline_reason = allocation
        .as_ref()
        .and_then(|a| a.tunnel_released_at.as_ref())
        .map(|_| "tunnel_released");
    let offline = |error: String, failure: &'static str, status: Option<u16>| StatusResponse {
        machine_id: link.machine_id.clone(),
        endpoint: endpoint.clone(),
        status: "offline",
        checked_at: checked_at.clone(),
        descriptor: None,
        error: Some(error),
        endpoint_failure: Some(failure),
        endpoint_status: status,
        offline_reason,
        trace_id: Some(crate::http::errors::trace_id()),
    };
    let response = match post(relay, &endpoint, HEALTH_PATH, &proof).await {
        Outcome::Ok(v) => v,
        Outcome::TimedOut => {
            tracing::warn!(machine_id = %link.machine_id, endpoint = %endpoint.http_base_url, "managed endpoint health request timed out");
            return Ok(offline(
                "Managed endpoint health request timed out.".into(),
                "timeout",
                None,
            ));
        }
        Outcome::Failed {
            failure,
            status,
            message,
        } => {
            tracing::warn!(machine_id = %link.machine_id, endpoint = %endpoint.http_base_url, endpoint_failure = failure, "managed endpoint health request failed");
            let error = message.map_or_else(
                || "Managed endpoint health request failed.".to_owned(),
                |m| format!("Managed endpoint health request failed: {m}"),
            );
            return Ok(offline(error, failure, status));
        }
    };
    // `RelayMachineHealthResponse`.
    let decoded = (
        tns(response.get("machineId")),
        response.get("status").and_then(Value::as_str) == Some("online"),
        response.get("descriptor").filter(|d| valid_descriptor(d)),
        tns(response.get("checkedAt")),
        tns(response.get("proof")),
    );
    let (Some(resp_machine), true, Some(descriptor), Some(resp_checked_at), Some(resp_proof)) =
        decoded
    else {
        return Ok(offline(
            "Managed endpoint health request failed.".into(),
            "invalid_response",
            None,
        ));
    };
    let after = now_ms();
    let verified = verify_machine_signed(
        relay,
        &link,
        &resp_proof,
        jws::RELAY_HEALTH_RESPONSE_TYP,
        after / 1000,
    )
    .is_some_and(|c| {
        resp_machine == machine_id
                && tns(c.get("machineId")).as_deref() == Some(machine_id)
                && tns(c.get("requestNonce")).as_deref() == Some(&nonce)
                && c.get("status").and_then(Value::as_str) == Some("online")
                && tns(c.get("checkedAt")).as_deref() == Some(&resp_checked_at)
                // `stableStringify` equality: key order does not matter, values do.
                && c.get("descriptor") == Some(descriptor)
    }) && parse_iso_ms(&resp_checked_at).is_some_and(|ms| {
        ms >= now_millis - HEALTH_CLOCK_SKEW_MS && ms <= after + HEALTH_CLOCK_SKEW_MS
    });
    if !verified {
        return Err(ConnectError::ResponseInvalid);
    }
    Ok(StatusResponse {
        machine_id: link.machine_id.clone(),
        endpoint,
        status: "online",
        checked_at: resp_checked_at,
        descriptor: Some(descriptor.clone()),
        error: None,
        endpoint_failure: None,
        endpoint_status: None,
        offline_reason: None,
        trace_id: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jws::tests::{fixture, test_only_key, token};

    fn sign_vector(name: &str) -> Value {
        fixture()["sign"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["name"] == name)
            .unwrap()
            .clone()
    }

    fn request_of(p: &Value) -> MachineRequest<'_> {
        MachineRequest {
            issuer: p["iss"].as_str().unwrap(),
            machine_id: p["machineId"].as_str().unwrap(),
            user: p["sub"].as_str().unwrap(),
            jti: p["jti"].as_str().unwrap(),
            iat: p["iat"].as_i64().unwrap(),
            nonce: p["nonce"].as_str().unwrap(),
        }
    }

    // Byte parity with the jose-signed requests Shared produces (`gen-vectors.ts`).
    #[test]
    fn machine_requests_sign_what_shared_signs() {
        let key = test_only_key("relayMint");
        for name in ["mint_request", "mint_request_no_device"] {
            let v = sign_vector(name);
            let p = &v["payload"];
            let claims = mint_request(
                &request_of(p),
                p["clientProofKeyThumbprint"].as_str().unwrap(),
                p["deviceId"].as_str(),
            );
            assert_eq!(
                jws::sign(&key, jws::RELAY_MINT_REQUEST_TYP, &claims),
                token(&v),
                "{name}"
            );
        }
        let v = sign_vector("health_request");
        let claims = health_request(&request_of(&v["payload"]));
        assert_eq!(
            jws::sign(&key, jws::RELAY_HEALTH_REQUEST_TYP, &claims),
            token(&v)
        );
    }

    #[test]
    fn cloudflare_failures_are_classified_as_t3_does() {
        assert_eq!(
            classify_endpoint_response(530, "error code: 1033"),
            "tunnel_down"
        );
        assert_eq!(classify_endpoint_response(530, "Error Code:1016"), "dns");
        assert_eq!(classify_endpoint_response(530, ""), "tunnel_down");
        assert_eq!(
            classify_endpoint_response(530, "error code: 1000"),
            "unknown"
        );
        assert_eq!(classify_endpoint_response(502, ""), "origin_unreachable");
        assert_eq!(classify_endpoint_response(521, ""), "refused");
        assert_eq!(classify_endpoint_response(524, ""), "timeout");
        assert_eq!(classify_endpoint_response(526, ""), "tls");
        assert_eq!(classify_endpoint_response(302, ""), "invalid_response");
    }

    #[test]
    fn managed_hostnames_must_sit_in_the_zone() {
        assert!(is_managed_endpoint_hostname(
            "prod-abc.tunnels.example",
            "tunnels.example"
        ));
        assert!(is_managed_endpoint_hostname(
            "prod-abc.tunnels.example",
            ".Tunnels.Example."
        ));
        assert!(!is_managed_endpoint_hostname(
            "Prod-abc.tunnels.example",
            "tunnels.example"
        ));
        assert!(!is_managed_endpoint_hostname(
            "tunnels.example",
            "tunnels.example"
        ));
        assert!(!is_managed_endpoint_hostname(
            "evil.example",
            "tunnels.example"
        ));
        assert!(!is_managed_endpoint_hostname(
            "-x.tunnels.example",
            "tunnels.example"
        ));
    }
}
