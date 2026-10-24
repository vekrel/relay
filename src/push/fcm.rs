// FCM (Android): a port of T3 Code's `infra/relay/src/agentActivity/FcmAssertionSigner.ts`,
// `FcmClient.ts` and `FcmDeliveries.ts` (MIT, Copyright (c) T3 Tools Inc.; see NOTICE). As in T3,
// FCM deliveries record no attempt rows. FCM v1 has no client-chosen message id, so a re-send
// after a crash is not deduplicated by Google (status-only updates share a `collapse_key`).
use std::time::{Duration, Instant};

use jsonwebtoken::{Algorithm, EncodingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use sqlx::PgConnection;
use uuid::Uuid;

use super::Push;
use super::agent_activity;
use super::config::ServiceAccount;
use super::devices::{self, Kind, Target};
use super::jobs::{self, JobError};
use super::payloads::*;
use crate::config::Secret;
use crate::jws::b64url_encode;
use crate::machines::{now_ms, wire_user_id};

const HTTP_STAGE_TIMEOUT: Duration = Duration::from_secs(10);
const ACCESS_TOKEN_TTL: Duration = Duration::from_secs(50 * 60);
const MAX_QUEUE_AGE_MS: i64 = 5 * 60_000;

/// `FCM_SERVICE_ACCOUNT`: `project_id`, `client_email` and a PKCS#8 RSA `private_key`.
pub fn service_account(json: &str) -> Option<ServiceAccount> {
    #[derive(Deserialize)]
    struct Raw {
        project_id: String,
        client_email: String,
        private_key: String,
    }
    let r: Raw = serde_json::from_str(json).ok()?;
    if r.project_id.is_empty() || r.client_email.is_empty() {
        return None;
    }
    EncodingKey::from_rsa_pem(r.private_key.as_bytes()).ok()?;
    Some(ServiceAccount {
        project_id: r.project_id,
        client_email: r.client_email,
        private_key: Secret(r.private_key),
    })
}

/// `FcmAssertionSigner.sign`.
pub fn assertion(a: &ServiceAccount, iat: i64) -> Result<String, ()> {
    let header = serde_json::to_vec(&json!({"alg": "RS256", "typ": "JWT"})).expect("json");
    let claims = serde_json::to_vec(&json!({
        "iss": a.client_email,
        "scope": "https://www.googleapis.com/auth/firebase.messaging",
        "aud": "https://oauth2.googleapis.com/token",
        "iat": iat,
        "exp": iat + 3600,
    }))
    .expect("json");
    let input = format!("{}.{}", b64url_encode(header), b64url_encode(claims));
    let key = EncodingKey::from_rsa_pem(a.private_key.0.as_bytes()).map_err(|_| ())?;
    let sig =
        jsonwebtoken::crypto::sign(input.as_bytes(), &key, Algorithm::RS256).map_err(|_| ())?;
    Ok(format!("{input}.{sig}"))
}

#[derive(Default)]
pub struct AccessToken(tokio::sync::Mutex<Option<(String, Instant)>>);

/// `FcmClientError` operations.
#[derive(Debug, PartialEq, Eq)]
pub enum FcmError {
    Configuration,
    Authorize(Option<u16>),
    Send(Option<u16>),
}

async fn authorize(push: &Push, a: &ServiceAccount) -> Result<String, FcmError> {
    let mut cached = push.fcm_token.0.lock().await;
    if let Some((t, at)) = cached.as_ref()
        && at.elapsed() < ACCESS_TOKEN_TTL
    {
        return Ok(t.clone());
    }
    let assertion = assertion(a, now_ms() / 1000).map_err(|_| FcmError::Authorize(None))?;
    let req = push.http.post(&push.config.fcm_token_url).form(&[
        ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
        ("assertion", &assertion),
    ]);
    let res = tokio::time::timeout(HTTP_STAGE_TIMEOUT, req.send())
        .await
        .ok()
        .and_then(Result::ok)
        .ok_or(FcmError::Authorize(None))?;
    let status = res.status().as_u16();
    if status != 200 {
        return Err(FcmError::Authorize(Some(status)));
    }
    let body: Value = tokio::time::timeout(HTTP_STAGE_TIMEOUT, res.json())
        .await
        .ok()
        .and_then(Result::ok)
        .ok_or(FcmError::Authorize(Some(status)))?;
    let token = body["access_token"]
        .as_str()
        .filter(|t| !t.is_empty())
        .ok_or(FcmError::Authorize(Some(status)))?
        .to_owned();
    *cached = Some((token.clone(), Instant::now()));
    Ok(token)
}

/// `FcmClient.send`: `Ok(true)` when FCM says the token is `UNREGISTERED`.
pub async fn send(
    push: &Push,
    token: &str,
    package: Option<&str>,
    data: &Map<String, Value>,
    alert: bool,
) -> Result<bool, FcmError> {
    if serde_json::to_string(data).expect("json").len() > 4096 {
        return Err(FcmError::Send(None));
    }
    let a = push.config.fcm.as_ref().ok_or(FcmError::Configuration)?;
    let access = authorize(push, a).await?;
    let mut android = Map::new();
    android.insert("priority".into(), "HIGH".into());
    android.insert("ttl".into(), "300s".into());
    if !alert {
        android.insert("collapse_key".into(), "t3-agent-activity".into());
    }
    if let Some(p) = package {
        android.insert("restricted_package_name".into(), p.into());
    }
    let body = json!({"message": {"token": token, "data": data, "android": android}});
    let project: String = form_urlencoded::byte_serialize(a.project_id.as_bytes()).collect();
    let url = format!(
        "{}/v1/projects/{project}/messages:send",
        push.config.fcm_api_base
    );
    let req = push
        .http
        .post(url)
        .bearer_auth(&access)
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&body).expect("json"));
    let res = tokio::time::timeout(HTTP_STAGE_TIMEOUT, req.send())
        .await
        .ok()
        .and_then(Result::ok)
        .ok_or(FcmError::Send(None))?;
    let status = res.status().as_u16();
    if (200..300).contains(&status) {
        return Ok(false);
    }
    if status == 401 {
        *push.fcm_token.0.lock().await = None;
    }
    let body: Value = tokio::time::timeout(HTTP_STAGE_TIMEOUT, res.json())
        .await
        .ok()
        .and_then(Result::ok)
        .ok_or(FcmError::Send(Some(status)))?;
    let unregistered = body["error"]["details"].as_array().is_some_and(|d| {
        d.iter().any(|x| {
            x["@type"] == "type.googleapis.com/google.firebase.fcm.v1.FcmError"
                && x["errorCode"] == "UNREGISTERED"
        })
    });
    if unregistered {
        Ok(true)
    } else {
        Err(FcmError::Send(Some(status)))
    }
}

/// `FcmDeliveryJob`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Job {
    pub user_id: Uuid,
    pub device_id: String,
    pub token: String,
    pub state: Option<ActivityState>,
    pub queued_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay: Option<bool>,
}

/// `FcmDeliveries.enqueue`.
pub async fn enqueue(
    conn: &mut PgConnection,
    push: &Push,
    t: &Target,
    state: Option<&ActivityState>,
    replay: bool,
) -> Result<Option<Value>, sqlx::Error> {
    let Some(token) = t.push_token.as_ref().filter(|_| t.platform == "android") else {
        return Ok(None);
    };
    if push.config.fcm.is_none() {
        tracing::warn!("Android notifications are not configured for this relay");
        return Ok(Some(
            json!({"deviceId": t.device_id, "kind": "push_notification", "ok": false,
            "apnsStatus": null, "apnsReason": null, "apnsId": null}),
        ));
    }
    let job = Job {
        user_id: t.user_id,
        device_id: t.device_id.clone(),
        token: token.clone(),
        state: state.cloned(),
        queued_at: now_ms(),
        replay: replay.then_some(true),
    };
    jobs::enqueue(
        &mut *conn,
        Uuid::new_v4(),
        "fcm",
        &serde_json::to_value(&job).expect("json"),
    )
    .await?;
    Ok(Some(super::apns::queued_result(
        &t.device_id,
        Kind::PushNotification,
    )))
}

/// `FcmDeliveries.process`: re-reads links and state, so a queued message honours sign-out,
/// token rotation, disabled publishing and newer thread states.
pub async fn process(push: &Push, payload: &Value) -> Result<(), JobError> {
    let job: Job =
        serde_json::from_value(payload.clone()).map_err(|_| JobError::retry("FcmDeliveryError"))?;
    let now = now_ms();
    if now - job.queued_at > MAX_QUEUE_AGE_MS {
        return Ok(());
    }
    let mut conn = push.pool.acquire().await?;
    let user = job.user_id;
    let targets = devices::list_targets(&mut conn, user).await?;
    let Some(target) = targets.into_iter().find(|d| {
        d.device_id == job.device_id
            && d.platform == "android"
            && d.push_token.as_deref() == Some(&job.token)
    }) else {
        return Ok(());
    };
    let Some(prefs) = target.preferences else {
        return Ok(());
    };
    let states = if prefs.live_activities_enabled {
        agent_activity::list_for_user(&mut conn, user).await?
    } else {
        vec![]
    };
    let aggregate = make_aggregate(&states, None, now);
    let previous = target.last_aggregate.clone();
    let mut alert: Option<Map<String, Value>> = None;
    // Deletion jobs may see another thread's new terminal state: they update the card but leave
    // that transition for its own job's alert.
    let mut acknowledge = job.state.is_some() || job.replay == Some(true) || aggregate.is_none();
    if let (Some(js), true) = (&job.state, prefs.notifications_enabled) {
        let state =
            agent_activity::get_for_user_thread(&mut conn, user, &js.machine_id, &js.thread_id)
                .await?;
        let same = state
            .as_ref()
            .is_some_and(|s| s.phase == js.phase && s.updated_at == js.updated_at);
        if previous.is_none() && !same {
            return Ok(());
        }
        let delivery_user = agent_activity::delivery_user(&mut conn, user, &js.machine_id).await?;
        acknowledge = delivery_user.is_some_and(|d| d.live_activities_enabled)
            || !prefs.live_activities_enabled;
        match (&delivery_user, &previous, &aggregate) {
            (Some(d), Some(prev), Some(next))
                if d.live_activities_enabled && prefs.live_activities_enabled =>
            {
                let mut allowed = std::collections::HashSet::new();
                for r in &next.activities {
                    if !allowed.contains(&r.machine_id)
                        && agent_activity::delivery_user(&mut conn, user, &r.machine_id)
                            .await?
                            .is_some_and(|d| d.notifications_enabled)
                    {
                        allowed.insert(r.machine_id.clone());
                    }
                }
                let filtered = Aggregate {
                    activities: next
                        .activities
                        .iter()
                        .filter(|r| allowed.contains(&r.machine_id))
                        .cloned()
                        .collect(),
                    ..next.clone()
                };
                alert = android_alert_for_aggregate(prev, &filtered, &prefs, now);
            }
            (Some(d), _, _) if d.notifications_enabled && same => {
                let s = state.expect("same");
                if !is_expired(&s, now) {
                    alert = android_alert_for_state(&s, &prefs, now);
                }
            }
            _ => {}
        }
    }
    let displayed = (prefs.notifications_enabled && prefs.live_activities_enabled)
        .then_some(aggregate.as_ref())
        .flatten();
    let active = displayed.is_some_and(|a| a.active_count > 0);
    if displayed.is_none() && alert.is_none() && previous.is_none() && job.state.is_some() {
        return Ok(());
    }
    let mut data = Map::new();
    data.insert("t3_kind".into(), "agent_activity".into());
    data.insert("device_id".into(), job.device_id.clone().into());
    data.insert("user_id".into(), wire_user_id(user).into());
    data.insert("updated_at".into(), now.to_string().into());
    data.extend(android_activity_data(displayed));
    let is_alert = alert.is_some();
    if let Some(a) = alert {
        data.extend(a);
        // Group ids can hold five sets of ids; hash the stable identity instead.
        let id = data["alert_id"].as_str().unwrap_or_default().to_owned();
        data.insert(
            "alert_id".into(),
            hex(&Sha256::digest(id.as_bytes())).into(),
        );
    }
    drop(conn);
    let sent = send(
        push,
        &job.token,
        target.bundle_id.as_deref(),
        &fit_fcm_data(&data),
        is_alert,
    )
    .await;
    let mut conn = push.pool.acquire().await?;
    match sent {
        Ok(true) => {
            sqlx::query("UPDATE relay_mobile_devices SET push_token = NULL WHERE user_id = $1 AND device_id = $2 AND push_token = $3")
                .bind(user)
                .bind(&job.device_id)
                .bind(&job.token)
                .execute(&mut *conn)
                .await?;
        }
        Ok(false) if acknowledge => {
            let kind = if active {
                Kind::LiveActivityUpdate
            } else {
                Kind::LiveActivityEnd
            };
            // The delivered terminal rows are the next transition baseline, so a replay cannot alert again.
            let baseline = prefs
                .live_activities_enabled
                .then_some(aggregate.as_ref())
                .flatten();
            devices::mark_delivery(
                &mut conn,
                user,
                &job.device_id,
                kind,
                baseline,
                &crate::auth::dpop_proofs::iso_millis(now),
            )
            .await?;
        }
        Ok(false) => {}
        Err(_) => return Err(JobError::retry("FcmClientError")),
    }
    Ok(())
}
