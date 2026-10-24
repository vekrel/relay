// APNs: a port of T3 Code's `infra/relay/src/agentActivity/apnsJwt.ts`, `ApnsProviderTokens.ts`,
// `ApnsClient.ts`, `ApnsDeliveries.ts`, `ApnsDeliveryQueue.ts`, `apnsDeliveryJobs.ts` and
// `DeliveryAttempts.ts` (MIT, Copyright (c) T3 Tools Inc.; see NOTICE).
//
// Changes from T3: jobs are `relay_push_jobs` rows in our own database instead of HMAC-signed
// queue messages, so the HMAC is gone (nothing untrusted carries them); each request carries
// `apns-id: <job id>`, so a re-send after a crash has the same id; the source-job lease is the
// job claim timeout (`jobs::CLAIM_TIMEOUT_SECONDS`, T3: 10 minutes).
use std::collections::HashMap;
use std::time::Duration;

use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::Signer;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::PgConnection;
use uuid::Uuid;

use super::Push;
use super::agent_activity;
use super::config::{ApnsCredentials, ApnsEnvironment};
use super::devices::{self, Kind, Target};
use super::jobs::{self, JobError};
use super::payloads::*;
use crate::jws::b64url_encode;
use crate::machines::{now_iso, now_ms, parse_iso_ms};

const LIVE_ACTIVITY_NAME: &str = "AgentActivity";
const HTTP_STAGE_TIMEOUT: Duration = Duration::from_secs(10);
const STALE_AFTER_SECONDS: i64 = 10 * 60;
const DISMISS_AFTER_SECONDS: i64 = 5 * 60;
const CONTENTLESS_DISMISS_AFTER_SECONDS: i64 = 15;
const MIN_LIVE_ACTIVITY_UPDATE_INTERVAL_MS: i64 = 15_000;
const FRESHLY_ARMED_GRACE_MS: i64 = 2 * 60 * 1_000;
const MAX_JOB_AGE_MS: i64 = 10 * 60 * 1_000;
/// APNs answers 429 TooManyProviderTokenUpdates when a token is refreshed more than about every
/// 20 minutes; each signed token is reused for 45 of its 60 minutes.
pub const APNS_JWT_REUSE_SECONDS: i64 = 45 * 60;
const PERMANENT_TOKEN_REASONS: [&str; 3] =
    ["BadDeviceToken", "DeviceTokenNotForTopic", "Unregistered"];

// ---- provider token (apnsJwt.ts, ApnsProviderTokens.ts) ----

/// The `.p8` key; T3 also accepts literal `\n` in the PEM.
pub fn signing_key(pem: &str) -> Result<SigningKey, ()> {
    use p256::pkcs8::DecodePrivateKey;
    p256::SecretKey::from_pkcs8_pem(&pem.replace("\\n", "\n"))
        .map(SigningKey::from)
        .map_err(|_| ())
}

pub fn quantized_issued_at(now_s: i64) -> i64 {
    now_s.div_euclid(APNS_JWT_REUSE_SECONDS) * APNS_JWT_REUSE_SECONDS
}

/// `makeApnsJwt`: deterministic ES256 (RFC 6979), so every replica derives the same token.
pub fn make_jwt(key: &SigningKey, team_id: &str, key_id: &str, iat: i64) -> String {
    let header = serde_json::to_vec(&json!({"alg": "ES256", "kid": key_id})).expect("json");
    let payload = serde_json::to_vec(&json!({"iss": team_id, "iat": iat})).expect("json");
    let input = format!("{}.{}", b64url_encode(header), b64url_encode(payload));
    let sig: p256::ecdsa::Signature = key.sign(input.as_bytes());
    // noble signs with low-S (T3 `p256.sign`), so normalize to match its bytes.
    let sig = sig.normalize_s();
    format!("{input}.{}", b64url_encode(sig.to_bytes()))
}

#[derive(Default)]
pub struct TokenCache(std::sync::Mutex<HashMap<String, (i64, String)>>);

impl TokenCache {
    /// `ApnsProviderTokens.getJwt`.
    fn get(&self, c: &ApnsCredentials, now_s: i64) -> Result<String, ()> {
        let iat = quantized_issued_at(now_s);
        let fingerprint = &hex(&Sha256::digest(c.private_key.0.as_bytes()))[..16];
        let key = format!("{}:{}:{fingerprint}", c.team_id, c.key_id);
        let mut cache = self.0.lock().expect("token cache");
        if let Some((at, jwt)) = cache.get(&key)
            && *at == iat
        {
            return Ok(jwt.clone());
        }
        let jwt = make_jwt(&signing_key(&c.private_key.0)?, &c.team_id, &c.key_id, iat);
        cache.insert(key, (iat, jwt.clone()));
        Ok(jwt)
    }
}

// ---- requests (ApnsClient.ts) ----

pub struct Request {
    pub token: String,
    pub priority: &'static str,
    /// `liveactivity` or `alert`.
    pub push_type: &'static str,
    pub payload: Value,
}

fn content_state(a: &Aggregate) -> Value {
    json!({"name": LIVE_ACTIVITY_NAME, "props": serde_json::to_string(a).expect("json")})
}

fn alert_payload(a: &Alert) -> Value {
    json!({"title": a.title, "body": a.body, "sound": "default"})
}

/// `makeLiveActivityRequest` for `update` and `end`.
pub fn live_activity_request(
    token: &str,
    kind: Kind,
    state: Option<&Aggregate>,
    alert: Option<&Alert>,
    now_s: i64,
) -> Request {
    let mut aps = serde_json::Map::new();
    aps.insert("timestamp".into(), now_s.into());
    let priority = if kind == Kind::LiveActivityEnd {
        aps.insert("event".into(), "end".into());
        if let Some(s) = state {
            aps.insert("content-state".into(), content_state(s));
        }
        if let Some(a) = alert {
            aps.insert("alert".into(), alert_payload(a));
        }
        let dismiss = if state.is_some() {
            DISMISS_AFTER_SECONDS
        } else {
            CONTENTLESS_DISMISS_AFTER_SECONDS
        };
        aps.insert("dismissal-date".into(), (now_s + dismiss).into());
        "10"
    } else {
        aps.insert("event".into(), "update".into());
        if let Some(a) = alert {
            aps.insert("alert".into(), alert_payload(a));
        }
        aps.insert(
            "content-state".into(),
            content_state(state.expect("an update carries state")),
        );
        aps.insert("stale-date".into(), (now_s + STALE_AFTER_SECONDS).into());
        if alert.is_some() { "10" } else { "5" }
    };
    Request {
        token: token.into(),
        priority,
        push_type: "liveactivity",
        payload: json!({ "aps": aps }),
    }
}

/// `makePushNotificationRequest`. Expo exposes `body` as the notification's data.
pub fn push_notification_request(token: &str, n: &Notification) -> Request {
    let thread = if n.thread_id.is_empty() {
        "t3-agent-alerts".to_owned()
    } else {
        format!("{}/{}", n.machine_id, n.thread_id)
    };
    Request {
        token: token.into(),
        priority: "10",
        push_type: "alert",
        payload: json!({
            "aps": {
                "alert": {"title": n.title, "body": n.body},
                "sound": "default",
                "thread-id": thread,
            },
            "body": {"machineId": n.machine_id, "threadId": n.thread_id, "deepLink": n.deep_link},
        }),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub ok: bool,
    /// 0: no HTTP response (transport error, signing error).
    pub status: u16,
    pub reason: Option<String>,
    pub apns_id: Option<String>,
}

/// `apnsReasonFromBody`.
fn reason_from_body(body: &str) -> Option<String> {
    if body.trim().is_empty() {
        return None;
    }
    match serde_json::from_str::<Value>(body) {
        Ok(Value::Object(m)) => match m.get("reason") {
            Some(Value::String(r)) => Some(r.clone()),
            None => Some(body.into()),
            Some(_) => Some(body.into()),
        },
        _ => Some(body.into()),
    }
}

fn host(push: &Push, env: ApnsEnvironment) -> String {
    if let Some(base) = &push.config.apns_api_base {
        return base.clone();
    }
    match env {
        ApnsEnvironment::Production => "https://api.push.apple.com".into(),
        ApnsEnvironment::Sandbox => "https://api.sandbox.push.apple.com".into(),
    }
}

/// `credentialsForTarget`: the device's own bundle id and APS environment win.
pub(crate) fn credentials_for(
    c: &ApnsCredentials,
    bundle_id: Option<&str>,
    aps: Option<&str>,
) -> ApnsCredentials {
    let mut c = c.clone();
    if let Some(b) = bundle_id {
        c.bundle_id = b.into();
    }
    if let Some(e) = aps.and_then(ApnsEnvironment::parse) {
        c.environment = e;
    }
    c
}

/// `sendLiveActivityRequest` / `sendPushNotificationRequest`, with transport failures turned into
/// a status-0 outcome as `recoverApnsDeliveryTransportError` does.
pub async fn send(
    push: &Push,
    c: &ApnsCredentials,
    r: &Request,
    apns_id: Option<Uuid>,
    now_s: i64,
) -> Outcome {
    let (kind, topic) = if r.push_type == "liveactivity" {
        (
            "live-activity",
            format!("{}.push-type.liveactivity", c.bundle_id),
        )
    } else {
        ("push-notification", c.bundle_id.clone())
    };
    let env = match c.environment {
        ApnsEnvironment::Production => "production",
        ApnsEnvironment::Sandbox => "sandbox",
    };
    let failed = |stage: &str| {
        let message = format!("APNs {kind} request failed during {stage} in {env}.");
        // The token suffix only, as T3 logs it; never the token or the key.
        let suffix: String = r
            .token
            .chars()
            .rev()
            .take(8)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        tracing::error!(token_suffix = %suffix, kind, stage, "{message}");
        Outcome {
            ok: false,
            status: 0,
            reason: Some(message),
            apns_id: None,
        }
    };
    let Ok(jwt) = push.apns_tokens.get(c, now_s) else {
        let message = format!("Failed to sign APNs JWT for key {}.", c.key_id);
        tracing::error!("{message}");
        return Outcome {
            ok: false,
            status: 0,
            reason: Some(message),
            apns_id: None,
        };
    };
    let mut req = push
        .apns_http
        .post(format!(
            "{}/3/device/{}",
            host(push, c.environment),
            r.token
        ))
        .header("authorization", format!("bearer {jwt}"))
        .header("apns-priority", r.priority)
        .header("apns-push-type", r.push_type)
        .header("apns-topic", topic)
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&r.payload).expect("json"));
    if let Some(id) = apns_id {
        req = req.header("apns-id", id.to_string());
    }
    let res = match tokio::time::timeout(HTTP_STAGE_TIMEOUT, req.send()).await {
        Ok(Ok(res)) => res,
        _ => return failed("send"),
    };
    let status = res.status().as_u16();
    let apns_id = res
        .headers()
        .get("apns-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let Ok(Ok(text)) = tokio::time::timeout(HTTP_STAGE_TIMEOUT, res.text()).await else {
        return failed("read-response");
    };
    Outcome {
        ok: (200..300).contains(&status),
        status,
        reason: reason_from_body(&text),
        apns_id,
    }
}

fn is_permanent_token_failure(o: &Outcome) -> bool {
    !o.ok
        && (o.status == 410
            || (o.status == 400
                && o.reason
                    .as_deref()
                    .is_some_and(|r| PERMANENT_TOKEN_REASONS.contains(&r))))
}

// ---- jobs (apnsDeliveryJobs.ts, ApnsDeliveryQueue.ts) ----

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JobTarget {
    pub user_id: Uuid,
    pub device_id: String,
    pub token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aps_environment: Option<String>,
}

/// `ApnsDeliveryJobPayload` (version 1).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Job {
    pub version: u8,
    pub job_id: Uuid,
    pub kind: Kind,
    pub target: JobTarget,
    pub aggregate: Option<Aggregate>,
    pub notification: Option<Notification>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alert: Option<Alert>,
    pub created_at: String,
    pub expires_at: String,
}

/// `RelayDeliveryResult` of a queued delivery.
pub fn queued_result(device: &str, kind: Kind) -> Value {
    json!({"deviceId": device, "kind": kind.as_str(), "ok": true, "queued": true,
           "apnsStatus": null, "apnsReason": null, "apnsId": null})
}

async fn enqueue(
    conn: &mut PgConnection,
    t: &Target,
    kind: Kind,
    token: &str,
    aggregate: Option<Aggregate>,
    notification: Option<Notification>,
    alert: Option<Alert>,
) -> Result<Value, sqlx::Error> {
    let now = now_ms();
    let job = Job {
        version: 1,
        job_id: Uuid::new_v4(),
        kind,
        target: JobTarget {
            user_id: t.user_id,
            device_id: t.device_id.clone(),
            token: token.into(),
            bundle_id: t.bundle_id.clone(),
            aps_environment: t.aps_environment.clone(),
        },
        aggregate: aggregate.as_ref().map(sanitize_aggregate),
        notification: notification.as_ref().map(sanitize_notification),
        alert,
        created_at: crate::auth::dpop_proofs::iso_millis(now),
        expires_at: crate::auth::dpop_proofs::iso_millis(now + MAX_JOB_AGE_MS),
    };
    jobs::enqueue(
        conn,
        job.job_id,
        "apns",
        &serde_json::to_value(&job).expect("json"),
    )
    .await?;
    Ok(queued_result(&t.device_id, kind))
}

/// `validatePayloadShape` + the time checks of `verifySignedApnsDeliveryJob`.
fn verify(job: &Job, now_ms: i64) -> Result<(), JobError> {
    let shape = match job.kind {
        Kind::LiveActivityUpdate if job.aggregate.is_none() => {
            Some("ApnsDeliveryJobLiveActivityAggregateMissing")
        }
        Kind::LiveActivityUpdate | Kind::LiveActivityEnd if job.notification.is_some() => {
            Some("ApnsDeliveryJobLiveActivityNotificationUnexpected")
        }
        Kind::PushNotification if job.notification.is_none() => {
            Some("ApnsDeliveryJobPushNotificationMissing")
        }
        Kind::PushNotification if job.aggregate.is_some() => {
            Some("ApnsDeliveryJobPushNotificationAggregateUnexpected")
        }
        _ => None,
    };
    if let Some(tag) = shape {
        return Err(JobError::retry(tag));
    }
    let created =
        parse_iso_ms(&job.created_at).ok_or(JobError::retry("ApnsDeliveryJobCreatedAtInvalid"))?;
    let expires =
        parse_iso_ms(&job.expires_at).ok_or(JobError::retry("ApnsDeliveryJobExpiresAtInvalid"))?;
    if expires <= created {
        return Err(JobError::retry("ApnsDeliveryJobTimeWindowInvalid"));
    }
    if expires - created > MAX_JOB_AGE_MS {
        return Err(JobError::retry("ApnsDeliveryJobTimeWindowTooLong"));
    }
    // T3 retries an expired job until its dead-letter queue; it can only expire again.
    if expires <= now_ms {
        return Err(JobError::fatal("ApnsDeliveryJobExpired"));
    }
    Ok(())
}

// ---- choosing deliveries at publish time (ApnsDeliveries.ts) ----

fn needs_attention(a: &Aggregate) -> bool {
    a.activities
        .iter()
        .any(|r| matches!(r.phase, Phase::WaitingForApproval | Phase::WaitingForInput))
}

fn should_update(prev: Option<&Aggregate>, next: &Aggregate, last: Option<&str>, now: i64) -> bool {
    let Some(prev) = prev else { return true };
    if prev == next {
        return false;
    }
    if prev.active_count != next.active_count
        || needs_attention(next)
        || row_phases_changed(prev, next)
    {
        return true;
    }
    last.and_then(parse_iso_ms)
        .is_none_or(|at| now - at >= MIN_LIVE_ACTIVITY_UPDATE_INTERVAL_MS)
}

/// `notificationForAggregate`.
fn notification_for_aggregate(t: &Target, a: Option<&Aggregate>, now: i64) -> Option<Notification> {
    t.push_token.as_ref()?;
    let prefs = t.preferences.filter(|p| p.notifications_enabled)?;
    let row = a?.activities.first()?;
    should_alert_for_activity(row.phase, &row.updated_at, Some(&prefs), now)
        .then(|| notification_for_activity(row))
}

enum Chosen {
    /// A Live Activity owns this state but no update is due: no alert push either.
    Suppressed,
    Live {
        kind: Kind,
        token: String,
        aggregate: Option<Aggregate>,
        alert: Option<Alert>,
    },
}

/// `chooseLiveActivityDelivery`.
fn choose_live_activity(
    t: &Target,
    a: Option<&Aggregate>,
    now: i64,
    replay: bool,
) -> Option<Chosen> {
    let end = |token: &String| Chosen::Live {
        kind: Kind::LiveActivityEnd,
        token: token.clone(),
        aggregate: None,
        alert: None,
    };
    if t.preferences.is_some_and(|p| !p.live_activities_enabled) {
        return t.activity_push_token.as_ref().map(end);
    }
    let token = t.activity_push_token.as_ref()?;
    let Some(next) = a else {
        // A freshly armed card keeps its seed until the machine's first publish lands.
        let armed = t.remote_started_at.as_deref().and_then(parse_iso_ms);
        if armed.is_some_and(|at| now - at < FRESHLY_ARMED_GRACE_MS) {
            return None;
        }
        return Some(end(token));
    };
    let prev = t.last_aggregate.as_ref();
    if !should_update(prev, next, t.last_live_activity_delivery_at.as_deref(), now) {
        return Some(Chosen::Suppressed);
    }
    let prefs = t.preferences.as_ref();
    let alert = if replay {
        None
    } else {
        alert_for_attention_transition(prev, next, prefs)
            .or_else(|| alert_for_newly_terminal(prev, next, prefs, now, true))
    };
    Some(Chosen::Live {
        kind: Kind::LiveActivityUpdate,
        token: token.clone(),
        aggregate: Some(next.clone()),
        alert,
    })
}

/// `sendForTarget`: queues what this device should get for `aggregate`.
pub async fn send_for_target(
    conn: &mut PgConnection,
    push: &Push,
    t: &Target,
    aggregate: Option<&Aggregate>,
    now: i64,
    replay: bool,
) -> Result<Option<Value>, sqlx::Error> {
    if push.config.apns.is_none() {
        return Ok(None);
    }
    let (kind, token, chosen_aggregate, chosen_alert) =
        match choose_live_activity(t, aggregate, now, replay) {
            Some(Chosen::Suppressed) => return Ok(None),
            Some(Chosen::Live {
                kind,
                token,
                aggregate,
                alert,
            }) => (kind, token, aggregate, alert),
            None => {
                let n = if replay {
                    None
                } else {
                    notification_for_aggregate(t, aggregate, now)
                };
                return match (n, &t.push_token) {
                    (Some(n), Some(token)) => {
                        enqueue(conn, t, Kind::PushNotification, token, None, Some(n), None)
                            .await
                            .map(Some)
                    }
                    _ => Ok(None),
                };
            }
        };
    let notification = if replay {
        None
    } else {
        notification_for_aggregate(t, aggregate, now)
    };
    let companion = notification.filter(|_| t.push_token.is_some());
    // The end is the "finished" moment: silent when a companion alert push rings the device.
    let alert = if replay {
        None
    } else if kind == Kind::LiveActivityEnd {
        if companion.is_some() {
            None
        } else {
            alert_for_terminal_aggregate(chosen_aggregate.as_ref(), t.preferences.as_ref())
        }
    } else {
        chosen_alert
    };
    let result = enqueue(conn, t, kind, &token, chosen_aggregate, None, alert).await?;
    if kind == Kind::LiveActivityEnd
        && let (Some(n), Some(push_token)) = (companion, &t.push_token)
    {
        enqueue(
            conn,
            t,
            Kind::PushNotification,
            push_token,
            None,
            Some(n),
            None,
        )
        .await?;
    }
    Ok(Some(result))
}

/// `sendPushNotificationForTarget`.
pub async fn send_push_notification_for_target(
    conn: &mut PgConnection,
    push: &Push,
    t: &Target,
    aggregate: &Aggregate,
    now: i64,
) -> Result<Option<Value>, sqlx::Error> {
    if push.config.apns.is_none() {
        return Ok(None);
    }
    match (
        notification_for_aggregate(t, Some(aggregate), now),
        &t.push_token,
    ) {
        (Some(n), Some(token)) => {
            enqueue(conn, t, Kind::PushNotification, token, None, Some(n), None)
                .await
                .map(Some)
        }
        _ => Ok(None),
    }
}

// ---- delivery attempts (DeliveryAttempts.ts) ----

enum Claim {
    Claimed,
    Completed,
    InFlight,
}

async fn claim_source_job(
    conn: &mut PgConnection,
    job: &Job,
    machine_id: Option<&str>,
    thread_id: Option<&str>,
    now: i64,
) -> Result<Claim, sqlx::Error> {
    let created_at = crate::auth::dpop_proofs::iso_millis(now);
    let suffix: String = {
        let u: Vec<u16> = job.target.token.encode_utf16().collect();
        String::from_utf16_lossy(&u[u.len().saturating_sub(8)..])
    };
    let inserted = sqlx::query(
        "INSERT INTO relay_delivery_attempts (id, created_at, user_id, machine_id, thread_id,
            device_id, kind, source_job_id, token_suffix)
         SELECT $1, $2, u.id, $4, $5, $6, $7, $8, $9 FROM (SELECT $3::uuid AS id) x
         LEFT JOIN users u ON u.id = x.id
         ON CONFLICT (source_job_id) DO NOTHING",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&created_at)
    .bind(job.target.user_id)
    .bind(machine_id)
    .bind(thread_id)
    .bind(&job.target.device_id)
    .bind(job.kind.as_str())
    .bind(job.job_id.to_string())
    .bind(suffix)
    .execute(&mut *conn)
    .await?;
    if inserted.rows_affected() > 0 {
        return Ok(Claim::Claimed);
    }
    let row: Option<(String, bool)> = sqlx::query_as(
        "SELECT created_at, (apns_status IS NOT NULL OR apns_reason IS NOT NULL
                OR apns_id IS NOT NULL OR transport_error IS NOT NULL)
         FROM relay_delivery_attempts WHERE source_job_id = $1",
    )
    .bind(job.job_id.to_string())
    .fetch_optional(&mut *conn)
    .await?;
    let Some((claimed_at, completed)) = row else {
        return Ok(Claim::InFlight);
    };
    if completed {
        return Ok(Claim::Completed);
    }
    let lease_ms = jobs::CLAIM_TIMEOUT_SECONDS * 1000;
    if parse_iso_ms(&claimed_at).is_some_and(|at| now - at < lease_ms) {
        return Ok(Claim::InFlight);
    }
    let reclaimed = sqlx::query(
        "UPDATE relay_delivery_attempts SET created_at = $3
         WHERE source_job_id = $1 AND created_at = $2 AND apns_status IS NULL
           AND apns_reason IS NULL AND apns_id IS NULL AND transport_error IS NULL",
    )
    .bind(job.job_id.to_string())
    .bind(&claimed_at)
    .bind(&created_at)
    .execute(&mut *conn)
    .await?;
    tracing::warn!(job_id = %job.job_id, "APNs delivery claim expired; sending again");
    Ok(if reclaimed.rows_affected() > 0 {
        Claim::Claimed
    } else {
        Claim::InFlight
    })
}

async fn complete_source_job(
    conn: &mut PgConnection,
    job: &Job,
    o: &Outcome,
) -> Result<(), sqlx::Error> {
    let (status, transport) = if o.status == 0 {
        (
            None,
            Some(
                o.reason
                    .clone()
                    .unwrap_or_else(|| "APNs request failed.".into()),
            ),
        )
    } else {
        (Some(i32::from(o.status)), None)
    };
    sqlx::query(
        "UPDATE relay_delivery_attempts SET created_at = $2, apns_status = $3, apns_reason = $4,
            apns_id = $5, transport_error = $6
         WHERE source_job_id = $1",
    )
    .bind(job.job_id.to_string())
    .bind(now_iso())
    .bind(status)
    .bind(&o.reason)
    .bind(&o.apns_id)
    .bind(transport)
    .execute(conn)
    .await?;
    Ok(())
}

/// A job that is skipped, not sent: the attempt row records why.
async fn skip(conn: &mut PgConnection, job: &Job, reason: &str) -> Result<(), JobError> {
    sqlx::query(
        "UPDATE relay_delivery_attempts SET created_at = $2, apns_status = NULL, apns_reason = $3,
            apns_id = NULL, transport_error = NULL WHERE source_job_id = $1",
    )
    .bind(job.job_id.to_string())
    .bind(now_iso())
    .bind(reason)
    .execute(conn)
    .await?;
    Ok(())
}

fn expected_token(t: &Target, kind: Kind) -> Option<&str> {
    match kind {
        Kind::PushNotification => t.push_token.as_deref(),
        _ => t.activity_push_token.as_deref(),
    }
}

/// `processSignedJob` -> `sendLiveActivity` / `sendPushNotification`.
pub async fn process(push: &Push, job_id: Uuid, payload: &Value) -> Result<(), JobError> {
    let job: Job = serde_json::from_value(payload.clone())
        .map_err(|_| JobError::retry("ApnsDeliveryJobQueuePayloadInvalid"))?;
    if job.job_id != job_id {
        return Err(JobError::retry("ApnsDeliveryJobQueuePayloadInvalid"));
    }
    let now = now_ms();
    verify(&job, now)?;
    let Some(creds) = &push.config.apns else {
        return Err(JobError::retry("ApnsNotConfigured"));
    };
    let mut conn = push.pool.acquire().await?;
    let user = job.target.user_id;
    let notification = job.notification.as_ref().map(sanitize_notification);
    let (machine, thread) = notification.as_ref().map_or((None, None), |n| {
        (Some(n.machine_id.as_str()), Some(n.thread_id.as_str()))
    });
    match claim_source_job(&mut conn, &job, machine, thread, now).await? {
        Claim::Completed => return Ok(()),
        Claim::InFlight => return Err(JobError::retry("ApnsDeliveryJobClaimInFlight")),
        Claim::Claimed => {}
    }
    let targets = devices::list_targets(&mut conn, user).await?;
    let Some(current) = targets.into_iter().find(|t| {
        t.device_id == job.target.device_id
            && expected_token(t, job.kind) == Some(&job.target.token)
    }) else {
        return skip(&mut conn, &job, "Stale APNs delivery job skipped.").await;
    };
    let prefs = current.preferences;
    let request = if job.kind == Kind::PushNotification {
        let n = notification.expect("verified");
        if let (Some(phase), Some(at)) = (n.phase, &n.updated_at) {
            let current_state = match agent_activity::get_for_user_thread(
                &mut conn,
                user,
                &n.machine_id,
                &n.thread_id,
            )
            .await
            {
                Ok(s) => s.is_some_and(|s| s.phase == phase && &s.updated_at == at),
                Err(e) => {
                    tracing::warn!(error = %e, "agent-activity state recheck failed; allowing queued delivery");
                    true
                }
            };
            if !current_state {
                return skip(&mut conn, &job, "Stale agent activity state skipped.").await;
            }
        }
        let allowed = match (n.phase, &n.updated_at) {
            (Some(phase), Some(at)) => should_alert_for_activity(phase, at, prefs.as_ref(), now),
            _ => prefs.is_some_and(|p| p.notifications_enabled),
        };
        if !allowed {
            return skip(
                &mut conn,
                &job,
                "Notification is disabled or no longer fresh.",
            )
            .await;
        }
        push_notification_request(&job.target.token, &n)
    } else {
        let aggregate = job.aggregate.as_ref().map(sanitize_aggregate);
        let alert = match (&job.alert, &aggregate) {
            (None, _) => None,
            (Some(_), Some(next)) if prefs.is_some_and(|p| p.notifications_enabled) => {
                let prev = current.last_aggregate.as_ref();
                alert_for_attention_transition(prev, next, prefs.as_ref())
                    .or_else(|| alert_for_newly_terminal(prev, next, prefs.as_ref(), now, true))
            }
            _ => None,
        };
        if let Some(a) = &aggregate {
            let rows = agent_activity::list_for_user(&mut conn, user).await;
            let current_rows = rows.as_ref().map_or(true, |states| {
                a.activities.iter().all(|r| {
                    states.iter().any(|s| {
                        s.machine_id == r.machine_id
                            && s.thread_id == r.thread_id
                            && s.phase == r.phase
                            && s.updated_at == r.updated_at
                    })
                })
            });
            if !current_rows {
                return skip(&mut conn, &job, "Stale agent activity state skipped.").await;
            }
        }
        // A contentless end must not retire a card that newer work now owns.
        if job.kind == Kind::LiveActivityEnd
            && aggregate.is_none()
            && prefs.is_none_or(|p| p.live_activities_enabled)
        {
            let has_content = match agent_activity::list_for_user(&mut conn, user).await {
                Ok(states) => make_aggregate(&states, None, now).is_some(),
                Err(_) => true,
            };
            if has_content {
                return skip(&mut conn, &job, "Stale APNs end job skipped.").await;
            }
        }
        let r = live_activity_request(
            &job.target.token,
            job.kind,
            aggregate.as_ref(),
            alert.as_ref(),
            now / 1000,
        );
        drop(conn);
        let o = send(
            push,
            &credentials_for(
                creds,
                current.bundle_id.as_deref(),
                current.aps_environment.as_deref(),
            ),
            &r,
            Some(job.job_id),
            now / 1000,
        )
        .await;
        let mut conn = push.pool.acquire().await?;
        if o.ok {
            devices::mark_delivery(
                &mut conn,
                user,
                &current.device_id,
                job.kind,
                aggregate.as_ref(),
                &crate::auth::dpop_proofs::iso_millis(now),
            )
            .await?;
        } else if is_permanent_token_failure(&o) {
            devices::invalidate_token(&mut conn, user, &current.device_id, job.kind).await?;
        }
        complete_source_job(&mut conn, &job, &o).await?;
        return Ok(());
    };
    drop(conn);
    let o = send(
        push,
        &credentials_for(
            creds,
            current.bundle_id.as_deref(),
            current.aps_environment.as_deref(),
        ),
        &request,
        Some(job.job_id),
        now / 1000,
    )
    .await;
    let mut conn = push.pool.acquire().await?;
    if is_permanent_token_failure(&o) {
        devices::invalidate_token(&mut conn, user, &current.device_id, Kind::PushNotification)
            .await?;
    }
    complete_source_job(&mut conn, &job, &o).await?;
    Ok(())
}
