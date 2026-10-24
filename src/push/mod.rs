// Push notifications (plan 6A Task 12): APNs alerts and Live Activities, FCM for Android. Ports
// T3 Code's `infra/relay/src/agentActivity/*` (MIT, Copyright (c) T3 Tools Inc.; see NOTICE). T3's
// Cloudflare Queues become `relay_push_jobs` rows worked by background tasks in this process.
use std::sync::Arc;
use std::time::Duration;

use sqlx::PgPool;

pub mod agent_activity;
pub mod apns;
pub mod config;
pub mod devices;
pub mod fcm;
pub mod jobs;
pub mod payloads;
#[cfg(test)]
mod tests;

pub use config::PushConfig;

pub struct Push {
    pub pool: PgPool,
    pub config: PushConfig,
    /// APNs speaks HTTP/2 only.
    pub apns_http: reqwest::Client,
    pub http: reqwest::Client,
    pub apns_tokens: apns::TokenCache,
    pub fcm_token: fcm::AccessToken,
}

impl Push {
    pub fn new(pool: PgPool, config: PushConfig) -> Self {
        Self {
            pool,
            config,
            apns_http: reqwest::Client::builder()
                .http2_prior_knowledge()
                .build()
                .expect("HTTP client builds"),
            http: reqwest::Client::new(),
            apns_tokens: apns::TokenCache::default(),
            fcm_token: fcm::AccessToken::default(),
        }
    }
}

/// Starts the delivery worker and the 5-minute housekeeping (T3's cron).
pub fn spawn(push: Arc<Push>) {
    if push.config.apns.is_none() {
        tracing::info!("APNs is not configured; iOS push is off");
    } else if !push.config.apns_enabled {
        tracing::warn!("APNS_ENABLED=false: APNs jobs are queued but not delivered");
    }
    if push.config.fcm.is_none() {
        tracing::info!("FCM is not configured; Android push is off");
    } else if !push.config.fcm_enabled {
        tracing::warn!("FCM_ENABLED=false: FCM jobs are queued but not delivered");
    }
    tokio::spawn(jobs::work(push.clone()));
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(300));
        loop {
            tick.tick().await;
            if let Err(e) = agent_activity::maintain(&push).await {
                tracing::warn!(error = %e, "push housekeeping failed");
            }
        }
    });
}

/// `admin push-test <email>`: one alert to every phone of the account, sent now (no job), and
/// APNs/FCM's answer per device. Ids only, as every relay push.
pub async fn push_test(push: &Push, email: &str) -> Result<String, String> {
    use payloads::Notification;
    let db = |e: sqlx::Error| e.to_string();
    let user: uuid::Uuid = sqlx::query_scalar("SELECT id FROM users WHERE email = $1::citext")
        .bind(email)
        .fetch_optional(&push.pool)
        .await
        .map_err(db)?
        .ok_or_else(|| format!("no user with email {email}"))?;
    let mut conn = push.pool.acquire().await.map_err(db)?;
    let targets = devices::list_targets(&mut conn, user).await.map_err(db)?;
    drop(conn);
    let (title, body) = ("Vekrel", "Test notification from the relay.");
    let now = crate::machines::now_ms();
    let mut out = Vec::new();
    for t in &targets {
        let Some(token) = &t.push_token else {
            out.push(format!("{} {}: no push token", t.platform, t.device_id));
            continue;
        };
        let line = if t.platform == "android" {
            let Some(package) = t
                .bundle_id
                .as_deref()
                .filter(|p| push.config.app_allowed("android", Some(p)))
            else {
                out.push(format!(
                    "android {}: package not in FCM_PACKAGE_NAMES",
                    t.device_id
                ));
                continue;
            };
            let mut data = serde_json::Map::new();
            data.insert("t3_kind".into(), "agent_activity".into());
            data.insert("device_id".into(), t.device_id.clone().into());
            data.insert("user_id".into(), crate::machines::wire_user_id(user).into());
            data.insert("updated_at".into(), now.to_string().into());
            data.extend(payloads::android_activity_data(None));
            data.insert(
                "alert_id".into(),
                uuid::Uuid::new_v4().simple().to_string().into(),
            );
            data.insert("alert_title".into(), title.into());
            data.insert("alert_body".into(), body.into());
            data.insert("alert_path".into(), "/".into());
            match fcm::send(push, token, package, &data, true).await {
                Ok(false) => "FCM accepted".into(),
                Ok(true) => "FCM: UNREGISTERED".into(),
                Err(e) => format!("FCM failed: {e:?}"),
            }
        } else {
            let Some(c) = &push.config.apns else {
                out.push(format!("ios {}: APNs is not configured", t.device_id));
                continue;
            };
            let n = Notification {
                title: title.into(),
                body: body.into(),
                machine_id: String::new(),
                thread_id: String::new(),
                deep_link: "/".into(),
                phase: None,
                updated_at: None,
            };
            let r = apns::push_notification_request(token, &n);
            let c = apns::credentials_for(c, t.bundle_id.as_deref(), t.aps_environment.as_deref());
            let o = apns::send(push, &c, &r, Some(uuid::Uuid::new_v4()), now / 1000).await;
            format!("APNs {} {}", o.status, o.reason.unwrap_or_default())
        };
        out.push(format!("{} {}: {line}", t.platform, t.device_id));
    }
    if out.is_empty() {
        return Err(format!("{email} has no registered phones"));
    }
    Ok(out.join("\n"))
}
