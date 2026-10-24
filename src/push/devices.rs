// Mobile devices and Live Activity tokens: a port of T3 Code's
// `infra/relay/src/agentActivity/Devices.ts` and `LiveActivities.ts` (MIT, Copyright (c) T3 Tools
// Inc.; see NOTICE). Timestamps are ISO strings, as T3 stores them.
use serde::Deserialize;
use serde_json::Value;
use sqlx::{PgConnection, Row};
use uuid::Uuid;

use super::payloads::{Aggregate, Preferences, opt_tns as optional_tns, tns};
use crate::http::errors::int;
use crate::machines::now_iso;

/// `Schema.optional(X)`: the key may be absent, `null` is refused.
fn present<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Value>, D::Error> {
    match Value::deserialize(d)? {
        Value::Null => Err(serde::de::Error::custom("null")),
        v => Ok(Some(v)),
    }
}

/// `RelayDeviceRegistrationRequest` (decode only; `valid` applies the schema's checks).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Registration {
    #[serde(deserialize_with = "tns")]
    pub device_id: String,
    #[serde(deserialize_with = "tns")]
    pub label: String,
    pub platform: Platform,
    #[serde(default, deserialize_with = "present")]
    ios_major_version: Option<Value>,
    #[serde(default, deserialize_with = "present")]
    android_api_level: Option<Value>,
    #[serde(default, deserialize_with = "optional_tns")]
    pub app_version: Option<String>,
    #[serde(default, deserialize_with = "optional_tns")]
    pub bundle_id: Option<String>,
    #[serde(default, deserialize_with = "present")]
    aps_environment: Option<Value>,
    #[serde(default, deserialize_with = "optional_tns")]
    pub push_token: Option<String>,
    #[serde(default, deserialize_with = "optional_tns")]
    pub push_to_start_token: Option<String>,
    pub preferences: Preferences,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    Ios,
    Android,
}

/// The decoded, checked registration.
pub struct Device {
    pub r: Registration,
    pub ios_major_version: Option<i64>,
    pub android_api_level: Option<i64>,
    pub aps_environment: Option<&'static str>,
}

impl Registration {
    /// `Schema.Int` minimums and the platform filter of `RelayDeviceRegistrationRequest`.
    pub fn check(self) -> Option<Device> {
        let at_least = |v: &Option<Value>, min: i64| -> Option<Option<i64>> {
            match v {
                None => Some(None),
                Some(v) => int(v).filter(|i| *i >= min).map(Some),
            }
        };
        let ios = at_least(&self.ios_major_version, 18)?;
        let android = at_least(&self.android_api_level, 24)?;
        let aps = match &self.aps_environment {
            None => None,
            Some(Value::String(s)) if s == "sandbox" => Some("sandbox"),
            Some(Value::String(s)) if s == "production" => Some("production"),
            Some(_) => return None,
        };
        let ok = match self.platform {
            Platform::Ios => ios.is_some(),
            Platform::Android => {
                android.is_some()
                    && self.ios_major_version.is_none()
                    && aps.is_none()
                    && self.push_to_start_token.is_none()
            }
        };
        ok.then_some(Device {
            r: self,
            ios_major_version: ios,
            android_api_level: android,
            aps_environment: aps,
        })
    }
}

/// `Devices.register`: a token moves to the device that registers it last.
pub async fn register(conn: &mut PgConnection, user: Uuid, d: &Device) -> Result<(), sqlx::Error> {
    let now = now_iso();
    let r = &d.r;
    if let Some(t) = &r.push_token {
        sqlx::query("UPDATE relay_mobile_devices SET push_token = NULL, updated_at = $2 WHERE push_token = $1")
            .bind(t)
            .bind(&now)
            .execute(&mut *conn)
            .await?;
    }
    if let Some(t) = &r.push_to_start_token {
        sqlx::query("UPDATE relay_mobile_devices SET push_to_start_token = NULL, updated_at = $2 WHERE push_to_start_token = $1")
            .bind(t)
            .bind(&now)
            .execute(&mut *conn)
            .await?;
    }
    let platform = match r.platform {
        Platform::Ios => "ios",
        Platform::Android => "android",
    };
    // Routing from newer app builds survives an older build re-registering without it.
    sqlx::query(
        "INSERT INTO relay_mobile_devices (user_id, device_id, label, platform, ios_major_version,
            android_api_level, app_version, bundle_id, aps_environment, push_token,
            push_to_start_token, preferences_json, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $13)
         ON CONFLICT (user_id, device_id) DO UPDATE SET
            platform = EXCLUDED.platform,
            label = EXCLUDED.label,
            ios_major_version = EXCLUDED.ios_major_version,
            android_api_level = EXCLUDED.android_api_level,
            app_version = EXCLUDED.app_version,
            bundle_id = coalesce(EXCLUDED.bundle_id, relay_mobile_devices.bundle_id),
            aps_environment = coalesce(EXCLUDED.aps_environment, relay_mobile_devices.aps_environment),
            push_token = coalesce(EXCLUDED.push_token, relay_mobile_devices.push_token),
            push_to_start_token = coalesce(EXCLUDED.push_to_start_token, relay_mobile_devices.push_to_start_token),
            preferences_json = EXCLUDED.preferences_json,
            updated_at = EXCLUDED.updated_at",
    )
    .bind(user)
    .bind(&r.device_id)
    .bind(&r.label)
    .bind(platform)
    .bind(d.ios_major_version.map(|v| v as i32))
    .bind(d.android_api_level.map(|v| v as i32))
    .bind(&r.app_version)
    .bind(&r.bundle_id)
    .bind(d.aps_environment)
    .bind(&r.push_token)
    .bind(&r.push_to_start_token)
    .bind(serde_json::to_value(r.preferences).expect("preferences serialize"))
    .bind(&now)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// `Devices.unregister`.
pub async fn unregister(
    conn: &mut PgConnection,
    user: Uuid,
    device: &str,
) -> Result<(), sqlx::Error> {
    for sql in [
        "DELETE FROM relay_live_activities WHERE user_id = $1 AND device_id = $2",
        "DELETE FROM relay_mobile_devices WHERE user_id = $1 AND device_id = $2",
    ] {
        sqlx::query(sql)
            .bind(user)
            .bind(device)
            .execute(&mut *conn)
            .await?;
    }
    Ok(())
}

/// `LiveActivities.register`. Re-registering the current card's token keeps its arming time, so
/// the arming grace cannot swallow the end a replay owes a card whose work is gone.
pub async fn register_live_activity(
    conn: &mut PgConnection,
    user: Uuid,
    device: &str,
    token: &str,
) -> Result<(), sqlx::Error> {
    let now = now_iso();
    let current: Option<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT activity_push_token, remote_started_at FROM relay_live_activities
         WHERE user_id = $1 AND device_id = $2",
    )
    .bind(user)
    .bind(device)
    .fetch_optional(&mut *conn)
    .await?;
    let armed_at = current
        .filter(|(t, _)| t.as_deref() == Some(token))
        .and_then(|(_, at)| at)
        .unwrap_or_else(|| now.clone());
    sqlx::query(
        "UPDATE relay_live_activities SET activity_push_token = NULL, remote_start_queued_at = NULL,
            remote_started_at = NULL, ended_at = $2, updated_at = $2
         WHERE activity_push_token = $1",
    )
    .bind(token)
    .bind(&now)
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "INSERT INTO relay_live_activities (user_id, device_id, activity_push_token,
            remote_start_queued_at, remote_started_at, ended_at, last_aggregate_json,
            last_live_activity_delivery_at, created_at, updated_at)
         VALUES ($1, $2, $3, NULL, $4, NULL, NULL, NULL, $5, $5)
         ON CONFLICT (user_id, device_id) DO UPDATE SET
            activity_push_token = EXCLUDED.activity_push_token, remote_start_queued_at = NULL,
            remote_started_at = EXCLUDED.remote_started_at, ended_at = NULL,
            last_aggregate_json = NULL, last_live_activity_delivery_at = NULL,
            updated_at = EXCLUDED.updated_at",
    )
    .bind(user)
    .bind(device)
    .bind(token)
    .bind(&armed_at)
    .bind(&now)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// `LiveActivities.TargetRow`: a device and its Live Activity state.
#[derive(Debug, Clone)]
pub struct Target {
    pub user_id: Uuid,
    pub device_id: String,
    pub platform: String,
    pub bundle_id: Option<String>,
    pub aps_environment: Option<String>,
    pub push_token: Option<String>,
    /// `parsePreferences`: `None` when the stored JSON does not decode.
    pub preferences: Option<Preferences>,
    pub activity_push_token: Option<String>,
    pub remote_started_at: Option<String>,
    pub last_aggregate: Option<Aggregate>,
    pub last_live_activity_delivery_at: Option<String>,
}

/// `LiveActivities.listTargets`, oldest device first (T3 leaves the order to the database).
pub async fn list_targets(conn: &mut PgConnection, user: Uuid) -> Result<Vec<Target>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT d.user_id, d.device_id, d.platform, d.bundle_id, d.aps_environment, d.push_token,
                d.preferences_json, l.activity_push_token,
                l.remote_started_at, l.last_aggregate_json, l.last_live_activity_delivery_at
         FROM relay_mobile_devices d
         LEFT JOIN relay_live_activities l ON l.user_id = d.user_id AND l.device_id = d.device_id
         WHERE d.user_id = $1 ORDER BY d.created_at, d.device_id",
    )
    .bind(user)
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows
        .iter()
        .map(|r| Target {
            user_id: r.get("user_id"),
            device_id: r.get("device_id"),
            platform: r.get("platform"),
            bundle_id: r.get("bundle_id"),
            aps_environment: r.get("aps_environment"),
            push_token: r.get("push_token"),
            preferences: serde_json::from_value(r.get("preferences_json")).ok(),
            activity_push_token: r.get("activity_push_token"),
            remote_started_at: r.get("remote_started_at"),
            last_aggregate: r
                .get::<Option<Value>, _>("last_aggregate_json")
                .and_then(|v| serde_json::from_value(v).ok()),
            last_live_activity_delivery_at: r.get("last_live_activity_delivery_at"),
        })
        .collect())
}

/// `LiveActivities.listIdleArmedTargets`: (user, device) of cards nothing was delivered to since.
pub async fn list_idle_armed_targets(
    conn: &mut PgConnection,
    delivered_before: &str,
) -> Result<Vec<(Uuid, String)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT user_id, device_id FROM relay_live_activities
         WHERE activity_push_token IS NOT NULL
           AND coalesce(last_live_activity_delivery_at, remote_started_at, updated_at) < $1",
    )
    .bind(delivered_before)
    .fetch_all(conn)
    .await
}

/// Delivery kinds (`RelayDeliveryKind`). T3's chooser never picks `live_activity_start`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    LiveActivityUpdate,
    LiveActivityEnd,
    PushNotification,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LiveActivityUpdate => "live_activity_update",
            Self::LiveActivityEnd => "live_activity_end",
            Self::PushNotification => "push_notification",
        }
    }
}

/// `LiveActivities.markDelivery` for an update or end.
pub async fn mark_delivery(
    conn: &mut PgConnection,
    user: Uuid,
    device: &str,
    kind: Kind,
    aggregate: Option<&Aggregate>,
    delivered_at: &str,
) -> Result<(), sqlx::Error> {
    let json = aggregate.map(|a| serde_json::to_value(a).expect("aggregate serializes"));
    let end = kind == Kind::LiveActivityEnd;
    // A delivered end retires the card's update token; a plain update keeps it.
    sqlx::query(
        "INSERT INTO relay_live_activities (user_id, device_id, remote_started_at,
            remote_start_queued_at, ended_at, last_aggregate_json, last_live_activity_delivery_at,
            created_at, updated_at)
         VALUES ($1, $2, NULL, NULL, CASE WHEN $3 THEN $5 END, $4, $5, $5, $5)
         ON CONFLICT (user_id, device_id) DO UPDATE SET
            activity_push_token = CASE WHEN $6 THEN relay_live_activities.activity_push_token END,
            remote_started_at = coalesce(relay_live_activities.remote_started_at, EXCLUDED.remote_started_at),
            remote_start_queued_at = NULL,
            ended_at = CASE WHEN $3 THEN $5 ELSE relay_live_activities.ended_at END,
            last_aggregate_json = $4,
            last_live_activity_delivery_at = $5,
            updated_at = $5",
    )
    .bind(user)
    .bind(device)
    .bind(end)
    .bind(json)
    .bind(delivered_at)
    .bind(kind == Kind::LiveActivityUpdate)
    .execute(conn)
    .await?;
    Ok(())
}

/// `LiveActivities.invalidateDeliveryToken`: APNs or FCM said the token is gone, so it is
/// cleared; the device record stays (T3).
pub async fn invalidate_token(
    conn: &mut PgConnection,
    user: Uuid,
    device: &str,
    kind: Kind,
) -> Result<(), sqlx::Error> {
    let now = now_iso();
    let sql = match kind {
        Kind::PushNotification => {
            "UPDATE relay_mobile_devices SET push_token = NULL, updated_at = $3
             WHERE user_id = $1 AND device_id = $2"
        }
        _ => {
            "UPDATE relay_live_activities SET activity_push_token = NULL,
                remote_start_queued_at = NULL, remote_started_at = NULL, ended_at = $3,
                updated_at = $3
             WHERE user_id = $1 AND device_id = $2"
        }
    };
    sqlx::query(sql)
        .bind(user)
        .bind(device)
        .bind(now)
        .execute(conn)
        .await?;
    Ok(())
}
