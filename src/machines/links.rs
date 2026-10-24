// Machine links: a port of T3 Code's `infra/relay/src/environments/EnvironmentLinks.ts`
// (MIT, Copyright (c) T3 Tools Inc.; see NOTICE). Timestamps are ISO strings, as T3 stores them.
use serde::Serialize;
use sqlx::{PgConnection, PgPool, Row};
use uuid::Uuid;

use super::{Endpoint, now_iso};

/// `RelayClientMachineRecord` plus the key that proved the link.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkedMachine {
    pub machine_id: String,
    pub label: String,
    pub endpoint: Endpoint,
    pub linked_at: String,
    #[serde(skip)]
    pub machine_public_key: String,
    #[serde(skip)]
    pub managed_tunnels_enabled: bool,
}

pub struct UpsertInput<'a> {
    pub user_id: Uuid,
    pub machine_id: &'a str,
    pub label: &'a str,
    pub machine_public_key: &'a str,
    pub endpoint: &'a Endpoint,
    pub notifications_enabled: bool,
    pub live_activities_enabled: bool,
    pub managed_tunnels_enabled: bool,
    pub device_id: Option<&'a str>,
}

fn record(row: &sqlx::postgres::PgRow) -> LinkedMachine {
    let machine_id: String = row.get("machine_id");
    let label: String = row.get("machine_label");
    LinkedMachine {
        label: if label.trim().is_empty() {
            machine_id.clone()
        } else {
            label
        },
        machine_id,
        endpoint: Endpoint {
            http_base_url: row.get("endpoint_http_base_url"),
            ws_base_url: row.get("endpoint_ws_base_url"),
            provider_kind: row.get("endpoint_provider_kind"),
        },
        linked_at: row.get("created_at"),
        machine_public_key: row.get("machine_public_key"),
        managed_tunnels_enabled: row.get("managed_tunnels_enabled"),
    }
}

/// `upsert`. The webhook-hold opt-in carries over from the machine's other active links proven by
/// the same key only: a machine id is public, so anyone can link one.
pub async fn upsert(conn: &mut PgConnection, i: &UpsertInput<'_>) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO relay_machine_links (user_id, machine_id, hold_webhooks_while_offline,
            machine_label, machine_public_key, endpoint_http_base_url, endpoint_ws_base_url,
            endpoint_provider_kind, notifications_enabled, live_activities_enabled,
            managed_tunnels_enabled, created_by_device_id, revoked_at, created_at, updated_at)
         VALUES ($1, $2, EXISTS (SELECT 1 FROM relay_machine_links AS other
                   WHERE other.machine_id = $2 AND other.machine_public_key = $4
                     AND other.revoked_at IS NULL AND other.hold_webhooks_while_offline),
                 $3, $4, $5, $6, $7, $8, $9, $10, $11, NULL, $12, $12)
         ON CONFLICT (user_id, machine_id) DO UPDATE SET
            machine_public_key = EXCLUDED.machine_public_key,
            machine_label = EXCLUDED.machine_label,
            endpoint_http_base_url = EXCLUDED.endpoint_http_base_url,
            endpoint_ws_base_url = EXCLUDED.endpoint_ws_base_url,
            endpoint_provider_kind = EXCLUDED.endpoint_provider_kind,
            notifications_enabled = EXCLUDED.notifications_enabled,
            live_activities_enabled = EXCLUDED.live_activities_enabled,
            managed_tunnels_enabled = EXCLUDED.managed_tunnels_enabled,
            created_by_device_id = EXCLUDED.created_by_device_id,
            revoked_at = NULL,
            updated_at = EXCLUDED.updated_at,
            hold_webhooks_while_offline = EXCLUDED.hold_webhooks_while_offline",
    )
    .bind(i.user_id)
    .bind(i.machine_id)
    .bind(i.label)
    .bind(i.machine_public_key)
    .bind(&i.endpoint.http_base_url)
    .bind(&i.endpoint.ws_base_url)
    .bind(&i.endpoint.provider_kind)
    .bind(i.notifications_enabled)
    .bind(i.live_activities_enabled)
    .bind(i.managed_tunnels_enabled)
    .bind(i.device_id)
    .bind(now_iso())
    .execute(conn)
    .await?;
    Ok(())
}

/// `listForUser` (active links; oldest first, T3 leaves the order to the database).
pub async fn list_for_user(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Vec<LinkedMachine>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT machine_id, machine_label, machine_public_key, endpoint_http_base_url,
                endpoint_ws_base_url, endpoint_provider_kind, created_at, managed_tunnels_enabled
         FROM relay_machine_links
         WHERE user_id = $1 AND revoked_at IS NULL ORDER BY created_at, machine_id",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(rows.iter().map(record).collect())
}

/// `getForUser`: the user's active link to this machine.
pub async fn get_for_user(
    conn: &mut PgConnection,
    user_id: Uuid,
    machine_id: &str,
) -> Result<Option<LinkedMachine>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT machine_id, machine_label, machine_public_key, endpoint_http_base_url,
                endpoint_ws_base_url, endpoint_provider_kind, created_at, managed_tunnels_enabled
         FROM relay_machine_links
         WHERE user_id = $1 AND machine_id = $2 AND revoked_at IS NULL LIMIT 1",
    )
    .bind(user_id)
    .bind(machine_id)
    .fetch_optional(conn)
    .await?;
    Ok(row.as_ref().map(record))
}

/// `revokeForUser`: true when an active link was revoked.
pub async fn revoke_for_user(
    conn: &mut PgConnection,
    user_id: Uuid,
    machine_id: &str,
) -> Result<bool, sqlx::Error> {
    let now = now_iso();
    Ok(sqlx::query(
        "UPDATE relay_machine_links SET revoked_at = $3, updated_at = $3
         WHERE user_id = $1 AND machine_id = $2 AND revoked_at IS NULL",
    )
    .bind(user_id)
    .bind(machine_id)
    .bind(now)
    .execute(conn)
    .await?
    .rows_affected()
        > 0)
}

/// `setHoldWebhooksWhileOffline`: every active link proven by this key.
pub async fn set_hold_webhooks_while_offline(
    conn: &mut PgConnection,
    machine_id: &str,
    machine_public_key: &str,
    hold: bool,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE relay_machine_links SET hold_webhooks_while_offline = $3
         WHERE machine_id = $1 AND machine_public_key = $2 AND revoked_at IS NULL",
    )
    .bind(machine_id)
    .bind(machine_public_key)
    .bind(hold)
    .execute(conn)
    .await?;
    Ok(())
}
