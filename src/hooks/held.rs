// Which link a webhook URL names, the hold opt-in and wake. Port of T3 Code's
// `infra/relay/src/hooks/HeldHooks.ts` (MIT, Copyright (c) T3 Tools Inc.; see NOTICE).
use sqlx::{PgPool, Row};
use uuid::Uuid;

use super::{endpoint_key_for_tunnel_name, inbox};
use crate::machines::connector::validate_managed_endpoint;
use crate::machines::provider::allocation;
use crate::machines::{Relay, links};

/// `HookEndpoint`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookEndpoint {
    /// Always the allocation's own `https://<managed hostname>/`, never anything from a request.
    pub http_base_url: String,
    pub machine_id: String,
    pub hold_while_offline: bool,
}

/// `resolveEndpoint`: the active managed link that owns the endpoint key, if its allocation is ready
/// and its endpoint is the allocation's managed hostname in the tunnel zone. Vekrel: a disabled
/// user's machines get nothing.
pub async fn resolve_endpoint(
    relay: &Relay,
    endpoint_key: &str,
) -> Result<Option<HookEndpoint>, sqlx::Error> {
    if !super::is_endpoint_key(endpoint_key) {
        return Ok(None);
    }
    let owner = sqlx::query(
        "SELECT a.user_id, a.machine_id, a.tunnel_name
         FROM relay_managed_endpoint_allocations a
         JOIN users u ON u.id = a.user_id AND u.disabled_at IS NULL
         WHERE right(a.tunnel_name, 17) = '-' || $1",
    )
    .bind(endpoint_key)
    .fetch_optional(&relay.pool)
    .await?;
    let Some(owner) = owner else {
        return Ok(None);
    };
    let (user_id, machine_id): (Uuid, String) = (owner.get(0), owner.get(1));
    let Some(a) = allocation(&relay.pool, user_id, &machine_id).await? else {
        return Ok(None);
    };
    let mut conn = relay.pool.acquire().await?;
    let Some(link) = links::get_for_user(&mut conn, user_id, &machine_id).await? else {
        return Ok(None);
    };
    let hold: bool = sqlx::query_scalar(
        "SELECT hold_webhooks_while_offline FROM relay_machine_links
         WHERE user_id = $1 AND machine_id = $2 AND revoked_at IS NULL",
    )
    .bind(user_id)
    .bind(&machine_id)
    .fetch_optional(&mut *conn)
    .await?
    .unwrap_or(false);
    Ok(
        validate_managed_endpoint(&link, Some(&a), relay.tunnel_zone.as_deref())
            .ok()
            .map(|e| HookEndpoint {
                http_base_url: e.http_base_url,
                machine_id,
                hold_while_offline: hold,
            }),
    )
}

/// `ownEndpointKeys`: the endpoint keys of the managed links this machine key proved. The machine
/// id alone would also match other accounts' links of it.
pub async fn own_endpoint_keys(
    conn: &mut sqlx::PgConnection,
    machine_id: &str,
    machine_public_key: &str,
) -> Result<Vec<String>, sqlx::Error> {
    let names: Vec<String> = sqlx::query_scalar(
        "SELECT a.tunnel_name FROM relay_machine_links l
         JOIN relay_managed_endpoint_allocations a
           ON a.user_id = l.user_id AND a.machine_id = l.machine_id
         WHERE l.machine_id = $1 AND l.machine_public_key = $2 AND l.revoked_at IS NULL
           AND l.endpoint_provider_kind = 'cloudflare_tunnel'
         ORDER BY a.tunnel_name",
    )
    .bind(machine_id)
    .bind(machine_public_key)
    .fetch_all(conn)
    .await?;
    Ok(names
        .iter()
        .filter_map(|n| endpoint_key_for_tunnel_name(n))
        .collect())
}

/// `setHoldWhileOffline`: turning it off also drops what is held for the caller's endpoints.
pub async fn set_hold_while_offline(
    pool: &PgPool,
    machine_id: &str,
    machine_public_key: &str,
    hold: bool,
) -> Result<(), sqlx::Error> {
    // One transaction: a request deadline cancelling midway must not leave the hold off with
    // requests still held.
    let mut tx = pool.begin().await?;
    links::set_hold_webhooks_while_offline(&mut tx, machine_id, machine_public_key, hold).await?;
    if !hold {
        for key in own_endpoint_keys(&mut tx, machine_id, machine_public_key).await? {
            inbox::clear(&mut tx, &key).await?;
        }
    }
    tx.commit().await
}

/// `wake`: deliver the caller's held requests now. True when any are held.
pub async fn wake(
    relay: &Relay,
    machine_id: &str,
    machine_public_key: &str,
) -> Result<bool, sqlx::Error> {
    let mut pending = false;
    let keys = own_endpoint_keys(
        &mut *relay.pool.acquire().await?,
        machine_id,
        machine_public_key,
    )
    .await?;
    for key in keys {
        let Some(endpoint) = resolve_endpoint(relay, &key).await? else {
            continue;
        };
        if inbox::wake(&relay.pool, &key, &endpoint.http_base_url).await? {
            pending = true;
        }
    }
    Ok(pending)
}

/// The endpoint key an unlink tears down (`unlinkEnvironmentRecord`), read before revocation.
pub async fn endpoint_key_of(
    pool: &PgPool,
    user_id: Uuid,
    machine_id: &str,
) -> Result<Option<String>, sqlx::Error> {
    Ok(allocation(pool, user_id, machine_id)
        .await?
        .and_then(|a| endpoint_key_for_tunnel_name(&a.tunnel_name)))
}
