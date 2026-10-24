// Managed tunnel cap: a port of T3 Code's `infra/relay/src/environments/ManagedTunnelLimits.ts`
// (MIT, Copyright (c) T3 Tools Inc.; see NOTICE). The provider checks it before reserving an
// allocation (`ManagedEndpointProvider.ts` stage `check-tunnel-limit`).
use sqlx::PgPool;
use uuid::Uuid;

/// `DEFAULT_MANAGED_TUNNEL_LIMIT`.
pub const DEFAULT_MANAGED_TUNNEL_LIMIT: i32 = 3;

#[derive(Debug)]
pub enum LimitError {
    /// `ManagedTunnelLimitExceeded`.
    Exceeded {
        max_tunnels: i32,
        active_tunnels: i64,
    },
    /// `ManagedTunnelLimitPersistenceError`.
    Persistence(sqlx::Error),
}

/// `ensureCapacity`. Allocations already held for this machine are not counted, so re-linking a
/// machine the user already has a tunnel for stays idempotent at the limit.
pub async fn ensure_capacity(
    pool: &PgPool,
    user_id: Uuid,
    machine_id: &str,
) -> Result<(), LimitError> {
    let max_tunnels: i32 = sqlx::query_scalar(
        "SELECT max_tunnels FROM relay_managed_tunnel_limits WHERE user_id = $1 LIMIT 1",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .map_err(LimitError::Persistence)?
    .unwrap_or(DEFAULT_MANAGED_TUNNEL_LIMIT);
    let active_tunnels: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM relay_managed_endpoint_allocations a
         JOIN relay_machine_links l ON l.user_id = a.user_id AND l.machine_id = a.machine_id
         WHERE a.user_id = $1 AND a.machine_id <> $2
           AND l.revoked_at IS NULL AND l.managed_tunnels_enabled",
    )
    .bind(user_id)
    .bind(machine_id)
    .fetch_one(pool)
    .await
    .map_err(LimitError::Persistence)?;
    if active_tunnels >= i64::from(max_tunnels) {
        return Err(LimitError::Exceeded {
            max_tunnels,
            active_tunnels,
        });
    }
    Ok(())
}
