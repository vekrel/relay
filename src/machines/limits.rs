// Managed tunnel cap: a port of T3 Code's `infra/relay/src/environments/ManagedTunnelLimits.ts`
// (MIT, Copyright (c) T3 Tools Inc.; see NOTICE). The provider checks it before reserving an
// allocation (`ManagedEndpointProvider.ts` stage `check-tunnel-limit`).
use sqlx::PgConnection;
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

/// A reserved allocation with no link row yet counts this long: the link in flight that holds it
/// (provisioning finishes within the 9 s request deadline), or one whose link step failed.
const UNLINKED_ALLOCATION_COUNTS_MS: i64 = 10 * 60_000;

/// `ensureCapacity`, run in the caller's transaction, which must also reserve the allocation: the
/// per-user advisory lock taken here holds until it commits, so parallel links for one user are
/// counted one after another. Allocations already held for this machine are not counted, so
/// re-linking a machine at the limit stays idempotent.
///
/// Vekrel: T3 counts only allocations joined to an active managed link, so parallel first links
/// (reserved, not yet linked) all pass its check. Here a recent allocation without any link row
/// counts too.
pub async fn ensure_capacity(
    conn: &mut PgConnection,
    user_id: Uuid,
    machine_id: &str,
) -> Result<(), LimitError> {
    sqlx::query(
        "SELECT pg_advisory_xact_lock(hashtextextended('managed-tunnel-limit:' || $1::text, 0))",
    )
    .bind(user_id)
    .execute(&mut *conn)
    .await
    .map_err(LimitError::Persistence)?;
    let max_tunnels: i32 = sqlx::query_scalar(
        "SELECT max_tunnels FROM relay_managed_tunnel_limits WHERE user_id = $1 LIMIT 1",
    )
    .bind(user_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(LimitError::Persistence)?
    .unwrap_or(DEFAULT_MANAGED_TUNNEL_LIMIT);
    let active_tunnels: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM relay_managed_endpoint_allocations a
         LEFT JOIN relay_machine_links l ON l.user_id = a.user_id AND l.machine_id = a.machine_id
         WHERE a.user_id = $1 AND a.machine_id <> $2
           AND ((l.user_id IS NOT NULL AND l.revoked_at IS NULL AND l.managed_tunnels_enabled)
             OR (l.user_id IS NULL AND a.updated_at > $3))",
    )
    .bind(user_id)
    .bind(machine_id)
    .bind(crate::auth::dpop_proofs::iso_millis(
        super::now_ms() - UNLINKED_ALLOCATION_COUNTS_MS,
    ))
    .fetch_one(&mut *conn)
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
