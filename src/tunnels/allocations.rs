// Managed endpoint allocations: a port of T3 Code's
// `infra/relay/src/environments/ManagedEndpointAllocations.ts` (MIT, Copyright (c) T3 Tools Inc.;
// see NOTICE). Every write bumps `generation` and matches the generation the caller loaded, so a
// stale writer (a release racing a fresh provision, an unlink racing a relink) changes nothing.
use sqlx::{PgConnection, PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

use crate::machines::provider::Allocation;
use crate::machines::{Origin, now_iso};

/// `MANAGED_ENDPOINT_ALLOCATION_LOOKUP_BATCH_SIZE`.
const LOOKUP_BATCH_SIZE: usize = 500;

const SELECTION: &str = "hostname, tunnel_id, tunnel_name, dns_record_id, ready_at, \
     tunnel_released_at, generation, origin::text";

fn from_row(r: &sqlx::postgres::PgRow) -> Allocation {
    let origin: Option<String> = r.get(7);
    Allocation {
        hostname: r.get(0),
        tunnel_id: r.get(1),
        tunnel_name: r.get(2),
        dns_record_id: r.get(3),
        ready_at: r.get(4),
        tunnel_released_at: r.get(5),
        generation: r.get(6),
        origin: origin.and_then(|o| serde_json::from_str(&o).ok()),
    }
}

fn origin_json(origin: &Origin) -> String {
    serde_json::to_string(origin).expect("origin serializes")
}

/// `get`.
pub async fn get(
    conn: &mut PgConnection,
    user: Uuid,
    machine_id: &str,
) -> Result<Option<Allocation>, sqlx::Error> {
    let row = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {SELECTION} FROM relay_managed_endpoint_allocations
         WHERE user_id = $1 AND machine_id = $2 LIMIT 1"
    )))
    .bind(user)
    .bind(machine_id)
    .fetch_optional(conn)
    .await?;
    Ok(row.as_ref().map(from_row))
}

/// `reserve`: the existing row when there is one (the hostname of a machine never changes).
pub async fn reserve(
    conn: &mut PgConnection,
    user: Uuid,
    machine_id: &str,
    hostname: &str,
    tunnel_name: &str,
) -> Result<Option<Allocation>, sqlx::Error> {
    let now = now_iso();
    let inserted = sqlx::query(sqlx::AssertSqlSafe(format!(
        "INSERT INTO relay_managed_endpoint_allocations
             (user_id, machine_id, hostname, tunnel_name, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $5) ON CONFLICT DO NOTHING RETURNING {SELECTION}"
    )))
    .bind(user)
    .bind(machine_id)
    .bind(hostname)
    .bind(tunnel_name)
    .bind(&now)
    .fetch_optional(&mut *conn)
    .await?;
    match inserted {
        Some(r) => Ok(Some(from_row(&r))),
        None => get(conn, user, machine_id).await,
    }
}

/// `recordTunnel`: a different tunnel clears readiness, origin and recovery registration (each is
/// per tunnel; a replacement must register again before the reaper may treat it as recoverable).
pub async fn record_tunnel(
    pool: &PgPool,
    user: Uuid,
    machine_id: &str,
    tunnel_id: &str,
    generation: i32,
) -> Result<Option<i32>, sqlx::Error> {
    sqlx::query_scalar(
        "UPDATE relay_managed_endpoint_allocations SET
             tunnel_id = $3,
             ready_at = CASE WHEN tunnel_id = $3 THEN ready_at ELSE NULL END,
             origin = CASE WHEN tunnel_id = $3 THEN origin ELSE NULL END,
             recovery_enabled_at = CASE WHEN tunnel_id = $3 THEN recovery_enabled_at ELSE NULL END,
             recovery_machine_public_key = CASE WHEN tunnel_id = $3 THEN recovery_machine_public_key ELSE NULL END,
             tunnel_released_at = NULL,
             updated_at = $5,
             generation = generation + 1
         WHERE user_id = $1 AND machine_id = $2 AND generation = $4
         RETURNING generation",
    )
    .bind(user)
    .bind(machine_id)
    .bind(tunnel_id)
    .bind(generation)
    .bind(now_iso())
    .fetch_optional(pool)
    .await
}

/// `recordDns`.
pub async fn record_dns(
    conn: &mut PgConnection,
    user: Uuid,
    machine_id: &str,
    dns_record_id: &str,
    tunnel_id: &str,
    generation: i32,
) -> Result<Option<i32>, sqlx::Error> {
    sqlx::query_scalar(
        "UPDATE relay_managed_endpoint_allocations
         SET dns_record_id = $3, updated_at = $6, generation = generation + 1
         WHERE user_id = $1 AND machine_id = $2 AND tunnel_id = $4 AND generation = $5
         RETURNING generation",
    )
    .bind(user)
    .bind(machine_id)
    .bind(dns_record_id)
    .bind(tunnel_id)
    .bind(generation)
    .bind(now_iso())
    .fetch_optional(conn)
    .await
}

/// `markReady`.
pub async fn mark_ready(
    conn: &mut PgConnection,
    user: Uuid,
    machine_id: &str,
    tunnel_id: &str,
    generation: i32,
    origin: &Origin,
) -> Result<bool, sqlx::Error> {
    let now = now_iso();
    Ok(sqlx::query(
        "UPDATE relay_managed_endpoint_allocations
         SET ready_at = $5, origin = $6::jsonb, updated_at = $5, generation = generation + 1
         WHERE user_id = $1 AND machine_id = $2 AND tunnel_id = $3 AND generation = $4",
    )
    .bind(user)
    .bind(machine_id)
    .bind(tunnel_id)
    .bind(generation)
    .bind(&now)
    .bind(origin_json(origin))
    .execute(conn)
    .await?
    .rows_affected()
        > 0)
}

/// `enableRecovery`: only for the tunnel and origin on record, while the same machine key holds an
/// active managed link (locked, so a concurrent unlink waits).
pub async fn enable_recovery(
    pool: &PgPool,
    user: Uuid,
    machine_id: &str,
    tunnel_id: &str,
    machine_public_key: &str,
    origin: &Origin,
) -> Result<bool, sqlx::Error> {
    let now = now_iso();
    Ok(sqlx::query(
        "UPDATE relay_managed_endpoint_allocations
         SET recovery_enabled_at = $6, recovery_machine_public_key = $4, updated_at = $6,
             generation = generation + 1
         WHERE user_id = $1 AND machine_id = $2 AND tunnel_id = $3 AND origin = $5::jsonb
           AND EXISTS (
             SELECT 1 FROM relay_machine_links
             WHERE user_id = $1 AND machine_id = $2 AND machine_public_key = $4
               AND endpoint_provider_kind = 'cloudflare_tunnel' AND revoked_at IS NULL
             FOR UPDATE)",
    )
    .bind(user)
    .bind(machine_id)
    .bind(tunnel_id)
    .bind(machine_public_key)
    .bind(origin_json(origin))
    .bind(&now)
    .execute(pool)
    .await?
    .rows_affected()
        > 0)
}

/// `ManagedEndpointTunnelAllocation`: an allocation, its owner, and whether its machine can
/// replace a deleted tunnel on its own (registered recovery with the key still linked).
#[derive(Debug, Clone)]
pub struct TunnelAllocation {
    pub user_id: Uuid,
    pub machine_id: String,
    pub allocation: Allocation,
    pub recovery_enabled: bool,
}

/// `listByTunnelNames`.
pub async fn list_by_tunnel_names(
    pool: &PgPool,
    names: &[String],
) -> Result<Vec<TunnelAllocation>, sqlx::Error> {
    let mut out = Vec::new();
    for batch in names.chunks(LOOKUP_BATCH_SIZE) {
        let rows = sqlx::query(
            "SELECT a.hostname, a.tunnel_id, a.tunnel_name, a.dns_record_id, a.ready_at,
                    a.tunnel_released_at, a.generation, a.origin::text,
                    a.user_id, a.machine_id,
                    a.recovery_enabled_at IS NOT NULL AND a.recovery_machine_public_key IS NOT NULL
                      AND a.recovery_machine_public_key = l.machine_public_key
             FROM relay_managed_endpoint_allocations a
             LEFT JOIN relay_machine_links l ON l.user_id = a.user_id
               AND l.machine_id = a.machine_id AND l.revoked_at IS NULL
             WHERE a.tunnel_name = ANY($1)",
        )
        .bind(batch)
        .fetch_all(pool)
        .await?;
        out.extend(rows.iter().map(|r| TunnelAllocation {
            user_id: r.get(8),
            machine_id: r.get(9),
            allocation: from_row(r),
            recovery_enabled: r.get::<Option<bool>, _>(10).unwrap_or(false),
        }));
    }
    Ok(out)
}

/// `claimRelease`: claims the right to delete the recorded tunnel while tunnel and generation still
/// match what the caller loaded; `mark_released` also stamps `tunnel_released_at`.
pub async fn claim_release(
    conn: &mut PgConnection,
    user: Uuid,
    machine_id: &str,
    tunnel_id: &str,
    generation: i32,
    mark_released: bool,
) -> Result<Option<i32>, sqlx::Error> {
    sqlx::query_scalar(
        "UPDATE relay_managed_endpoint_allocations
         SET updated_at = $5, generation = generation + 1,
             tunnel_released_at = CASE WHEN $6 THEN $5 ELSE tunnel_released_at END
         WHERE user_id = $1 AND machine_id = $2 AND tunnel_id = $3 AND generation = $4
         RETURNING generation",
    )
    .bind(user)
    .bind(machine_id)
    .bind(tunnel_id)
    .bind(generation)
    .bind(now_iso())
    .bind(mark_released)
    .fetch_optional(conn)
    .await
}

/// `withClaimedTunnel`: a transaction holding the row lock while tunnel and generation match, or
/// `None`. The caller does its Cloudflare calls and writes inside it, then commits; dropping it
/// rolls back.
pub async fn lock_claimed(
    pool: &PgPool,
    user: Uuid,
    machine_id: &str,
    tunnel_id: &str,
    generation: i32,
) -> Result<Option<Transaction<'static, Postgres>>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let locked: Option<i32> = sqlx::query_scalar(
        "SELECT generation FROM relay_managed_endpoint_allocations
         WHERE user_id = $1 AND machine_id = $2 AND tunnel_id = $3 AND generation = $4
         LIMIT 1 FOR UPDATE",
    )
    .bind(user)
    .bind(machine_id)
    .bind(tunnel_id)
    .bind(generation)
    .fetch_optional(&mut *tx)
    .await?;
    Ok(locked.map(|_| tx))
}

/// `claimDeprovision`.
pub async fn claim_deprovision(
    pool: &PgPool,
    user: Uuid,
    machine_id: &str,
    generation: i32,
) -> Result<Option<i32>, sqlx::Error> {
    sqlx::query_scalar(
        "UPDATE relay_managed_endpoint_allocations
         SET updated_at = $4, generation = generation + 1
         WHERE user_id = $1 AND machine_id = $2 AND generation = $3
         RETURNING generation",
    )
    .bind(user)
    .bind(machine_id)
    .bind(generation)
    .bind(now_iso())
    .fetch_optional(pool)
    .await
}

/// `removeClaimed`.
pub async fn remove_claimed(
    conn: &mut PgConnection,
    user: Uuid,
    machine_id: &str,
    generation: i32,
) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query(
        "DELETE FROM relay_managed_endpoint_allocations
         WHERE user_id = $1 AND machine_id = $2 AND generation = $3",
    )
    .bind(user)
    .bind(machine_id)
    .bind(generation)
    .execute(conn)
    .await?
    .rows_affected()
        > 0)
}
