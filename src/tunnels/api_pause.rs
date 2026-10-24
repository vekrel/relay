// The shared Cloudflare API pause: a port of T3 Code's
// `infra/relay/src/environments/CloudflareApiPause.ts` (MIT, Copyright (c) T3 Tools Inc.; see
// NOTICE). Cloudflare's rate limit is per account, so a 429 seen by one replica pauses all of them.
// Both operations fail open (a pause that cannot be read or recorded must not block provisioning)
// and run on the pool, never inside a caller's transaction, so a rollback cannot drop the pause.
use sqlx::PgPool;

const CLOUDFLARE_API: &str = "cloudflare";

/// `pausedUntilMillis`: epoch ms until which calls are paused, or 0.
pub async fn paused_until_ms(pool: &PgPool) -> i64 {
    let read = sqlx::query_scalar(
        "SELECT paused_until_ms FROM relay_upstream_api_pauses WHERE api = $1 LIMIT 1",
    )
    .bind(CLOUDFLARE_API)
    .fetch_optional(pool)
    .await;
    match read {
        Ok(v) => v.unwrap_or(0),
        Err(e) => {
            tracing::warn!(error = %e, "could not read the shared Cloudflare API pause");
            0
        }
    }
}

/// `pauseUntil`: keeps the later of the stored and the new instant.
pub async fn pause_until(pool: &PgPool, until_ms: i64) {
    let write = sqlx::query(
        "INSERT INTO relay_upstream_api_pauses (api, paused_until_ms) VALUES ($1, $2)
         ON CONFLICT (api) DO UPDATE
         SET paused_until_ms = greatest(relay_upstream_api_pauses.paused_until_ms, excluded.paused_until_ms)",
    )
    .bind(CLOUDFLARE_API)
    .bind(until_ms)
    .execute(pool)
    .await;
    if let Err(e) = write {
        tracing::warn!(error = %e, "could not record the shared Cloudflare API pause");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[sqlx::test]
    async fn the_pause_only_moves_forward(pool: PgPool) {
        assert_eq!(paused_until_ms(&pool).await, 0);
        pause_until(&pool, 2_000).await;
        assert_eq!(paused_until_ms(&pool).await, 2_000);
        pause_until(&pool, 1_000).await;
        assert_eq!(paused_until_ms(&pool).await, 2_000);
        pause_until(&pool, 3_000).await;
        assert_eq!(paused_until_ms(&pool).await, 3_000);
    }
}
