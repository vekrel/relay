// The 5-minute maintenance pass: T3 Code's relay cron `*/5 * * * *` (`infra/relay/src/worker.ts`;
// MIT, Copyright (c) T3 Tools Inc.; see NOTICE) as a tokio interval. Each pass runs under a
// transaction-scoped advisory lock, so with several replicas exactly one does the work; the others
// skip that tick. It prunes expired relay state and sweeps idle tunnels.
use std::sync::Arc;
use std::time::Duration;

use sqlx::PgPool;

use crate::config::CleanupConfig;
use crate::machines::now_ms;
use crate::tunnels::provider::CloudflareTunnels;
use crate::tunnels::reaper;

pub const INTERVAL: Duration = Duration::from_secs(5 * 60);
/// `reaper.sweep.pipe(Effect.timeout("2 minutes"))`.
const SWEEP_TIMEOUT: Duration = Duration::from_secs(120);
/// `pg_try_advisory_xact_lock` key ("vekrel-relay-cron").
const LOCK_KEY: i64 = 0x7665_6b72_656c_6372;

/// Rows a pass removed, per table.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Pruned {
    pub dpop_proofs: u64,
    pub auth_requests: u64,
    pub auth_codes: u64,
    pub magic_links: u64,
    pub device_codes: u64,
    pub refresh_tokens: u64,
    pub rate_limits: u64,
}

/// Expired rows of our own tables (T3 had Clerk for accounts). Everything is kept a day past its
/// expiry so a late replay still finds its row and is refused as reused, not as unknown.
/// Refresh tokens go a whole family at a time once every row of the family has expired: a revoked
/// row must stay while its family has a live one, or reuse could no longer revoke the family.
// shortcut: rate-limit rows go one day after their window opened; the longest window is 1 h
// (magic links). Raise the margin if a limit ever gets a longer window.
pub async fn prune(pool: &PgPool) -> Result<Pruned, sqlx::Error> {
    let del = |sql: &'static str| async move {
        Ok::<_, sqlx::Error>(sqlx::query(sql).execute(pool).await?.rows_affected())
    };
    Ok(Pruned {
        dpop_proofs: crate::auth::dpop_proofs::prune_expired(pool, now_ms()).await?,
        // Cascades to the request's magic links.
        auth_requests: del("DELETE FROM auth_requests WHERE expires_at < now() - interval '1 day'")
            .await?,
        auth_codes: del("DELETE FROM auth_codes WHERE expires_at < now() - interval '1 day'")
            .await?,
        magic_links: del("DELETE FROM magic_links WHERE expires_at < now() - interval '1 day'")
            .await?,
        device_codes: del("DELETE FROM device_codes WHERE expires_at < now() - interval '1 day'")
            .await?,
        refresh_tokens: del("DELETE FROM refresh_tokens WHERE family_id IN (
               SELECT family_id FROM refresh_tokens GROUP BY family_id
               HAVING max(expires_at) < now() - interval '1 day')")
        .await?,
        rate_limits: del(
            "DELETE FROM relay_rate_limits WHERE window_start < now() - interval '1 day'",
        )
        .await?,
    })
}

/// One pass. `false` when another replica holds the lock (nothing was done).
pub async fn run_once(
    pool: &PgPool,
    tunnels: Option<&CloudflareTunnels>,
    cleanup: CleanupConfig,
) -> Result<bool, sqlx::Error> {
    let mut lock = pool.begin().await?;
    let held: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1)")
        .bind(LOCK_KEY)
        .fetch_one(&mut *lock)
        .await?;
    if !held {
        tracing::info!("maintenance pass skipped: another replica holds the lock");
        return Ok(false);
    }
    match prune(pool).await {
        Ok(p) => tracing::info!(?p, "pruned expired relay state"),
        Err(e) => tracing::warn!(error = %e, "failed to prune expired relay state"),
    }
    if let Some(t) = tunnels {
        match tokio::time::timeout(SWEEP_TIMEOUT, reaper::sweep(t, cleanup)).await {
            Ok(Ok(r)) if r.scanned > 0 => {
                tracing::info!(result = ?r, "finished managed tunnel cleanup")
            }
            Ok(Ok(_)) => {}
            Ok(Err(e)) => tracing::warn!(error = %e, "failed to clean up inactive managed tunnels"),
            Err(_) => tracing::warn!("managed tunnel cleanup timed out"),
        }
    }
    lock.commit().await?;
    Ok(true)
}

/// Runs a pass every 5 minutes for the life of the process.
pub fn spawn(pool: PgPool, tunnels: Option<Arc<CloudflareTunnels>>, cleanup: CleanupConfig) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            if let Err(e) = run_once(&pool, tunnels.as_deref(), cleanup).await {
                tracing::warn!(error = %e, "maintenance pass failed");
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn exec(pool: &PgPool, sql: &str) {
        sqlx::query(sqlx::AssertSqlSafe(sql.to_owned()))
            .execute(pool)
            .await
            .unwrap();
    }

    async fn count(pool: &PgPool, sql: &str) -> i64 {
        sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_owned()))
            .fetch_one(pool)
            .await
            .unwrap()
    }

    #[sqlx::test]
    async fn prune_drops_expired_state_but_keeps_revoked_tokens_of_live_families(pool: PgPool) {
        let old = "now() - interval '2 days'";
        let live = "now() + interval '1 hour'";
        exec(&pool, "INSERT INTO users (id, email) VALUES ('00000000-0000-0000-0000-000000000001', 'a@x.test')").await;
        let u = "'00000000-0000-0000-0000-000000000001'";
        for (id, exp) in [("old", old), ("live", live)] {
            exec(&pool, &format!("INSERT INTO auth_requests (id, client_id, redirect_uri, code_challenge, expires_at) VALUES ('{id}', 'c', 'r', 'x', {exp})")).await;
            exec(&pool, &format!("INSERT INTO auth_codes (code_hash, user_id, client_id, redirect_uri, code_challenge, expires_at) VALUES ('{id}', {u}, 'c', 'r', 'x', {exp})")).await;
            exec(&pool, &format!("INSERT INTO magic_links (token_hash, email, code_hash, expires_at) VALUES ('{id}', 'a@x.test', 'h', {exp})")).await;
            exec(&pool, &format!("INSERT INTO device_codes (device_code_hash, user_code, client_id, expires_at) VALUES ('{id}', '{id}', 'c', {exp})")).await;
            exec(&pool, &format!("INSERT INTO relay_rate_limits (key, window_start, count) VALUES ('{id}', {exp} - interval '1 hour', 1)")).await;
        }
        // Family 1: every row expired. Family 2: a revoked row long expired, a live successor.
        let f1 = "'00000000-0000-0000-0000-0000000000f1'";
        let f2 = "'00000000-0000-0000-0000-0000000000f2'";
        exec(&pool, &format!("INSERT INTO refresh_tokens (hash, family_id, user_id, client_id, expires_at, revoked_at) VALUES ('a', {f1}, {u}, 'c', {old}, now()), ('b', {f1}, {u}, 'c', {old}, NULL)")).await;
        exec(&pool, &format!("INSERT INTO refresh_tokens (hash, family_id, user_id, client_id, expires_at, revoked_at) VALUES ('c', {f2}, {u}, 'c', {old}, now()), ('d', {f2}, {u}, 'c', {live}, NULL)")).await;
        exec(&pool, "INSERT INTO relay_dpop_proofs (thumbprint, jti, iat, expires_at, created_at) VALUES ('t', 'old', 0, '1970-01-01T00:05:00.000Z', 'x'), ('t', 'live', 0, '2999-01-01T00:00:00.000Z', 'x')").await;

        let p = prune(&pool).await.unwrap();
        assert_eq!(
            p,
            Pruned {
                dpop_proofs: 1,
                auth_requests: 1,
                auth_codes: 1,
                magic_links: 1,
                device_codes: 1,
                refresh_tokens: 2,
                rate_limits: 1,
            }
        );
        for t in [
            "auth_requests",
            "auth_codes",
            "magic_links",
            "device_codes",
            "relay_rate_limits",
            "relay_dpop_proofs",
        ] {
            assert_eq!(
                count(&pool, &format!("SELECT count(*) FROM {t}")).await,
                1,
                "{t}"
            );
        }
        let left: Vec<String> = sqlx::query_scalar("SELECT hash FROM refresh_tokens ORDER BY hash")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(left, ["c", "d"], "the revoked row of a live family stays");
    }

    #[sqlx::test]
    async fn a_pass_skips_while_another_replica_holds_the_lock(pool: PgPool) {
        let mut other = pool.begin().await.unwrap();
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(LOCK_KEY)
            .execute(&mut *other)
            .await
            .unwrap();
        assert!(
            !run_once(&pool, None, CleanupConfig::default())
                .await
                .unwrap()
        );
        other.rollback().await.unwrap();
        assert!(
            run_once(&pool, None, CleanupConfig::default())
                .await
                .unwrap()
        );
    }
}
