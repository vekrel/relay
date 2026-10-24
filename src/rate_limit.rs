// Rate limits over `relay_rate_limits` (T3 used Cloudflare RateLimit bindings, infra/relay/src/worker.ts)
// and the client address they key on. Shared by every limited route.
use std::net::{IpAddr, SocketAddr};

use axum::extract::ConnectInfo;
use axum::http::{Extensions, HeaderMap};
use sqlx::PgPool;

// shortcut: assumes Railway's edge sets X-Real-IP (plan Global Constraints); confirm on staging (Task 2).
/// The one forwarded header trusted for the client address; every other one is ignored.
pub const CLIENT_IP_HEADER: &str = "x-real-ip";

/// The edge's header when it holds an IP, else the socket peer (`serve` attaches `ConnectInfo`).
/// `None` only for a request that came through neither (unit tests without `MockConnectInfo`).
pub fn client_ip(headers: &HeaderMap, extensions: &Extensions) -> Option<IpAddr> {
    headers
        .get(CLIENT_IP_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse().ok())
        .or_else(|| {
            extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|c| c.0.ip())
        })
}

/// `(key, max hits, window seconds)`, sliding window.
pub type Limit = (String, i64, i64);

/// Records one hit on every key if all of them are under their limit, else records nothing and
/// returns false. Atomic: an advisory lock per key (taken in the given order, so callers must pass
/// keys in a fixed order) serializes concurrent checks of the same key until commit.
pub async fn allow_all(pool: &PgPool, limits: &[Limit]) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;
    for (key, max, secs) in limits {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(key)
            .execute(&mut *tx)
            .await?;
        let used: i64 = sqlx::query_scalar(
            "SELECT coalesce(sum(count), 0)::int8 FROM relay_rate_limits
             WHERE key = $1 AND window_start > now() - make_interval(secs => $2)",
        )
        .bind(key)
        .bind(*secs as f64)
        .fetch_one(&mut *tx)
        .await?;
        if used >= *max {
            return Ok(false); // rollback: nothing recorded
        }
    }
    for (key, _, _) in limits {
        sqlx::query(
            "INSERT INTO relay_rate_limits (key, window_start, count) VALUES ($1, clock_timestamp(), 1)
             ON CONFLICT (key, window_start) DO UPDATE SET count = relay_rate_limits.count + 1",
        )
        .bind(key)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_ip_prefers_the_edge_header_then_the_peer() {
        let mut h = HeaderMap::new();
        let mut ext = Extensions::new();
        assert_eq!(client_ip(&h, &ext), None);
        ext.insert(ConnectInfo(SocketAddr::from(([192, 0, 2, 9], 5000))));
        assert_eq!(client_ip(&h, &ext), Some([192, 0, 2, 9].into()));
        h.insert("x-forwarded-for", "198.51.100.1".parse().unwrap());
        assert_eq!(client_ip(&h, &ext), Some([192, 0, 2, 9].into()));
        h.insert(CLIENT_IP_HEADER, "not an ip".parse().unwrap());
        assert_eq!(client_ip(&h, &ext), Some([192, 0, 2, 9].into()));
        h.insert(CLIENT_IP_HEADER, "203.0.113.4".parse().unwrap());
        assert_eq!(client_ip(&h, &ext), Some([203, 0, 113, 4].into()));
    }

    /// Many concurrent hits on one key, each on its own pool connection: exactly `max` pass.
    #[sqlx::test]
    async fn concurrent_hits_never_exceed_the_limit(pool: PgPool) {
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..12 {
            let pool = pool.clone();
            set.spawn(async move {
                allow_all(&pool, &[("k".into(), 3, 900), ("g".into(), 100, 3600)])
                    .await
                    .unwrap()
            });
        }
        let allowed = set.join_all().await.into_iter().filter(|a| *a).count();
        assert_eq!(allowed, 3);
        let recorded: i64 =
            sqlx::query_scalar("SELECT sum(count)::int8 FROM relay_rate_limits WHERE key = 'g'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(recorded, 3, "refused hits record nothing");
    }
}
