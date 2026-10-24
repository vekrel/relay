// Rate limits over `relay_rate_limits` (T3 used Cloudflare RateLimit bindings, infra/relay/src/worker.ts)
// and the client address they key on. Shared by every limited route.
use std::net::{IpAddr, SocketAddr};

use axum::extract::ConnectInfo;
use axum::http::{Extensions, HeaderMap};
use sqlx::PgPool;

/// The one forwarded header that may name the client (Railway's edge, plan Global Constraints),
/// read only with `TRUST_PROXY_IP_HEADER=true`; every other forwarded header is ignored.
pub const CLIENT_IP_HEADER: &str = "x-real-ip";

/// A trusted `X-Real-IP` that is present but not exactly one IP address. Answer 400: falling back
/// to the peer would put the client in the edge's bucket, shared by everyone.
#[derive(Debug, PartialEq, Eq)]
pub struct MalformedIpHeader;

/// With `trust_header`, the edge's header when present (it must hold one IP); without the header,
/// or untrusted, the socket peer that `serve` attaches as `ConnectInfo`. `Ok(None)` only when
/// neither exists (tests).
pub fn client_ip(
    headers: &HeaderMap,
    extensions: &Extensions,
    trust_header: bool,
) -> Result<Option<IpAddr>, MalformedIpHeader> {
    let mut values = headers.get_all(CLIENT_IP_HEADER).iter();
    if let (true, Some(v)) = (trust_header, values.next()) {
        if values.next().is_some() {
            return Err(MalformedIpHeader);
        }
        let ip = v.to_str().ok().and_then(|v| v.trim().parse().ok());
        return ip.map(Some).ok_or(MalformedIpHeader);
    }
    Ok(extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip()))
}

/// The rate-limit bucket of an address: IPv4 as is, IPv6 by its /64 (one customer's prefix holds
/// any number of addresses). IPv4-mapped IPv6 counts as IPv4.
pub fn ip_bucket(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let s = v6.segments();
                let net = std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0);
                format!("{net}/64")
            }
        },
    }
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
        assert_eq!(client_ip(&h, &ext, true), Ok(None));
        ext.insert(ConnectInfo(SocketAddr::from(([192, 0, 2, 9], 5000))));
        let peer = Ok(Some([192, 0, 2, 9].into()));
        assert_eq!(client_ip(&h, &ext, true), peer);
        h.insert("x-forwarded-for", "198.51.100.1".parse().unwrap());
        assert_eq!(client_ip(&h, &ext, true), peer);
        h.insert(CLIENT_IP_HEADER, "203.0.113.4".parse().unwrap());
        assert_eq!(client_ip(&h, &ext, true), Ok(Some([203, 0, 113, 4].into())));
        // Not trusted (the default): a client-sent header is ignored.
        assert_eq!(client_ip(&h, &ext, false), peer);
        assert_eq!(client_ip(&h, &Extensions::new(), false), Ok(None));
        // Trusted but malformed: an error, never the shared edge peer.
        for bad in [
            "not an ip",
            "",
            "203.0.113.4, 198.51.100.1",
            "203.0.113.4:80",
        ] {
            h.insert(CLIENT_IP_HEADER, bad.parse().unwrap());
            assert_eq!(client_ip(&h, &ext, true), Err(MalformedIpHeader), "{bad:?}");
            assert_eq!(client_ip(&h, &ext, false), peer, "{bad:?}");
        }
        h.insert(CLIENT_IP_HEADER, "203.0.113.4".parse().unwrap());
        h.append(CLIENT_IP_HEADER, "203.0.113.5".parse().unwrap());
        assert_eq!(client_ip(&h, &ext, true), Err(MalformedIpHeader));
    }

    #[test]
    fn ipv6_buckets_by_64_ipv4_as_is() {
        let b = |s: &str| ip_bucket(s.parse().unwrap());
        assert_eq!(b("203.0.113.4"), "203.0.113.4");
        assert_eq!(b("2001:db8:1:2:aaaa::1"), "2001:db8:1:2::/64");
        assert_eq!(b("2001:db8:1:2:ffff:ffff:ffff:ffff"), "2001:db8:1:2::/64");
        assert_ne!(b("2001:db8:1:3::1"), b("2001:db8:1:2::1"));
        assert_eq!(b("::ffff:203.0.113.4"), "203.0.113.4");
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
