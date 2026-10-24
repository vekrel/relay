// Postgres pool and migrations. T3 ran Drizzle migrations from `infra/relay/migrations/postgres`
// at deploy (`infra/relay/src/db.ts`, table `relay_migrations`); here `sqlx::migrate!` embeds
// `migrations/` in the binary and applies it at boot (`_sqlx_migrations`).
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!();

// TLS follows the URL's own `sslmode`: Railway's private network (postgres.railway.internal) is
// WireGuard-encrypted and its Postgres has no TLS, so forcing `require` would break boot.
pub async fn connect(url: &str) -> Result<PgPool, String> {
    PgPoolOptions::new()
        .connect(url)
        .await
        .map_err(|e| format!("connect to database: {e}"))
}

/// Applies pending migrations and returns every applied version, oldest first.
pub async fn migrate(pool: &PgPool) -> Result<Vec<i64>, String> {
    MIGRATOR
        .run(pool)
        .await
        .map_err(|e| format!("migrate: {e}"))?;
    sqlx::query_scalar("SELECT version FROM _sqlx_migrations WHERE success ORDER BY version")
        .fetch_all(pool)
        .await
        .map_err(|e| format!("read migration versions: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn new_user(pool: &PgPool, email: &str) -> sqlx::Result<String> {
        sqlx::query_scalar("INSERT INTO users (email) VALUES ($1) RETURNING id::text")
            .bind(email)
            .fetch_one(pool)
            .await
    }

    async fn count(pool: &PgPool, table: &str) -> i64 {
        sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT count(*) FROM {table}")))
            .fetch_one(pool)
            .await
            .unwrap()
    }

    fn is_unique_violation(e: sqlx::Error) -> bool {
        e.as_database_error()
            .is_some_and(|d| d.is_unique_violation())
    }

    #[sqlx::test(migrations = false)]
    async fn migrations_apply_on_empty_db_and_are_idempotent(pool: PgPool) {
        let first = migrate(&pool).await.unwrap();
        assert_eq!(first, vec![1, 2, 3, 4]);
        for table in [
            "relay_machine_links",
            "relay_managed_endpoint_allocations",
            "relay_managed_tunnel_limits",
            "relay_machine_credentials",
            "relay_dpop_proofs",
            "relay_mobile_devices",
            "relay_live_activities",
            "relay_agent_activity_rows",
            "relay_delivery_attempts",
            "relay_upstream_api_pauses",
            "users",
            "identities",
            "auth_requests",
            "auth_codes",
            "magic_links",
            "device_codes",
            "refresh_tokens",
            "signup_allowlist",
            "relay_held_hooks",
            "relay_held_hook_targets",
            "relay_push_jobs",
            "relay_rate_limits",
        ] {
            assert_eq!(count(&pool, table).await, 0, "{table}");
        }
        // Second boot: nothing new to apply, nothing fails.
        assert_eq!(migrate(&pool).await.unwrap(), first);
        assert_eq!(count(&pool, "_sqlx_migrations").await, 4);
    }

    #[sqlx::test(migrator = "MIGRATOR")]
    async fn identity_is_unique_per_provider_user(pool: PgPool) {
        let a = new_user(&pool, "a@example.com").await.unwrap();
        let b = new_user(&pool, "b@example.com").await.unwrap();
        let link = |user: String, provider: &'static str| {
            let pool = pool.clone();
            async move {
                sqlx::query(
                    "INSERT INTO identities (provider, provider_user_id, user_id, email)
                     VALUES ($1, '42', $2::uuid, 'a@example.com')",
                )
                .bind(provider)
                .bind(user)
                .execute(&pool)
                .await
            }
        };
        link(a.clone(), "github").await.unwrap();
        link(a, "google").await.unwrap();
        assert!(is_unique_violation(link(b, "github").await.unwrap_err()));
    }

    #[sqlx::test(migrator = "MIGRATOR")]
    async fn email_is_unique_across_case(pool: PgPool) {
        new_user(&pool, "Owner@Example.com").await.unwrap();
        let dup = new_user(&pool, "owner@example.COM").await.unwrap_err();
        assert!(is_unique_violation(dup));
        let found: i64 =
            sqlx::query_scalar("SELECT count(*) FROM users WHERE email = 'OWNER@EXAMPLE.COM'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(found, 1);

        sqlx::query("INSERT INTO signup_allowlist (email) VALUES ('Friend@Example.com')")
            .execute(&pool)
            .await
            .unwrap();
        let dup = sqlx::query("INSERT INTO signup_allowlist (email) VALUES ('friend@example.com')")
            .execute(&pool)
            .await
            .unwrap_err();
        assert!(is_unique_violation(dup));
    }

    #[sqlx::test(migrator = "MIGRATOR")]
    async fn deleting_a_user_cascades(pool: PgPool) {
        let user = new_user(&pool, "gone@example.com").await.unwrap();
        let other = new_user(&pool, "stays@example.com").await.unwrap();
        for u in [&user, &other] {
            sqlx::query(
                "INSERT INTO identities (provider, provider_user_id, user_id, email)
                 VALUES ('github', $1, $1::uuid, 'x@example.com')",
            )
            .bind(u)
            .execute(&pool)
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO relay_machine_links (user_id, machine_id, machine_public_key,
                   endpoint_http_base_url, endpoint_ws_base_url, endpoint_provider_kind,
                   created_at, updated_at)
                 VALUES ($1::uuid, 'm1', 'pk', 'https://h', 'wss://h', 'vekrel_relay', 't', 't')",
            )
            .bind(u)
            .execute(&pool)
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO relay_mobile_devices (user_id, device_id, platform, preferences_json,
                   created_at, updated_at)
                 VALUES ($1::uuid, 'd1', 'ios', '{}', 't', 't')",
            )
            .bind(u)
            .execute(&pool)
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO refresh_tokens (hash, family_id, user_id, client_id, expires_at)
                 VALUES ($1, gen_random_uuid(), $1::uuid, 'vekrel-web', now() + interval '30 days')",
            )
            .bind(u)
            .execute(&pool)
            .await
            .unwrap();
        }

        sqlx::query("DELETE FROM users WHERE id = $1::uuid")
            .bind(&user)
            .execute(&pool)
            .await
            .unwrap();

        for table in [
            "identities",
            "relay_machine_links",
            "relay_mobile_devices",
            "refresh_tokens",
        ] {
            assert_eq!(count(&pool, table).await, 1, "{table}");
        }
    }
}
