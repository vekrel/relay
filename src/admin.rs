// Admin CLI (plan 6A Task 5): `vekrel-relay admin ...`, run against production with
// `railway run vekrel-relay admin ...`. Talks to the database in `DATABASE_URL` directly.
use clap::Subcommand;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Subcommand)]
pub enum Admin {
    /// Let this email create an account while `SIGNUP_MODE=allowlist`.
    Allow {
        email: String,
        #[arg(long)]
        note: Option<String>,
    },
    /// Remove an email from the allowlist (an existing account keeps working).
    Disallow { email: String },
    /// Print the allowlist.
    ListAllowed,
    /// Disable an account: refuse sign-in, revoke its refresh tokens, machine links and machine credentials, and delete its held webhooks.
    DisableUser { email: String },
    /// Re-enable a disabled account (revoked links stay revoked).
    EnableUser { email: String },
}

pub async fn run(pool: &PgPool, cmd: Admin) -> Result<String, String> {
    run_db(pool, cmd).await.map_err(|e| e.to_string())?
}

async fn run_db(pool: &PgPool, cmd: Admin) -> Result<Result<String, String>, sqlx::Error> {
    Ok(match cmd {
        Admin::Allow { email, note } => {
            sqlx::query(
                "INSERT INTO signup_allowlist (email, note) VALUES ($1, $2)
                 ON CONFLICT (email) DO UPDATE SET note = coalesce(EXCLUDED.note, signup_allowlist.note)",
            )
            .bind(&email)
            .bind(note)
            .execute(pool)
            .await?;
            Ok(format!("allowed {email}"))
        }
        Admin::Disallow { email } => {
            let n = sqlx::query("DELETE FROM signup_allowlist WHERE email = $1::citext")
                .bind(&email)
                .execute(pool)
                .await?
                .rows_affected();
            if n == 0 {
                Err(format!("{email} is not on the allowlist"))
            } else {
                Ok(format!("disallowed {email}"))
            }
        }
        Admin::ListAllowed => {
            let rows: Vec<(String, Option<String>)> = sqlx::query_as(
                "SELECT email::text, note FROM signup_allowlist ORDER BY added_at, email",
            )
            .fetch_all(pool)
            .await?;
            Ok(rows
                .into_iter()
                .map(|(e, n)| match n {
                    Some(n) => format!("{e}\t{n}"),
                    None => e,
                })
                .collect::<Vec<_>>()
                .join("\n"))
        }
        Admin::DisableUser { email } => {
            let mut tx = pool.begin().await?;
            let Some(user): Option<Uuid> = sqlx::query_scalar(
                "UPDATE users SET disabled_at = coalesce(disabled_at, now()) WHERE email = $1::citext RETURNING id",
            )
            .bind(&email)
            .fetch_optional(&mut *tx)
            .await?
            else {
                return Ok(Err(format!("no user with email {email}")));
            };
            let tokens = sqlx::query(
                "UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL",
            )
            .bind(user)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            // T3 stores relay timestamps as `new Date().toISOString()`.
            let now: String = sqlx::query_scalar(
                r#"SELECT to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')"#,
            )
            .fetch_one(&mut *tx)
            .await?;
            // Credentials are keyed by machine (T3); keep those another user still links live.
            let credentials = sqlx::query(
                "UPDATE relay_machine_credentials c SET revoked_at = $2, updated_at = $2
                 WHERE c.revoked_at IS NULL
                   AND c.machine_id IN (SELECT machine_id FROM relay_machine_links
                                        WHERE user_id = $1 AND revoked_at IS NULL)
                   AND NOT EXISTS (SELECT 1 FROM relay_machine_links o
                                   WHERE o.machine_id = c.machine_id AND o.user_id <> $1
                                     AND o.revoked_at IS NULL)",
            )
            .bind(user)
            .bind(&now)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            let links = sqlx::query(
                "UPDATE relay_machine_links SET revoked_at = $2, updated_at = $2
                 WHERE user_id = $1 AND revoked_at IS NULL",
            )
            .bind(user)
            .bind(&now)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            let held = crate::hooks::inbox::clear_for_user(&mut tx, user).await?;
            tx.commit().await?;
            Ok(format!(
                "disabled {email}: revoked {tokens} refresh tokens, {links} machine links, {credentials} machine credentials; deleted {held} held webhooks"
            ))
        }
        Admin::EnableUser { email } => {
            let n = sqlx::query("UPDATE users SET disabled_at = NULL WHERE email = $1::citext")
                .bind(&email)
                .execute(pool)
                .await?
                .rows_affected();
            if n == 0 {
                Err(format!("no user with email {email}"))
            } else {
                Ok(format!("enabled {email}"))
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn exec(pool: &PgPool, sql: &'static str) {
        sqlx::query(sql).execute(pool).await.unwrap();
    }

    #[sqlx::test]
    async fn allowlist_commands(pool: PgPool) {
        let allow = |email: &str, note: Option<&str>| Admin::Allow {
            email: email.into(),
            note: note.map(Into::into),
        };
        run(&pool, allow("a@example.test", Some("friend")))
            .await
            .unwrap();
        run(&pool, allow("B@example.test", None)).await.unwrap();
        run(&pool, allow("b@example.test", None)).await.unwrap();
        assert_eq!(
            run(&pool, Admin::ListAllowed).await.unwrap(),
            "a@example.test\tfriend\nB@example.test"
        );
        run(
            &pool,
            Admin::Disallow {
                email: "A@EXAMPLE.test".into(),
            },
        )
        .await
        .unwrap();
        assert!(
            run(
                &pool,
                Admin::Disallow {
                    email: "a@example.test".into()
                }
            )
            .await
            .is_err()
        );
        assert_eq!(
            run(&pool, Admin::ListAllowed).await.unwrap(),
            "B@example.test"
        );
    }

    #[sqlx::test]
    async fn disable_user_revokes_tokens_links_and_credentials(pool: PgPool) {
        exec(
            &pool,
            "INSERT INTO users (id, email) VALUES
               ('00000000-0000-0000-0000-00000000000a', 'a@example.test'),
               ('00000000-0000-0000-0000-00000000000b', 'b@example.test')",
        )
        .await;
        exec(
            &pool,
            "INSERT INTO refresh_tokens (hash, family_id, user_id, client_id, expires_at) VALUES
               ('ha', gen_random_uuid(), '00000000-0000-0000-0000-00000000000a', 'vekrel-cli', now() + interval '1 day'),
               ('hb', gen_random_uuid(), '00000000-0000-0000-0000-00000000000b', 'vekrel-cli', now() + interval '1 day')",
        )
        .await;
        // m1: only a links it. m2: a and b link it, so its credential stays.
        exec(
            &pool,
            "INSERT INTO relay_machine_links (user_id, machine_id, machine_public_key, endpoint_http_base_url,
                 endpoint_ws_base_url, endpoint_provider_kind, created_at, updated_at) VALUES
               ('00000000-0000-0000-0000-00000000000a', 'm1', 'k', 'https://h', 'wss://h', 'manual', 'x', 'x'),
               ('00000000-0000-0000-0000-00000000000a', 'm2', 'k', 'https://h', 'wss://h', 'manual', 'x', 'x'),
               ('00000000-0000-0000-0000-00000000000b', 'm2', 'k', 'https://h', 'wss://h', 'manual', 'x', 'x')",
        )
        .await;
        exec(
            &pool,
            "INSERT INTO relay_machine_credentials (credential_id, machine_id, machine_public_key,
                 credential_hash, created_at, updated_at) VALUES
               ('c1', 'm1', 'k', 'h1', 'x', 'x'), ('c2', 'm2', 'k', 'h2', 'x', 'x')",
        )
        .await;
        let out = run(
            &pool,
            Admin::DisableUser {
                email: "A@example.test".into(),
            },
        )
        .await
        .unwrap();
        assert_eq!(
            out,
            "disabled A@example.test: revoked 1 refresh tokens, 2 machine links, 1 machine credentials"
        );
        let revoked: Vec<(String, bool)> =
            sqlx::query_as("SELECT hash, revoked_at IS NOT NULL FROM refresh_tokens ORDER BY hash")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(revoked, [("ha".into(), true), ("hb".into(), false)]);
        let links: Vec<(String, bool)> = sqlx::query_as(
            "SELECT user_id::text || machine_id, revoked_at IS NOT NULL FROM relay_machine_links
             ORDER BY 1",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(
            links,
            [
                ("00000000-0000-0000-0000-00000000000am1".into(), true),
                ("00000000-0000-0000-0000-00000000000am2".into(), true),
                ("00000000-0000-0000-0000-00000000000bm2".into(), false),
            ]
        );
        let creds: Vec<(String, Option<String>)> = sqlx::query_as(
            "SELECT credential_id, revoked_at FROM relay_machine_credentials ORDER BY 1",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(creds[1], ("c2".into(), None));
        let iso = creds[0].1.as_deref().unwrap();
        assert!(
            iso.len() == 24 && iso.ends_with('Z') && iso.as_bytes()[10] == b'T',
            "{iso}"
        );
        let disabled: bool = sqlx::query_scalar(
            "SELECT disabled_at IS NOT NULL FROM users WHERE email = 'a@example.test'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(disabled);
        run(
            &pool,
            Admin::EnableUser {
                email: "a@example.test".into(),
            },
        )
        .await
        .unwrap();
        assert!(
            run(
                &pool,
                Admin::DisableUser {
                    email: "nobody@example.test".into()
                }
            )
            .await
            .is_err()
        );
    }
}
