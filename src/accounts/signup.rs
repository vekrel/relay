// The one place that creates users (plan 6A Task 5, Review Focus 5). Every sign-in path (OAuth
// providers, magic link, device code) ends here with an identity the provider has verified.
use sqlx::PgPool;
use uuid::Uuid;

use crate::config::SignupMode;

/// A signed-in identity. `email` must be verified by the provider: an identity seen for the first
/// time attaches to the existing user with that email (Review Focus 1).
pub struct VerifiedIdentity {
    pub provider: &'static str,
    pub subject: String,
    pub email: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// New email, `SIGNUP_MODE=allowlist`, not in `signup_allowlist`.
    NotAllowed,
    Disabled,
}

pub async fn resolve_user(
    pool: &PgPool,
    mode: SignupMode,
    id: &VerifiedIdentity,
) -> Result<Result<Uuid, Refusal>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let known: Option<(Uuid, bool)> = sqlx::query_as(
        "SELECT u.id, u.disabled_at IS NOT NULL FROM identities i JOIN users u ON u.id = i.user_id
         WHERE i.provider = $1 AND i.provider_user_id = $2",
    )
    .bind(id.provider)
    .bind(&id.subject)
    .fetch_optional(&mut *tx)
    .await?;
    let (user_id, disabled) = match known {
        Some(u) => u,
        None => {
            let by_email: Option<(Uuid, bool)> = sqlx::query_as(
                "SELECT id, disabled_at IS NOT NULL FROM users WHERE email = $1::citext",
            )
            .bind(&id.email)
            .fetch_optional(&mut *tx)
            .await?;
            let user = match by_email {
                Some(u) => u,
                None => {
                    let allowed = mode == SignupMode::Open
                        || sqlx::query_scalar::<_, bool>(
                            "SELECT EXISTS (SELECT 1 FROM signup_allowlist WHERE email = $1::citext)",
                        )
                        .bind(&id.email)
                        .fetch_one(&mut *tx)
                        .await?;
                    if !allowed {
                        return Ok(Err(Refusal::NotAllowed));
                    }
                    // A concurrent sign-up with the same email lands on the same row.
                    let u: (Uuid, bool) = sqlx::query_as(
                        "INSERT INTO users (email) VALUES ($1)
                         ON CONFLICT (email) DO UPDATE SET email = users.email
                         RETURNING id, disabled_at IS NOT NULL",
                    )
                    .bind(&id.email)
                    .fetch_one(&mut *tx)
                    .await?;
                    tracing::info!(user_id = %u.0, provider = id.provider, "user created");
                    u
                }
            };
            if user.1 {
                return Ok(Err(Refusal::Disabled));
            }
            sqlx::query(
                "INSERT INTO identities (provider, provider_user_id, user_id, email)
                 VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
            )
            .bind(id.provider)
            .bind(&id.subject)
            .bind(user.0)
            .bind(&id.email)
            .execute(&mut *tx)
            .await?;
            user
        }
    };
    if disabled {
        return Ok(Err(Refusal::Disabled));
    }
    tx.commit().await?;
    Ok(Ok(user_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ident(subject: &str, email: &str) -> VerifiedIdentity {
        VerifiedIdentity {
            provider: "test",
            subject: subject.into(),
            email: email.into(),
        }
    }

    async fn users(pool: &PgPool) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM users")
            .fetch_one(pool)
            .await
            .unwrap()
    }

    #[sqlx::test]
    async fn allowlist_mode_creates_only_listed_emails(pool: PgPool) {
        let a = SignupMode::Allowlist;
        assert_eq!(
            resolve_user(&pool, a, &ident("1", "out@example.test"))
                .await
                .unwrap(),
            Err(Refusal::NotAllowed)
        );
        assert_eq!(users(&pool).await, 0);
        sqlx::query("INSERT INTO signup_allowlist (email) VALUES ('In@Example.test')")
            .execute(&pool)
            .await
            .unwrap();
        let id = resolve_user(&pool, a, &ident("2", "in@example.test"))
            .await
            .unwrap()
            .unwrap();
        // Same identity again: same user, no new row.
        let again = resolve_user(&pool, a, &ident("2", "in@example.test"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(id, again);
        assert_eq!(users(&pool).await, 1);
    }

    #[sqlx::test]
    async fn open_mode_creates_users(pool: PgPool) {
        let id = resolve_user(&pool, SignupMode::Open, &ident("1", "a@example.test"))
            .await
            .unwrap();
        assert!(id.is_ok());
        assert_eq!(users(&pool).await, 1);
    }

    #[sqlx::test]
    async fn existing_user_signs_in_even_when_not_listed(pool: PgPool) {
        let id = resolve_user(&pool, SignupMode::Open, &ident("1", "a@example.test"))
            .await
            .unwrap()
            .unwrap();
        // A second verified identity with the same email links to the same user in allowlist mode.
        let linked = resolve_user(
            &pool,
            SignupMode::Allowlist,
            &ident("other", "A@example.test"),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(id, linked);
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM identities WHERE user_id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 2);
    }

    #[sqlx::test]
    async fn disabled_user_is_refused(pool: PgPool) {
        resolve_user(&pool, SignupMode::Open, &ident("1", "a@example.test"))
            .await
            .unwrap()
            .unwrap();
        sqlx::query("UPDATE users SET disabled_at = now()")
            .execute(&pool)
            .await
            .unwrap();
        for i in [ident("1", "a@example.test"), ident("new", "a@example.test")] {
            assert_eq!(
                resolve_user(&pool, SignupMode::Open, &i).await.unwrap(),
                Err(Refusal::Disabled)
            );
        }
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM identities")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 1, "no identity attached to a disabled user");
    }
}
