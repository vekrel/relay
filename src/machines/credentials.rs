// Machine credentials: a port of T3 Code's `infra/relay/src/environments/EnvironmentCredentials.ts`
// (MIT, Copyright (c) T3 Tools Inc.; see NOTICE). Only `b64url(sha256(token))` is stored. As in T3
// a credential is keyed by machine and key, not by user, so it authenticates only while some
// active link proven by the same key exists, and (Vekrel) only while that link's user is enabled.
use sha2::{Digest, Sha256};
use sqlx::{Connection, PgConnection, PgPool, Row};
use uuid::Uuid;

use super::now_iso;
use crate::jws::b64url_encode;

/// T3 `t3env_`; only the relay reads it, so it carries our name.
const TOKEN_PREFIX: &str = "vekrelm_";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub credential_id: String,
    pub machine_id: String,
    pub machine_public_key: String,
}

fn hash(token: &str) -> String {
    b64url_encode(Sha256::digest(token.as_bytes()))
}

/// `randomTokenPart`: `segments` UUID v4s, dashes removed.
fn random_part(segments: usize) -> String {
    (0..segments)
        .map(|_| Uuid::new_v4().simple().to_string())
        .collect()
}

/// `create`: a new credential for this machine key; the key's earlier credentials are revoked
/// in the same transaction.
pub async fn create(
    conn: &mut PgConnection,
    machine_id: &str,
    machine_public_key: &str,
) -> Result<String, sqlx::Error> {
    let credential_id = random_part(2);
    let token = format!("{TOKEN_PREFIX}{credential_id}_{}", random_part(3));
    let now = now_iso();
    // One unit: a savepoint inside the caller's transaction, else its own.
    let mut tx = conn.begin().await?;
    sqlx::query(
        "INSERT INTO relay_machine_credentials (credential_id, machine_id, machine_public_key,
            credential_hash, revoked_at, created_at, updated_at)
         VALUES ($1, $2, $3, $4, NULL, $5, $5)",
    )
    .bind(&credential_id)
    .bind(machine_id)
    .bind(machine_public_key)
    .bind(hash(&token))
    .bind(&now)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE relay_machine_credentials SET revoked_at = $4, updated_at = $4
         WHERE machine_id = $1 AND machine_public_key = $2 AND credential_id <> $3
           AND revoked_at IS NULL",
    )
    .bind(machine_id)
    .bind(machine_public_key)
    .bind(&credential_id)
    .bind(&now)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(token)
}

/// `authenticate`.
pub async fn authenticate(pool: &PgPool, token: &str) -> Result<Option<Principal>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT c.credential_id, c.machine_id, c.machine_public_key
         FROM relay_machine_credentials c
         WHERE c.credential_hash = $1 AND c.revoked_at IS NULL
           AND EXISTS (SELECT 1 FROM relay_machine_links l JOIN users u ON u.id = l.user_id
                       WHERE l.machine_id = c.machine_id
                         AND l.machine_public_key = c.machine_public_key
                         AND l.revoked_at IS NULL AND u.disabled_at IS NULL)
         LIMIT 1",
    )
    .bind(hash(token))
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| Principal {
        credential_id: r.get(0),
        machine_id: r.get(1),
        machine_public_key: r.get(2),
    }))
}

/// `revokeForEnvironmentPublicKey`: only once no active link proven by this key remains.
pub async fn revoke_for_machine_public_key(
    conn: &mut PgConnection,
    machine_id: &str,
    machine_public_key: &str,
) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query(
        "UPDATE relay_machine_credentials SET revoked_at = $3, updated_at = $3
         WHERE machine_id = $1 AND machine_public_key = $2 AND revoked_at IS NULL
           AND NOT EXISTS (SELECT 1 FROM relay_machine_links
                           WHERE machine_id = $1 AND machine_public_key = $2
                             AND revoked_at IS NULL)",
    )
    .bind(machine_id)
    .bind(machine_public_key)
    .bind(now_iso())
    .execute(conn)
    .await?
    .rows_affected()
        > 0)
}
