// DPoP proof replay table: a port of T3 Code's `infra/relay/src/auth/DpopProofs.ts`
// (MIT, Copyright (c) T3 Tools Inc.; see NOTICE). A proof is spent by inserting
// `(thumbprint, jti)` into `relay_dpop_proofs`; the primary key makes a second insert a no-op,
// from any connection or replica, so a replay is refused everywhere.
use sqlx::PgPool;

use super::dpop::{self, DPOP_MAX_CLOCK_SKEW_SECONDS, Failure};

#[derive(Debug)]
pub enum Rejected {
    /// `DpopProofRejected` with a `verifyDpopProof` code.
    Proof(Failure),
    /// `DpopProofRejected { code: "replayed" }`.
    Replayed,
    /// `DpopProofReplayPersistenceError`.
    Persistence(sqlx::Error),
}

impl Rejected {
    /// `DpopProofFailureCode`, `None` for a persistence error.
    pub fn code(&self) -> Option<&'static str> {
        match self {
            Self::Proof(f) => Some(f.code()),
            Self::Replayed => Some("replayed"),
            Self::Persistence(_) => None,
        }
    }
}

/// `Date.prototype.toISOString` for epoch milliseconds (years 0000-9999); T3 stores these as text.
pub fn iso_millis(ms: i64) -> String {
    let (days, rem) = (ms.div_euclid(86_400_000), ms.rem_euclid(86_400_000));
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3_600_000,
        rem / 60_000 % 60,
        rem / 1000 % 60,
        rem % 1000
    )
}

/// `consume`: true when this call spent the proof, false when it was already spent.
pub async fn consume(
    pool: &PgPool,
    proof: &dpop::Proof,
    expires_at_ms: i64,
    now_ms: i64,
) -> Result<bool, sqlx::Error> {
    let inserted = sqlx::query(
        "INSERT INTO relay_dpop_proofs (thumbprint, jti, iat, expires_at, created_at)
         VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
    )
    .bind(&proof.thumbprint)
    .bind(&proof.jti)
    // `iat` passed the ±300 s window around a real clock, so it fits `integer`.
    .bind(proof.iat as i32)
    .bind(iso_millis(expires_at_ms))
    .bind(iso_millis(now_ms))
    .execute(pool)
    .await?;
    Ok(inserted.rows_affected() > 0)
}

/// `verifyAndConsume`: verifies the proof, then spends it; returns its key thumbprint.
/// `request.now_epoch_seconds` is ignored: the clock is `now_ms`, floored to seconds as T3 does.
pub async fn verify_and_consume(
    pool: &PgPool,
    request: &dpop::Request<'_>,
    now_ms: i64,
) -> Result<String, Rejected> {
    let request = dpop::Request {
        now_epoch_seconds: now_ms.div_euclid(1000),
        ..*request
    };
    let proof = dpop::verify(&request).map_err(|failure| {
        tracing::warn!(
            code = failure.code(),
            method = request.method,
            url = request.url,
            expected_thumbprint_present = request.expected_thumbprint.is_some(),
            expected_access_token_present = request.expected_access_token.is_some(),
            "relay dpop proof rejected"
        );
        Rejected::Proof(failure)
    })?;
    // The time check floors the clock to seconds, so the proof passes until the end of second
    // `iat + DPOP_MAX_CLOCK_SKEW_SECONDS`.
    let expires_at_ms = (proof.iat + DPOP_MAX_CLOCK_SKEW_SECONDS + 1) * 1000;
    if !consume(pool, &proof, expires_at_ms, now_ms)
        .await
        .map_err(Rejected::Persistence)?
    {
        tracing::warn!(
            thumbprint = proof.thumbprint,
            jti = proof.jti,
            iat = proof.iat,
            "relay dpop proof replay rejected"
        );
        return Err(Rejected::Replayed);
    }
    Ok(proof.thumbprint)
}

/// `pruneExpired`: drops spent proofs whose window has closed (ISO strings sort by time).
pub async fn prune_expired(pool: &PgPool, now_ms: i64) -> Result<u64, sqlx::Error> {
    Ok(
        sqlx::query("DELETE FROM relay_dpop_proofs WHERE expires_at < $1")
            .bind(iso_millis(now_ms))
            .execute(pool)
            .await?
            .rows_affected(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::dpop::tests::{proof_of, request_of, vector};
    use crate::db::MIGRATOR;
    use sqlx::postgres::PgPoolOptions;

    fn now_ms(v: &serde_json::Value) -> i64 {
        v["now"].as_i64().unwrap() * 1000
    }

    #[test]
    fn iso_millis_matches_to_iso_string() {
        // Node's `new Date(ms).toISOString()`.
        assert_eq!(iso_millis(1_893_456_000_123), "2030-01-01T00:00:00.123Z");
        assert_eq!(iso_millis(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso_millis(951_782_400_000), "2000-02-29T00:00:00.000Z");
    }

    #[sqlx::test(migrator = "MIGRATOR")]
    async fn a_replay_is_refused_from_another_connection(pool: PgPool) {
        // A second pool to the same database: no connection is shared with the first.
        let other = PgPoolOptions::new()
            .max_connections(1)
            .connect_with(pool.connect_options().as_ref().clone())
            .await
            .unwrap();
        let v = vector("valid");
        let proof = proof_of(&v);
        let r = request_of(&v, &proof);
        let thumb = verify_and_consume(&pool, &r, now_ms(&v)).await.unwrap();
        assert_eq!(thumb, v["shared"]["thumbprint"]);
        let again = verify_and_consume(&other, &r, now_ms(&v))
            .await
            .unwrap_err();
        assert_eq!(again.code(), Some("replayed"));
        let again = verify_and_consume(&pool, &r, now_ms(&v)).await.unwrap_err();
        assert_eq!(again.code(), Some("replayed"));
        other.close().await;
    }

    #[sqlx::test(migrator = "MIGRATOR")]
    async fn racing_the_same_proof_on_two_connections_spends_it_once(pool: PgPool) {
        let other = PgPoolOptions::new()
            .max_connections(1)
            .connect_with(pool.connect_options().as_ref().clone())
            .await
            .unwrap();
        let v = vector("valid_with_ath");
        let proof = proof_of(&v);
        let r = request_of(&v, &proof);
        let (a, b) = tokio::join!(
            verify_and_consume(&pool, &r, now_ms(&v)),
            verify_and_consume(&other, &r, now_ms(&v))
        );
        let codes = [a.err().map(|e| e.code()), b.err().map(|e| e.code())];
        assert_eq!(codes.iter().filter(|c| c.is_none()).count(), 1, "{codes:?}");
        assert!(codes.contains(&Some(Some("replayed"))), "{codes:?}");
        other.close().await;
    }

    #[sqlx::test(migrator = "MIGRATOR")]
    async fn a_refused_proof_writes_nothing(pool: PgPool) {
        for name in [
            "time_window_plus_301",
            "ath_missing",
            "bad_signature_before_time_window",
        ] {
            let v = vector(name);
            let proof = proof_of(&v);
            let e = verify_and_consume(&pool, &request_of(&v, &proof), now_ms(&v))
                .await
                .unwrap_err();
            assert_eq!(e.code(), v["shared"]["code"].as_str(), "{name}");
        }
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM relay_dpop_proofs")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 0);
    }

    // DpopProofs.verifyAndConsume.test.ts "rejects replays until a future proof's time window closes".
    #[sqlx::test(migrator = "MIGRATOR")]
    async fn replays_are_refused_until_a_future_proofs_window_closes(pool: PgPool) {
        let v = vector("valid_future_iat_300_for_replay_window");
        let proof = proof_of(&v);
        let r = request_of(&v, &proof);
        let now = now_ms(&v);
        verify_and_consume(&pool, &r, now).await.unwrap();
        let row: (i32, String, String) =
            sqlx::query_as("SELECT iat, expires_at, created_at FROM relay_dpop_proofs")
                .fetch_one(&pool)
                .await
                .unwrap();
        let iat = v["now"].as_i64().unwrap() + 300;
        assert_eq!(
            row,
            (iat as i32, iso_millis((iat + 301) * 1000), iso_millis(now))
        );
        for (elapsed_ms, code) in [
            (0, "replayed"),
            (301_000, "replayed"),
            (600_999, "replayed"),
            (601_000, "time_window"),
        ] {
            prune_expired(&pool, now + elapsed_ms).await.unwrap();
            let e = verify_and_consume(&pool, &r, now + elapsed_ms)
                .await
                .unwrap_err();
            assert_eq!(e.code(), Some(code), "replay after {elapsed_ms} ms");
        }
        // Pruning keeps a row until its window has closed, then drops it.
        assert_eq!(prune_expired(&pool, (iat + 301) * 1000).await.unwrap(), 0);
        assert_eq!(
            prune_expired(&pool, (iat + 301) * 1000 + 1).await.unwrap(),
            1
        );
    }
}
