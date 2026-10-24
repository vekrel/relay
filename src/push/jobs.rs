// Push jobs as rows (T3 used Cloudflare Queues with dead-letter queues, `infra/relay/src/worker.ts`
// `consumeQueueMessages`: batch 10, 5 retries 30 s apart, then the dead-letter queue). A worker
// claims due rows with `FOR UPDATE SKIP LOCKED` and holds them for CLAIM_TIMEOUT; a row whose
// claim ran out (its worker died) is claimed again, so a crash loses no push. Every state change
// after the claim checks the row is still this worker's (`status`, `attempts`), so two workers
// never finish one job.
use std::time::Duration;

use serde_json::Value;
use sqlx::{PgConnection, PgPool, Row};
use uuid::Uuid;

use super::Push;

/// How long a claim lasts. Vekrel, not T3: T3's 10-minute source-job lease equals its job
/// lifetime, so a crashed claim could never re-send; this one re-sends within the lifetime.
pub const CLAIM_TIMEOUT_SECONDS: i64 = 120;
/// T3: `maxRetries: 5` after the first delivery.
pub const MAX_ATTEMPTS: i32 = 6;
/// T3: `retryDelay: "30 seconds"`.
pub const RETRY_DELAY_SECONDS: i64 = 30;
const BATCH: i64 = 10;

/// Why a job did not finish. `retry: false` means retrying cannot help (it goes `dead` now).
#[derive(Debug)]
pub struct JobError {
    pub tag: &'static str,
    pub retry: bool,
}

impl JobError {
    pub fn retry(tag: &'static str) -> Self {
        Self { tag, retry: true }
    }
    pub fn fatal(tag: &'static str) -> Self {
        Self { tag, retry: false }
    }
}

impl From<sqlx::Error> for JobError {
    fn from(e: sqlx::Error) -> Self {
        tracing::error!(error = %e, "push job persistence failed");
        Self::retry("PersistenceError")
    }
}

pub async fn enqueue(
    conn: &mut PgConnection,
    id: Uuid,
    kind: &str,
    payload: &Value,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO relay_push_jobs (id, kind, payload) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(kind)
        .bind(payload)
        .execute(conn)
        .await?;
    Ok(())
}

pub struct Claimed {
    pub id: Uuid,
    pub kind: String,
    pub payload: Value,
    pub attempts: i32,
}

/// Due jobs of these kinds, plus running ones whose claim ran out.
pub async fn claim(pool: &PgPool, kinds: &[&str]) -> Result<Vec<Claimed>, sqlx::Error> {
    let rows = sqlx::query(
        "WITH due AS (
            SELECT id, status AS was FROM relay_push_jobs
            WHERE kind = ANY($1)
              AND ((status = 'pending' AND run_at <= now())
                   OR (status = 'running' AND locked_until < now()))
            ORDER BY run_at, created_at
            LIMIT $2
            FOR UPDATE SKIP LOCKED)
         UPDATE relay_push_jobs j SET status = 'running', attempts = j.attempts + 1,
            locked_until = now() + make_interval(secs => $3)
         FROM due WHERE j.id = due.id
         RETURNING j.id, j.kind, j.payload, j.attempts, due.was",
    )
    .bind(kinds)
    .bind(BATCH)
    .bind(CLAIM_TIMEOUT_SECONDS as f64)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .iter()
        .map(|r| {
            let job = Claimed {
                id: r.get("id"),
                kind: r.get("kind"),
                payload: r.get("payload"),
                attempts: r.get("attempts"),
            };
            if r.get::<String, _>("was") == "running" {
                tracing::warn!(job_id = %job.id, kind = %job.kind, attempt = job.attempts, "push job claim timed out; sending again");
            }
            job
        })
        .collect())
}

/// Records how a claimed job ended; a no-op if the claim was lost to another worker meanwhile.
pub async fn finish(
    pool: &PgPool,
    job: &Claimed,
    result: Result<(), JobError>,
) -> Result<(), sqlx::Error> {
    let (status, error, delay) = match &result {
        Ok(()) => ("done", None, 0),
        Err(e) if e.retry && job.attempts < MAX_ATTEMPTS => {
            ("pending", Some(e.tag), RETRY_DELAY_SECONDS)
        }
        Err(e) => ("dead", Some(e.tag), 0),
    };
    if let Some(tag) = error {
        tracing::warn!(job_id = %job.id, kind = %job.kind, attempt = job.attempts, error = tag, status, "push job failed");
    }
    sqlx::query(
        "UPDATE relay_push_jobs SET status = $3, last_error = coalesce($4, last_error),
            locked_until = NULL, run_at = now() + make_interval(secs => $5)
         WHERE id = $1 AND status = 'running' AND attempts = $2",
    )
    .bind(job.id)
    .bind(job.attempts)
    .bind(status)
    .bind(error)
    .bind(delay as f64)
    .execute(pool)
    .await?;
    Ok(())
}

/// One claim-and-process pass; returns the number of jobs claimed.
pub async fn run_once(push: &Push) -> Result<usize, sqlx::Error> {
    let mut kinds = Vec::new();
    if push.config.apns.is_some() && push.config.apns_enabled {
        kinds.push("apns");
    }
    if push.config.fcm.is_some() && push.config.fcm_enabled {
        kinds.push("fcm");
    }
    if kinds.is_empty() {
        return Ok(0);
    }
    let jobs = claim(&push.pool, &kinds).await?;
    for job in &jobs {
        let result = match job.kind.as_str() {
            "apns" => super::apns::process(push, job.id, &job.payload).await,
            _ => super::fcm::process(push, &job.payload).await,
        };
        finish(&push.pool, job, result).await?;
    }
    Ok(jobs.len())
}

/// The delivery loop: polls every second while idle.
pub async fn work(push: std::sync::Arc<Push>) {
    loop {
        match run_once(&push).await {
            Ok(n) if n > 0 => continue,
            Ok(_) => {}
            Err(e) => tracing::error!(error = %e, "push worker could not claim jobs"),
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}
