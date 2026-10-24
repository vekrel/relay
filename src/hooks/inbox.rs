// Held webhooks while a machine is offline. Port of T3 Code's `infra/relay/src/hooks/HookInboxStore.ts`
// and `HookInboxObject.ts` (MIT, Copyright (c) T3 Tools Inc.; see NOTICE): T3 keeps one Durable Object
// per endpoint with an alarm; here the rows of every endpoint share `relay_held_hooks` (keyed by
// `endpoint_key`), the alarm is `relay_held_hook_targets.next_attempt_at_ms`, and a background task
// claims due endpoints under a lease (`locked_until_ms`), so replicas never deliver one endpoint at
// once and a crashed claim is retried after the lease. Caps, TTL, batch size and backoff are T3's.
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Map, Value};
use sqlx::{PgConnection, PgPool, Row};
use uuid::Uuid;

use super::upstream::{self, Hook, TUNNEL_OFFLINE_STATUS};
use crate::machines::{Relay, now_ms};

/// `HOOK_INBOX_TTL_MS`.
pub const TTL_MS: i64 = 24 * 60 * 60 * 1000;
/// `HOOK_INBOX_MAX_REQUESTS`.
pub const MAX_REQUESTS: i64 = 1_000;
/// `HOOK_INBOX_MAX_BYTES`.
pub const MAX_BYTES: i64 = 50 * 1_048_576;
/// `HOOK_INBOX_MAX_PER_HOOK`: the relay cannot check tokens, so junk sent to one hook id cannot
/// crowd out the others.
pub const MAX_PER_HOOK: i64 = 100;
/// `DELIVERIES_PER_RUN`.
const DELIVERIES_PER_RUN: usize = 20;
/// `ROWS_READ_PER_PAGE`.
const ROWS_READ_PER_PAGE: i64 = 50;
/// `BUSY_RETRY_MS`.
const BUSY_RETRY_MS: i64 = 30_000;
/// `MAX_RETRY_DELAY`.
const MAX_RETRY_DELAY_MS: i64 = 10 * 60_000;
/// `MAX_COUNTED_FAILURES`.
const MAX_COUNTED_FAILURES: i32 = 25;
/// `HookInboxObject` `RUN_FAILURE_RETRY_MS`.
const RUN_FAILURE_RETRY_MS: i64 = 60_000;
/// A claim covers one run: at most 20 sends of 8 s each, plus database time.
const LEASE_MS: i64 = 5 * 60_000;
/// At most this many endpoints are delivered at once per replica.
pub const MAX_CONCURRENT_RUNS: usize = 8;
/// How often the background task looks for due endpoints (T3's alarm fires at the due time; a wake
/// sets the due time to now, so it waits at most this long).
const POLL: Duration = Duration::from_secs(1);
const PRUNE_EVERY: Duration = Duration::from_secs(60);

/// `retrySchedule` / `retryDelayMs`: a wake means the tunnel just connected, but Cloudflare can take
/// a few minutes to route to it, so the first 18 tries (3 minutes) are 10 s apart; then 30 s, 1 min,
/// 2 min, ... up to 10 min.
pub fn retry_delay_ms(failures: i32) -> i64 {
    let attempt = failures.clamp(1, MAX_COUNTED_FAILURES) as i64;
    if attempt <= 18 {
        10_000
    } else {
        (30_000i64 << (attempt - 19)).min(MAX_RETRY_DELAY_MS)
    }
}

fn iso(ms: i64) -> String {
    crate::auth::dpop_proofs::iso_millis(ms)
}

/// Serializes holds per endpoint, so the caps hold however many requests arrive at once (T3 gets
/// this from the Durable Object running one request at a time).
async fn lock_endpoint(conn: &mut PgConnection, endpoint_key: &str) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("relay-held-hooks:{endpoint_key}"))
        .execute(conn)
        .await?;
    Ok(())
}

/// What `hold` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Held {
    Stored,
    /// The inbox is full (or the id is already held): T3's `false`.
    Full,
    /// Vekrel: no active managed link of an enabled user holds webhooks for this endpoint (any
    /// more). Checked under the endpoint lock, so a hold racing an unlink, opt-out or disable
    /// (each clears under the same lock) stores nothing.
    NotAllowed,
}

/// The endpoint key names an active managed link that opted in, of a user who is not disabled.
const AUTHORIZED: &str = "EXISTS (SELECT 1 FROM relay_managed_endpoint_allocations a
    JOIN users u ON u.id = a.user_id AND u.disabled_at IS NULL
    JOIN relay_machine_links l ON l.user_id = a.user_id AND l.machine_id = a.machine_id
     AND l.revoked_at IS NULL AND l.hold_webhooks_while_offline
     AND l.endpoint_provider_kind = 'cloudflare_tunnel'
    WHERE right(a.tunnel_name, 17) = '-' || $1)";

/// `hold`: stores the request; the first attempt is due after the current backoff.
pub async fn hold(
    pool: &PgPool,
    endpoint_key: &str,
    base_url: &str,
    hook: &Hook,
) -> Result<Held, sqlx::Error> {
    let mut tx = pool.begin().await?;
    lock_endpoint(&mut tx, endpoint_key).await?;
    let allowed: bool = sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT {AUTHORIZED}")))
        .bind(endpoint_key)
        .fetch_one(&mut *tx)
        .await?;
    if !allowed {
        return Ok(Held::NotAllowed);
    }
    let inserted = sqlx::query(
        "INSERT INTO relay_held_hooks (id, endpoint_key, received_at, method, raw_hook_id,
            raw_token, hook_key, query, headers, body)
         SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10
         WHERE (SELECT count(*) FROM relay_held_hooks WHERE endpoint_key = $2) < $11
           AND (SELECT count(*) FROM relay_held_hooks WHERE endpoint_key = $2 AND hook_key = $7) < $12
           AND (SELECT coalesce(sum(length(body)), 0) FROM relay_held_hooks WHERE endpoint_key = $2)
               + length($10) <= $13
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(&hook.id)
    .bind(endpoint_key)
    .bind(&hook.received_at)
    .bind(&hook.method)
    .bind(&hook.raw_hook_id)
    .bind(&hook.raw_token)
    .bind(&hook.hook_key)
    .bind(&hook.query)
    .bind(Value::Object(hook.headers.clone()).to_string())
    .bind(&hook.body)
    .bind(MAX_REQUESTS)
    .bind(MAX_PER_HOOK)
    .bind(MAX_BYTES)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if inserted == 0 {
        tracing::info!(endpoint_key, "held webhook refused: inbox full");
        return Ok(Held::Full);
    }
    let failures: i32 = sqlx::query_scalar(
        "INSERT INTO relay_held_hook_targets (endpoint_key, base_url) VALUES ($1, $2)
         ON CONFLICT (endpoint_key) DO UPDATE SET base_url = EXCLUDED.base_url
         RETURNING failures",
    )
    .bind(endpoint_key)
    .bind(base_url)
    .fetch_one(&mut *tx)
    .await?;
    schedule_by(&mut tx, endpoint_key, now_ms() + retry_delay_ms(failures)).await?;
    tx.commit().await?;
    Ok(Held::Stored)
}

/// `scheduleBy`: never pushes an earlier due time out.
async fn schedule_by(
    conn: &mut PgConnection,
    endpoint_key: &str,
    at: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE relay_held_hook_targets
         SET next_attempt_at_ms = LEAST(coalesce(next_attempt_at_ms, $2), $2)
         WHERE endpoint_key = $1",
    )
    .bind(endpoint_key)
    .bind(at)
    .execute(conn)
    .await?;
    Ok(())
}

/// `wake`: when requests are held, deliver now with the backoff reset. True when any are held.
pub async fn wake(pool: &PgPool, endpoint_key: &str, base_url: &str) -> Result<bool, sqlx::Error> {
    let now = now_ms();
    let pending = sqlx::query(
        "INSERT INTO relay_held_hook_targets (endpoint_key, base_url, failures, next_attempt_at_ms)
         SELECT $1, $2, 0, $3
         WHERE EXISTS (SELECT 1 FROM relay_held_hooks WHERE endpoint_key = $1)
         ON CONFLICT (endpoint_key) DO UPDATE SET base_url = EXCLUDED.base_url, failures = 0,
            next_attempt_at_ms = $3",
    )
    .bind(endpoint_key)
    .bind(base_url)
    .bind(now)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(pending > 0)
}

/// `clear`: drops every held request of the endpoint. Takes the endpoint lock (held to the end of
/// the caller's transaction), so it serializes with `hold`.
pub async fn clear(conn: &mut PgConnection, endpoint_key: &str) -> Result<u64, sqlx::Error> {
    lock_endpoint(conn, endpoint_key).await?;
    let n = sqlx::query("DELETE FROM relay_held_hooks WHERE endpoint_key = $1")
        .bind(endpoint_key)
        .execute(&mut *conn)
        .await?
        .rows_affected();
    sqlx::query("DELETE FROM relay_held_hook_targets WHERE endpoint_key = $1")
        .bind(endpoint_key)
        .execute(conn)
        .await?;
    Ok(n)
}

/// Drops the held requests of every endpoint the user's allocations own (a disabled user's
/// machines must not get them later).
pub async fn clear_for_user(conn: &mut PgConnection, user_id: Uuid) -> Result<u64, sqlx::Error> {
    let keys: Vec<String> = sqlx::query_scalar(
        "SELECT tunnel_name FROM relay_managed_endpoint_allocations WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_all(&mut *conn)
    .await?;
    let mut n = 0;
    for key in keys
        .iter()
        .filter_map(|t| super::endpoint_key_for_tunnel_name(t))
    {
        n += clear(conn, &key).await?;
    }
    Ok(n)
}

/// Deletes held requests past the TTL (T3 does it at the start of each delivery run).
pub async fn prune_expired(pool: &PgPool) -> Result<u64, sqlx::Error> {
    Ok(
        sqlx::query("DELETE FROM relay_held_hooks WHERE received_at < $1")
            .bind(iso(now_ms() - TTL_MS))
            .execute(pool)
            .await?
            .rows_affected(),
    )
}

/// `DeliveryOutcome`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Delivered,
    /// The machine is there but did not take it yet: queue full (429) or failed (500). It drops a
    /// delivery id it already ran, so retrying is safe.
    Busy,
    Unreachable,
    /// Vekrel: the machine URL is refused (`upstream::checked_url`); it can never be delivered.
    Refused,
}

/// `HookInboxObject` `deliver`.
async fn deliver(relay: &Relay, base_url: &str, hook: &Hook) -> Outcome {
    let (outcome, reason) = match upstream::send(relay, base_url, hook).await {
        Err(upstream::INVALID_URL) => (Outcome::Refused, upstream::INVALID_URL.to_owned()),
        Err(tag) => (Outcome::Unreachable, tag.to_owned()),
        Ok(None) => (Outcome::Unreachable, "timeout".to_owned()),
        Ok(Some(r)) => {
            let o = match r.status {
                502 | 503 | 504 | TUNNEL_OFFLINE_STATUS => Outcome::Unreachable,
                429 | 500 => Outcome::Busy,
                _ => Outcome::Delivered,
            };
            (o, format!("status {}", r.status))
        }
    };
    if outcome != Outcome::Delivered {
        tracing::info!(?outcome, reason, delivery_id = %hook.id, "held webhook not delivered yet");
    }
    outcome
}

fn decode_headers(text: &str) -> Option<Map<String, Value>> {
    match serde_json::from_str(text).ok()? {
        Value::Object(m) if m.values().all(Value::is_string) => Some(m),
        _ => None,
    }
}

async fn still_held(pool: &PgPool, seq: i64) -> Result<bool, sqlx::Error> {
    Ok(
        sqlx::query_scalar::<_, i64>("SELECT seq FROM relay_held_hooks WHERE seq = $1")
            .bind(seq)
            .fetch_optional(pool)
            .await?
            .is_some(),
    )
}

/// The endpoint may still get its held requests (the hold's `AUTHORIZED` check).
async fn authorized(pool: &PgPool, endpoint_key: &str) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT {AUTHORIZED}")))
        .bind(endpoint_key)
        .fetch_one(pool)
        .await
}

/// Drops everything held for the endpoint (its own transaction).
async fn drop_all(pool: &PgPool, endpoint_key: &str, why: &'static str) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    let n = clear(&mut tx, endpoint_key).await?;
    tx.commit().await?;
    tracing::info!(endpoint_key, dropped = n, why, "held webhooks dropped");
    Ok(())
}

async fn has_pending(pool: &PgPool, endpoint_key: &str) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM relay_held_hooks WHERE endpoint_key = $1)")
        .bind(endpoint_key)
        .fetch_one(pool)
        .await
}

async fn reset_failures(pool: &PgPool, endpoint_key: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE relay_held_hook_targets SET failures = 0 WHERE endpoint_key = $1")
        .bind(endpoint_key)
        .execute(pool)
        .await?;
    Ok(())
}

/// `deliverDue` for one endpoint: oldest first, at most 20 sends; stops at the first unreachable
/// answer and backs off; a busy hook's later requests wait while other hooks go on. Returns when
/// the endpoint is next due (`None`: nothing left).
pub async fn deliver_due(
    relay: &Relay,
    endpoint_key: &str,
    mut failures: i32,
) -> Result<Option<i64>, sqlx::Error> {
    let pool = &relay.pool;
    let started_at = now_ms();
    // Vekrel: the endpoint must still be allowed its held requests (active link, hold on, user
    // enabled); if not, drop them instead of delivering. The base URL is the one resolved now.
    let resolved = super::held::resolve_endpoint(relay, endpoint_key).await?;
    let Some(endpoint) = resolved.filter(|e| e.hold_while_offline) else {
        drop_all(pool, endpoint_key, "endpoint no longer holds").await?;
        return Ok(None);
    };
    // T3 `deliverDue` starts by deleting what is past the TTL.
    sqlx::query("DELETE FROM relay_held_hooks WHERE endpoint_key = $1 AND received_at < $2")
        .bind(endpoint_key)
        .bind(iso(started_at - TTL_MS))
        .execute(pool)
        .await?;
    let base_url = endpoint.http_base_url.as_str();
    let read_page = |after: i64, skip: Vec<String>| {
        sqlx::query(
            "SELECT seq, id, received_at, method, raw_hook_id, raw_token, hook_key, query, headers,
                    body
             FROM relay_held_hooks
             WHERE endpoint_key = $1 AND seq > $2 AND hook_key <> ALL($3)
             ORDER BY seq LIMIT $4",
        )
        .bind(endpoint_key.to_owned())
        .bind(after)
        .bind(skip)
        .bind(ROWS_READ_PER_PAGE)
        .fetch_all(pool)
    };
    let mut batch = read_page(0, vec![]).await?;
    if batch.is_empty() {
        reset_failures(pool, endpoint_key).await?;
        return Ok(None);
    }
    let mut sent = 0;
    let mut delivered = 0;
    let mut busy: HashSet<String> = HashSet::new();
    // Pages run out only once every non-busy request has been tried, so a backlog behind busy
    // hooks never hides another hook's requests.
    'pages: while let Some(last) = batch.last().map(|r| r.get::<i64, _>("seq")) {
        for row in &batch {
            if sent == DELIVERIES_PER_RUN {
                break 'pages;
            }
            let hook_key: String = row.get("hook_key");
            if busy.contains(&hook_key) {
                continue;
            }
            let seq: i64 = row.get("seq");
            // Clear can discard this prefetched page while a send is in flight.
            if !still_held(pool, seq).await? {
                return Ok(None);
            }
            let id: String = row.get("id");
            let Some(headers) = decode_headers(row.get("headers")) else {
                // Unreadable: it can never be delivered and must not block the rest.
                sqlx::query("DELETE FROM relay_held_hooks WHERE id = $1")
                    .bind(&id)
                    .execute(pool)
                    .await?;
                continue;
            };
            // Vekrel: authorization is re-checked before every send, so an unlink, opt-out or
            // disable during a run stops it (and drops the rest).
            if !authorized(pool, endpoint_key).await? {
                drop_all(pool, endpoint_key, "endpoint no longer holds").await?;
                return Ok(None);
            }
            sent += 1;
            let hook = Hook {
                id: id.clone(),
                received_at: row.get("received_at"),
                method: row.get("method"),
                raw_hook_id: row.get("raw_hook_id"),
                raw_token: row.get("raw_token"),
                hook_key: hook_key.clone(),
                query: row.get("query"),
                headers,
                body: row.get("body"),
            };
            let outcome = deliver(relay, base_url, &hook).await;
            // A cleared request must neither advance this run nor schedule a retry.
            if !still_held(pool, seq).await? {
                return Ok(None);
            }
            if outcome == Outcome::Unreachable {
                // Incremented in place, so a wake that reset the count meanwhile is kept.
                let f: Option<i32> = sqlx::query_scalar(
                    "UPDATE relay_held_hook_targets SET failures = LEAST(failures + 1, $2)
                     WHERE endpoint_key = $1 RETURNING failures",
                )
                .bind(endpoint_key)
                .bind(MAX_COUNTED_FAILURES)
                .fetch_optional(pool)
                .await?;
                return Ok(Some(now_ms() + retry_delay_ms(f.unwrap_or(1))));
            }
            if failures != 0 {
                failures = 0;
                reset_failures(pool, endpoint_key).await?;
            }
            if outcome == Outcome::Busy {
                busy.insert(hook_key);
                continue;
            }
            // Refused: dropped like a delivered request, never retried and never an outage.
            sqlx::query("DELETE FROM relay_held_hooks WHERE id = $1")
                .bind(&id)
                .execute(pool)
                .await?;
            delivered += 1;
        }
        batch = read_page(last, busy.iter().cloned().collect()).await?;
    }
    if !has_pending(pool, endpoint_key).await? {
        reset_failures(pool, endpoint_key).await?;
        tracing::info!(
            endpoint_key,
            delivered,
            elapsed_ms = now_ms() - started_at,
            "held webhooks drained"
        );
        return Ok(None);
    }
    let now = now_ms();
    Ok(Some(if delivered == 0 && !busy.is_empty() {
        now + BUSY_RETRY_MS
    } else {
        now
    }))
}

/// One due endpoint, leased to this caller: `(endpoint_key, failures, lease_mark)`.
pub(crate) async fn claim(pool: &PgPool) -> Result<Option<Claim>, sqlx::Error> {
    let now = now_ms();
    let mark = now + LEASE_MS;
    // The due time moves to the lease end, so a crashed claim is due again when its lease ends.
    let row = sqlx::query(
        "UPDATE relay_held_hook_targets SET locked_until_ms = $2, next_attempt_at_ms = $2
         WHERE endpoint_key = (
            SELECT endpoint_key FROM relay_held_hook_targets
            WHERE next_attempt_at_ms <= $1 AND (locked_until_ms IS NULL OR locked_until_ms <= $1)
            ORDER BY next_attempt_at_ms LIMIT 1 FOR UPDATE SKIP LOCKED)
         RETURNING endpoint_key, failures",
    )
    .bind(now)
    .bind(mark)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| (r.get(0), r.get(1), mark)))
}

/// Ends a claim. A hold or wake during the run moved the due time off the lease mark; keep the
/// earlier of the two then (T3's `scheduleBy` after the alarm).
async fn release(
    pool: &PgPool,
    endpoint_key: &str,
    mark: i64,
    next: Option<i64>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE relay_held_hook_targets SET locked_until_ms = NULL, next_attempt_at_ms = CASE
            WHEN next_attempt_at_ms IS DISTINCT FROM $2
                THEN LEAST(next_attempt_at_ms, coalesce($3, next_attempt_at_ms))
            WHEN $3 IS NOT NULL THEN $3
            WHEN EXISTS (SELECT 1 FROM relay_held_hooks WHERE endpoint_key = $1) THEN $2
            ELSE NULL END
         WHERE endpoint_key = $1 AND locked_until_ms = $2",
    )
    .bind(endpoint_key)
    .bind(mark)
    .bind(next)
    .execute(pool)
    .await?;
    Ok(())
}

pub(crate) type Claim = (String, i32, i64);

async fn run_claimed(relay: &Relay, (key, failures, mark): Claim) -> Result<(), sqlx::Error> {
    let next = match deliver_due(relay, &key, failures).await {
        Ok(next) => next,
        Err(e) => {
            tracing::warn!(error = %e, endpoint_key = %key, "held webhook delivery run failed");
            Some(now_ms() + RUN_FAILURE_RETRY_MS)
        }
    };
    release(&relay.pool, &key, mark, next).await
}

/// Claims and runs due endpoints one after another until none is due; how many runs it made.
#[cfg(test)]
pub async fn run_due(relay: &Relay) -> Result<usize, sqlx::Error> {
    let mut runs = 0;
    while let Some(c) = claim(&relay.pool).await? {
        runs += 1;
        run_claimed(relay, c).await?;
    }
    Ok(runs)
}

/// Claims due endpoints while a run slot is free and runs each on its own task, so one slow
/// machine never holds up the others. A slot is taken before the claim, so no lease ticks while
/// a claimed endpoint waits for one.
pub async fn dispatch_due(relay: &Arc<Relay>, runs: &Arc<tokio::sync::Semaphore>) {
    loop {
        let Ok(slot) = runs.clone().acquire_owned().await else {
            return;
        };
        match claim(&relay.pool).await {
            Ok(Some(c)) => {
                let relay = relay.clone();
                tokio::spawn(async move {
                    if let Err(e) = run_claimed(&relay, c).await {
                        tracing::warn!(error = %e, "held webhook claim release failed");
                    }
                    drop(slot);
                });
            }
            Ok(None) => return,
            Err(e) => {
                tracing::warn!(error = %e, "held webhook claim failed");
                return;
            }
        }
    }
}

/// The background task: prunes expired requests and delivers due endpoints. Safe on any number of
/// replicas (claims are leased with `SKIP LOCKED`).
pub async fn worker(relay: Arc<Relay>) {
    let runs = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_RUNS));
    let mut last_prune: Option<tokio::time::Instant> = None;
    loop {
        if last_prune.is_none_or(|t| t.elapsed() >= PRUNE_EVERY) {
            last_prune = Some(tokio::time::Instant::now());
            match prune_expired(&relay.pool).await {
                Ok(0) => {}
                Ok(n) => tracing::info!(pruned = n, "expired held webhooks deleted"),
                Err(e) => tracing::warn!(error = %e, "held webhook prune failed"),
            }
        }
        dispatch_due(&relay, &runs).await;
        tokio::time::sleep(POLL).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_follows_t3s_schedule() {
        assert_eq!(retry_delay_ms(0), 10_000);
        assert_eq!(retry_delay_ms(1), 10_000);
        assert_eq!(retry_delay_ms(18), 10_000);
        assert_eq!(retry_delay_ms(19), 30_000);
        assert_eq!(retry_delay_ms(20), 60_000);
        assert_eq!(retry_delay_ms(23), 480_000);
        assert_eq!(retry_delay_ms(24), 600_000);
        assert_eq!(retry_delay_ms(99), 600_000);
    }
}
