// Idle tunnel cleanup: a port of T3 Code's `infra/relay/src/environments/ManagedEndpointReaper.ts`
// (MIT, Copyright (c) T3 Tools Inc.; see NOTICE). Lists this stage's down and never-connected
// tunnels past their grace period, keeps every tunnel without a fully recorded owner, and releases
// the rest through the provider's generation-checked claim, which re-reads the tunnel from
// Cloudflare first, so a tunnel that reconnected meanwhile is never deleted. `dry-run` only counts.
use std::collections::HashMap;
use std::sync::Mutex;

use serde::Serialize;

use super::allocations::{self, TunnelAllocation};
use super::cloudflare::{ApiError, ListRequest, Tunnel, parse_time};
use super::provider::{CloudflareTunnels, ExpectInactive};
use crate::auth::dpop_proofs::iso_millis;
use crate::config::{CleanupConfig, CleanupMode};
use crate::machines::now_ms;
use crate::zone;

/// `MANAGED_ENDPOINT_GRACE_PERIOD_MINUTES`.
const GRACE_PERIOD_MINUTES: i64 = 5;
/// `MANAGED_ENDPOINT_INACTIVE_GRACE_PERIOD_MINUTES`: a tunnel that never connected is usually a
/// link still being set up.
const INACTIVE_GRACE_PERIOD_MINUTES: i64 = 60;
const SWEEP_PAGE_SIZE: u32 = 100;
const SWEEP_ATTEMPT_LIMIT: usize = 100;
const SWEEP_LIST_REQUEST_LIMIT: usize = 10;
const LEGACY_AGE_BUCKET_DAYS: [i64; 3] = [7, 30, 90];
/// A machine that never registered recovery cannot replace a deleted tunnel itself.
const LEGACY_GRACE_PERIOD_DAYS: i64 = 7;
/// `MANAGED_ENDPOINT_ZONE_OWNER_STAGE`: only other stages may shorten the legacy grace.
const ZONE_OWNER_STAGE: &str = "prod";
const SWEEP_DELETE_CONCURRENCY: usize = 4;
/// Stop starting deletions this long after the sweep starts.
const SWEEP_DELETE_BUDGET_MS: i64 = 90_000;
const MINUTE_MS: i64 = 60_000;

/// `ManagedEndpointSweepResult`.
#[derive(Debug, Default, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SweepResult {
    pub mode: &'static str,
    pub legacy_mode: &'static str,
    pub list_requests: usize,
    pub scanned: usize,
    pub attempted: usize,
    pub deleted: usize,
    pub would_delete: usize,
    pub would_delete_legacy: usize,
    pub deleted_legacy: usize,
    pub skipped_legacy: usize,
    pub legacy_over7_days: usize,
    pub legacy_over30_days: usize,
    pub legacy_over90_days: usize,
    pub skipped_orphan: usize,
    pub skipped_replaced: usize,
    pub skipped_unrecorded: usize,
    pub total_down: Option<i64>,
    pub total_inactive: Option<i64>,
    pub failed: usize,
    pub truncated: bool,
}

#[derive(Debug)]
pub enum SweepError {
    Cloudflare(ApiError),
    Persistence(sqlx::Error),
}

impl std::fmt::Display for SweepError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cloudflare(e) => write!(f, "cloudflare {} failed: {:?}", e.operation, e.failure),
            Self::Persistence(e) => write!(f, "persistence failed: {e}"),
        }
    }
}

struct Expired {
    id: String,
    name: String,
    tunnel: Tunnel,
    status: &'static str,
    cutoff_ms: i64,
}

/// `isExpiredManagedTunnel`.
fn is_expired(t: &Tunnel, status: &str, prefix: &str, cutoff_ms: i64) -> bool {
    let (Some(_), Some(name)) = (&t.id, &t.name) else {
        return false;
    };
    let suffix = name.strip_prefix(prefix);
    if t.status.as_deref() != Some(status)
        || !suffix.is_some_and(|s| {
            s.len() == 16
                && s.bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        })
    {
        return false;
    }
    inactive_since(t, status).is_some_and(|ms| ms <= cutoff_ms)
}

fn inactive_since(t: &Tunnel, status: &str) -> Option<i64> {
    let since = if status == "down" {
        t.conns_inactive_at.as_deref()
    } else {
        t.created_at.as_deref()
    };
    since.and_then(parse_time)
}

/// `rotatedPages`.
fn rotated_pages(total_count: Option<i64>, slot: i64, limit: usize) -> Vec<u32> {
    if limit == 0 {
        return vec![];
    }
    let Some(total) = total_count else {
        return (0..limit as u32).map(|i| i + 2).collect();
    };
    let later = ((total + SWEEP_PAGE_SIZE as i64 - 1) / SWEEP_PAGE_SIZE as i64 - 1).max(0);
    if later == 0 {
        return vec![];
    }
    let count = (limit as i64).min(later);
    let start = slot.rem_euclid(later);
    (0..count)
        .map(|i| (2 + (start + i) % later) as u32)
        .collect()
}

/// `sweep`.
pub async fn sweep(
    provider: &CloudflareTunnels,
    cleanup: CleanupConfig,
) -> Result<SweepResult, SweepError> {
    let (mode, legacy_mode) = (cleanup.mode, cleanup.legacy_mode);
    let mut r = SweepResult {
        mode: mode.as_str(),
        legacy_mode: legacy_mode.as_str(),
        ..Default::default()
    };
    let Some(namespace) = provider.namespace.as_deref().filter(|n| !n.is_empty()) else {
        return Ok(r);
    };
    if mode == CleanupMode::Off && legacy_mode == CleanupMode::Off {
        return Ok(r);
    }
    let now = now_ms();
    let started = now;
    let legacy_grace_minutes = match cleanup.legacy_grace_minutes {
        Some(m) if namespace != ZONE_OWNER_STAGE => m,
        _ => LEGACY_GRACE_PERIOD_DAYS * 24 * 60,
    };
    let legacy_cutoff = now - legacy_grace_minutes * MINUTE_MS;
    let prefix = zone::tunnel_name_prefix(namespace);
    let slot = now.div_euclid(GRACE_PERIOD_MINUTES * MINUTE_MS);
    let mut expired: Vec<Expired> = Vec::new();

    for status in ["down", "inactive"] {
        let grace = if status == "down" {
            GRACE_PERIOD_MINUTES
        } else {
            INACTIVE_GRACE_PERIOD_MINUTES
        };
        let cutoff_ms = now - grace * MINUTE_MS;
        let cutoff_iso = iso_millis(cutoff_ms);
        let list = |page| ListRequest {
            include_prefix: Some(&prefix),
            status: Some(status),
            existed_at: Some(&cutoff_iso),
            was_inactive_at: (status == "down").then_some(cutoff_iso.as_str()),
            page: Some(page),
            per_page: Some(SWEEP_PAGE_SIZE),
            ..Default::default()
        };
        r.list_requests += 1;
        let first = provider
            .cf
            .list_tunnels(&list(1))
            .await
            .map_err(SweepError::Cloudflare)?;
        let total = first.total_count;
        if status == "down" {
            r.total_down = total;
        } else {
            r.total_inactive = total;
        }
        let mut pages = vec![first];
        for p in rotated_pages(total, slot, SWEEP_LIST_REQUEST_LIMIT / 2 - 1) {
            r.list_requests += 1;
            pages.push(
                provider
                    .cf
                    .list_tunnels(&list(p))
                    .await
                    .map_err(SweepError::Cloudflare)?,
            );
        }
        match total {
            Some(t)
                if (t + SWEEP_PAGE_SIZE as i64 - 1) / (SWEEP_PAGE_SIZE as i64)
                    > pages.len() as i64 =>
            {
                r.truncated = true;
            }
            None if pages.last().map(|p| p.result.len()) == Some(SWEEP_PAGE_SIZE as usize) => {
                r.truncated = true;
            }
            _ => {}
        }
        for page in pages {
            for t in page.result {
                if is_expired(&t, status, &prefix, cutoff_ms) {
                    expired.push(Expired {
                        id: t.id.clone().unwrap_or_default(),
                        name: t.name.clone().unwrap_or_default(),
                        tunnel: t,
                        status,
                        cutoff_ms,
                    });
                }
            }
        }
    }

    // Unique by tunnel id, the last listing winning, in first-seen order (`new Map(...).values()`).
    let mut index: HashMap<String, usize> = HashMap::new();
    let mut collected: Vec<Expired> = Vec::new();
    for e in expired {
        match index.get(&e.id) {
            Some(&i) => collected[i] = e,
            None => {
                index.insert(e.id.clone(), collected.len());
                collected.push(e);
            }
        }
    }
    // Start each sweep one attempt budget further along, so failing deletes cannot starve the rest.
    if !collected.is_empty() {
        let offset = (slot * SWEEP_ATTEMPT_LIMIT as i64).rem_euclid(collected.len() as i64);
        collected.rotate_left(offset as usize);
    }
    r.scanned = collected.len();
    let names: Vec<String> = collected.iter().map(|e| e.name.clone()).collect();
    let recorded = allocations::list_by_tunnel_names(&provider.pool, &names)
        .await
        .map_err(SweepError::Persistence)?;
    let by_name: HashMap<&str, &TunnelAllocation> = recorded
        .iter()
        .map(|a| (a.allocation.tunnel_name.as_str(), a))
        .collect();

    struct Candidate<'a> {
        owner: &'a TunnelAllocation,
        id: String,
        name: String,
        status: &'static str,
        legacy: bool,
        inactive_before: i64,
    }
    let mut candidates: Vec<Candidate> = Vec::new();
    let mut legacy_over = [0usize; 3];
    for e in &collected {
        let alloc = by_name.get(e.name.as_str()).copied();
        if let Some(a) = alloc
            && a.allocation.tunnel_id.as_deref().is_some_and(|t| t != e.id)
        {
            r.skipped_replaced += 1;
            continue;
        }
        let owner = alloc.filter(|a| a.allocation.tunnel_id.as_deref() == Some(e.id.as_str()));
        if alloc.is_some() && owner.is_none() {
            r.skipped_unrecorded += 1;
            continue;
        }
        // A tunnel with no allocation row cannot be claimed, so a relink adopting it by name races
        // any delete here: count it and leave it for a manual sweep.
        let Some(owner) = owner else {
            r.skipped_orphan += 1;
            continue;
        };
        let legacy = !owner.recovery_enabled;
        if legacy {
            r.skipped_legacy += 1;
            if let Some(since) = inactive_since(&e.tunnel, e.status) {
                let days = (now - since) as f64 / 86_400_000.0;
                for (i, d) in LEGACY_AGE_BUCKET_DAYS.iter().enumerate() {
                    if days > *d as f64 {
                        legacy_over[i] += 1;
                    }
                }
            }
            if legacy_mode == CleanupMode::Off
                || !is_expired(&e.tunnel, e.status, &prefix, legacy_cutoff)
            {
                continue;
            }
            r.would_delete_legacy += 1;
            if legacy_mode == CleanupMode::DryRun {
                continue;
            }
        } else {
            if mode == CleanupMode::Off {
                continue;
            }
            r.would_delete += 1;
            if mode == CleanupMode::DryRun {
                tracing::info!(
                    tunnel_id = %e.id,
                    tunnel_name = %e.name,
                    status = e.status,
                    "dry run: would delete an inactive managed tunnel"
                );
                continue;
            }
        }
        if candidates.len() >= SWEEP_ATTEMPT_LIMIT {
            r.truncated = true;
            break;
        }
        candidates.push(Candidate {
            owner,
            id: e.id.clone(),
            name: e.name.clone(),
            status: e.status,
            legacy,
            inactive_before: if legacy { legacy_cutoff } else { e.cutoff_ms },
        });
    }
    [
        r.legacy_over7_days,
        r.legacy_over30_days,
        r.legacy_over90_days,
    ] = legacy_over;

    let deadline = started + SWEEP_DELETE_BUDGET_MS;
    let shared = Mutex::new((false, 0usize, 0usize, 0usize, 0usize, false));
    // (stop, attempted, deleted, deleted_legacy, failed, truncated)
    let queue = Mutex::new(candidates.into_iter());
    let worker = || async {
        loop {
            let Some(c) = queue.lock().unwrap().next() else {
                return;
            };
            {
                let mut s = shared.lock().unwrap();
                if s.0 || now_ms() >= deadline {
                    s.0 = true;
                    s.5 = true;
                    continue;
                }
                s.1 += 1;
            }
            let result = provider
                .release_with(
                    c.owner.user_id,
                    &c.owner.machine_id,
                    Some(&c.id),
                    Some(ExpectInactive {
                        before_ms: c.inactive_before,
                        status: c.status,
                    }),
                    c.legacy,
                )
                .await;
            let mut s = shared.lock().unwrap();
            match result {
                Err(f) => {
                    s.4 += 1;
                    tracing::warn!(
                        tunnel_id = %c.id,
                        tunnel_name = %c.name,
                        legacy = c.legacy,
                        stage = f.stage,
                        "failed to delete an inactive managed tunnel"
                    );
                    if f.retry_after_ms.is_some() {
                        s.0 = true;
                        s.5 = true;
                    }
                }
                Ok(true) => {
                    s.2 += 1;
                    if c.legacy {
                        s.3 += 1;
                    }
                    tracing::info!(
                        tunnel_id = %c.id,
                        tunnel_name = %c.name,
                        status = c.status,
                        legacy = c.legacy,
                        "deleted an inactive managed tunnel"
                    );
                }
                Ok(false) => {}
            }
        }
    };
    let workers: Vec<_> = (0..SWEEP_DELETE_CONCURRENCY).map(|_| worker()).collect();
    futures_join_all(workers).await;
    let (_, attempted, deleted, deleted_legacy, failed, truncated) = *shared.lock().unwrap();
    r.attempted = attempted;
    r.deleted = deleted;
    r.deleted_legacy = deleted_legacy;
    r.failed = failed;
    r.truncated |= truncated;
    Ok(r)
}

/// Runs the futures concurrently on this task (no `futures` dependency for one join).
async fn futures_join_all<F: std::future::Future<Output = ()>>(fs: Vec<F>) {
    let mut set = Vec::new();
    for f in fs {
        set.push(Box::pin(f));
    }
    std::future::poll_fn(|cx| {
        let mut pending = false;
        set.retain_mut(|f| {
            let done = f.as_mut().poll(cx).is_ready();
            pending |= !done;
            !done
        });
        if pending {
            std::task::Poll::Pending
        } else {
            std::task::Poll::Ready(())
        }
    })
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pages_rotate_through_later_pages() {
        assert_eq!(rotated_pages(None, 0, 4), vec![2, 3, 4, 5]);
        assert_eq!(rotated_pages(Some(100), 3, 4), Vec::<u32>::new());
        assert_eq!(rotated_pages(Some(250), 0, 4), vec![2, 3]);
        assert_eq!(rotated_pages(Some(1_000), 5, 4), vec![7, 8, 9, 10]);
        assert_eq!(rotated_pages(Some(1_000), 7, 4), vec![9, 10, 2, 3]);
    }
}
