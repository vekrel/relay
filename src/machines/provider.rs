// The managed-endpoint (Cloudflare tunnel) seam: the interface of T3 Code's
// `infra/relay/src/environments/ManagedEndpointProvider.ts` (MIT, Copyright (c) T3 Tools Inc.;
// see NOTICE). Task 10 implements it against the Cloudflare API (`src/tunnels/*`); until then the
// relay runs `NoTunnels`, which answers as T3 does when Cloudflare is not configured.
use std::future::Future;
use std::pin::Pin;

use serde::Serialize;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use super::{Endpoint, Origin};

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// `RelayManagedEndpointRuntimeConfig`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeConfig {
    pub provider_kind: String,
    pub connector_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tunnel_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tunnel_name: Option<String>,
}

/// `ManagedEndpointProvisioningResult`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provisioned {
    pub endpoint: Endpoint,
    pub runtime: RuntimeConfig,
}

/// `ManagedEndpointProviderError`.
#[derive(Debug)]
#[cfg_attr(not(test), allow(dead_code))] // `Failed`, `LimitExceeded`: the Cloudflare provider (Task 10)
pub enum ProviderError {
    /// `ManagedEndpointProvisioningNotConfigured`.
    NotConfigured,
    /// `ManagedEndpointProvisioningFailed` with its stage (e.g. `ensure-tunnel`).
    Failed { stage: &'static str },
    /// `ManagedEndpointOriginNotAllowed`.
    OriginNotAllowed,
    /// `ManagedTunnelLimitExceeded`.
    LimitExceeded { max_tunnels: i32 },
}

/// `ManagedEndpointDeprovisioningFailed` with its stage.
#[derive(Debug)]
pub struct DeprovisionFailed {
    pub stage: &'static str,
}

/// `ManagedEndpointOriginSyncResult`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginSync {
    Ready,
    RecoveryRequired,
}

impl OriginSync {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::RecoveryRequired => "recovery_required",
        }
    }
}

/// A `relay_managed_endpoint_allocations` row (`ManagedEndpointAllocation`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allocation {
    pub hostname: String,
    pub tunnel_id: Option<String>,
    pub tunnel_name: String,
    pub dns_record_id: Option<String>,
    pub ready_at: Option<String>,
    pub tunnel_released_at: Option<String>,
    pub generation: i32,
}

/// `ManagedEndpointAllocations.get`.
pub async fn allocation(
    pool: &PgPool,
    user_id: Uuid,
    machine_id: &str,
) -> Result<Option<Allocation>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT hostname, tunnel_id, tunnel_name, dns_record_id, ready_at, tunnel_released_at,
                generation
         FROM relay_managed_endpoint_allocations WHERE user_id = $1 AND machine_id = $2",
    )
    .bind(user_id)
    .bind(machine_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| Allocation {
        hostname: r.get(0),
        tunnel_id: r.get(1),
        tunnel_name: r.get(2),
        dns_record_id: r.get(3),
        ready_at: r.get(4),
        tunnel_released_at: r.get(5),
        generation: r.get(6),
    }))
}

/// `ManagedEndpointProvider` (plus `ManagedEndpointAllocations.enableRecovery`, which only the
/// recovery routes call and which belongs with the allocations Task 10 owns).
pub trait ManagedEndpoints: Send + Sync {
    fn provision<'a>(
        &'a self,
        user_id: Uuid,
        machine_id: &'a str,
        origin: &'a Origin,
        reuse_ready_tunnel: bool,
    ) -> BoxFuture<'a, Result<Provisioned, ProviderError>>;

    fn reconcile_origin<'a>(
        &'a self,
        user_id: Uuid,
        machine_id: &'a str,
        tunnel_id: &'a str,
        origin: &'a Origin,
        endpoint: &'a Endpoint,
    ) -> BoxFuture<'a, Result<OriginSync, ProviderError>>;

    /// Captures the allocation an unlink owns before its revocation commits.
    fn prepare_deprovision<'a>(
        &'a self,
        user_id: Uuid,
        machine_id: &'a str,
    ) -> BoxFuture<'a, Result<Option<Allocation>, DeprovisionFailed>>;

    /// `target: None` loads the allocation itself (T3's `target === undefined`).
    fn deprovision<'a>(
        &'a self,
        user_id: Uuid,
        machine_id: &'a str,
        target: Option<Option<Allocation>>,
    ) -> BoxFuture<'a, Result<bool, DeprovisionFailed>>;

    /// True when the caller's connector token is now dead.
    fn release<'a>(
        &'a self,
        user_id: Uuid,
        machine_id: &'a str,
        expected_tunnel_id: Option<&'a str>,
    ) -> BoxFuture<'a, Result<bool, DeprovisionFailed>>;

    fn enable_recovery<'a>(
        &'a self,
        user_id: Uuid,
        machine_id: &'a str,
        tunnel_id: &'a str,
        machine_public_key: &'a str,
        origin: &'a Origin,
    ) -> BoxFuture<'a, Result<bool, sqlx::Error>>;
}

/// `isLoopbackOrigin` (`EnvironmentLinker.ts` `isLoopbackManagedTunnelOrigin`).
pub fn is_loopback_origin(origin: &Origin) -> bool {
    let host = origin.local_http_host.trim().to_lowercase();
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(&host);
    matches!(host, "127.0.0.1" | "::1" | "localhost")
        && (1..=65_535).contains(&origin.local_http_port)
}

/// No Cloudflare: `provision` checks the origin, then answers `NotConfigured` as T3's
/// `requireCloudflareSettings` does; nothing was ever allocated, so teardown has nothing to do.
// shortcut: assumes no allocation rows exist (only Task 10 writes them); Task 10 replaces this.
pub struct NoTunnels;

impl ManagedEndpoints for NoTunnels {
    fn provision<'a>(
        &'a self,
        _: Uuid,
        _: &'a str,
        origin: &'a Origin,
        _: bool,
    ) -> BoxFuture<'a, Result<Provisioned, ProviderError>> {
        let loopback = is_loopback_origin(origin);
        Box::pin(async move {
            Err(if loopback {
                ProviderError::NotConfigured
            } else {
                ProviderError::OriginNotAllowed
            })
        })
    }

    fn reconcile_origin<'a>(
        &'a self,
        _: Uuid,
        _: &'a str,
        _: &'a str,
        _: &'a Origin,
        _: &'a Endpoint,
    ) -> BoxFuture<'a, Result<OriginSync, ProviderError>> {
        // No ready allocation records this tunnel.
        Box::pin(async { Ok(OriginSync::RecoveryRequired) })
    }

    fn prepare_deprovision<'a>(
        &'a self,
        _: Uuid,
        _: &'a str,
    ) -> BoxFuture<'a, Result<Option<Allocation>, DeprovisionFailed>> {
        Box::pin(async { Ok(None) })
    }

    fn deprovision<'a>(
        &'a self,
        _: Uuid,
        _: &'a str,
        _: Option<Option<Allocation>>,
    ) -> BoxFuture<'a, Result<bool, DeprovisionFailed>> {
        Box::pin(async { Ok(true) })
    }

    fn release<'a>(
        &'a self,
        _: Uuid,
        _: &'a str,
        _: Option<&'a str>,
    ) -> BoxFuture<'a, Result<bool, DeprovisionFailed>> {
        Box::pin(async { Ok(true) })
    }

    fn enable_recovery<'a>(
        &'a self,
        _: Uuid,
        _: &'a str,
        _: &'a str,
        _: &'a str,
        _: &'a Origin,
    ) -> BoxFuture<'a, Result<bool, sqlx::Error>> {
        Box::pin(async { Ok(false) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_loopback_origins_are_allowed() {
        let o = |h: &str, p| Origin {
            local_http_host: h.into(),
            local_http_port: p,
        };
        for ok in ["127.0.0.1", "::1", "[::1]", "localhost", " LOCALHOST "] {
            assert!(is_loopback_origin(&o(ok, 3773)), "{ok}");
        }
        for bad in [
            "10.0.0.2",
            "example.com",
            "127.0.0.2",
            "0.0.0.0",
            "localhost.evil",
        ] {
            assert!(!is_loopback_origin(&o(bad, 3773)), "{bad}");
        }
        assert!(!is_loopback_origin(&o("127.0.0.1", 0)));
        assert!(!is_loopback_origin(&o("127.0.0.1", 65_536)));
    }
}
