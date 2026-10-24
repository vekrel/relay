// Cloudflare tunnel provisioning: a port of T3 Code's
// `infra/relay/src/environments/ManagedEndpointProvider.ts` (MIT, Copyright (c) T3 Tools Inc.; see
// NOTICE). One named tunnel per user and machine, ingress `hostname -> http://127.0.0.1:<port>` then
// `http_status:404` (`:805-815`), a proxied CNAME `<host> -> <tunnelId>.cfargotunnel.com`
// (`:1374-1380`), and the connector token (`:1479`). Each step checkpoints into the allocation row
// under its generation, so a retry resumes and a stale caller changes nothing.
use std::sync::Arc;

use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use super::allocations;
use super::cloudflare::{ApiError, Cloudflare, ListRequest, cname_record, parse_time};
use crate::machines::connector::{endpoint_for_hostname, is_managed_endpoint_hostname};
use crate::machines::limits::{self, LimitError};
use crate::machines::provider::{
    Allocation, BoxFuture, DeprovisionFailed, ManagedEndpoints, OriginSync, ProviderError,
    Provisioned, RuntimeConfig, is_loopback_origin,
};
use crate::machines::{Endpoint, Origin, wire_user_id};
use crate::zone;

pub struct CloudflareTunnels {
    pub cf: Arc<Cloudflare>,
    pub pool: PgPool,
    /// `managedEndpointBaseDomain` (`RELAY_TUNNEL_ZONE_NAME`).
    pub base_domain: Option<String>,
    /// `managedEndpointNamespace` (`RELAY_STAGE`).
    pub namespace: Option<String>,
}

/// `release` options the reaper passes (`expectedInactiveBefore`, `expectedStatus`).
#[derive(Debug, Clone, Copy)]
pub struct ExpectInactive {
    pub before_ms: i64,
    /// `down` (compares `conns_inactive_at`) or `inactive` (compares `created_at`).
    pub status: &'static str,
}

fn failed(stage: &'static str, cause: Option<&ApiError>) -> ProviderError {
    match cause {
        Some(e) => tracing::warn!(
            stage,
            operation = e.operation,
            failure = ?e.failure,
            "managed endpoint provisioning failed"
        ),
        None => tracing::warn!(stage, "managed endpoint provisioning failed"),
    }
    ProviderError::Failed {
        stage,
        retry_after_ms: cause.and_then(ApiError::retry_after_ms),
    }
}

fn failed_db(stage: &'static str, e: sqlx::Error) -> ProviderError {
    tracing::error!(stage, error = %e, "managed endpoint persistence failed");
    ProviderError::Failed {
        stage,
        retry_after_ms: None,
    }
}

/// A claim another provision won (`reason: "claim-lost"`).
fn claim_lost(stage: &'static str) -> ProviderError {
    tracing::warn!(
        stage,
        reason = "claim-lost",
        "managed endpoint provisioning failed"
    );
    ProviderError::Failed {
        stage,
        retry_after_ms: None,
    }
}

fn deprovision_failed(stage: &'static str, cause: &ApiError) -> DeprovisionFailed {
    tracing::warn!(stage, operation = cause.operation, failure = ?cause.failure, "managed endpoint deprovisioning failed");
    DeprovisionFailed {
        stage,
        retry_after_ms: cause.retry_after_ms(),
    }
}

fn deprovision_db(stage: &'static str, e: sqlx::Error) -> DeprovisionFailed {
    tracing::error!(stage, error = %e, "managed endpoint deprovisioning persistence failed");
    DeprovisionFailed {
        stage,
        retry_after_ms: None,
    }
}

/// `ignoreNotFound`.
fn ignore_not_found(r: Result<(), ApiError>) -> Result<(), ApiError> {
    match r {
        Err(e) if e.is_not_found() => Ok(()),
        r => r,
    }
}

/// `formatOriginService`.
pub fn origin_service(origin: &Origin) -> String {
    let h = &origin.local_http_host;
    let host = if h.contains(':') {
        let bare = h
            .strip_prefix('[')
            .and_then(|x| x.strip_suffix(']'))
            .unwrap_or(h);
        format!("[{bare}]")
    } else {
        h.clone()
    };
    format!("http://{host}:{}", origin.local_http_port)
}

fn same_origin(a: Option<&Origin>, b: &Origin) -> bool {
    a.is_some_and(|a| {
        a.local_http_host == b.local_http_host && a.local_http_port == b.local_http_port
    })
}

impl CloudflareTunnels {
    fn settings(&self) -> Result<(&str, &str), ProviderError> {
        match (self.base_domain.as_deref(), self.namespace.as_deref()) {
            (Some(b), Some(n)) if !b.is_empty() && !n.is_empty() => Ok((b, n)),
            _ => Err(ProviderError::NotConfigured),
        }
    }

    /// `updateExistingDnsRecords`.
    async fn update_existing_records(
        &self,
        records: &[String],
        preferred: Option<&str>,
        record: &Value,
    ) -> Result<Option<String>, ApiError> {
        let Some(kept) = records
            .iter()
            .find(|r| Some(r.as_str()) == preferred)
            .or(records.first())
        else {
            return Ok(None);
        };
        for r in records.iter().filter(|r| *r != kept) {
            self.cf.delete_record(r).await?;
        }
        self.cf.update_record(kept, record).await?;
        Ok(Some(kept.clone()))
    }

    /// `ensureDnsRecord`.
    async fn ensure_dns_record(
        &self,
        hostname: &str,
        preferred: Option<&str>,
        record: &Value,
    ) -> Result<String, ApiError> {
        if let Some(id) = preferred {
            match self.cf.update_record(id, record).await {
                Ok(()) => return Ok(id.to_owned()),
                Err(e) if e.is_not_found() => {}
                Err(e) => return Err(e),
            }
        }
        let existing = self.cf.list_records(hostname).await?;
        if let Some(id) = self
            .update_existing_records(&existing, preferred, record)
            .await?
        {
            return Ok(id);
        }
        let create_error = match self.cf.create_record(record).await {
            Ok(id) => return Ok(id),
            Err(e) => e,
        };
        // A create that reports failure may still have made the record visible a moment later.
        let mut records = self.cf.list_records(hostname).await?;
        for _ in 0..4 {
            if !records.is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            records = self.cf.list_records(hostname).await?;
        }
        self.update_existing_records(&records, preferred, record)
            .await?
            .ok_or(create_error)
    }

    /// `reuseReadyTunnel`: a ready tunnel that already serves this origin costs two reads.
    async fn reuse_ready_tunnel(
        &self,
        a: &Allocation,
        origin: &Origin,
    ) -> Result<Option<Provisioned>, ProviderError> {
        let Some(tunnel_id) = a.tunnel_id.as_deref() else {
            return Ok(None);
        };
        if a.ready_at.is_none()
            || a.dns_record_id.is_none()
            || a.tunnel_released_at.is_some()
            || !same_origin(a.origin.as_ref(), origin)
        {
            return Ok(None);
        }
        match self.cf.get_tunnel(tunnel_id).await {
            Err(e) if e.is_not_found() => return Ok(None),
            Err(e) => return Err(failed("verify-tunnel", Some(&e))),
            Ok(t) if t.deleted_at.is_some() => return Ok(None),
            Ok(_) => {}
        }
        let token = self
            .cf
            .get_token(tunnel_id)
            .await
            .map_err(|e| failed("get-tunnel-token", Some(&e)))?;
        Ok(Some(Provisioned {
            endpoint: endpoint_for_hostname(&a.hostname),
            runtime: RuntimeConfig {
                provider_kind: "cloudflare_tunnel".into(),
                connector_token: token,
                tunnel_id: Some(tunnel_id.to_owned()),
                tunnel_name: Some(a.tunnel_name.clone()),
            },
        }))
    }

    async fn provision_impl(
        &self,
        user: Uuid,
        machine_id: &str,
        origin: &Origin,
        reuse_ready_tunnel: bool,
    ) -> Result<Provisioned, ProviderError> {
        if !is_loopback_origin(origin) {
            return Err(ProviderError::OriginNotAllowed);
        }
        let (base_domain, namespace) = self.settings()?;
        let hash = zone::machine_hash(namespace, &wire_user_id(user), machine_id);
        let hostname = zone::hostname(namespace, base_domain, &hash);
        let tunnel_name = zone::tunnel_name(namespace, &hash);
        // Cap check and reservation commit together under the per-user lock.
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| failed_db("check-tunnel-limit", e))?;
        match limits::ensure_capacity(&mut tx, user, machine_id).await {
            Ok(()) => {}
            Err(LimitError::Exceeded {
                max_tunnels,
                active_tunnels,
            }) => {
                tracing::info!(%user, max_tunnels, active_tunnels, "managed tunnel limit reached");
                return Err(ProviderError::LimitExceeded { max_tunnels });
            }
            Err(LimitError::Persistence(e)) => return Err(failed_db("check-tunnel-limit", e)),
        }
        let a = allocations::reserve(&mut tx, user, machine_id, &hostname, &tunnel_name)
            .await
            .map_err(|e| failed_db("reserve-allocation", e))?
            .ok_or_else(|| claim_lost("reserve-allocation"))?;
        tx.commit()
            .await
            .map_err(|e| failed_db("reserve-allocation", e))?;
        let (hostname, tunnel_name) = (a.hostname.clone(), a.tunnel_name.clone());

        if reuse_ready_tunnel && let Some(p) = self.reuse_ready_tunnel(&a, origin).await? {
            return Ok(p);
        }

        let listed = self
            .cf
            .list_tunnels(&ListRequest {
                name: Some(&tunnel_name),
                ..Default::default()
            })
            .await
            .map_err(|e| failed("ensure-tunnel", Some(&e)))?;
        let tunnel = match listed
            .result
            .into_iter()
            .find(|t| t.name.as_deref() == Some(tunnel_name.as_str()))
        {
            Some(t) => t,
            None => self
                .cf
                .create_tunnel(&tunnel_name)
                .await
                .map_err(|e| failed("ensure-tunnel", Some(&e)))?,
        };
        let tunnel_id = match (&tunnel.id, &tunnel.name) {
            (Some(id), Some(name)) if !id.is_empty() && *name == tunnel_name => id.clone(),
            _ => {
                tracing::warn!(
                    stage = "validate-tunnel-response",
                    reason = "invalid-tunnel-response",
                    returned_tunnel_id = tunnel.id.as_deref(),
                    returned_tunnel_name = tunnel.name.as_deref(),
                    "managed endpoint provisioning failed"
                );
                return Err(ProviderError::Failed {
                    stage: "validate-tunnel-response",
                    retry_after_ms: None,
                });
            }
        };
        // A newer provision can adopt this tunnel by name once our claim fails; leave it for that
        // provision or a retry.
        let tunnel_gen =
            allocations::record_tunnel(&self.pool, user, machine_id, &tunnel_id, a.generation)
                .await
                .map_err(|e| failed_db("record-tunnel", e))?
                .ok_or_else(|| claim_lost("record-tunnel"))?;

        let service = origin_service(origin);
        let tx = allocations::lock_claimed(&self.pool, user, machine_id, &tunnel_id, tunnel_gen)
            .await
            .map_err(|e| failed_db("configure-tunnel", e))?
            .ok_or_else(|| claim_lost("configure-tunnel"))?;
        self.cf
            .put_configuration(&tunnel_id, &hostname, &service)
            .await
            .map_err(|e| failed("configure-tunnel", Some(&e)))?;
        tx.commit()
            .await
            .map_err(|e| failed_db("configure-tunnel", e))?;

        let record = cname_record(&hostname, &tunnel_id);
        let mut tx =
            allocations::lock_claimed(&self.pool, user, machine_id, &tunnel_id, tunnel_gen)
                .await
                .map_err(|e| failed_db("record-dns", e))?
                .ok_or_else(|| claim_lost("record-dns"))?;
        let dns_record_id = self
            .ensure_dns_record(&hostname, a.dns_record_id.as_deref(), &record)
            .await
            .map_err(|e| failed("ensure-dns-record", Some(&e)))?;
        let dns_gen = allocations::record_dns(
            &mut tx,
            user,
            machine_id,
            &dns_record_id,
            &tunnel_id,
            tunnel_gen,
        )
        .await
        .map_err(|e| failed_db("record-dns", e))?
        .ok_or_else(|| claim_lost("record-dns"))?;
        tx.commit().await.map_err(|e| failed_db("record-dns", e))?;

        let connector_token = self
            .cf
            .get_token(&tunnel_id)
            .await
            .map_err(|e| failed("get-tunnel-token", Some(&e)))?;
        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(|e| failed_db("mark-allocation-ready", e))?;
        let ready =
            allocations::mark_ready(&mut conn, user, machine_id, &tunnel_id, dns_gen, origin)
                .await
                .map_err(|e| failed_db("mark-allocation-ready", e))?;
        if !ready {
            return Err(claim_lost("mark-allocation-ready"));
        }
        Ok(Provisioned {
            endpoint: endpoint_for_hostname(&hostname),
            runtime: RuntimeConfig {
                provider_kind: "cloudflare_tunnel".into(),
                connector_token,
                tunnel_id: Some(tunnel_id),
                tunnel_name: Some(tunnel_name),
            },
        })
    }

    async fn reconcile_origin_impl(
        &self,
        user: Uuid,
        machine_id: &str,
        tunnel_id: &str,
        origin: &Origin,
        endpoint: &Endpoint,
    ) -> Result<OriginSync, ProviderError> {
        if !is_loopback_origin(origin) {
            return Err(ProviderError::OriginNotAllowed);
        }
        let a = crate::machines::provider::allocation(&self.pool, user, machine_id)
            .await
            .map_err(|e| failed_db("load-allocation", e))?;
        let Some(a) = a.filter(|a| {
            a.tunnel_id.as_deref() == Some(tunnel_id)
                && a.dns_record_id.is_some()
                && a.ready_at.is_some()
        }) else {
            return Ok(OriginSync::RecoveryRequired);
        };
        let (base_domain, _) = self.settings()?;
        // `resolveReadyManagedEndpoint`.
        if !is_managed_endpoint_hostname(&a.hostname, base_domain)
            || endpoint_for_hostname(&a.hostname) != *endpoint
        {
            tracing::warn!(
                stage = "verify-endpoint",
                reason = "endpoint-mismatch",
                "managed endpoint provisioning failed"
            );
            return Err(ProviderError::Failed {
                stage: "verify-endpoint",
                retry_after_ms: None,
            });
        }
        // A release keeps the recorded tunnel id, so only Cloudflare can tell a live tunnel from
        // one deleted by a shutdown whose host died before it dropped its config.
        match self.cf.get_tunnel(tunnel_id).await {
            Err(e) if e.is_not_found() => return Ok(OriginSync::RecoveryRequired),
            Err(e) => return Err(failed("verify-tunnel", Some(&e))),
            Ok(t) if t.deleted_at.is_some() => return Ok(OriginSync::RecoveryRequired),
            Ok(_) => {}
        }
        if same_origin(a.origin.as_ref(), origin) {
            return Ok(OriginSync::Ready);
        }
        let mut tx =
            allocations::lock_claimed(&self.pool, user, machine_id, tunnel_id, a.generation)
                .await
                .map_err(|e| failed_db("sync-origin", e))?
                .ok_or_else(|| claim_lost("sync-origin"))?;
        match self
            .cf
            .put_configuration(tunnel_id, &a.hostname, &origin_service(origin))
            .await
        {
            Err(e) if e.is_not_found() => return Ok(OriginSync::RecoveryRequired),
            Err(e) => return Err(failed("sync-origin", Some(&e))),
            Ok(()) => {}
        }
        let updated =
            allocations::mark_ready(&mut tx, user, machine_id, tunnel_id, a.generation, origin)
                .await
                .map_err(|e| failed_db("sync-origin", e))?;
        if !updated {
            return Err(claim_lost("sync-origin"));
        }
        tx.commit().await.map_err(|e| failed_db("sync-origin", e))?;
        Ok(OriginSync::Ready)
    }

    async fn deprovision_impl(
        &self,
        user: Uuid,
        machine_id: &str,
        target: Option<Option<Allocation>>,
    ) -> Result<bool, DeprovisionFailed> {
        let a = match target {
            Some(t) => t,
            None => crate::machines::provider::allocation(&self.pool, user, machine_id)
                .await
                .map_err(|e| deprovision_db("load-allocation", e))?,
        };
        let Some(a) = a else {
            return Ok(true);
        };
        let Some(claimed) =
            allocations::claim_deprovision(&self.pool, user, machine_id, a.generation)
                .await
                .map_err(|e| deprovision_db("claim-deprovision", e))?
        else {
            return Ok(false);
        };
        let cloudflare = async {
            if let Some(dns) = a.dns_record_id.as_deref() {
                ignore_not_found(self.cf.delete_record(dns).await)
                    .map_err(|e| deprovision_failed("delete-dns-record", &e))?;
            }
            if let Some(t) = a.tunnel_id.as_deref() {
                ignore_not_found(self.cf.delete_tunnel(t).await)
                    .map_err(|e| deprovision_failed("delete-tunnel", &e))?;
            }
            Ok::<_, DeprovisionFailed>(())
        };
        let Some(tunnel_id) = a.tunnel_id.as_deref() else {
            cloudflare.await?;
            let mut conn = self
                .pool
                .acquire()
                .await
                .map_err(|e| deprovision_db("remove-allocation", e))?;
            return allocations::remove_claimed(&mut conn, user, machine_id, claimed)
                .await
                .map_err(|e| deprovision_db("remove-allocation", e));
        };
        let Some(mut tx) =
            allocations::lock_claimed(&self.pool, user, machine_id, tunnel_id, claimed)
                .await
                .map_err(|e| deprovision_db("claim-deprovision", e))?
        else {
            return Ok(false);
        };
        cloudflare.await?;
        let removed = allocations::remove_claimed(&mut tx, user, machine_id, claimed)
            .await
            .map_err(|e| deprovision_db("remove-allocation", e))?;
        tx.commit()
            .await
            .map_err(|e| deprovision_db("claim-deprovision", e))?;
        Ok(removed)
    }

    /// `release`: true when the caller's connector token is now dead. The allocation row (and with
    /// it hostname and DNS record) is kept: connect/status need it, and an offline machine must keep
    /// reporting "offline" rather than "not authorized".
    pub async fn release_with(
        &self,
        user: Uuid,
        machine_id: &str,
        expected_tunnel_id: Option<&str>,
        expect_inactive: Option<ExpectInactive>,
        mark_released: bool,
    ) -> Result<bool, DeprovisionFailed> {
        let a = crate::machines::provider::allocation(&self.pool, user, machine_id)
            .await
            .map_err(|e| deprovision_db("load-allocation", e))?;
        let Some((a, tunnel_id)) = a.and_then(|a| a.tunnel_id.clone().map(|t| (a, t))) else {
            return Ok(true);
        };
        if expected_tunnel_id.is_some_and(|e| e != tunnel_id) {
            return Ok(false);
        }
        // Claim against the current generation before touching Cloudflare: a provision racing this
        // release bumps the generation, and its tunnel may already back a fresh connector.
        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(|e| deprovision_db("claim-release", e))?;
        let claimed = allocations::claim_release(
            &mut conn,
            user,
            machine_id,
            &tunnel_id,
            a.generation,
            false,
        )
        .await
        .map_err(|e| deprovision_db("claim-release", e))?;
        drop(conn);
        let Some(claimed) = claimed else {
            return Ok(false);
        };
        if let Some(x) = expect_inactive {
            let current = match self.cf.get_tunnel(&tunnel_id).await {
                Err(e) if e.is_not_found() => return Ok(true),
                Err(e) => return Err(deprovision_failed("load-tunnel", &e)),
                Ok(t) => t,
            };
            let inactive_at = if x.status == "down" {
                current.conns_inactive_at.as_deref()
            } else {
                current.created_at.as_deref()
            };
            let still_idle = current.id.as_deref() == Some(tunnel_id.as_str())
                && current.status.as_deref() == Some(x.status)
                && inactive_at
                    .and_then(parse_time)
                    .is_some_and(|t| t <= x.before_ms);
            if !still_idle {
                return Ok(false);
            }
        }
        let Some(mut tx) =
            allocations::lock_claimed(&self.pool, user, machine_id, &tunnel_id, claimed)
                .await
                .map_err(|e| deprovision_db("claim-release", e))?
        else {
            return Ok(false);
        };
        let final_gen = allocations::claim_release(
            &mut tx,
            user,
            machine_id,
            &tunnel_id,
            claimed,
            mark_released,
        )
        .await
        .map_err(|e| deprovision_db("claim-release", e))?;
        if final_gen.is_none() {
            return Ok(false);
        }
        let released = match ignore_not_found(self.cf.delete_tunnel(&tunnel_id).await) {
            Ok(()) => true,
            Err(e) if e.is_tunnel_in_use() => false,
            Err(e) => {
                // A delete whose answer was lost may still have happened. If the tunnel is gone the
                // claim must commit: no later sweep can find this tunnel to retry.
                let failure = deprovision_failed("delete-tunnel", &e);
                match self.cf.get_tunnel(&tunnel_id).await {
                    Err(lookup) if lookup.is_not_found() => true,
                    _ => return Err(failure),
                }
            }
        };
        tx.commit()
            .await
            .map_err(|e| deprovision_db("claim-release", e))?;
        Ok(released)
    }
}

impl ManagedEndpoints for CloudflareTunnels {
    fn provision<'a>(
        &'a self,
        user_id: Uuid,
        machine_id: &'a str,
        origin: &'a Origin,
        reuse_ready_tunnel: bool,
    ) -> BoxFuture<'a, Result<Provisioned, ProviderError>> {
        Box::pin(self.provision_impl(user_id, machine_id, origin, reuse_ready_tunnel))
    }

    fn reconcile_origin<'a>(
        &'a self,
        user_id: Uuid,
        machine_id: &'a str,
        tunnel_id: &'a str,
        origin: &'a Origin,
        endpoint: &'a Endpoint,
    ) -> BoxFuture<'a, Result<OriginSync, ProviderError>> {
        Box::pin(self.reconcile_origin_impl(user_id, machine_id, tunnel_id, origin, endpoint))
    }

    fn prepare_deprovision<'a>(
        &'a self,
        user_id: Uuid,
        machine_id: &'a str,
    ) -> BoxFuture<'a, Result<Option<Allocation>, DeprovisionFailed>> {
        Box::pin(async move {
            crate::machines::provider::allocation(&self.pool, user_id, machine_id)
                .await
                .map_err(|e| deprovision_db("load-allocation", e))
        })
    }

    fn deprovision<'a>(
        &'a self,
        user_id: Uuid,
        machine_id: &'a str,
        target: Option<Option<Allocation>>,
    ) -> BoxFuture<'a, Result<bool, DeprovisionFailed>> {
        Box::pin(self.deprovision_impl(user_id, machine_id, target))
    }

    fn release<'a>(
        &'a self,
        user_id: Uuid,
        machine_id: &'a str,
        expected_tunnel_id: Option<&'a str>,
    ) -> BoxFuture<'a, Result<bool, DeprovisionFailed>> {
        Box::pin(self.release_with(user_id, machine_id, expected_tunnel_id, None, false))
    }

    fn enable_recovery<'a>(
        &'a self,
        user_id: Uuid,
        machine_id: &'a str,
        tunnel_id: &'a str,
        machine_public_key: &'a str,
        origin: &'a Origin,
    ) -> BoxFuture<'a, Result<bool, sqlx::Error>> {
        Box::pin(allocations::enable_recovery(
            &self.pool,
            user_id,
            machine_id,
            tunnel_id,
            machine_public_key,
            origin,
        ))
    }
}
