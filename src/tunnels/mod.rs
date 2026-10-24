// Machine tunnels on Cloudflare (plan 6A Task 10): the provider behind `machines::provider`'s
// `ManagedEndpoints` seam, its allocation rows, the shared rate-limit pause and the idle reaper.
use std::sync::Arc;

use sqlx::PgPool;

use crate::config::Config;

pub mod allocations;
pub mod api_pause;
pub mod cloudflare;
pub mod provider;
pub mod reaper;
#[cfg(test)]
pub(crate) mod tests;

/// The Cloudflare provider when `CLOUDFLARE_*` is set. Zone or stage missing still builds it: it
/// then answers `NotConfigured` as T3's `requireCloudflareSettings` does.
pub fn from_config(pool: &PgPool, config: &Config) -> Option<Arc<provider::CloudflareTunnels>> {
    let cf = config.cloudflare.clone()?;
    Some(Arc::new(provider::CloudflareTunnels {
        cf: Arc::new(cloudflare::Cloudflare::new(cf, pool.clone())),
        pool: pool.clone(),
        base_domain: config.tunnel_zone.clone(),
        namespace: config.stage.clone(),
    }))
}
