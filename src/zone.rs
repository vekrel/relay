// Managed tunnel names: a port of T3 Code's `infra/relay/src/deploymentConfig.ts` (the
// `managedEndpoint*` helpers `zone.ts:22-40` wires to `RELAY_TUNNEL_ZONE_NAME`; MIT, Copyright (c)
// T3 Tools Inc.; see NOTICE). Hosts are `<stage>-<digest16>.<tunnel zone>`, tunnels
// `vekrelrelay-managedendpoint-<stage>-<digest16>` (T3: `t3coderelay-managedendpoint-`).
use sha2::{Digest, Sha256};

use crate::machines::connector::normalize_zone;

const DNS_LABEL_MAX_LENGTH: usize = 63;
const MANAGED_ENDPOINT_HASH_LENGTH: usize = 16;
const MANAGED_ENDPOINT_TUNNEL_PREFIX: &str = "vekrelrelay-managedendpoint";

/// `relayStageSlug`.
fn stage_slug(stage: &str) -> String {
    let mut out = String::new();
    for c in stage.to_lowercase().chars() {
        let c = if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' {
            c
        } else {
            '-'
        };
        if !(c == '-' && out.ends_with('-')) {
            out.push(c);
        }
    }
    out.trim_matches('-').to_owned()
}

fn stable_suffix(hash: &str) -> String {
    hash.to_lowercase()
        .chars()
        .take(MANAGED_ENDPOINT_HASH_LENGTH)
        .collect()
}

/// `appendDnsSafeSuffix`.
fn append_dns_safe_suffix(prefix: &str, suffix: &str) -> String {
    let keep = DNS_LABEL_MAX_LENGTH.saturating_sub(suffix.len() + 1);
    let truncated: String = prefix.chars().take(keep).collect();
    format!("{}-{suffix}", truncated.trim_end_matches('-'))
}

/// Hex SHA-256 of `managedEndpointDigestInput(stage, userId, environmentId)`.
pub fn machine_hash(stage: &str, wire_user_id: &str, machine_id: &str) -> String {
    let digest = Sha256::digest(format!("{stage}:{wire_user_id}:{machine_id}").as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// `managedEndpointHostname`.
pub fn hostname(stage: &str, base_domain: &str, hash: &str) -> String {
    let label = append_dns_safe_suffix(&stage_slug(stage), &stable_suffix(hash));
    format!("{label}.{}", normalize_zone(base_domain))
}

/// `managedEndpointTunnelNamePrefix`.
pub fn tunnel_name_prefix(stage: &str) -> String {
    format!("{MANAGED_ENDPOINT_TUNNEL_PREFIX}-{}-", stage_slug(stage))
}

/// `managedEndpointTunnelName`.
pub fn tunnel_name(stage: &str, hash: &str) -> String {
    format!("{}{}", tunnel_name_prefix(stage), stable_suffix(hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machines::connector::is_managed_endpoint_hostname;

    #[test]
    fn names_follow_deployment_config() {
        let hash = machine_hash("prod", "usr_1", "m");
        assert_eq!(hash.len(), 64);
        let host = hostname("prod", "Tunnels.Example.Test.", &hash);
        assert_eq!(host, format!("prod-{}.tunnels.example.test", &hash[..16]));
        assert!(is_managed_endpoint_hostname(&host, "tunnels.example.test"));
        assert_eq!(
            tunnel_name("Dev_Harun", &hash),
            format!("vekrelrelay-managedendpoint-dev-harun-{}", &hash[..16])
        );
        // A long stage is cut so the label stays a DNS label.
        let long = hostname(&"s".repeat(80), "z.test", &hash);
        assert_eq!(long.split('.').next().unwrap().len(), 63);
        // Different users or machines never share a name.
        assert_ne!(hash, machine_hash("prod", "usr_2", "m"));
        assert_ne!(hash, machine_hash("prod", "usr_1", "n"));
    }
}
