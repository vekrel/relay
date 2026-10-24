// Webhooks (plan 6A Task 11): the relay gives senders a stable URL and forwards each request to the
// machine through its tunnel; with the link's opt-in it holds requests while the machine is
// offline. Ports T3 Code's `infra/relay/src/hooks/*` (MIT, Copyright (c) T3 Tools Inc.; see NOTICE).
// The relay never checks the hook token; the machine does.
pub mod forwarder;
pub mod held;
pub mod inbox;
#[cfg(test)]
mod tests;
pub mod upstream;

/// `MANAGED_ENDPOINT_HASH_LENGTH`: an endpoint key is the hash suffix its tunnel name ends with.
const ENDPOINT_KEY_LEN: usize = 16;

/// `MANAGED_ENDPOINT_KEY_PATTERN` (`^[0-9a-f]{16}$`).
pub fn is_endpoint_key(key: &str) -> bool {
    key.len() == ENDPOINT_KEY_LEN && key.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

/// `endpointKeyForTunnelName`: the key of a `<prefix>-<16 hex>` tunnel name. The hash covers user
/// and machine, so one key names exactly one allocation; the prefix (T3's stage namespace) is not
/// checked because each relay deployment has its own database.
pub fn endpoint_key_for_tunnel_name(tunnel_name: &str) -> Option<String> {
    let (_, key) = tunnel_name.rsplit_once('-')?;
    is_endpoint_key(key).then(|| key.to_owned())
}

#[cfg(test)]
mod key_tests {
    use super::*;

    #[test]
    fn endpoint_keys_are_the_tunnel_name_hash_suffix() {
        assert_eq!(
            endpoint_key_for_tunnel_name("vekrelrelay-managedendpoint-prod-0123456789abcdef")
                .as_deref(),
            Some("0123456789abcdef")
        );
        for bad in [
            "x-0123456789ABCDEF",
            "x-0123456789abcde",
            "x-0123456789abcdef0",
            "0123456789abcdef",
            "prod-0123456789abcdef.tunnels.example",
        ] {
            assert_eq!(endpoint_key_for_tunnel_name(bad), None, "{bad}");
        }
    }
}
