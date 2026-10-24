// Machine links, credentials and connect (plan 6A Task 9). Ports T3 Code's
// `infra/relay/src/environments/*` (MIT, Copyright (c) T3 Tools Inc.; see NOTICE);
// "environment" is "machine", wire shapes follow Vekrel-Shared `packages/contracts/src/relay.ts`.
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::relay_tokens::RelayTokens;

pub mod connector;
pub mod credentials;
// shortcut: the Cloudflare provider (Task 10) calls `ensure_capacity` while provisioning; drop the allow then.
#[cfg(test)]
mod http_tests;
#[allow(dead_code)]
pub mod limits;
pub mod linker;
pub mod links;
pub mod provider;

/// What linking and connecting need (T3's `RelayConfiguration` plus services).
pub struct Relay {
    pub pool: PgPool,
    pub tokens: RelayTokens,
    /// The mint key (`cloudMintPrivateKey`); signs relay -> machine requests.
    pub mint_key: SigningKey,
    /// `cloudMintPublicKey`: SPKI PEM, pinned by the machine at link time.
    pub mint_public_key_pem: String,
    /// `relayIssuer` as configured (the relay origin); compared normalized.
    pub issuer: String,
    /// `managedEndpointBaseDomain`.
    pub tunnel_zone: Option<String>,
    pub provider: Arc<dyn provider::ManagedEndpoints>,
    /// Redirects disabled (`withoutRedirects`).
    pub http: reqwest::Client,
    /// Tests send machine requests to a local fake instead of the managed https endpoint.
    #[cfg(test)]
    pub endpoint_override: Option<String>,
}

impl Relay {
    pub fn new(
        pool: PgPool,
        mint_key: SigningKey,
        issuer: &str,
        tunnel_zone: Option<String>,
        provider: Arc<dyn provider::ManagedEndpoints>,
    ) -> Self {
        use ed25519_dalek::pkcs8::{EncodePublicKey, spki::der::pem::LineEnding};
        let mint_public_key_pem = mint_key
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("Ed25519 SPKI encodes")
            .trim_end()
            .to_owned();
        Self {
            pool,
            tokens: RelayTokens::new(mint_key.clone(), issuer),
            mint_key,
            mint_public_key_pem,
            issuer: issuer.to_owned(),
            tunnel_zone,
            provider,
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("HTTP client builds"),
            #[cfg(test)]
            endpoint_override: None,
        }
    }

    /// `normalizeRelayIssuer(config.relayIssuer)`.
    pub fn normalized_issuer(&self) -> &str {
        crate::jws::normalize_issuer(&self.issuer)
    }
}

/// `RelayManagedEndpoint`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Endpoint {
    pub http_base_url: String,
    pub ws_base_url: String,
    pub provider_kind: String,
}

/// `RelayManagedEndpointOrigin`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Origin {
    pub local_http_host: String,
    pub local_http_port: i64,
}

/// `RelayManagedEndpointProviderKind`.
pub const PROVIDER_KINDS: [&str; 3] = ["manual", "cloudflare_tunnel", "vekrel_relay"];

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after 1970")
        .as_millis() as i64
}

/// `DateTime.formatIso(now)`.
pub fn now_iso() -> String {
    crate::auth::dpop_proofs::iso_millis(now_ms())
}

/// The wire user id (`sub`, `cloudUserId`): `usr_<uuid>`.
pub fn wire_user_id(id: Uuid) -> String {
    format!("usr_{id}")
}

pub fn parse_wire_user_id(s: &str) -> Option<Uuid> {
    s.strip_prefix("usr_")?.parse().ok()
}

/// Epoch milliseconds of an ISO-8601 UTC instant (`YYYY-MM-DDTHH:MM:SS[.fff]Z`), the form
/// `Date.prototype.toISOString` writes.
// shortcut: `DateTime.make` (JS `Date`) also takes offsets and date-only strings; machines send
// `toISOString` output, so others are refused (the safe side). Upgrade if a machine ever differs.
pub fn parse_iso_ms(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let t = s.get(r)?;
        t.bytes()
            .all(|c| c.is_ascii_digit())
            .then(|| t.parse().ok())?
    };
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, sec) = (num(11..13)?, num(14..16)?, num(17..19)?);
    let rest = &s[19..];
    let ms = match rest {
        "Z" => 0,
        _ => {
            let frac = rest.strip_prefix('.')?.strip_suffix('Z')?;
            if frac.is_empty() || frac.len() > 3 || !frac.bytes().all(|c| c.is_ascii_digit()) {
                return None;
            }
            format!("{frac:0<3}").parse().ok()?
        }
    };
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 59 {
        return None;
    }
    // Howard Hinnant's days_from_civil.
    let y2 = if mo <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let out = ((days * 24 + h) * 60 + mi) * 60_000 + sec * 1000 + ms;
    // Refuse impossible dates (Feb 30) the way `Date` would roll them: by round trip.
    (crate::auth::dpop_proofs::iso_millis(out)[..10] == s[..10]).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_round_trips() {
        for ms in [0, 1_761_264_000_123, 1_761_264_000_000, 951_782_400_000] {
            let s = crate::auth::dpop_proofs::iso_millis(ms);
            assert_eq!(parse_iso_ms(&s), Some(ms), "{s}");
        }
        assert_eq!(
            parse_iso_ms("2025-10-24T00:00:00Z"),
            Some(1_761_264_000_000)
        );
        assert_eq!(
            parse_iso_ms("2025-10-24T00:00:00.5Z"),
            Some(1_761_264_000_500)
        );
        for bad in [
            "2026-02-30T00:00:00.000Z",
            "2026-10-24 00:00:00Z",
            "x",
            "2026-10-24T00:00:00.000+01:00",
        ] {
            assert_eq!(parse_iso_ms(bad), None, "{bad}");
        }
    }

    #[test]
    fn wire_user_ids() {
        let id = Uuid::new_v4();
        assert_eq!(parse_wire_user_id(&wire_user_id(id)), Some(id));
        assert_eq!(parse_wire_user_id(&id.to_string()), None);
    }
}
