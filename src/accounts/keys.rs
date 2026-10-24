// Account-token signing keys from `AUTH_SIGNING_KEYS`: a JSON list
// `[{kid, private_jwk, status: next|active|retired}]` (plan 6A Task 4, research §3 "JWT").
// Rotation: publish `next`, wait 24 h, promote it to `active`, keep the old one `retired`
// for 24 h, then drop it. The JWKS publishes every listed key; only `active` signs.
// No `Debug` on purpose: these types hold private keys, and errors never echo the input.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use jsonwebtoken::{DecodingKey, EncodingKey};
use serde::Deserialize;
use serde_json::{Value, json};

pub const ENV_VAR: &str = "AUTH_SIGNING_KEYS";

#[derive(Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Status {
    Next,
    Active,
    Retired,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    kid: String,
    private_jwk: PrivateJwk,
    status: Status,
}

#[derive(Deserialize)]
struct PrivateJwk {
    kty: String,
    crv: String,
    x: String,
    d: String,
}

struct Key {
    kid: String,
    status: Status,
    /// Public key bytes, base64url (the JWK `x`).
    x: String,
}

pub struct SigningKeys {
    keys: Vec<Key>,
    active_kid: String,
    active: EncodingKey,
}

impl SigningKeys {
    pub fn from_env() -> Result<Self, String> {
        let raw = std::env::var(ENV_VAR).map_err(|_| format!("{ENV_VAR} is required"))?;
        Self::from_json(&raw)
    }

    pub fn from_json(raw: &str) -> Result<Self, String> {
        // serde_json errors can quote the offending value (a pasted PEM, a `d`), so keep only the position.
        let entries: Vec<Entry> = serde_json::from_str(raw).map_err(|e| {
            format!(
                "{ENV_VAR} must be a JSON list of {{kid, private_jwk, status}} (error at line {}, column {})",
                e.line(),
                e.column()
            )
        })?;
        let mut keys = Vec::with_capacity(entries.len());
        let mut active = None;
        for e in entries {
            if e.kid.is_empty() || keys.iter().any(|k: &Key| k.kid == e.kid) {
                return Err(format!("{ENV_VAR}: empty or duplicate kid {:?}", e.kid));
            }
            let jwk = &e.private_jwk;
            if jwk.kty != "OKP" || jwk.crv != "Ed25519" {
                return Err(format!(
                    "{ENV_VAR}: key {:?} must be an OKP Ed25519 JWK",
                    e.kid
                ));
            }
            let seed: [u8; 32] = URL_SAFE_NO_PAD
                .decode(&jwk.d)
                .ok()
                .and_then(|d| d.try_into().ok())
                .ok_or_else(|| format!("{ENV_VAR}: key {:?} has an invalid d", e.kid))?;
            let signing = SigningKey::from_bytes(&seed);
            let x = URL_SAFE_NO_PAD.encode(signing.verifying_key().as_bytes());
            if x != jwk.x {
                return Err(format!("{ENV_VAR}: key {:?} x does not match its d", e.kid));
            }
            if e.status == Status::Active {
                if active.is_some() {
                    return Err(format!(
                        "{ENV_VAR} must have exactly one active key, found more"
                    ));
                }
                let der = signing
                    .to_pkcs8_der()
                    .map_err(|_| format!("{ENV_VAR}: key {:?} cannot be encoded", e.kid))?;
                active = Some((e.kid.clone(), EncodingKey::from_ed_der(der.as_bytes())));
            }
            keys.push(Key {
                kid: e.kid,
                status: e.status,
                x,
            });
        }
        let (active_kid, active) = active
            .ok_or_else(|| format!("{ENV_VAR} must have exactly one active key, found none"))?;
        let summary: Vec<String> = keys
            .iter()
            .map(|k| format!("{}:{}", k.kid, k.status.as_str()))
            .collect();
        tracing::info!(keys = ?summary, "auth signing keys loaded");
        Ok(Self {
            keys,
            active_kid,
            active,
        })
    }

    /// The key that signs new tokens, with its `kid`.
    pub fn active(&self) -> (&str, &EncodingKey) {
        (&self.active_kid, &self.active)
    }

    /// `/.well-known/jwks.json`: every listed key (`next`, `active`, `retired`), public parts only.
    pub fn jwks(&self) -> Value {
        let keys: Vec<Value> = self
            .keys
            .iter()
            .map(|k| {
                json!({
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": k.x,
                    "kid": k.kid,
                    "use": "sig",
                    "alg": "EdDSA",
                })
            })
            .collect();
        json!({ "keys": keys })
    }
}

impl Status {
    fn as_str(self) -> &'static str {
        match self {
            Status::Next => "next",
            Status::Active => "active",
            Status::Retired => "retired",
        }
    }
}

/// Verification keys by `kid`, built from a JWKS document (ours, or one fetched from `jwks_uri`).
pub struct PublicKeys(Vec<(String, DecodingKey)>);

impl PublicKeys {
    pub fn from_jwks(jwks: &Value) -> Result<Self, String> {
        let keys = jwks["keys"].as_array().ok_or("JWKS has no keys list")?;
        let mut out = Vec::with_capacity(keys.len());
        for k in keys {
            if k["kty"] != "OKP" || k["crv"] != "Ed25519" {
                continue;
            }
            let (Some(kid), Some(x)) = (k["kid"].as_str(), k["x"].as_str()) else {
                return Err("JWKS key without kid or x".into());
            };
            let key = DecodingKey::from_ed_components(x).map_err(|e| e.to_string())?;
            out.push((kid.to_owned(), key));
        }
        Ok(Self(out))
    }

    pub fn get(&self, kid: &str) -> Option<&DecodingKey> {
        self.0.iter().find(|(k, _)| k == kid).map(|(_, key)| key)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::test_logs::capture_logs;

    /// A fresh `{kid, private_jwk, status}` entry; returns it with its `d` so tests can grep for it.
    pub(crate) fn entry(kid: &str, status: &str) -> (Value, String) {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).unwrap();
        let key = SigningKey::from_bytes(&seed);
        let d = URL_SAFE_NO_PAD.encode(seed);
        let x = URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes());
        let e = json!({
            "kid": kid,
            "private_jwk": { "kty": "OKP", "crv": "Ed25519", "x": x, "d": d },
            "status": status,
        });
        (e, d)
    }

    #[test]
    fn exactly_one_active_key_is_enforced() {
        let (a, _) = entry("a", "active");
        let (b, _) = entry("b", "active");
        let (n, _) = entry("n", "next");
        let (r, _) = entry("r", "retired");
        let none = json!([n.clone(), r.clone()]).to_string();
        let two = json!([a.clone(), b]).to_string();
        let one = json!([n, a, r]).to_string();
        assert!(
            SigningKeys::from_json(&none)
                .err()
                .unwrap()
                .contains("found none")
        );
        assert!(
            SigningKeys::from_json(&two)
                .err()
                .unwrap()
                .contains("found more")
        );
        assert!(SigningKeys::from_json("[]").is_err());
        let keys = SigningKeys::from_json(&one).unwrap();
        assert_eq!(keys.active().0, "a");
    }

    #[test]
    fn rejects_bad_entries() {
        let (a, _) = entry("a", "active");
        let (a2, _) = entry("a", "retired");
        let mut wrong_x = a.clone();
        wrong_x["private_jwk"]["x"] = entry("z", "next").0["private_jwk"]["x"].clone();
        let mut wrong_crv = a.clone();
        wrong_crv["private_jwk"]["crv"] = json!("P-256");
        let mut bad_status = a.clone();
        bad_status["status"] = json!("primary");
        for bad in [
            json!([a.clone(), a2]),
            json!([wrong_x]),
            json!([wrong_crv]),
            json!([bad_status]),
        ] {
            assert!(SigningKeys::from_json(&bad.to_string()).is_err(), "{bad}");
        }
    }

    #[test]
    fn jwks_publishes_every_status_without_private_parts() {
        let (n, dn) = entry("n", "next");
        let (a, da) = entry("a", "active");
        let (r, dr) = entry("r", "retired");
        let keys = SigningKeys::from_json(&json!([n, a, r]).to_string()).unwrap();
        let jwks = keys.jwks();
        let kids: Vec<&str> = jwks["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| k["kid"].as_str().unwrap())
            .collect();
        assert_eq!(kids, ["n", "a", "r"]);
        let text = jwks.to_string();
        assert!(!text.contains("\"d\""));
        for d in [dn, da, dr] {
            assert!(!text.contains(&d));
        }
    }

    #[test]
    fn private_keys_never_reach_logs_or_errors() {
        let (n, dn) = entry("n", "next");
        let (a, da) = entry("a", "active");
        let (b, db) = entry("b", "active");
        let mut wrong_x = a.clone();
        wrong_x["kid"] = json!("w");
        wrong_x["private_jwk"]["x"] = n["private_jwk"]["x"].clone();
        let mut pem_instead = a.clone();
        pem_instead["kid"] = json!("p");
        pem_instead["private_jwk"] = json!(format!("-----BEGIN PRIVATE KEY-----\n{da}\n"));
        let mut d_number = a.clone();
        d_number["private_jwk"]["d"] = json!(1234567890123456789u64);
        let inputs = [
            json!([n.clone(), a.clone()]).to_string(),
            json!([a.clone(), b]).to_string(),
            json!([wrong_x]).to_string(),
            json!([pem_instead]).to_string(),
            json!([d_number]).to_string(),
            format!("not json {da}"),
        ];
        let mut errors = Vec::new();
        let logs = capture_logs(|| {
            for raw in &inputs {
                match SigningKeys::from_json(raw) {
                    Ok(_) => tracing::info!("loaded"),
                    Err(e) => {
                        // What `serve` does with a boot error.
                        tracing::error!(error = %e, "relay stopped");
                        errors.push(e);
                    }
                }
            }
        });
        assert!(logs.contains("auth signing keys loaded"), "{logs}");
        assert!(logs.contains("relay stopped"), "{logs}");
        assert_eq!(errors.len(), 5);
        let all = format!("{logs}\n{}", errors.join("\n"));
        for secret in [dn, da, db, "1234567890123456789".to_owned()] {
            assert!(!all.contains(&secret), "private key material leaked: {all}");
        }
    }
}
