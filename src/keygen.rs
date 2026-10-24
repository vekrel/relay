// `vekrel-relay keygen`: a fresh Ed25519 key pair for `RELAY_MINT_PRIVATE_KEY` / `AUTH_SIGNING_KEYS`.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::{EncodePrivateKey, spki::der::pem::LineEnding};
use serde_json::json;

pub struct KeyPair {
    pub private_pem: String,
    /// Public JWK (OKP / Ed25519), no `d`.
    pub public_jwk: serde_json::Value,
}

fn seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("OS random source");
    seed
}

/// One `AUTH_SIGNING_KEYS` entry with a fresh key, status `next` (rotation step 1).
pub fn auth_signing_key(kid: &str) -> serde_json::Value {
    let seed = seed();
    let x = URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&seed).verifying_key().as_bytes());
    json!({
        "kid": kid,
        "private_jwk": { "kty": "OKP", "crv": "Ed25519", "x": x, "d": URL_SAFE_NO_PAD.encode(seed) },
        "status": "next",
    })
}

pub fn generate() -> KeyPair {
    let key = SigningKey::from_bytes(&seed());
    let private_pem = key
        .to_pkcs8_pem(LineEnding::LF)
        .expect("PKCS#8 encode")
        .to_string();
    let x = URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes());
    KeyPair {
        private_pem,
        public_jwk: json!({ "kty": "OKP", "crv": "Ed25519", "x": x }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::pkcs8::DecodePrivateKey;

    #[test]
    fn output_round_trips() {
        let kp = generate();
        assert!(kp.private_pem.starts_with("-----BEGIN PRIVATE KEY-----\n"));
        let key = SigningKey::from_pkcs8_pem(&kp.private_pem).unwrap();
        let x = URL_SAFE_NO_PAD
            .decode(kp.public_jwk["x"].as_str().unwrap())
            .unwrap();
        assert_eq!(x, key.verifying_key().as_bytes());
        assert_eq!(kp.public_jwk["kty"], "OKP");
        assert_eq!(kp.public_jwk["crv"], "Ed25519");
        assert_ne!(generate().private_pem, kp.private_pem);
    }

    #[test]
    fn auth_signing_key_loads_as_an_auth_signing_keys_entry() {
        let mut e = auth_signing_key("2026-10");
        assert_eq!(e["status"], "next");
        e["status"] = json!("active");
        let keys = crate::accounts::keys::SigningKeys::from_json(&json!([e]).to_string()).unwrap();
        assert_eq!(keys.active().0, "2026-10");
    }
}
