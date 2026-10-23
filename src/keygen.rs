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

pub fn generate() -> KeyPair {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("OS random source");
    let key = SigningKey::from_bytes(&seed);
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
}
