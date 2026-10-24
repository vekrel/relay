// Compact JWS with EdDSA (Ed25519), as Vekrel-Shared `packages/shared/src/relayJwt.ts` signs and
// verifies relay <-> machine messages through jose 6 (`SignJWT`, `jwtVerify`). The checks, their
// order and their error codes follow jose 6.2.2 `jws/flattened/verify.js`,
// `lib/validate_crit.js` and `lib/jwt_claims_set.js`, so a token gets the verdict Shared gives it
// (`tests/fixtures/relay/jws.json`, made by Engine `apps/server/test/relay-conformance/gen-vectors.ts`).
use base64::Engine;
use base64::alphabet::URL_SAFE;
use base64::engine::DecodePaddingMode;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use ed25519_dalek::pkcs8::{DecodePrivateKey, DecodePublicKey};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::Serialize;
use serde_json::{Map, Value};

// `relayJwt.ts:7-14`. The Engine checks these, so they keep T3's names (plan 6A, research R3).
pub const RELAY_LINK_PROOF_TYP: &str = "t3-env-link+jwt";
pub const RELAY_MINT_REQUEST_TYP: &str = "t3-cloud-mint+jwt";
pub const RELAY_HEALTH_REQUEST_TYP: &str = "t3-cloud-health+jwt";
pub const RELAY_MINT_RESPONSE_TYP: &str = "t3-env-mint+jwt";
pub const RELAY_HEALTH_RESPONSE_TYP: &str = "t3-env-health+jwt";
// shortcut: used by agent activity (Task 12) and hook delivery (Task 11); drop the allows then.
#[allow(dead_code)]
pub const RELAY_ACTIVITY_PUBLISH_TYP: &str = "t3-env-activity+jwt";
pub const RELAY_MANAGED_TUNNEL_RECOVERY_TYP: &str = "t3-env-managed-tunnel-recovery+jwt";
#[allow(dead_code)]
pub const RELAY_HOOK_DELIVERY_TYP: &str = "t3-relay-hook-delivery+jwt";

/// `verifyRelayJwt` defaults: `maxTokenAge: "5 minutes"`, `clockTolerance: 60`.
pub const DEFAULT_MAX_AGE_SECONDS: i64 = 300;
const CLOCK_TOLERANCE_SECONDS: f64 = 60.0;

/// A machine's `iss` / `aud`: `vekrel-machine:<machineId>` (Engine `cloud/CloudLink.ts`; T3 `t3-env:`).
pub fn machine_principal(machine_id: &str) -> String {
    format!("vekrel-machine:{machine_id}")
}

/// `normalizeRelayIssuer`: trimmed, without trailing slashes.
pub fn normalize_issuer(value: &str) -> &str {
    value.trim().trim_end_matches('/')
}

/// `normalizePem`: env values may carry literal `\n`.
fn normalize_pem(value: &str) -> String {
    value.replace("\\n", "\n").trim().to_owned()
}

/// Ed25519 private key from PKCS#8 PEM (`importPKCS8`), e.g. `RELAY_MINT_PRIVATE_KEY`.
pub fn signing_key_from_pem(pem: &str) -> Result<SigningKey, String> {
    SigningKey::from_pkcs8_pem(&normalize_pem(pem)).map_err(|e| format!("Ed25519 PKCS#8 key: {e}"))
}

/// Ed25519 public key from SPKI PEM (`importSPKI`), e.g. a machine's `machinePublicKey`.
pub fn verifying_key_from_pem(pem: &str) -> Result<VerifyingKey, String> {
    VerifyingKey::from_public_key_pem(&normalize_pem(pem))
        .map_err(|e| format!("Ed25519 SPKI key: {e}"))
}

fn b64url() -> GeneralPurpose {
    GeneralPurpose::new(
        &URL_SAFE,
        GeneralPurposeConfig::new()
            .with_encode_padding(false)
            .with_decode_allow_trailing_bits(true)
            .with_decode_padding_mode(DecodePaddingMode::RequireNone),
    )
}

pub fn b64url_encode(bytes: impl AsRef<[u8]>) -> String {
    b64url().encode(bytes)
}

/// jose's `base64url.decode` on Node 26: `Uint8Array.fromBase64(s, {alphabet: "base64url"})`,
/// which skips ASCII whitespace, takes optional `=` padding and ignores trailing bits.
fn jose_b64_decode(s: &str) -> Option<Vec<u8>> {
    let s: String = s
        .chars()
        .filter(|c| !matches!(c, '\t' | '\n' | '\x0c' | '\r' | ' '))
        .collect();
    let body = if s.ends_with('=') {
        let body = s
            .strip_suffix("==")
            .or_else(|| s.strip_suffix('='))
            .unwrap_or(&s);
        if !s.len().is_multiple_of(4) {
            return None;
        }
        body
    } else {
        &s
    };
    b64url().decode(body).ok()
}

/// `TextDecoder().decode` (lossy UTF-8, leading BOM dropped) then `JSON.parse`.
// shortcut: serde_json refuses lone-surrogate escapes and numbers beyond f64 that JSON.parse takes;
// such tokens are refused (the safe side). Upgrade if a real signer ever emits them.
pub(crate) fn parse_json_text(bytes: &[u8]) -> Option<Value> {
    let text = String::from_utf8_lossy(bytes);
    serde_json::from_str(text.strip_prefix('\u{feff}').unwrap_or(&text)).ok()
}

/// `signRelayJwt`: header `{"alg":"EdDSA","typ":<typ>}`, the claims in their field order.
pub fn sign(key: &SigningKey, typ: &str, claims: &impl Serialize) -> String {
    let header = serde_json::to_vec(&serde_json::json!({ "alg": "EdDSA", "typ": typ }))
        .expect("header serializes");
    let payload = serde_json::to_vec(claims).expect("claims serialize");
    let input = format!("{}.{}", b64url_encode(header), b64url_encode(payload));
    let signature = key.sign(input.as_bytes());
    format!("{input}.{}", b64url_encode(signature.to_bytes()))
}

/// `decodeRelayJwt` (jose `decodeJwt`): the claims of a compact JWS, unverified. Used only to
/// pick the key a link proof claims before verifying it.
pub fn decode_unverified(token: &str) -> Option<Map<String, Value>> {
    let segments: Vec<&str> = token.split('.').collect();
    let [_, payload, _] = segments[..] else {
        return None;
    };
    match jose_b64_decode(payload).and_then(|b| parse_json_text(&b))? {
        Value::Object(claims) => Some(claims),
        _ => None,
    }
}

/// What `verifyRelayJwt` checks besides the signature.
pub struct Expect<'a> {
    pub typ: &'a str,
    pub issuer: &'a str,
    pub audience: &'a str,
    pub now_epoch_seconds: i64,
    pub max_age_seconds: i64,
}

/// A jose error: `code` is `RelayJwtError.diagnosticCode`; `claim` and `reason` are set for
/// claim failures (`JWTClaimValidationFailed` / `JWTExpired`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwsError {
    pub code: &'static str,
    pub claim: Option<&'static str>,
    pub reason: Option<&'static str>,
}

const JWS_INVALID: JwsError = err("ERR_JWS_INVALID");
const JWT_INVALID: JwsError = err("ERR_JWT_INVALID");

const fn err(code: &'static str) -> JwsError {
    JwsError {
        code,
        claim: None,
        reason: None,
    }
}

const fn claim(code: &'static str, claim: &'static str, reason: &'static str) -> JwsError {
    JwsError {
        code,
        claim: Some(claim),
        reason: Some(reason),
    }
}

fn failed(c: &'static str, reason: &'static str) -> JwsError {
    claim("ERR_JWT_CLAIM_VALIDATION_FAILED", c, reason)
}

/// jose `normalizeTyp`.
fn normalize_typ(value: &str) -> String {
    let lower = value.to_lowercase();
    if value.contains('/') {
        lower
    } else {
        format!("application/{lower}")
    }
}

/// `verifyRelayJwt`: returns the claims set on success.
pub fn verify(
    key: &VerifyingKey,
    token: &str,
    expect: &Expect,
) -> Result<Map<String, Value>, JwsError> {
    let segments: Vec<&str> = token.split('.').collect();
    let [protected, payload, signature] = segments[..] else {
        return Err(JWS_INVALID);
    };
    // An empty protected segment is no header at all, hence no `alg`.
    let header = if protected.is_empty() {
        Value::Object(Map::new())
    } else {
        jose_b64_decode(protected)
            .and_then(|b| parse_json_text(&b))
            .ok_or(JWS_INVALID)?
    };
    // Any non-object header has no `alg` either.
    let header = match header {
        Value::Object(h) => h,
        _ => return Err(JWS_INVALID),
    };

    // validate_crit.js: only `b64` is recognized.
    let mut b64 = true;
    if let Some(crit) = header.get("crit") {
        let names = crit
            .as_array()
            .filter(|a| !a.is_empty())
            .ok_or(JWS_INVALID)?;
        for name in names {
            let name = name.as_str().filter(|s| !s.is_empty()).ok_or(JWS_INVALID)?;
            if name != "b64" {
                return Err(err("ERR_JOSE_NOT_SUPPORTED"));
            }
            if !header.contains_key(name) {
                return Err(JWS_INVALID);
            }
        }
        if names.iter().any(|n| n == "b64") {
            b64 = header["b64"].as_bool().ok_or(JWS_INVALID)?;
        }
    }
    match header.get("alg").and_then(Value::as_str) {
        Some("EdDSA") => {}
        Some(alg) if !alg.is_empty() => return Err(err("ERR_JOSE_ALG_NOT_ALLOWED")),
        _ => return Err(JWS_INVALID),
    }
    let signature = jose_b64_decode(signature).ok_or(JWS_INVALID)?;
    let verified = Signature::from_slice(&signature).is_ok_and(|s| {
        key.verify(format!("{protected}.{payload}").as_bytes(), &s)
            .is_ok()
    });
    if !verified {
        return Err(err("ERR_JWS_SIGNATURE_VERIFICATION_FAILED"));
    }
    if !b64 {
        // jwt/verify.js: "JWTs MUST NOT use unencoded payload".
        return Err(JWT_INVALID);
    }
    let payload = jose_b64_decode(payload).ok_or(JWS_INVALID)?;
    let claims = match parse_json_text(&payload) {
        Some(Value::Object(c)) => c,
        _ => return Err(JWT_INVALID),
    };
    check_claims(&header, &claims, expect)?;
    Ok(claims)
}

/// jwt_claims_set.js `validateClaimsSet` with `typ`, `issuer`, `audience`, `maxTokenAge` and a
/// 60 s `clockTolerance`.
fn check_claims(
    header: &Map<String, Value>,
    c: &Map<String, Value>,
    e: &Expect,
) -> Result<(), JwsError> {
    let typ_ok = header
        .get("typ")
        .and_then(Value::as_str)
        .is_some_and(|t| normalize_typ(t) == normalize_typ(e.typ));
    if !typ_ok {
        return Err(failed("typ", "check_failed"));
    }
    for name in ["iss", "aud", "iat"] {
        if !c.contains_key(name) {
            return Err(failed(name, "missing"));
        }
    }
    if c["iss"].as_str() != Some(e.issuer) {
        return Err(failed("iss", "check_failed"));
    }
    let aud_ok = match &c["aud"] {
        Value::String(a) => a == e.audience,
        Value::Array(a) => a.iter().any(|v| v.as_str() == Some(e.audience)),
        _ => false,
    };
    if !aud_ok {
        return Err(failed("aud", "check_failed"));
    }
    let now = e.now_epoch_seconds as f64;
    let tol = CLOCK_TOLERANCE_SECONDS;
    let number = |name: &'static str| -> Result<Option<f64>, JwsError> {
        match c.get(name) {
            None => Ok(None),
            Some(v) => v.as_f64().map(Some).ok_or(failed(name, "invalid")),
        }
    };
    let iat = number("iat")?.expect("iat presence checked above");
    if let Some(nbf) = number("nbf")?
        && nbf > now + tol
    {
        return Err(failed("nbf", "check_failed"));
    }
    if let Some(exp) = number("exp")?
        && exp <= now - tol
    {
        return Err(claim("ERR_JWT_EXPIRED", "exp", "check_failed"));
    }
    let age = now - iat;
    if age - tol > e.max_age_seconds as f64 {
        return Err(claim("ERR_JWT_EXPIRED", "iat", "check_failed"));
    }
    if age < -tol {
        return Err(failed("iat", "check_failed"));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    pub(crate) fn fixture() -> Value {
        serde_json::from_str(include_str!("../tests/fixtures/relay/jws.json")).unwrap()
    }

    /// A fixture key: TEST-ONLY, its seed is sha256 of the label in `jws.json`.
    pub(crate) fn test_only_key(name: &str) -> SigningKey {
        let label = fixture()["keys"][name]["seedIsSha256Of"]
            .as_str()
            .unwrap()
            .to_owned();
        SigningKey::from_bytes(&Sha256::digest(label.as_bytes()).into())
    }

    pub(crate) fn token(v: &Value) -> String {
        v["parts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p.as_str().unwrap())
            .collect::<Vec<_>>()
            .join(".")
    }

    fn public_key(name: &str) -> VerifyingKey {
        verifying_key_from_pem(
            fixture()["keys"][name]["publicKeySpkiPem"]
                .as_str()
                .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn test_only_keys_match_their_published_public_keys() {
        for name in ["relayMint", "machine", "stranger"] {
            assert_eq!(
                test_only_key(name).verifying_key(),
                public_key(name),
                "{name}"
            );
        }
    }

    #[test]
    fn every_vector_gets_the_verdict_shared_gives_it() {
        let f = fixture();
        let vectors = f["verify"].as_array().unwrap();
        assert!(vectors.len() >= 60);
        for v in vectors {
            let name = v["name"].as_str().unwrap();
            let got = verify(
                &public_key(v["key"].as_str().unwrap()),
                &token(v),
                &Expect {
                    typ: v["typ"].as_str().unwrap(),
                    issuer: v["issuer"].as_str().unwrap(),
                    audience: v["audience"].as_str().unwrap(),
                    now_epoch_seconds: v["now"].as_i64().unwrap(),
                    max_age_seconds: v["maxTokenAgeSeconds"]
                        .as_i64()
                        .unwrap_or(DEFAULT_MAX_AGE_SECONDS),
                },
            );
            let shared = &v["shared"];
            match got {
                Ok(claims) => {
                    assert_eq!(
                        shared["ok"], true,
                        "{name}: Rust accepted, Shared refused {shared}"
                    );
                    assert_eq!(Value::Object(claims), shared["payload"], "{name}");
                }
                Err(e) => {
                    assert_eq!(shared["ok"], false, "{name}: Rust refused with {e:?}");
                    assert_eq!(e.code, shared["code"], "{name}");
                    assert_eq!(e.claim, shared["claim"].as_str(), "{name}");
                    assert_eq!(e.reason, shared["reason"].as_str(), "{name}");
                }
            }
        }
    }

    #[test]
    fn rust_signs_byte_for_byte_what_shared_signs() {
        let key = test_only_key("relayMint");
        for v in fixture()["sign"].as_array().unwrap() {
            let name = v["name"].as_str().unwrap();
            assert_eq!(v["shared"]["ok"], true, "{name}");
            assert_eq!(
                sign(&key, v["typ"].as_str().unwrap(), &v["payload"]),
                token(v),
                "{name}"
            );
        }
    }

    #[test]
    fn pem_keys_load_with_literal_newlines_and_round_trip() {
        use ed25519_dalek::pkcs8::{EncodePrivateKey, spki::der::pem::LineEnding};
        let key = test_only_key("machine");
        let pem = key
            .to_pkcs8_pem(LineEnding::LF)
            .unwrap()
            .replace('\n', "\\n");
        assert_eq!(signing_key_from_pem(&format!(" {pem} ")).unwrap(), key);
        assert!(signing_key_from_pem("not a key").is_err());
        assert!(verifying_key_from_pem("not a key").is_err());
    }

    #[test]
    fn names_follow_the_engine() {
        assert_eq!(machine_principal("m1"), "vekrel-machine:m1");
        assert_eq!(
            normalize_issuer(" https://relay.example.test// "),
            "https://relay.example.test"
        );
    }
}
