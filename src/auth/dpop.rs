// DPoP proof verification: a port of Vekrel-Shared `packages/shared/src/dpop.ts` `verifyDpopProof`
// (T3 Code, MIT, Copyright (c) T3 Tools Inc.; see NOTICE), which T3's relay calls from
// `infra/relay/src/auth/DpopProofs.ts`. Same check order and failure codes; decoding follows
// Effect's `Base64Url.decodeString` and `Schema.fromJsonString` (vectors: `tests/fixtures/relay/dpop.json`).
// Shapes follow the Vekrel-Daemon port (`src/auth/dpop.rs`), which declines where this one decides.
use base64::Engine;
use base64::alphabet::URL_SAFE;
use base64::engine::DecodePaddingMode;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use p256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::jws::{b64url_encode, parse_json_text};

/// `DPOP_MAX_CLOCK_SKEW_SECONDS`: how far `iat` may sit from the relay's clock, either way.
pub const DPOP_MAX_CLOCK_SKEW_SECONDS: i64 = 300;
/// `Number.MAX_SAFE_INTEGER` (`Schema.Int` is `isSafeInteger`).
const MAX_SAFE: f64 = 9_007_199_254_740_991.0;

/// `DpopVerificationFailureCode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    MissingProof,
    MalformedProof,
    KeyMismatch,
    MethodMismatch,
    UrlMismatch,
    AccessTokenHashMismatch,
    TimeWindow,
    InvalidSignature,
    InvalidProof,
}

impl Failure {
    pub fn code(self) -> &'static str {
        match self {
            Self::MissingProof => "missing_proof",
            Self::MalformedProof => "malformed_proof",
            Self::KeyMismatch => "key_mismatch",
            Self::MethodMismatch => "method_mismatch",
            Self::UrlMismatch => "url_mismatch",
            Self::AccessTokenHashMismatch => "access_token_hash_mismatch",
            Self::TimeWindow => "time_window",
            Self::InvalidSignature => "invalid_signature",
            Self::InvalidProof => "invalid_proof",
        }
    }
}

/// A proof that passed every check (the replay table is `dpop_proofs`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    pub thumbprint: String,
    pub jti: String,
    pub iat: i64,
}

pub struct Request<'a> {
    pub proof: Option<&'a str>,
    pub method: &'a str,
    /// The request URL as the relay sees it; query and fragment are dropped (`normalizeDpopHtu`).
    pub url: &'a str,
    pub now_epoch_seconds: i64,
    pub expected_thumbprint: Option<&'a str>,
    pub expected_access_token: Option<&'a str>,
}

/// `b64url(sha256(s))`: `computeDpopAccessTokenHash`.
pub fn access_token_hash(token: &str) -> String {
    b64url_encode(Sha256::digest(token.as_bytes()))
}

/// `computeDpopJwkThumbprint`: RFC 7638 members in code-unit order, `JSON.stringify` strings.
pub fn thumbprint(crv: &str, kty: &str, x: &str, y: &str) -> String {
    let j = |s: &str| serde_json::to_string(s).expect("string");
    access_token_hash(&format!(
        r#"{{"crv":{},"kty":{},"x":{},"y":{}}}"#,
        j(crv),
        j(kty),
        j(x),
        j(y)
    ))
}

/// `normalizeDpopHtu`: the WHATWG URL without query and fragment.
pub fn normalize_htu(url: &str) -> Option<String> {
    let mut u = url::Url::parse(url).ok()?;
    u.set_query(None);
    u.set_fragment(None);
    Some(u.into())
}

/// Effect `Base64Url.decode`: CR/LF dropped, optional `=` padding, trailing bits ignored.
fn effect_b64_decode(s: &str) -> Option<Vec<u8>> {
    let s: String = s.chars().filter(|c| !matches!(c, '\r' | '\n')).collect();
    let body = s.trim_end_matches('=');
    let pad = s.len() - body.len();
    if s.len() % 4 == 1
        || pad > 2
        || !body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return None;
    }
    // Padding is added up to a multiple of 4; more `=` than that leaves one in the middle.
    let padded_len = s.len() + (4 - s.len() % 4) % 4;
    if padded_len - body.len() > 2 {
        return None;
    }
    let engine = GeneralPurpose::new(
        &URL_SAFE,
        GeneralPurposeConfig::new()
            .with_decode_allow_trailing_bits(true)
            .with_decode_padding_mode(DecodePaddingMode::RequireNone),
    );
    engine.decode(body).ok()
}

/// `Base64Url.decodeString` + `Schema.fromJsonString` of a struct: `None` is a schema failure.
fn object(segment: &str) -> Result<Option<Map<String, Value>>, Failure> {
    // An undecodable segment throws in `Result.getOrThrow`, caught as `invalid_proof`.
    let bytes = effect_b64_decode(segment).ok_or(Failure::InvalidProof)?;
    Ok(match parse_json_text(&bytes) {
        Some(Value::Object(m)) => Some(m),
        _ => None,
    })
}

fn non_empty<'a>(m: &'a Map<String, Value>, k: &str) -> Option<&'a str> {
    m.get(k)?.as_str().filter(|s| !s.is_empty())
}

/// JS `String.prototype.trim` whitespace: Unicode White_Space plus the BOM.
fn is_blank(s: &str) -> bool {
    s.chars().all(|c| c.is_whitespace() || c == '\u{feff}')
}

pub fn verify(r: &Request) -> Result<Proof, Failure> {
    use Failure::*;
    let proof = r.proof.filter(|p| !is_blank(p)).ok_or(MissingProof)?;
    let parts: Vec<&str> = proof.split('.').collect();
    if parts.len() != 3 || parts.iter().any(|p| p.is_empty()) {
        return Err(MalformedProof);
    }
    let header = object(parts[0])?;
    let payload = object(parts[1])?;
    let header = header.ok_or(MalformedProof)?;
    let payload = payload.ok_or(MalformedProof)?;

    // DpopJwtHeaderJson: typ, alg literals; jwk EC/P-256 with non-empty x, y and no `d`.
    let jwk = match header.get("jwk") {
        Some(Value::Object(j)) => j,
        _ => return Err(MalformedProof),
    };
    let (Some(x), Some(y)) = (non_empty(jwk, "x"), non_empty(jwk, "y")) else {
        return Err(MalformedProof);
    };
    if header.get("typ").and_then(Value::as_str) != Some("dpop+jwt")
        || header.get("alg").and_then(Value::as_str) != Some("ES256")
        || jwk.get("kty").and_then(Value::as_str) != Some("EC")
        || jwk.get("crv").and_then(Value::as_str) != Some("P-256")
        || jwk.contains_key("d")
    {
        return Err(MalformedProof);
    }
    // DpopJwtPayloadJson: htm, htu, jti non-empty; iat a safe integer; ath optional string.
    let iat = match payload.get("iat").and_then(Value::as_f64) {
        Some(f) if f.fract() == 0.0 && f.abs() <= MAX_SAFE => f as i64,
        _ => return Err(MalformedProof),
    };
    let (Some(htm), Some(htu), Some(jti)) = (
        non_empty(&payload, "htm"),
        non_empty(&payload, "htu"),
        non_empty(&payload, "jti"),
    ) else {
        return Err(MalformedProof);
    };
    let ath = match payload.get("ath") {
        None => None,
        Some(Value::String(s)) => Some(s.as_str()),
        Some(_) => return Err(MalformedProof),
    };

    let thumb = thumbprint("P-256", "EC", x, y);
    if r.expected_thumbprint
        .is_some_and(|e| !e.is_empty() && e != thumb)
    {
        return Err(KeyMismatch);
    }
    if htm.to_uppercase() != r.method.to_uppercase() {
        return Err(MethodMismatch);
    }
    if normalize_htu(r.url).as_deref() != Some(htu) {
        return Err(UrlMismatch);
    }
    if let Some(t) = r.expected_access_token.filter(|t| !t.is_empty())
        && ath != Some(access_token_hash(t).as_str())
    {
        return Err(AccessTokenHashMismatch);
    }

    // `base64UrlToBytes` and `publicKeyBytesFromJwk` throw (invalid_proof); noble's
    // `p256.verify` answers false for a bad signature or point (invalid_signature).
    let sig = effect_b64_decode(parts[2]).ok_or(InvalidProof)?;
    let (xb, yb) = (
        effect_b64_decode(x).ok_or(InvalidProof)?,
        effect_b64_decode(y).ok_or(InvalidProof)?,
    );
    if xb.len() != 32 || yb.len() != 32 {
        return Err(InvalidProof);
    }
    let sec1 = [&[4u8][..], &xb, &yb].concat();
    let digest = Sha256::digest(format!("{}.{}", parts[0], parts[1]).as_bytes());
    // `{prehash: false, format: "compact"}`; noble accepts high-S for P-256.
    let verified = matches!(
        (VerifyingKey::from_sec1_bytes(&sec1), Signature::from_slice(&sig)),
        (Ok(key), Ok(sig)) if key.verify_prehash(&digest, &sig).is_ok()
    );
    if !verified {
        return Err(InvalidSignature);
    }
    if (i128::from(r.now_epoch_seconds) - i128::from(iat)).abs()
        > i128::from(DPOP_MAX_CLOCK_SKEW_SECONDS)
    {
        return Err(TimeWindow);
    }
    Ok(Proof {
        thumbprint: thumb,
        jti: jti.to_owned(),
        iat,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn fixture() -> Value {
        serde_json::from_str(include_str!("../../tests/fixtures/relay/dpop.json")).unwrap()
    }

    pub(crate) fn vector(name: &str) -> Value {
        fixture()["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["name"] == name)
            .unwrap_or_else(|| panic!("no vector {name}"))
            .clone()
    }

    pub(crate) fn proof_of(v: &Value) -> String {
        crate::jws::tests::token(v)
    }

    pub(crate) fn request_of<'a>(v: &'a Value, proof: &'a str) -> Request<'a> {
        Request {
            proof: Some(proof),
            method: v["method"].as_str().unwrap(),
            url: v["url"].as_str().unwrap(),
            now_epoch_seconds: v["now"].as_i64().unwrap(),
            expected_thumbprint: v["expectedThumbprint"].as_str(),
            expected_access_token: v["expectedAccessToken"].as_str(),
        }
    }

    #[test]
    fn every_vector_gets_the_verdict_shared_gives_it() {
        let f = fixture();
        let vectors = f["vectors"].as_array().unwrap();
        assert!(vectors.len() >= 43);
        for v in vectors {
            let name = v["name"].as_str().unwrap();
            let proof = proof_of(v);
            let got = verify(&request_of(v, &proof));
            let s = &v["shared"];
            match got {
                Ok(p) => {
                    assert_eq!(s["ok"], true, "{name}: Rust accepted, Shared refused {s}");
                    assert_eq!(p.thumbprint, s["thumbprint"], "{name}");
                    assert_eq!(p.jti, s["jti"], "{name}");
                    assert_eq!(p.iat, s["iat"].as_i64().unwrap(), "{name}");
                }
                Err(e) => {
                    assert_eq!(s["ok"], false, "{name}: Rust refused with {e:?}");
                    assert_eq!(e.code(), s["code"], "{name}");
                }
            }
        }
    }

    #[test]
    fn no_proof_at_all_is_missing() {
        let v = vector("valid");
        let mut r = request_of(&v, "");
        r.proof = None;
        assert_eq!(verify(&r), Err(Failure::MissingProof));
        // `trim()` also strips a BOM.
        r.proof = Some("\u{feff} ");
        assert_eq!(verify(&r), Err(Failure::MissingProof));
    }
}
