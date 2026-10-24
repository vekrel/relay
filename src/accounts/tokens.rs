// Account access tokens (plan 6A Task 4, research §3 "JWT"). Our own layer, replacing the Clerk
// bearer T3's relay checks in `infra/relay/src/http/Api.ts:1653-1719` (`sub` and `aud`).
// Verification follows `packages/shared/src/relayJwt.ts` `verifyRelayJwt`: EdDSA only, `typ`,
// `iss` and `aud` checked, 60 s clock tolerance.
use jsonwebtoken::{Algorithm, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::keys::{PublicKeys, SigningKeys};

pub const ACCESS_TOKEN_TYP: &str = "at+jwt";
pub const AUDIENCE: &str = "vekrel-relay";
/// 10 min (owner decision 4).
pub const ACCESS_TOKEN_TTL_SECS: u64 = 600;
/// `relayJwt.ts` `clockTolerance: 60`.
pub const LEEWAY_SECS: u64 = 60;

/// Claims in wire order.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct AccessClaims {
    pub iss: String,
    pub aud: String,
    /// `usr_<uuid>`.
    pub sub: String,
    pub iat: u64,
    pub exp: u64,
    pub jti: String,
    /// Refresh-token family.
    pub sid: String,
    pub client_id: String,
    pub email: String,
}

impl AccessClaims {
    pub fn new(
        issuer: &str,
        user_id: Uuid,
        family_id: Uuid,
        client_id: &str,
        email: &str,
        now: u64,
    ) -> Self {
        Self {
            iss: issuer.to_owned(),
            aud: AUDIENCE.to_owned(),
            sub: format!("usr_{user_id}"),
            iat: now,
            exp: now + ACCESS_TOKEN_TTL_SECS,
            jti: Uuid::new_v4().to_string(),
            sid: family_id.to_string(),
            client_id: client_id.to_owned(),
            email: email.to_owned(),
        }
    }

    /// The user id inside `sub`.
    pub fn user_id(&self) -> Option<Uuid> {
        self.sub.strip_prefix("usr_")?.parse().ok()
    }
}

/// Signs `claims` with the active key: header `{typ, alg: EdDSA, kid}`.
pub fn sign<T: Serialize>(keys: &SigningKeys, typ: &str, claims: &T) -> String {
    let (kid, key) = keys.active();
    let mut header = Header::new(Algorithm::EdDSA);
    header.typ = Some(typ.to_owned());
    header.kid = Some(kid.to_owned());
    jsonwebtoken::encode(&header, claims, key).expect("Ed25519 signing cannot fail")
}

pub fn sign_access_token(keys: &SigningKeys, claims: &AccessClaims) -> String {
    sign(keys, ACCESS_TOKEN_TYP, claims)
}

#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// Not a JWS we accept: bad shape, wrong `alg` or `typ`, unknown `kid`.
    Malformed,
    BadSignature,
    Expired,
    WrongAudience,
    WrongIssuer,
    /// A required claim is missing or has the wrong type.
    BadClaims,
}

/// Verifies an access token against published keys. `issuer` is the relay origin.
pub fn verify_access_token(
    keys: &PublicKeys,
    issuer: &str,
    token: &str,
) -> Result<AccessClaims, VerifyError> {
    // An `alg` outside jsonwebtoken's list (e.g. `none`) fails here, before any key is chosen.
    let header = jsonwebtoken::decode_header(token).map_err(|_| VerifyError::Malformed)?;
    if header.alg != Algorithm::EdDSA || header.typ.as_deref() != Some(ACCESS_TOKEN_TYP) {
        return Err(VerifyError::Malformed);
    }
    let key = header
        .kid
        .as_deref()
        .and_then(|kid| keys.get(kid))
        .ok_or(VerifyError::Malformed)?;
    let mut v = Validation::new(Algorithm::EdDSA);
    v.leeway = LEEWAY_SECS;
    v.set_audience(&[AUDIENCE]);
    v.set_issuer(&[issuer]);
    v.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    use jsonwebtoken::errors::ErrorKind as K;
    jsonwebtoken::decode::<AccessClaims>(token, key, &v)
        .map(|d| d.claims)
        .map_err(|e| match e.kind() {
            K::InvalidSignature => VerifyError::BadSignature,
            K::ExpiredSignature => VerifyError::Expired,
            K::InvalidAudience => VerifyError::WrongAudience,
            K::InvalidIssuer => VerifyError::WrongIssuer,
            K::MissingRequiredClaim(_) | K::Json(_) => VerifyError::BadClaims,
            _ => VerifyError::Malformed,
        })
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after 1970")
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::keys::tests::entry;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use jsonwebtoken::EncodingKey;
    use serde_json::{Value, json};

    const ISS: &str = "https://relay.example.test";

    fn keys(entries: &[Value]) -> SigningKeys {
        SigningKeys::from_json(&Value::Array(entries.to_vec()).to_string()).unwrap()
    }

    fn claims(now: u64) -> AccessClaims {
        AccessClaims::new(
            ISS,
            Uuid::new_v4(),
            Uuid::new_v4(),
            "vekrel-web",
            "a@example.test",
            now,
        )
    }

    fn b64(v: &Value) -> String {
        URL_SAFE_NO_PAD.encode(v.to_string())
    }

    fn published(keys: &SigningKeys) -> PublicKeys {
        PublicKeys::from_jwks(&keys.jwks()).unwrap()
    }

    #[test]
    fn signed_token_has_the_planned_shape() {
        let k = keys(&[entry("k1", "active").0]);
        let c = claims(now_secs());
        let token = sign_access_token(&k, &c);
        let parts: Vec<&str> = token.split('.').collect();
        let header: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(
            header,
            json!({"typ": "at+jwt", "alg": "EdDSA", "kid": "k1"})
        );
        let payload: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        let order: Vec<&str> = payload
            .as_object()
            .unwrap()
            .keys()
            .map(|s| s.as_str())
            .collect();
        assert_eq!(
            order,
            [
                "iss",
                "aud",
                "sub",
                "iat",
                "exp",
                "jti",
                "sid",
                "client_id",
                "email"
            ]
        );
        assert_eq!(payload["aud"], "vekrel-relay");
        assert_eq!(c.exp - c.iat, 600);
        assert!(c.sub.starts_with("usr_"));
        assert!(c.user_id().is_some());
    }

    #[test]
    fn rotated_key_verifies_while_retired_and_not_after_removal() {
        let (old, _) = entry("old", "active");
        let before = keys(std::slice::from_ref(&old));
        let token = sign_access_token(&before, &claims(now_secs()));

        let (new, _) = entry("new", "active");
        let mut retired = old.clone();
        retired["status"] = json!("retired");
        let after = keys(&[new.clone(), retired]);
        assert_eq!(after.active().0, "new");
        let ok = verify_access_token(&published(&after), ISS, &token);
        assert!(ok.is_ok(), "{ok:?}");

        let dropped = keys(&[new]);
        assert_eq!(
            verify_access_token(&published(&dropped), ISS, &token),
            Err(VerifyError::Malformed)
        );
    }

    #[test]
    fn rejects_alg_none() {
        let k = keys(&[entry("k1", "active").0]);
        let c = serde_json::to_value(claims(now_secs())).unwrap();
        let header = json!({"alg": "none", "typ": "at+jwt", "kid": "k1"});
        for token in [
            format!("{}.{}.", b64(&header), b64(&c)),
            format!("{}.{}", b64(&header), b64(&c)),
        ] {
            assert!(verify_access_token(&published(&k), ISS, &token).is_err());
        }
    }

    #[test]
    fn rejects_hs256_signed_with_the_public_key() {
        let k = keys(&[entry("k1", "active").0]);
        let jwks = k.jwks();
        let x = jwks["keys"][0]["x"].as_str().unwrap();
        let mut header = Header::new(Algorithm::HS256);
        header.typ = Some("at+jwt".into());
        header.kid = Some("k1".into());
        let c = claims(now_secs());
        for secret in [
            x.as_bytes().to_vec(),
            URL_SAFE_NO_PAD.decode(x).unwrap(),
            jwks["keys"][0].to_string().into_bytes(),
        ] {
            let token =
                jsonwebtoken::encode(&header, &c, &EncodingKey::from_secret(&secret)).unwrap();
            assert_eq!(
                verify_access_token(&published(&k), ISS, &token),
                Err(VerifyError::Malformed)
            );
        }
    }

    #[test]
    fn rejects_wrong_audience_issuer_typ_and_signature() {
        let k = keys(&[entry("k1", "active").0]);
        let pk = published(&k);
        let mut c = claims(now_secs());
        c.aud = "vekrel-other".into();
        assert_eq!(
            verify_access_token(&pk, ISS, &sign_access_token(&k, &c)),
            Err(VerifyError::WrongAudience)
        );
        let mut c = claims(now_secs());
        c.iss = "https://evil.example.test".into();
        assert_eq!(
            verify_access_token(&pk, ISS, &sign_access_token(&k, &c)),
            Err(VerifyError::WrongIssuer)
        );
        let c = claims(now_secs());
        assert_eq!(
            verify_access_token(&pk, ISS, &sign(&k, "JWT", &c)),
            Err(VerifyError::Malformed)
        );
        // Same kid, different key: signature check fails.
        let other = keys(&[entry("k1", "active").0]);
        assert_eq!(
            verify_access_token(&pk, ISS, &sign_access_token(&other, &c)),
            Err(VerifyError::BadSignature)
        );
    }

    #[test]
    fn expiry_has_exactly_60_s_leeway() {
        let k = keys(&[entry("k1", "active").0]);
        let pk = published(&k);
        let at = |exp_offset: i64| {
            let now = now_secs();
            let mut c = claims(now - 3600);
            c.exp = (now as i64 + exp_offset) as u64;
            sign_access_token(&k, &c)
        };
        // Inside the leeway (generous margin for a loaded machine).
        assert!(verify_access_token(&pk, ISS, &at(-20)).is_ok());
        assert_eq!(
            verify_access_token(&pk, ISS, &at(-100)),
            Err(VerifyError::Expired)
        );
        assert!(verify_access_token(&pk, ISS, &at(300)).is_ok());
    }
}
