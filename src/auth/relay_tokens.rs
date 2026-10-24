// Relay-issued tokens: a port of T3 Code's `infra/relay/src/auth/RelayTokens.ts`
// (MIT, Copyright (c) T3 Tools Inc.; see NOTICE) and `packages/shared/src/oauthScope.ts`.
// Both are signed and verified only by the relay with its mint key, so their `typ`s carry
// Vekrel names (`vekrel-*`, "environment" is "machine"); clients treat them as opaque.
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::jws;

const LINK_CHALLENGE_TYP: &str = "vekrel-link-challenge+jwt";
const ACCESS_TOKEN_TYP: &str = "vekrel-relay-dpop-access+jwt";
const LINK_CHALLENGE_KIND: &str = "machine_link_challenge";
/// `RELAY_DPOP_ACCESS_TOKEN_TTL` ("30 minutes").
pub const RELAY_DPOP_ACCESS_TOKEN_TTL_SECONDS: i64 = 1800;

// Vekrel-Shared `packages/contracts/src/relay.ts`.
pub const RELAY_MOBILE_CLIENT_ID: &str = "vekrel-mobile";
pub const RELAY_WEB_CLIENT_ID: &str = "vekrel-web";
pub const RELAY_MACHINE_CONNECT_SCOPE: &str = "machine:connect";
pub const RELAY_MACHINE_STATUS_SCOPE: &str = "machine:status";
pub const RELAY_MOBILE_REGISTRATION_SCOPE: &str = "mobile:registration";

/// `RelayMachineLinkChallengeRequest`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkChallengeRequest {
    pub notifications_enabled: bool,
    pub live_activities_enabled: bool,
    pub managed_tunnels_enabled: bool,
}

/// `LinkChallengeClaims`, in the order `issueLinkChallenge` writes them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkChallengeClaims {
    pub kind: String,
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub jti: String,
    pub iat: i64,
    pub exp: i64,
    #[serde(flatten)]
    pub request: LinkChallengeRequest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cnf {
    pub jkt: String,
}

/// `RelayDpopAccessTokenClaims` as signed (`scope` is the space-separated OAuth string).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DpopAccessTokenClaims {
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub jti: String,
    pub iat: i64,
    pub exp: i64,
    pub client_id: String,
    pub scope: String,
    pub cnf: Cnf,
}

/// A verified access token: `scopes` replaces `scope`, as `verifyDpopAccessToken` returns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDpopAccessToken {
    pub claims: DpopAccessTokenClaims,
    pub scopes: Vec<&'static str>,
}

fn allowed_scopes(client_id: &str) -> Option<&'static [&'static str]> {
    match client_id {
        RELAY_MOBILE_CLIENT_ID => Some(&[
            RELAY_MACHINE_CONNECT_SCOPE,
            RELAY_MACHINE_STATUS_SCOPE,
            RELAY_MOBILE_REGISTRATION_SCOPE,
        ]),
        RELAY_WEB_CLIENT_ID => Some(&[RELAY_MACHINE_CONNECT_SCOPE, RELAY_MACHINE_STATUS_SCOPE]),
        _ => None,
    }
}

/// `resolveDpopAccessTokenScopes` (`parseAllowedOAuthScope`): space-separated RFC 6749 scope
/// tokens, duplicates dropped in first-seen order, each allowed for the client; else `None`.
pub fn resolve_dpop_access_token_scopes(client_id: &str, scope: &str) -> Option<Vec<&'static str>> {
    let allowed = allowed_scopes(client_id)?;
    if scope.is_empty() {
        return None;
    }
    let mut out: Vec<&'static str> = Vec::new();
    for token in scope.split(' ') {
        // OAUTH_SCOPE_TOKEN `[\x21\x23-\x5b\x5d-\x7e]+`; an empty token (double space) fails it.
        let valid = !token.is_empty()
            && token
                .bytes()
                .all(|b| matches!(b, 0x21 | 0x23..=0x5b | 0x5d..=0x7e));
        if !valid {
            return None;
        }
        let known = allowed.iter().find(|s| **s == token)?;
        if !out.contains(known) {
            out.push(known);
        }
    }
    Some(out)
}

/// The relay's `RelayTokens` service: its mint key and normalized issuer.
pub struct RelayTokens {
    key: SigningKey,
    public: VerifyingKey,
    issuer: String,
}

impl RelayTokens {
    pub fn new(key: SigningKey, relay_issuer: &str) -> Self {
        Self {
            public: key.verifying_key(),
            key,
            issuer: jws::normalize_issuer(relay_issuer).to_owned(),
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    fn expect<'a>(&'a self, typ: &'a str, now: i64, max_age: i64) -> jws::Expect<'a> {
        jws::Expect {
            typ,
            issuer: &self.issuer,
            audience: &self.issuer,
            now_epoch_seconds: now,
            max_age_seconds: max_age,
        }
    }

    pub fn issue_link_challenge(
        &self,
        user_id: &str,
        request: LinkChallengeRequest,
        jti: &str,
        issued_at: i64,
        expires_at: i64,
    ) -> String {
        let claims = LinkChallengeClaims {
            kind: LINK_CHALLENGE_KIND.to_owned(),
            iss: self.issuer.clone(),
            aud: self.issuer.clone(),
            sub: user_id.to_owned(),
            jti: jti.to_owned(),
            iat: issued_at,
            exp: expires_at,
            request,
        };
        jws::sign(&self.key, LINK_CHALLENGE_TYP, &claims)
    }

    /// `verifyLinkChallenge`: `None` unless the challenge is valid, for this user, and grants
    /// every capability the request asks for.
    pub fn verify_link_challenge(
        &self,
        token: &str,
        user_id: &str,
        request: LinkChallengeRequest,
        now: i64,
    ) -> Option<LinkChallengeClaims> {
        let claims = jws::verify(
            &self.public,
            token,
            &self.expect(LINK_CHALLENGE_TYP, now, jws::DEFAULT_MAX_AGE_SECONDS),
        )
        .ok()?;
        let c: LinkChallengeClaims = serde_json::from_value(claims.into()).ok()?;
        let r = c.request;
        let ok = c.kind == LINK_CHALLENGE_KIND
            && c.sub == user_id
            && (!request.notifications_enabled || r.notifications_enabled)
            && (!request.live_activities_enabled || r.live_activities_enabled)
            && (!request.managed_tunnels_enabled || r.managed_tunnels_enabled);
        ok.then_some(c)
    }

    #[allow(clippy::too_many_arguments)] // `issueDpopAccessToken` input, field by field.
    /// `issueDpopAccessToken`; `scopes` must be non-empty and unique (`encodeOAuthScope`).
    pub fn issue_dpop_access_token(
        &self,
        user_id: &str,
        proof_key_thumbprint: &str,
        jti: &str,
        issued_at: i64,
        expires_at: i64,
        client_id: &str,
        scopes: &[&str],
    ) -> String {
        debug_assert!(!scopes.is_empty(), "encodeOAuthScope refuses an empty list");
        let claims = DpopAccessTokenClaims {
            iss: self.issuer.clone(),
            aud: self.issuer.clone(),
            sub: user_id.to_owned(),
            jti: jti.to_owned(),
            iat: issued_at,
            exp: expires_at,
            client_id: client_id.to_owned(),
            scope: scopes.join(" "),
            cnf: Cnf {
                jkt: proof_key_thumbprint.to_owned(),
            },
        };
        jws::sign(&self.key, ACCESS_TOKEN_TYP, &claims)
    }

    /// `verifyDpopAccessToken`: 30-minute max age, a known client and scopes it may hold.
    pub fn verify_dpop_access_token(
        &self,
        token: &str,
        now: i64,
    ) -> Option<VerifiedDpopAccessToken> {
        let claims = jws::verify(
            &self.public,
            token,
            &self.expect(ACCESS_TOKEN_TYP, now, RELAY_DPOP_ACCESS_TOKEN_TTL_SECONDS),
        )
        .map_err(|e| tracing::debug!(code = e.code, "relay.tokens.verification_failure"))
        .ok()?;
        let claims: DpopAccessTokenClaims = serde_json::from_value(claims.into()).ok()?;
        let scopes = resolve_dpop_access_token_scopes(&claims.client_id, &claims.scope)?;
        Some(VerifiedDpopAccessToken { claims, scopes })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jws::tests::{fixture, test_only_key, token};
    use serde_json::{Value, json};

    const ALL: LinkChallengeRequest = LinkChallengeRequest {
        notifications_enabled: true,
        live_activities_enabled: true,
        managed_tunnels_enabled: true,
    };
    const NONE: LinkChallengeRequest = LinkChallengeRequest {
        notifications_enabled: false,
        live_activities_enabled: false,
        managed_tunnels_enabled: false,
    };

    fn tokens() -> RelayTokens {
        // T3's test config uses a trailing slash; the issuer is normalized.
        RelayTokens::new(test_only_key("relayMint"), "https://relay.example.test/")
    }

    fn sign_vector(name: &str) -> Value {
        fixture()["sign"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["name"] == name)
            .unwrap()
            .clone()
    }

    fn i(v: &Value) -> i64 {
        v.as_i64().unwrap()
    }

    fn s(v: &Value) -> &str {
        v.as_str().unwrap()
    }

    #[test]
    fn link_challenge_signs_what_shared_signs() {
        let v = sign_vector("link_challenge");
        let p = &v["payload"];
        let request: LinkChallengeRequest = serde_json::from_value(p.clone()).unwrap();
        let t = tokens().issue_link_challenge(
            s(&p["sub"]),
            request,
            s(&p["jti"]),
            i(&p["iat"]),
            i(&p["exp"]),
        );
        assert_eq!(t, token(&v));
    }

    #[test]
    fn dpop_access_tokens_sign_what_shared_signs() {
        for name in ["dpop_access_mobile", "dpop_access_web"] {
            let v = sign_vector(name);
            let p = &v["payload"];
            let scopes: Vec<&str> = s(&p["scope"]).split(' ').collect();
            let t = tokens().issue_dpop_access_token(
                s(&p["sub"]),
                s(&p["cnf"]["jkt"]),
                s(&p["jti"]),
                i(&p["iat"]),
                i(&p["exp"]),
                s(&p["client_id"]),
                &scopes,
            );
            assert_eq!(t, token(&v), "{name}");
        }
    }

    // RelayTokens.test.ts "issues a user-bound environment link challenge".
    #[test]
    fn link_challenges_are_bound_to_the_user() {
        let t = tokens();
        let token = t.issue_link_challenge("user_123", ALL, "challenge-1", 100, 200);
        let c = t
            .verify_link_challenge(&token, "user_123", ALL, 150)
            .unwrap();
        assert_eq!(
            (c.sub.as_str(), c.jti.as_str()),
            ("user_123", "challenge-1")
        );
        assert_eq!(c.iss, "https://relay.example.test");
        assert!(
            t.verify_link_challenge(&token, "attacker", ALL, 150)
                .is_none()
        );
        // Expired (exp 200 + 60 s tolerance).
        assert!(
            t.verify_link_challenge(&token, "user_123", ALL, 260)
                .is_none()
        );
    }

    #[test]
    fn link_challenges_grant_only_the_capabilities_they_carry() {
        let t = tokens();
        let token = t.issue_link_challenge("u", NONE, "c", 100, 200);
        assert!(t.verify_link_challenge(&token, "u", NONE, 150).is_some());
        for ask in [
            LinkChallengeRequest {
                notifications_enabled: true,
                ..NONE
            },
            LinkChallengeRequest {
                live_activities_enabled: true,
                ..NONE
            },
            LinkChallengeRequest {
                managed_tunnels_enabled: true,
                ..NONE
            },
        ] {
            assert!(
                t.verify_link_challenge(&token, "u", ask, 150).is_none(),
                "{ask:?}"
            );
        }
        // Asking for less than granted is fine.
        let all = t.issue_link_challenge("u", ALL, "c", 100, 200);
        assert!(t.verify_link_challenge(&all, "u", NONE, 150).is_some());
    }

    #[test]
    fn other_relay_tokens_are_not_link_challenges() {
        let t = tokens();
        let access = t.issue_dpop_access_token(
            "u",
            "jkt",
            "j",
            100,
            200,
            RELAY_WEB_CLIENT_ID,
            &[RELAY_MACHINE_CONNECT_SCOPE],
        );
        assert!(t.verify_link_challenge(&access, "u", NONE, 150).is_none());
        let link = t.issue_link_challenge("u", NONE, "c", 100, 200);
        assert!(t.verify_dpop_access_token(&link, 150).is_none());
        // Right typ, wrong kind.
        let mut claims = json!({"kind": "environment_link_challenge", "iss": t.issuer(), "aud": t.issuer(),
            "sub": "u", "jti": "c", "iat": 100, "exp": 200});
        claims.as_object_mut().unwrap().extend(
            serde_json::to_value(NONE)
                .unwrap()
                .as_object()
                .unwrap()
                .clone(),
        );
        let wrong_kind = jws::sign(&test_only_key("relayMint"), LINK_CHALLENGE_TYP, &claims);
        assert!(
            t.verify_link_challenge(&wrong_kind, "u", NONE, 150)
                .is_none()
        );
        // Signed by another key.
        let stranger = RelayTokens::new(test_only_key("stranger"), "https://relay.example.test");
        let forged = stranger.issue_link_challenge("u", NONE, "c", 100, 200);
        assert!(t.verify_link_challenge(&forged, "u", NONE, 150).is_none());
    }

    // RelayTokens.test.ts "issues and verifies DPoP access tokens bound to one proof-key thumbprint".
    #[test]
    fn dpop_access_tokens_live_30_minutes() {
        let t = tokens();
        let scopes = [
            RELAY_MACHINE_CONNECT_SCOPE,
            RELAY_MACHINE_STATUS_SCOPE,
            RELAY_MOBILE_REGISTRATION_SCOPE,
        ];
        let token = t.issue_dpop_access_token(
            "user_123",
            "proof-key-thumbprint",
            "access-token-1",
            100,
            1_900,
            RELAY_MOBILE_CLIENT_ID,
            &scopes,
        );
        let v = t.verify_dpop_access_token(&token, 700).unwrap();
        assert_eq!(v.claims.sub, "user_123");
        assert_eq!(v.claims.cnf.jkt, "proof-key-thumbprint");
        assert_eq!(v.claims.client_id, RELAY_MOBILE_CLIENT_ID);
        assert_eq!(v.scopes, scopes);
        assert!(t.verify_dpop_access_token(&token, 1_961).is_none());
    }

    // RelayTokens.test.ts: scope outside the policy, and mobile scope on a web token.
    #[test]
    fn dpop_access_tokens_hold_only_their_clients_scopes() {
        let t = tokens();
        let key = test_only_key("relayMint");
        let signed = |client: &str, scope: &str| {
            jws::sign(
                &key,
                ACCESS_TOKEN_TYP,
                &json!({"iss": t.issuer(), "aud": t.issuer(), "sub": "user_123",
                "jti": "j", "iat": 100, "exp": 200, "client_id": client, "scope": scope,
                "cnf": {"jkt": "proof-key-thumbprint"}}),
            )
        };
        assert!(
            t.verify_dpop_access_token(&signed(RELAY_MOBILE_CLIENT_ID, "machine:admin"), 150)
                .is_none()
        );
        assert!(
            t.verify_dpop_access_token(
                &signed(RELAY_WEB_CLIENT_ID, "machine:connect mobile:registration"),
                150
            )
            .is_none()
        );
        assert!(
            t.verify_dpop_access_token(&signed("t3-web", "machine:connect"), 150)
                .is_none()
        );
        let web = t
            .verify_dpop_access_token(
                &signed(RELAY_WEB_CLIENT_ID, "machine:connect machine:status"),
                150,
            )
            .unwrap();
        assert_eq!(
            web.scopes,
            [RELAY_MACHINE_CONNECT_SCOPE, RELAY_MACHINE_STATUS_SCOPE]
        );
    }

    #[test]
    fn scope_parsing_follows_oauth_scope_ts() {
        let r = |scope| resolve_dpop_access_token_scopes(RELAY_MOBILE_CLIENT_ID, scope);
        assert_eq!(
            r("machine:connect machine:connect"),
            Some(vec![RELAY_MACHINE_CONNECT_SCOPE])
        );
        assert_eq!(
            r("machine:status machine:connect"),
            Some(vec![
                RELAY_MACHINE_STATUS_SCOPE,
                RELAY_MACHINE_CONNECT_SCOPE
            ])
        );
        for bad in [
            "",
            " ",
            "machine:connect  machine:status",
            "machine:connect ",
            "\"x\"",
        ] {
            assert_eq!(r(bad), None, "{bad:?}");
        }
        assert_eq!(
            resolve_dpop_access_token_scopes("other", "machine:connect"),
            None
        );
    }
}
