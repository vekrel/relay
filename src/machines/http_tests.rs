// End-to-end tests of linking and connecting through the HTTP routes, with Engine-format proofs
// (`Vekrel-Engine/apps/server/src/cloud/CloudLink.ts` makeCloudLinkProof / mintCredential), a fake
// machine on loopback, and a fake tunnel provider that allocates without Cloudflare.
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::{EncodePrivateKey, EncodePublicKey, spki::der::pem::LineEnding};
use http_body_util::BodyExt;
use p256::ecdsa::signature::Signer;
use serde_json::{Value, json};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

use super::provider::{
    Allocation, BoxFuture, DeprovisionFailed, ManagedEndpoints, NoTunnels, OriginSync,
    ProviderError, Provisioned, RuntimeConfig,
};
use super::{Endpoint, Origin, Relay, limits, now_ms};
use crate::accounts::keys::SigningKeys;
use crate::accounts::oauth::AccountsState;
use crate::accounts::tokens::{AccessClaims, sign_access_token};
use crate::config::Config;
use crate::http::client::{MachineState, router};
use crate::jws::{self, b64url_encode, tests::test_only_key};

const ORIGIN: &str = "https://relay.example.test";
const ZONE: &str = "tunnels.example.test";

fn spki(key: &SigningKey) -> String {
    key.verifying_key()
        .to_public_key_pem(LineEnding::LF)
        .unwrap()
        .trim_end()
        .to_owned()
}

/// Allocates a ready tunnel row per machine, after the cap check, as Task 10's provider will.
struct FakeTunnels {
    pool: PgPool,
}

impl ManagedEndpoints for FakeTunnels {
    fn provision<'a>(
        &'a self,
        user: Uuid,
        machine_id: &'a str,
        _: &'a Origin,
        _: bool,
    ) -> BoxFuture<'a, Result<Provisioned, ProviderError>> {
        Box::pin(async move {
            match limits::ensure_capacity(&self.pool, user, machine_id).await {
                Err(limits::LimitError::Exceeded { max_tunnels, .. }) => {
                    return Err(ProviderError::LimitExceeded { max_tunnels });
                }
                Err(limits::LimitError::Persistence(_)) => {
                    return Err(ProviderError::Failed {
                        stage: "check-tunnel-limit",
                    });
                }
                Ok(()) => {}
            }
            let host = format!("prod-{}.{ZONE}", &Uuid::new_v4().simple().to_string()[..16]);
            let now = super::now_iso();
            sqlx::query(
                "INSERT INTO relay_managed_endpoint_allocations (user_id, machine_id, hostname,
                    tunnel_id, tunnel_name, dns_record_id, ready_at, created_at, updated_at)
                 VALUES ($1, $2, $3, 'tunnel-1', $3, 'dns-1', $4, $4, $4)
                 ON CONFLICT (user_id, machine_id) DO NOTHING",
            )
            .bind(user)
            .bind(machine_id)
            .bind(&host)
            .bind(&now)
            .execute(&self.pool)
            .await
            .unwrap();
            let a = super::provider::allocation(&self.pool, user, machine_id)
                .await
                .unwrap()
                .unwrap();
            Ok(Provisioned {
                endpoint: crate::machines::connector::endpoint_for_hostname(&a.hostname),
                runtime: RuntimeConfig {
                    provider_kind: "cloudflare_tunnel".into(),
                    connector_token: "connector-token".into(),
                    tunnel_id: a.tunnel_id,
                    tunnel_name: Some(a.tunnel_name),
                },
            })
        })
    }
    fn reconcile_origin<'a>(
        &'a self,
        _: Uuid,
        _: &'a str,
        _: &'a str,
        _: &'a Origin,
        _: &'a Endpoint,
    ) -> BoxFuture<'a, Result<OriginSync, ProviderError>> {
        Box::pin(async { Ok(OriginSync::Ready) })
    }
    fn prepare_deprovision<'a>(
        &'a self,
        _: Uuid,
        _: &'a str,
    ) -> BoxFuture<'a, Result<Option<Allocation>, DeprovisionFailed>> {
        Box::pin(async { Ok(None) })
    }
    fn deprovision<'a>(
        &'a self,
        _: Uuid,
        _: &'a str,
        _: Option<Option<Allocation>>,
    ) -> BoxFuture<'a, Result<bool, DeprovisionFailed>> {
        Box::pin(async { Ok(true) })
    }
    fn release<'a>(
        &'a self,
        _: Uuid,
        _: &'a str,
        _: Option<&'a str>,
    ) -> BoxFuture<'a, Result<bool, DeprovisionFailed>> {
        Box::pin(async { Ok(true) })
    }
    fn enable_recovery<'a>(
        &'a self,
        _: Uuid,
        _: &'a str,
        _: &'a str,
        _: &'a str,
        _: &'a Origin,
    ) -> BoxFuture<'a, Result<bool, sqlx::Error>> {
        Box::pin(async { Ok(true) })
    }
}

struct App {
    router: Router,
    pool: PgPool,
    keys: Arc<SigningKeys>,
    relay: Arc<Relay>,
}

struct Res {
    status: StatusCode,
    headers: axum::http::HeaderMap,
    body: Vec<u8>,
}

impl Res {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }
}

fn app_with(
    pool: PgPool,
    provider: Arc<dyn ManagedEndpoints>,
    endpoint_override: Option<String>,
) -> App {
    let mint = test_only_key("relayMint");
    let pem = mint.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
    let config = Config::for_tests(&[
        ("RELAY_ORIGIN", ORIGIN),
        ("RELAY_MINT_PRIVATE_KEY", &pem),
        ("RELAY_TUNNEL_ZONE_NAME", ZONE),
    ]);
    let (a, _) = crate::accounts::keys::tests::entry("a", "active");
    let keys = Arc::new(SigningKeys::from_json(&json!([a]).to_string()).unwrap());
    let mut relay = Relay::new(pool.clone(), mint, ORIGIN, Some(ZONE.into()), provider);
    relay.endpoint_override = endpoint_override;
    let relay = Arc::new(relay);
    let accounts = AccountsState::new(pool.clone(), keys.clone(), &config);
    App {
        router: router(MachineState {
            relay: relay.clone(),
            accounts,
        }),
        pool,
        keys,
        relay,
    }
}

fn app(pool: PgPool) -> App {
    app_with(pool, Arc::new(NoTunnels), None)
}

impl App {
    async fn send(&self, req: Request<Body>) -> Res {
        let res = self.router.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let headers = res.headers().clone();
        let body = res.into_body().collect().await.unwrap().to_bytes().to_vec();
        Res {
            status,
            headers,
            body,
        }
    }

    async fn call(&self, method: &str, path: &str, auth: Option<&str>, body: Option<Value>) -> Res {
        let mut b = Request::builder().method(method).uri(path);
        if let Some(a) = auth {
            b = b.header(header::AUTHORIZATION, a);
        }
        let body = match body {
            Some(v) => {
                b = b.header(header::CONTENT_TYPE, "application/json");
                Body::from(v.to_string())
            }
            None => Body::empty(),
        };
        self.send(b.body(body).unwrap()).await
    }

    async fn user(&self, email: &str) -> (Uuid, String) {
        let id: Uuid = sqlx::query_scalar("INSERT INTO users (email) VALUES ($1) RETURNING id")
            .bind(email)
            .fetch_one(&self.pool)
            .await
            .unwrap();
        let claims = AccessClaims::new(
            ORIGIN,
            id,
            Uuid::new_v4(),
            "vekrel-cli",
            email,
            crate::accounts::tokens::now_secs(),
        );
        (
            id,
            format!("Bearer {}", sign_access_token(&self.keys, &claims)),
        )
    }

    async fn challenge(&self, bearer: &str, managed: bool) -> String {
        let r = self
            .call(
                "POST",
                "/v1/client/machine-link-challenges",
                Some(bearer),
                Some(json!({"notificationsEnabled": true, "liveActivitiesEnabled": true, "managedTunnelsEnabled": managed})),
            )
            .await;
        assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
        r.json()["challenge"].as_str().unwrap().to_owned()
    }

    async fn link(&self, bearer: &str, proof: &str, managed: bool) -> Res {
        self.call(
            "POST",
            "/v1/client/machine-links",
            Some(bearer),
            Some(json!({"proof": proof, "notificationsEnabled": true, "liveActivitiesEnabled": true, "managedTunnelsEnabled": managed})),
        )
        .await
    }

    /// challenge -> Engine proof -> link; the link response.
    async fn link_machine(&self, bearer: &str, machine_id: &str, managed: bool) -> Value {
        let challenge = self.challenge(bearer, managed).await;
        let proof = ProofSpec::new(machine_id, &challenge, managed).sign();
        let r = self.link(bearer, &proof, managed).await;
        assert_eq!(
            r.status,
            StatusCode::OK,
            "{}",
            String::from_utf8_lossy(&r.body)
        );
        r.json()
    }
}

/// An Engine `makeCloudLinkProof` payload, field for field.
struct ProofSpec {
    key: SigningKey,
    machine_id: String,
    challenge: String,
    managed: bool,
    host: String,
    exp_offset: i64,
    descriptor_machine_id: String,
    aud: String,
    endpoint_kind: Option<&'static str>,
}

impl ProofSpec {
    fn new(machine_id: &str, challenge: &str, managed: bool) -> Self {
        Self {
            key: test_only_key("machine"),
            machine_id: machine_id.into(),
            challenge: challenge.into(),
            managed,
            host: "127.0.0.1".into(),
            exp_offset: 300,
            descriptor_machine_id: machine_id.into(),
            aud: ORIGIN.into(),
            endpoint_kind: None,
        }
    }

    fn sign(&self) -> String {
        let now = now_ms() / 1000;
        let base = if self.managed {
            "https://placeholder.invalid/"
        } else {
            "http://127.0.0.1:3773/"
        };
        let payload = json!({
            "iss": format!("vekrel-machine:{}", self.machine_id),
            "aud": self.aud,
            "sub": self.machine_id,
            "jti": Uuid::new_v4().to_string(),
            "iat": now,
            "exp": now + self.exp_offset,
            "challenge": self.challenge,
            "descriptor": {
                "machineId": self.descriptor_machine_id,
                "label": "Studio Mac",
                "platform": {"os": "darwin", "arch": "arm64"},
                "serverVersion": "0.0.1",
                "capabilities": {"repositoryIdentity": true},
            },
            "machineId": self.machine_id,
            "machinePublicKey": format!("{}\n", spki(&self.key)),
            "endpoint": {
                "httpBaseUrl": base,
                "wsBaseUrl": base.replace("http", "ws"),
                "providerKind": self.endpoint_kind.unwrap_or(if self.managed { "cloudflare_tunnel" } else { "manual" }),
            },
            "origin": {"localHttpHost": self.host, "localHttpPort": 3773},
            "scopes": if self.managed {
                json!(["agent_activity_notifications", "managed_tunnels"])
            } else {
                json!(["agent_activity_notifications"])
            },
        });
        jws::sign(&self.key, jws::RELAY_LINK_PROOF_TYP, &payload)
    }
}

fn tag(r: &Res) -> (StatusCode, Value, Value) {
    let j = r.json();
    (r.status, j["_tag"].clone(), j["reason"].clone())
}

#[sqlx::test]
async fn engine_format_link_proof_links_a_machine(pool: PgPool) {
    let app = app(pool);
    let (user, bearer) = app.user("a@example.test").await;
    let challenge = app.challenge(&bearer, false).await;
    let proof = ProofSpec::new("machine-1", &challenge, false).sign();
    let r = app.link(&bearer, &proof, false).await;
    assert_eq!(
        r.status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&r.body)
    );
    assert_eq!(r.headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(r.headers[header::PRAGMA], "no-cache");
    let j = r.json();
    let keys: Vec<&String> = j.as_object().unwrap().keys().collect();
    assert_eq!(
        keys,
        [
            "ok",
            "cloudUserId",
            "machineId",
            "endpoint",
            "endpointRuntime",
            "relayIssuer",
            "machineCredential",
            "cloudMintPublicKey"
        ]
    );
    assert_eq!(j["cloudUserId"], format!("usr_{user}"));
    assert_eq!(j["machineId"], "machine-1");
    assert_eq!(j["endpointRuntime"], Value::Null);
    assert_eq!(j["relayIssuer"], ORIGIN);
    assert_eq!(j["cloudMintPublicKey"], spki(&test_only_key("relayMint")));
    assert_eq!(
        j["endpoint"],
        json!({"httpBaseUrl": "http://127.0.0.1:3773/", "wsBaseUrl": "ws://127.0.0.1:3773/", "providerKind": "manual"})
    );
    // Only the hash of the credential is stored.
    let credential = j["machineCredential"].as_str().unwrap().to_owned();
    let stored: Vec<String> =
        sqlx::query_scalar("SELECT credential_hash FROM relay_machine_credentials")
            .fetch_all(&app.pool)
            .await
            .unwrap();
    assert_eq!(stored.len(), 1);
    assert_ne!(stored[0], credential);

    let list = app.call("GET", "/v1/machines", Some(&bearer), None).await;
    assert_eq!(list.status, StatusCode::OK);
    let m = &list.json()["machines"][0];
    assert_eq!(m["machineId"], "machine-1");
    assert_eq!(m["label"], "Studio Mac");
    assert!(m["linkedAt"].as_str().unwrap().ends_with('Z'));

    // The credential authenticates the machine's own routes.
    let prefs = app
        .call(
            "POST",
            "/v1/machines/machine-1/link-preferences",
            Some(&format!("Bearer {credential}")),
            Some(json!({"holdWebhooksWhileOffline": true})),
        )
        .await;
    assert_eq!(prefs.status, StatusCode::OK);
    assert_eq!(prefs.body, br#"{"holdWebhooksWhileOffline":true}"#);
    // ...but not another machine's.
    let other = app
        .call(
            "POST",
            "/v1/machines/machine-2/link-preferences",
            Some(&format!("Bearer {credential}")),
            Some(json!({"holdWebhooksWhileOffline": true})),
        )
        .await;
    assert_eq!(tag(&other).2, "not_authorized");
}

#[sqlx::test]
async fn bad_link_proofs_are_refused(pool: PgPool) {
    let app = app(pool);
    let (_, bearer) = app.user("a@example.test").await;
    let (_, other) = app.user("b@example.test").await;

    // Expired.
    let c = app.challenge(&bearer, false).await;
    let mut spec = ProofSpec::new("m", &c, false);
    spec.exp_offset = -1;
    let r = app.link(&bearer, &spec.sign(), false).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert_eq!(r.json()["_tag"], "RelayMachineLinkProofExpiredError");
    assert_eq!(r.json()["code"], "machine_link_proof_expired");

    // A challenge issued to another user.
    let theirs = app.challenge(&other, false).await;
    let r = app
        .link(&bearer, &ProofSpec::new("m", &theirs, false).sign(), false)
        .await;
    assert_eq!(
        tag(&r),
        (
            StatusCode::BAD_REQUEST,
            json!("RelayMachineLinkProofInvalidError"),
            json!("challenge_invalid")
        )
    );

    // A forged signature.
    let c = app.challenge(&bearer, false).await;
    let mut parts: Vec<String> = ProofSpec::new("m", &c, false)
        .sign()
        .split('.')
        .map(str::to_owned)
        .collect();
    parts[2] = b64url_encode([0u8; 64]);
    let r = app.link(&bearer, &parts.join("."), false).await;
    assert_eq!(tag(&r).2, "invalid_signature_or_scope");

    // Wrong audience.
    let mut spec = ProofSpec::new("m", &c, false);
    spec.aud = "https://other-relay.example.test".into();
    assert_eq!(
        tag(&app.link(&bearer, &spec.sign(), false).await).2,
        "invalid_signature_or_scope"
    );

    // Descriptor for another machine.
    let mut spec = ProofSpec::new("m", &c, false);
    spec.descriptor_machine_id = "n".into();
    assert_eq!(
        tag(&app.link(&bearer, &spec.sign(), false).await).2,
        "descriptor_mismatch"
    );

    // A managed link asks for more than the challenge granted.
    let r = app
        .link(&bearer, &ProofSpec::new("m", &c, true).sign(), true)
        .await;
    assert_eq!(tag(&r).2, "challenge_invalid");

    // Replayed proof, then a fresh proof over a spent challenge.
    let c = app.challenge(&bearer, false).await;
    let proof = ProofSpec::new("m", &c, false).sign();
    assert_eq!(
        app.link(&bearer, &proof, false).await.status,
        StatusCode::OK
    );
    assert_eq!(
        tag(&app.link(&bearer, &proof, false).await).2,
        "replayed_nonce"
    );
    let again = ProofSpec::new("m", &c, false).sign();
    assert_eq!(
        tag(&app.link(&bearer, &again, false).await).2,
        "challenge_invalid"
    );

    // Not a JWS at all; a body that is not the schema.
    assert_eq!(
        tag(&app.link(&bearer, "nope", false).await).2,
        "invalid_signature_or_scope"
    );
    let r = app
        .call(
            "POST",
            "/v1/client/machine-links",
            Some(&bearer),
            Some(json!({"proof": "x"})),
        )
        .await;
    assert_eq!((r.status, r.body.len()), (StatusCode::BAD_REQUEST, 0));
}

#[sqlx::test]
async fn managed_links_need_a_loopback_origin_and_a_provider(pool: PgPool) {
    let app = app(pool);
    let (_, bearer) = app.user("a@example.test").await;
    let c = app.challenge(&bearer, true).await;
    let mut spec = ProofSpec::new("m", &c, true);
    spec.host = "192.168.1.20".into();
    let r = app.link(&bearer, &spec.sign(), true).await;
    assert_eq!(
        tag(&r),
        (
            StatusCode::BAD_REQUEST,
            json!("RelayMachineLinkProofInvalidError"),
            json!("origin_not_allowed")
        )
    );
    // Loopback, but no tunnel provider is configured (until Task 10).
    let c = app.challenge(&bearer, true).await;
    let r = app
        .link(&bearer, &ProofSpec::new("m", &c, true).sign(), true)
        .await;
    assert_eq!(
        tag(&r),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            json!("RelayMachineLinkUnavailableError"),
            json!("managed_endpoint_not_configured")
        )
    );
    assert_eq!(r.headers[header::CACHE_CONTROL], "no-store");
}

#[sqlx::test]
async fn a_fourth_tunnel_is_refused(pool: PgPool) {
    let app = app_with(pool.clone(), Arc::new(FakeTunnels { pool }), None);
    let (_, bearer) = app.user("a@example.test").await;
    // The linker itself refuses a non-loopback origin, whatever the provider would do.
    let c = app.challenge(&bearer, true).await;
    let mut spec = ProofSpec::new("m0", &c, true);
    spec.host = "10.0.0.5".into();
    assert_eq!(
        tag(&app.link(&bearer, &spec.sign(), true).await).2,
        "origin_not_allowed"
    );
    for m in ["m1", "m2", "m3"] {
        let j = app.link_machine(&bearer, m, true).await;
        assert_eq!(j["endpoint"]["providerKind"], "cloudflare_tunnel");
        assert_eq!(j["endpointRuntime"]["connectorToken"], "connector-token");
    }
    let c = app.challenge(&bearer, true).await;
    let r = app
        .link(&bearer, &ProofSpec::new("m4", &c, true).sign(), true)
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let j = r.json();
    assert_eq!(j["_tag"], "RelayMachineLinkLimitExceededError");
    assert_eq!(j["code"], "machine_link_limit_exceeded");
    assert_eq!(j["maxTunnels"], 3);
    // Re-linking a machine that already holds a tunnel stays possible at the limit.
    app.link_machine(&bearer, "m2", true).await;
    // Another user has their own three.
    let (_, other) = app.user("b@example.test").await;
    app.link_machine(&other, "m4", true).await;
}

#[sqlx::test]
async fn unlinked_or_disabled_machines_get_401(pool: PgPool) {
    let app = app(pool);
    let (user, bearer) = app.user("a@example.test").await;
    let credential = app.link_machine(&bearer, "m", false).await["machineCredential"]
        .as_str()
        .unwrap()
        .to_owned();
    let machine = format!("Bearer {credential}");
    let prefs = |hold: bool| json!({"holdWebhooksWhileOffline": hold});
    let path = "/v1/machines/m/link-preferences";
    assert_eq!(
        app.call("POST", path, Some(&machine), Some(prefs(false)))
            .await
            .status,
        StatusCode::OK
    );

    // A disabled user's machines lose access, and so does the user's bearer.
    sqlx::query("UPDATE users SET disabled_at = now() WHERE id = $1")
        .bind(user)
        .execute(&app.pool)
        .await
        .unwrap();
    let r = app
        .call("POST", path, Some(&machine), Some(prefs(false)))
        .await;
    assert_eq!(
        tag(&r),
        (
            StatusCode::UNAUTHORIZED,
            json!("RelayAuthInvalidError"),
            json!("not_authorized")
        )
    );
    let r = app.call("GET", "/v1/machines", Some(&bearer), None).await;
    assert_eq!(tag(&r).2, "invalid_bearer");
    sqlx::query("UPDATE users SET disabled_at = NULL WHERE id = $1")
        .bind(user)
        .execute(&app.pool)
        .await
        .unwrap();
    assert_eq!(
        app.call("POST", path, Some(&machine), Some(prefs(false)))
            .await
            .status,
        StatusCode::OK
    );

    // Unlink: the link is revoked, the credential with it.
    let r = app
        .call("DELETE", "/v1/client/machine-links/m", Some(&bearer), None)
        .await;
    assert_eq!(
        (r.status, r.body.as_slice()),
        (StatusCode::OK, br#"{"ok":true}"#.as_slice())
    );
    let r = app
        .call("POST", path, Some(&machine), Some(prefs(false)))
        .await;
    assert_eq!(
        tag(&r),
        (
            StatusCode::UNAUTHORIZED,
            json!("RelayAuthInvalidError"),
            json!("not_authorized")
        )
    );
    let revoked: bool =
        sqlx::query_scalar("SELECT revoked_at IS NOT NULL FROM relay_machine_credentials")
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert!(revoked);
    // A second unlink finds nothing.
    let r = app
        .call("DELETE", "/v1/client/machine-links/m", Some(&bearer), None)
        .await;
    assert_eq!(r.body, br#"{"ok":false}"#);
    assert!(
        app.call("GET", "/v1/machines", Some(&bearer), None)
            .await
            .json()["machines"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[sqlx::test]
async fn a_live_credential_without_a_live_link_is_refused(pool: PgPool) {
    // T3 keys credentials by machine: revoke the link row directly and the credential, though
    // unrevoked, no longer authenticates.
    let app = app(pool);
    let (_, bearer) = app.user("a@example.test").await;
    let credential = app.link_machine(&bearer, "m", false).await["machineCredential"]
        .as_str()
        .unwrap()
        .to_owned();
    sqlx::query("UPDATE relay_machine_links SET revoked_at = 'x'")
        .execute(&app.pool)
        .await
        .unwrap();
    let r = app
        .call(
            "POST",
            "/v1/machines/m/link-preferences",
            Some(&format!("Bearer {credential}")),
            Some(json!({"holdWebhooksWhileOffline": false})),
        )
        .await;
    assert_eq!(tag(&r).2, "not_authorized");
}

#[sqlx::test]
async fn client_routes_refuse_bad_bearers(pool: PgPool) {
    let app = app(pool);
    for auth in [
        None,
        Some("Bearer nope"),
        Some("Basic abc"),
        Some("Bearer "),
    ] {
        let r = app.call("GET", "/v1/machines", auth, None).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{auth:?}");
        let j = r.json();
        let keys: Vec<&String> = j.as_object().unwrap().keys().collect();
        assert_eq!(keys, ["_tag", "code", "reason", "traceId"]);
        assert_eq!(
            (j["code"].as_str(), j["reason"].as_str()),
            (Some("auth_invalid"), Some("invalid_bearer"))
        );
        assert_eq!(j["traceId"].as_str().unwrap().len(), 32);
    }
    // CORS as T3's relay middleware.
    let r = app
        .send(
            Request::builder()
                .method("OPTIONS")
                .uri("/v1/machines")
                .header(header::ORIGIN, "https://app.example.test")
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
                .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "authorization")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(r.headers[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");
    assert_eq!(r.headers[header::ACCESS_CONTROL_MAX_AGE], "86400");
}

// ---- DPoP clients and connect ----

struct DpopKey {
    key: p256::ecdsa::SigningKey,
    jwk: Value,
    jkt: String,
}

impl DpopKey {
    fn new(seed: u8) -> Self {
        let key = p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap();
        let point = key.verifying_key().to_sec1_point(false);
        let b = point.as_bytes();
        let (x, y) = (b64url_encode(&b[1..33]), b64url_encode(&b[33..65]));
        let jkt = crate::auth::dpop::thumbprint("P-256", "EC", &x, &y);
        Self {
            key,
            jwk: json!({"kty": "EC", "crv": "P-256", "x": x, "y": y}),
            jkt,
        }
    }

    fn proof(&self, method: &str, url: &str, access_token: Option<&str>) -> String {
        let header = json!({"typ": "dpop+jwt", "alg": "ES256", "jwk": self.jwk});
        let mut claims = json!({"htm": method, "htu": url, "iat": now_ms() / 1000, "jti": Uuid::new_v4().to_string()});
        if let Some(t) = access_token {
            claims["ath"] = crate::auth::dpop::access_token_hash(t).into();
        }
        let input = format!(
            "{}.{}",
            b64url_encode(header.to_string()),
            b64url_encode(claims.to_string())
        );
        let sig: p256::ecdsa::Signature = self.key.sign(input.as_bytes());
        format!("{input}.{}", b64url_encode(sig.to_bytes()))
    }
}

impl App {
    async fn exchange(&self, bearer: &str, key: &DpopKey, form: &[(&str, &str)]) -> Res {
        let account = bearer.strip_prefix("Bearer ").unwrap();
        let mut pairs = vec![
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ),
            ("subject_token", account),
            ("subject_token_type", "urn:ietf:params:oauth:token-type:jwt"),
            (
                "requested_token_type",
                "urn:ietf:params:oauth:token-type:access_token",
            ),
            ("resource", ORIGIN),
            ("scope", "machine:connect machine:status"),
            ("client_id", "vekrel-web"),
        ];
        for (k, v) in form {
            pairs.retain(|(pk, _)| pk != k);
            pairs.push((k, v));
        }
        let body = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(pairs)
            .finish();
        let url = format!("{ORIGIN}/v1/client/dpop-token");
        self.send(
            Request::post("/v1/client/dpop-token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header("dpop", key.proof("POST", &url, None))
                .body(Body::from(body))
                .unwrap(),
        )
        .await
    }

    async fn relay_token(&self, bearer: &str, key: &DpopKey) -> String {
        let r = self.exchange(bearer, key, &[]).await;
        assert_eq!(
            r.status,
            StatusCode::OK,
            "{}",
            String::from_utf8_lossy(&r.body)
        );
        r.json()["access_token"].as_str().unwrap().to_owned()
    }

    async fn dpop_call(&self, path: &str, token: &str, key: &DpopKey, body: Option<Value>) -> Res {
        let url = format!("{ORIGIN}{path}");
        let mut b = Request::post(path)
            .header(header::AUTHORIZATION, format!("DPoP {token}"))
            .header("dpop", key.proof("POST", &url, Some(token)));
        let body = match body {
            Some(v) => {
                b = b.header(header::CONTENT_TYPE, "application/json");
                Body::from(v.to_string())
            }
            None => Body::empty(),
        };
        self.send(b.body(body).unwrap()).await
    }
}

#[sqlx::test]
async fn token_exchange_follows_t3(pool: PgPool) {
    let app = app(pool);
    let (user, bearer) = app.user("a@example.test").await;
    let key = DpopKey::new(7);
    let r = app.exchange(&bearer, &key, &[]).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.headers[header::CACHE_CONTROL], "no-store");
    let j = r.json();
    let keys: Vec<&String> = j.as_object().unwrap().keys().collect();
    assert_eq!(
        keys,
        [
            "access_token",
            "issued_token_type",
            "token_type",
            "expires_in",
            "scope"
        ]
    );
    assert_eq!(j["token_type"], "DPoP");
    assert_eq!(j["expires_in"], 1800);
    assert_eq!(j["scope"], "machine:connect machine:status");
    let v = app
        .relay
        .tokens
        .verify_dpop_access_token(j["access_token"].as_str().unwrap(), now_ms() / 1000)
        .unwrap();
    assert_eq!(v.claims.sub, format!("usr_{user}"));
    assert_eq!(v.claims.cnf.jkt, key.jkt);

    let r = app
        .exchange(&bearer, &key, &[("resource", "https://elsewhere.test")])
        .await;
    assert_eq!(
        (tag(&r).2, r.json()["dpopFailureReason"].clone()),
        (json!("invalid_dpop"), json!("invalid_proof"))
    );
    let r = app
        .exchange(&bearer, &key, &[("scope", "mobile:registration")])
        .await;
    assert_eq!(tag(&r).2, "invalid_dpop");
    let r = app.exchange("Bearer forged", &key, &[]).await;
    assert_eq!(
        tag(&r),
        (
            StatusCode::UNAUTHORIZED,
            json!("RelayAuthInvalidError"),
            json!("invalid_bearer")
        )
    );
    let r = app
        .exchange(&bearer, &key, &[("client_id", "t3-web")])
        .await;
    assert_eq!((r.status, r.body.len()), (StatusCode::BAD_REQUEST, 0));
    let r = app
        .send(
            Request::post("/v1/client/dpop-token")
                .header(header::CONTENT_TYPE, "application/json")
                .header("dpop", "x")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await;
    assert_eq!(r.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(r.body, b"Unsupported content-type: application/json");
}

#[derive(Clone, Copy, PartialEq)]
enum MachineMode {
    Honest,
    WrongNonce,
    Cloudflare1033,
}

/// A fake Engine `/api/vekrel-connect/*`: checks the relay's request as `CloudLink.ts` does and
/// answers signed with the machine key. Records each mint request's claims.
async fn fake_machine(mode: MachineMode, seen: Arc<Mutex<Vec<Value>>>) -> String {
    use axum::Json;
    use axum::routing::post;
    let mint_public = test_only_key("relayMint").verifying_key();
    let handler = move |path: &'static str| {
        let seen = seen.clone();
        move |Json(body): Json<Value>| {
            let seen = seen.clone();
            async move {
                if mode == MachineMode::Cloudflare1033 {
                    return (
                        StatusCode::from_u16(530).unwrap(),
                        "error code: 1033".to_owned(),
                    );
                }
                let typ = if path == "mint" {
                    jws::RELAY_MINT_REQUEST_TYP
                } else {
                    jws::RELAY_HEALTH_REQUEST_TYP
                };
                let claims = jws::verify(
                    &mint_public,
                    body["proof"].as_str().unwrap(),
                    &jws::Expect {
                        typ,
                        issuer: ORIGIN,
                        audience: "vekrel-machine:m",
                        now_epoch_seconds: now_ms() / 1000,
                        max_age_seconds: 300,
                    },
                )
                .expect("relay request verifies with the pinned mint key");
                let claims = Value::Object(claims);
                seen.lock().unwrap().push(claims.clone());
                let nonce = if mode == MachineMode::WrongNonce {
                    "other".into()
                } else {
                    claims["nonce"].clone()
                };
                let now = now_ms() / 1000;
                let key = test_only_key("machine");
                let base = json!({"iss": "vekrel-machine:m", "aud": ORIGIN, "sub": "m", "jti": Uuid::new_v4().to_string(), "iat": now});
                let out = if path == "mint" {
                    let exp = now + 120;
                    let mut p = base;
                    p["exp"] = exp.into();
                    p["machineId"] = "m".into();
                    p["clientProofKeyThumbprint"] = claims["clientProofKeyThumbprint"].clone();
                    p["requestNonce"] = nonce;
                    p["credential"] = "pairing-credential".into();
                    json!({
                        "credential": "pairing-credential",
                        "expiresAt": crate::auth::dpop_proofs::iso_millis(exp * 1000),
                        "proof": jws::sign(&key, jws::RELAY_MINT_RESPONSE_TYP, &p),
                    })
                } else {
                    let checked_at = crate::auth::dpop_proofs::iso_millis(now_ms());
                    let descriptor = json!({"machineId": "m", "label": "Studio Mac", "platform": {"os": "darwin"}, "serverVersion": "0.0.1", "capabilities": {}});
                    let mut p = base;
                    p["exp"] = (now + 300).into();
                    p["machineId"] = "m".into();
                    p["requestNonce"] = nonce;
                    p["status"] = "online".into();
                    p["descriptor"] = descriptor.clone();
                    p["checkedAt"] = checked_at.clone().into();
                    json!({"machineId": "m", "status": "online", "descriptor": descriptor, "checkedAt": checked_at,
                           "proof": jws::sign(&key, jws::RELAY_HEALTH_RESPONSE_TYP, &p)})
                };
                (StatusCode::OK, out.to_string())
            }
        }
    };
    let app = Router::new()
        .route("/api/vekrel-connect/mint-credential", post(handler("mint")))
        .route("/api/vekrel-connect/health", post(handler("health")));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}/")
}

async fn connect_app(pool: PgPool, mode: MachineMode) -> (App, String, Arc<Mutex<Vec<Value>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let base = fake_machine(mode, seen.clone()).await;
    let app = app_with(pool.clone(), Arc::new(FakeTunnels { pool }), Some(base));
    let (_, bearer) = app.user("a@example.test").await;
    app.link_machine(&bearer, "m", true).await;
    (app, bearer, seen)
}

#[sqlx::test]
async fn connect_mints_a_credential_bound_to_the_client_key(pool: PgPool) {
    let (app, bearer, seen) = connect_app(pool, MachineMode::Honest).await;
    let key = DpopKey::new(7);
    let token = app.relay_token(&bearer, &key).await;
    let r = app
        .dpop_call(
            "/v1/machines/m/connect",
            &token,
            &key,
            Some(json!({"clientProofKeyThumbprint": key.jkt, "deviceId": "d1"})),
        )
        .await;
    assert_eq!(
        r.status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&r.body)
    );
    assert_eq!(r.headers[header::CACHE_CONTROL], "no-store");
    let j = r.json();
    let keys: Vec<&String> = j.as_object().unwrap().keys().collect();
    assert_eq!(keys, ["machineId", "endpoint", "credential", "expiresAt"]);
    assert_eq!(j["credential"], "pairing-credential");
    assert!(
        j["endpoint"]["httpBaseUrl"]
            .as_str()
            .unwrap()
            .ends_with(&format!(".{ZONE}/"))
    );
    let sent = seen.lock().unwrap()[0].clone();
    assert_eq!(sent["cnf"]["jkt"], key.jkt.as_str());
    assert_eq!(sent["clientProofKeyThumbprint"], key.jkt.as_str());
    assert_eq!(sent["scope"], json!(["machine:connect"]));
    assert_eq!(sent["deviceId"], "d1");
    assert_eq!(
        sent["exp"].as_i64().unwrap() - sent["iat"].as_i64().unwrap(),
        120
    );

    // Another key's thumbprint: refused before anything is sent.
    let other = DpopKey::new(9);
    let r = app
        .dpop_call(
            "/v1/machines/m/connect",
            &token,
            &key,
            Some(json!({"clientProofKeyThumbprint": other.jkt})),
        )
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert_eq!(r.headers[header::WWW_AUTHENTICATE], "DPoP");
    assert_eq!(r.json()["dpopFailureReason"], "invalid_proof");
    // The token with a proof from another key.
    let r = app
        .dpop_call(
            "/v1/machines/m/connect",
            &token,
            &other,
            Some(json!({"clientProofKeyThumbprint": key.jkt})),
        )
        .await;
    assert_eq!(r.json()["dpopFailureReason"], "key_mismatch");
    // A bearer instead of DPoP.
    let r = app
        .call(
            "POST",
            "/v1/machines/m/connect",
            Some(&format!("Bearer {token}")),
            Some(json!({})),
        )
        .await;
    assert_eq!(
        (tag(&r).2, r.headers[header::WWW_AUTHENTICATE].clone()),
        (json!("invalid_bearer"), "DPoP".parse().unwrap())
    );
    // A machine this user never linked.
    let r = app
        .dpop_call(
            "/v1/machines/zz/connect",
            &token,
            &key,
            Some(json!({"clientProofKeyThumbprint": key.jkt})),
        )
        .await;
    assert_eq!(
        tag(&r),
        (
            StatusCode::FORBIDDEN,
            json!("RelayMachineConnectNotAuthorizedError"),
            json!("machine_link_not_found")
        )
    );
    assert_eq!(seen.lock().unwrap().len(), 1);

    // Status: online with the signed descriptor.
    let r = app
        .dpop_call("/v1/machines/m/status", &token, &key, None)
        .await;
    assert_eq!(
        r.status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&r.body)
    );
    assert!(r.headers.get(header::CACHE_CONTROL).is_none());
    assert_eq!(r.json()["status"], "online");
    assert_eq!(r.json()["descriptor"]["label"], "Studio Mac");
}

#[sqlx::test]
async fn connect_refuses_a_mint_response_with_the_wrong_nonce(pool: PgPool) {
    let (app, bearer, seen) = connect_app(pool, MachineMode::WrongNonce).await;
    let key = DpopKey::new(7);
    let token = app.relay_token(&bearer, &key).await;
    let r = app
        .dpop_call(
            "/v1/machines/m/connect",
            &token,
            &key,
            Some(json!({"clientProofKeyThumbprint": key.jkt})),
        )
        .await;
    assert_eq!(
        tag(&r),
        (
            StatusCode::BAD_GATEWAY,
            json!("RelayMachineEndpointUnavailableError"),
            json!("endpoint_response_invalid")
        )
    );
    assert_eq!(seen.lock().unwrap().len(), 1);
    let r = app
        .dpop_call("/v1/machines/m/status", &token, &key, None)
        .await;
    assert_eq!(tag(&r).2, "endpoint_response_invalid");
}

#[sqlx::test]
async fn a_dead_tunnel_reads_as_offline(pool: PgPool) {
    let (app, bearer, _) = connect_app(pool, MachineMode::Cloudflare1033).await;
    let key = DpopKey::new(7);
    let token = app.relay_token(&bearer, &key).await;
    let r = app
        .dpop_call("/v1/machines/m/status", &token, &key, None)
        .await;
    assert_eq!(r.status, StatusCode::OK);
    let j = r.json();
    assert_eq!(
        (
            j["status"].as_str(),
            j["endpointFailure"].as_str(),
            j["endpointStatus"].as_i64()
        ),
        (Some("offline"), Some("tunnel_down"), Some(530))
    );
    assert_eq!(j["error"], "Managed endpoint health request failed.");
    let r = app
        .dpop_call(
            "/v1/machines/m/connect",
            &token,
            &key,
            Some(json!({"clientProofKeyThumbprint": key.jkt})),
        )
        .await;
    let j = r.json();
    assert_eq!(
        (
            r.status,
            j["reason"].as_str(),
            j["endpointFailure"].as_str(),
            j["endpointStatus"].as_i64()
        ),
        (
            StatusCode::BAD_GATEWAY,
            Some("endpoint_request_failed"),
            Some("tunnel_down"),
            Some(530)
        )
    );
}

#[sqlx::test]
async fn disabled_users_lose_their_relay_dpop_tokens(pool: PgPool) {
    let (app, bearer, _) = connect_app(pool, MachineMode::Honest).await;
    let key = DpopKey::new(7);
    let token = app.relay_token(&bearer, &key).await;
    sqlx::query("UPDATE users SET disabled_at = now()")
        .execute(&app.pool)
        .await
        .unwrap();
    let r = app
        .dpop_call("/v1/machines/m/status", &token, &key, None)
        .await;
    assert_eq!(tag(&r).2, "invalid_bearer");
}

#[sqlx::test]
async fn secrets_never_reach_the_logs(pool: PgPool) {
    crate::test_logs::capture_logs(|| {});
    let (app, bearer, _) = connect_app(pool, MachineMode::WrongNonce).await;
    let credential = app.link_machine(&bearer, "m", true).await["machineCredential"]
        .as_str()
        .unwrap()
        .to_owned();
    let key = DpopKey::new(7);
    let token = app.relay_token(&bearer, &key).await;
    app.dpop_call(
        "/v1/machines/m/connect",
        &token,
        &key,
        Some(json!({"clientProofKeyThumbprint": key.jkt})),
    )
    .await;
    let logs = crate::test_logs::capture_logs(|| {});
    let account = bearer.strip_prefix("Bearer ").unwrap();
    let mint_pem = test_only_key("relayMint")
        .to_pkcs8_pem(LineEnding::LF)
        .unwrap()
        .to_string();
    let mint_body = mint_pem.lines().nth(1).unwrap();
    for secret in [
        credential.as_str(),
        token.as_str(),
        account,
        mint_body,
        "pairing-credential",
    ] {
        assert!(!logs.contains(secret), "a secret reached the logs");
    }
}

#[sqlx::test]
async fn publish_only_links_may_not_claim_a_managed_endpoint(pool: PgPool) {
    let app = app(pool);
    let (_, bearer) = app.user("a@example.test").await;
    for kind in ["cloudflare_tunnel", "vekrel_relay"] {
        let c = app.challenge(&bearer, false).await;
        let mut spec = ProofSpec::new("m", &c, false);
        spec.endpoint_kind = Some(kind);
        let r = app.link(&bearer, &spec.sign(), false).await;
        assert_eq!(
            tag(&r),
            (
                StatusCode::BAD_REQUEST,
                json!("RelayMachineLinkProofInvalidError"),
                json!("invalid_signature_or_scope")
            ),
            "{kind}"
        );
    }
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM relay_machine_links")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
}

#[sqlx::test]
async fn connect_needs_a_link_made_as_managed(pool: PgPool) {
    let (app, bearer, seen) = connect_app(pool, MachineMode::Honest).await;
    sqlx::query("UPDATE relay_machine_links SET managed_tunnels_enabled = false")
        .execute(&app.pool)
        .await
        .unwrap();
    let key = DpopKey::new(7);
    let token = app.relay_token(&bearer, &key).await;
    let r = app
        .dpop_call(
            "/v1/machines/m/connect",
            &token,
            &key,
            Some(json!({"clientProofKeyThumbprint": key.jkt})),
        )
        .await;
    assert_eq!(
        tag(&r),
        (
            StatusCode::FORBIDDEN,
            json!("RelayMachineConnectNotAuthorizedError"),
            json!("endpoint_provider_not_managed")
        )
    );
    assert!(seen.lock().unwrap().is_empty());
}

/// An Engine `makeManagedTunnelRecoveryProof`.
fn recovery_proof(user: Uuid, action: &str, host: &str) -> String {
    let now = now_ms() / 1000;
    let mut p = json!({
        "iss": "vekrel-machine:m", "aud": ORIGIN, "sub": "m", "jti": Uuid::new_v4().to_string(),
        "iat": now, "exp": now + 60, "machineId": "m", "cloudUserId": format!("usr_{user}"),
        "action": action,
    });
    if action == "register" {
        p["tunnelId"] = "tunnel-1".into();
    }
    p["origin"] = json!({"localHttpHost": host, "localHttpPort": 3773});
    jws::sign(
        &test_only_key("machine"),
        jws::RELAY_MANAGED_TUNNEL_RECOVERY_TYP,
        &p,
    )
}

#[sqlx::test]
async fn tunnel_recovery_needs_loopback_and_a_managed_link(pool: PgPool) {
    let app = app_with(pool.clone(), Arc::new(FakeTunnels { pool }), None);
    let (user, bearer) = app.user("a@example.test").await;
    let credential = app.link_machine(&bearer, "m", true).await["machineCredential"]
        .as_str()
        .unwrap()
        .to_owned();
    let machine = format!("Bearer {credential}");
    let call = |action: &'static str, host: &'static str| {
        let (path, mut body) = if action == "register" {
            (
                "/v1/machines/m/tunnel/recovery",
                json!({"tunnelId": "tunnel-1"}),
            )
        } else {
            ("/v1/machines/m/tunnel", json!({}))
        };
        body["cloudUserId"] = format!("usr_{user}").into();
        body["origin"] = json!({"localHttpHost": host, "localHttpPort": 3773});
        body["proof"] = recovery_proof(user, action, host).into();
        app.call("POST", path, Some(&machine), Some(body))
    };
    // Loopback works.
    let r = call("register", "127.0.0.1").await;
    assert_eq!(
        (r.status, r.body.as_slice()),
        (StatusCode::OK, br#"{"status":"ready"}"#.as_slice())
    );
    let r = call("recover", "127.0.0.1").await;
    assert_eq!(
        r.status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&r.body)
    );
    assert_eq!(
        r.json()["endpointRuntime"]["connectorToken"],
        "connector-token"
    );
    // A signed but non-loopback origin is refused before the provider runs.
    for action in ["register", "recover"] {
        let r = call(action, "10.0.0.5").await;
        assert_eq!(
            tag(&r),
            (
                StatusCode::UNAUTHORIZED,
                json!("RelayAuthInvalidError"),
                json!("not_authorized")
            ),
            "{action}"
        );
    }
    // A link not made as managed cannot recover a tunnel.
    sqlx::query("UPDATE relay_machine_links SET managed_tunnels_enabled = false")
        .execute(&app.pool)
        .await
        .unwrap();
    for action in ["register", "recover"] {
        assert_eq!(
            tag(&call(action, "127.0.0.1").await).2,
            "not_authorized",
            "{action}"
        );
    }
}

/// Link row and credential commit together: a failed credential insert leaves no live link
/// (so a deadline cancel or crash between them cannot either).
#[sqlx::test]
async fn link_and_credential_commit_together(pool: PgPool) {
    let app = app(pool);
    let (_, bearer) = app.user("a@example.test").await;
    for sql in [
        "CREATE FUNCTION refuse_credential() RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN RAISE EXCEPTION 'refused'; END $$",
        "CREATE TRIGGER refuse_credential BEFORE INSERT ON relay_machine_credentials
         FOR EACH ROW EXECUTE FUNCTION refuse_credential()",
    ] {
        sqlx::query(sql).execute(&app.pool).await.unwrap();
    }
    let challenge = app.challenge(&bearer, false).await;
    let proof = ProofSpec::new("m", &challenge, false).sign();
    let r = app.link(&bearer, &proof, false).await;
    assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR);
    let links: i64 = sqlx::query_scalar("SELECT count(*) FROM relay_machine_links")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(links, 0);
}

/// The new credential and the revocation of the key's older ones commit together.
#[sqlx::test]
async fn new_credential_and_revocation_commit_together(pool: PgPool) {
    let mut conn = pool.acquire().await.unwrap();
    crate::machines::credentials::create(&mut conn, "m", "key")
        .await
        .unwrap();
    for sql in [
        "CREATE FUNCTION refuse_revoke() RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN RAISE EXCEPTION 'refused'; END $$",
        "CREATE TRIGGER refuse_revoke BEFORE UPDATE ON relay_machine_credentials
         FOR EACH ROW EXECUTE FUNCTION refuse_revoke()",
    ] {
        sqlx::query(sql).execute(&pool).await.unwrap();
    }
    assert!(
        crate::machines::credentials::create(&mut conn, "m", "key")
            .await
            .is_err()
    );
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM relay_machine_credentials")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows, 1, "the second credential rolled back with its revoke");
}
