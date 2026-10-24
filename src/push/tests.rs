// Push end to end: mobile registration over DPoP, machine-signed publishes, jobs worked against a
// fake APNs (HTTP/2) and a fake FCM, and the request bytes compared with T3's
// (`tests/fixtures/push/t3-vectors.json`, made by `tests/fixtures/push/gen.ts`).
use std::sync::{Arc, Mutex, OnceLock};

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, Request, StatusCode, Version, header};
use axum::response::IntoResponse;
use axum::routing::post;
use ed25519_dalek::pkcs8::{EncodePrivateKey, EncodePublicKey, spki::der::pem::LineEnding};
use http_body_util::BodyExt;
use p256::ecdsa::signature::Signer;
use serde_json::{Value, json};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

use super::payloads::tests::{now as vector_now, vectors};
use super::payloads::*;
use super::{Push, apns, devices, fcm, jobs};
use crate::auth::relay_tokens::RelayTokens;
use crate::config::Config;
use crate::jws::{self, b64url_encode, tests::test_only_key};
use crate::machines::{now_ms, wire_user_id};

const ORIGIN: &str = "https://relay.example.test";
const MACHINE: &str = "machine-1";

// ---- fakes ----

#[derive(Clone, Debug)]
struct Seen {
    version: Version,
    path: String,
    headers: HeaderMap,
    body: String,
}

#[derive(Clone)]
struct Fake {
    url: String,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Fake {
    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

async fn serve(router: Router<Arc<Mutex<Vec<Seen>>>>) -> Fake {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let app = router.with_state(seen.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Fake { url, seen }
}

fn record(
    seen: &Mutex<Vec<Seen>>,
    version: Version,
    path: String,
    headers: HeaderMap,
    body: &Bytes,
) {
    seen.lock().unwrap().push(Seen {
        version,
        path,
        headers,
        body: String::from_utf8_lossy(body).into_owned(),
    });
}

/// APNs: tokens starting `gone` are 410 Unregistered, `bad` 400 BadDeviceToken, `slow` hang.
async fn fake_apns() -> Fake {
    async fn device(
        State(seen): State<Arc<Mutex<Vec<Seen>>>>,
        Path(token): Path<String>,
        req: Request<Body>,
    ) -> axum::response::Response {
        let (parts, body) = req.into_parts();
        let body = body.collect().await.unwrap().to_bytes();
        record(
            &seen,
            parts.version,
            parts.uri.path().into(),
            parts.headers.clone(),
            &body,
        );
        let id = parts.headers.get("apns-id").cloned();
        if token.starts_with("gone") {
            return (
                StatusCode::GONE,
                r#"{"reason":"Unregistered","timestamp":1}"#,
            )
                .into_response();
        }
        if token.starts_with("bad") {
            return (StatusCode::BAD_REQUEST, r#"{"reason":"BadDeviceToken"}"#).into_response();
        }
        let mut r = StatusCode::OK.into_response();
        if let Some(id) = id {
            r.headers_mut().insert("apns-id", id);
        }
        r
    }
    serve(Router::new().route("/3/device/{token}", post(device))).await
}

/// FCM: message tokens starting `gone` are UNREGISTERED, `fail` a 500.
async fn fake_fcm() -> Fake {
    async fn token(
        State(seen): State<Arc<Mutex<Vec<Seen>>>>,
        headers: HeaderMap,
        body: Bytes,
    ) -> impl IntoResponse {
        record(&seen, Version::HTTP_11, "/token".into(), headers, &body);
        axum::Json(json!({"access_token": "ya29.fake-fcm-access-token", "expires_in": 3599}))
    }
    async fn send(
        State(seen): State<Arc<Mutex<Vec<Seen>>>>,
        Path((project, method)): Path<(String, String)>,
        headers: HeaderMap,
        body: Bytes,
    ) -> axum::response::Response {
        record(
            &seen,
            Version::HTTP_11,
            format!("/v1/projects/{project}/{method}"),
            headers,
            &body,
        );
        let msg: Value = serde_json::from_slice(&body).unwrap();
        let t = msg["message"]["token"].as_str().unwrap_or_default();
        if t.starts_with("gone") {
            return (
                StatusCode::NOT_FOUND,
                axum::Json(json!({"error": {"status": "NOT_FOUND", "details": [
                    {"@type": "type.googleapis.com/google.firebase.fcm.v1.FcmError", "errorCode": "UNREGISTERED"}]}})),
            )
                .into_response();
        }
        if t.starts_with("fail") {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(json!({"error": {"status": "INTERNAL"}})),
            )
                .into_response();
        }
        axum::Json(json!({"name": "projects/p/messages/1"})).into_response()
    }
    serve(
        Router::new()
            .route("/token", post(token))
            .route("/v1/projects/{project}/{method}", post(send)),
    )
    .await
}

// ---- keys (generated in tests, never committed) ----

/// The APNs key the T3 vectors were signed with: scalar `sha256("vekrel-push-test-apns-key")`.
fn apns_pem() -> String {
    use p256::pkcs8::EncodePrivateKey;
    use sha2::{Digest, Sha256};
    let scalar = Sha256::digest(b"vekrel-push-test-apns-key");
    p256::SecretKey::from_slice(&scalar)
        .unwrap()
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
        .unwrap()
        .to_string()
}

fn rsa_pem() -> &'static str {
    static K: OnceLock<String> = OnceLock::new();
    K.get_or_init(|| {
        use rsa::pkcs8::EncodePrivateKey;
        rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048)
            .unwrap()
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap()
            .to_string()
    })
}

const FCM_EMAIL: &str = "push@vekrel-test.iam.gserviceaccount.com";

fn service_account_json() -> String {
    json!({"project_id": "vekrel-test", "client_email": FCM_EMAIL, "private_key": rsa_pem()})
        .to_string()
}

// ---- harness ----

struct H {
    router: Router,
    push: Arc<Push>,
    pool: PgPool,
    apns: Fake,
    fcm: Fake,
    tokens: RelayTokens,
}

async fn harness_with(pool: PgPool, extra: &[(&str, &str)]) -> H {
    let (apns_fake, fcm_fake) = (fake_apns().await, fake_fcm().await);
    let mint = test_only_key("relayMint");
    let mint_pem = mint.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
    let apns_key = apns_pem();
    let sa = service_account_json();
    let token_url = format!("{}/token", fcm_fake.url);
    let mut vars: Vec<(&str, &str)> = vec![
        ("RELAY_ORIGIN", ORIGIN),
        ("RELAY_MINT_PRIVATE_KEY", &mint_pem),
        ("APNS_TEAM_ID", "TEAM123456"),
        ("APNS_KEY_ID", "KEY1234567"),
        ("APNS_BUNDLE_ID", "com.example.vekrel"),
        ("APNS_PRIVATE_KEY", &apns_key),
        ("APNS_ENVIRONMENT", "sandbox"),
        ("APNS_API_BASE", &apns_fake.url),
        ("FCM_SERVICE_ACCOUNT", &sa),
        ("FCM_API_BASE", &fcm_fake.url),
        ("FCM_TOKEN_URL", &token_url),
        ("FCM_PACKAGE_NAMES", "com.example.vekrel"),
    ];
    for (k, v) in extra {
        vars.retain(|(vk, _)| vk != k);
        if !v.is_empty() {
            vars.push((k, v));
        }
    }
    let config = Config::for_tests(&vars);
    let (a, _) = crate::accounts::keys::tests::entry("a", "active");
    let keys =
        Arc::new(crate::accounts::keys::SigningKeys::from_json(&json!([a]).to_string()).unwrap());
    let (router, push) = crate::http::build(pool.clone(), keys, &config);
    H {
        router,
        push: push.unwrap(),
        pool,
        apns: apns_fake,
        fcm: fcm_fake,
        tokens: RelayTokens::new(mint, ORIGIN),
    }
}

async fn harness(pool: PgPool) -> H {
    harness_with(pool, &[]).await
}

struct Res {
    status: StatusCode,
    headers: HeaderMap,
    body: Value,
}

struct Dpop {
    key: p256::ecdsa::SigningKey,
    jwk: Value,
    jkt: String,
}

impl Dpop {
    fn new() -> Self {
        let key = p256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap();
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
    fn proof(&self, method: &str, url: &str, token: &str) -> String {
        let header = json!({"typ": "dpop+jwt", "alg": "ES256", "jwk": self.jwk});
        let claims = json!({"htm": method, "htu": url, "iat": now_ms() / 1000, "jti": Uuid::new_v4().to_string(),
            "ath": crate::auth::dpop::access_token_hash(token)});
        let input = format!(
            "{}.{}",
            b64url_encode(header.to_string()),
            b64url_encode(claims.to_string())
        );
        let sig: p256::ecdsa::Signature = self.key.sign(input.as_bytes());
        format!("{input}.{}", b64url_encode(sig.to_bytes()))
    }
}

struct User {
    id: Uuid,
    token: String,
    dpop: Dpop,
}

fn spki(key: &ed25519_dalek::SigningKey) -> String {
    format!(
        "{}\n",
        key.verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap()
            .trim_end()
    )
}

impl H {
    async fn send(&self, req: Request<Body>) -> Res {
        let res = self.router.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let headers = res.headers().clone();
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        Res {
            status,
            headers,
            body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        }
    }

    async fn user(&self, email: &str, scopes: &[&str]) -> User {
        let id: Uuid = sqlx::query_scalar("INSERT INTO users (email) VALUES ($1) RETURNING id")
            .bind(email)
            .fetch_one(&self.pool)
            .await
            .unwrap();
        let dpop = Dpop::new();
        let now = now_ms() / 1000;
        let token = self.tokens.issue_dpop_access_token(
            &wire_user_id(id),
            &dpop.jkt,
            &Uuid::new_v4().to_string(),
            now,
            now + 1800,
            "vekrel-mobile",
            scopes,
        );
        User { id, token, dpop }
    }

    async fn mobile(&self, u: &User, method: &str, path: &str, body: Option<Value>) -> Res {
        let url = format!("{ORIGIN}{path}");
        let mut b = Request::builder()
            .method(method)
            .uri(path)
            .header(header::AUTHORIZATION, format!("DPoP {}", u.token))
            .header("dpop", u.dpop.proof(method, &url, &u.token));
        let body = match body {
            Some(v) => {
                b = b.header(header::CONTENT_TYPE, "application/json");
                Body::from(v.to_string())
            }
            None => Body::empty(),
        };
        self.send(b.body(body).unwrap()).await
    }

    /// A live link from `user` to MACHINE (notifications and Live Activities on); the credential.
    async fn link(&self, user: Uuid, notifications: bool, live: bool) -> String {
        let key = spki(&test_only_key("machine"));
        let now = crate::machines::now_iso();
        sqlx::query(
            "INSERT INTO relay_machine_links (user_id, machine_id, machine_public_key,
                endpoint_http_base_url, endpoint_ws_base_url, endpoint_provider_kind,
                notifications_enabled, live_activities_enabled, created_at, updated_at)
             VALUES ($1, $2, $3, 'http://127.0.0.1:3773/', 'ws://127.0.0.1:3773/', 'manual', $4, $5, $6, $6)",
        )
        .bind(user)
        .bind(MACHINE)
        .bind(&key)
        .bind(notifications)
        .bind(live)
        .bind(&now)
        .execute(&self.pool)
        .await
        .unwrap();
        let mut conn = self.pool.acquire().await.unwrap();
        crate::machines::credentials::create(&mut conn, MACHINE, &key)
            .await
            .unwrap()
    }

    async fn ios(&self, u: &User, device: &str, push_token: &str) {
        let r = self
            .mobile(
                u,
                "POST",
                "/v1/mobile/devices",
                Some(json!({
                "deviceId": device, "label": "iPhone", "platform": "ios", "iosMajorVersion": 18,
                "pushToken": push_token, "preferences": prefs_json()})),
            )
            .await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.body);
        assert_eq!(r.body, json!({"ok": true}));
    }

    async fn android(&self, u: &User, device: &str, push_token: &str) {
        let r = self
            .mobile(u, "POST", "/v1/mobile/devices", Some(json!({
                "deviceId": device, "label": "Pixel", "platform": "android", "androidApiLevel": 34,
                "bundleId": "com.example.vekrel", "pushToken": push_token, "preferences": prefs_json()})))
            .await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    }

    async fn publish_raw(
        &self,
        credential: &str,
        thread: &str,
        state: Option<&Value>,
        claims: Value,
    ) -> Res {
        let body = json!({"state": state, "proof": jws::sign(&test_only_key("machine"), jws::RELAY_ACTIVITY_PUBLISH_TYP, &claims)});
        self.send(
            Request::post(format!(
                "/v1/machines/{MACHINE}/threads/{thread}/agent-activity"
            ))
            .header(header::AUTHORIZATION, format!("Bearer {credential}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
        )
        .await
    }

    async fn publish(&self, credential: &str, thread: &str, state: Option<&Value>) -> Res {
        let claims = proof_claims(thread, state);
        self.publish_raw(credential, thread, state, claims).await
    }

    async fn jobs(&self) -> Vec<(String, String, i32, Option<String>)> {
        sqlx::query_as(
            "SELECT kind, status, attempts, last_error FROM relay_push_jobs ORDER BY created_at",
        )
        .fetch_all(&self.pool)
        .await
        .unwrap()
    }

    async fn work(&self) -> usize {
        jobs::run_once(&self.push).await.unwrap()
    }
}

fn proof_claims(thread: &str, state: Option<&Value>) -> Value {
    let now = now_ms() / 1000;
    json!({"iss": format!("vekrel-machine:{MACHINE}"), "aud": ORIGIN, "sub": MACHINE,
           "jti": Uuid::new_v4().to_string(), "iat": now, "exp": now + 300,
           "machineId": MACHINE, "threadId": thread, "state": state})
}

fn prefs_json() -> Value {
    json!({"liveActivitiesEnabled": true, "notificationsEnabled": true, "notifyOnApproval": true,
           "notifyOnInput": true, "notifyOnCompletion": true, "notifyOnFailure": true})
}

/// A machine-published state; `headline` and `detail` are the closest thing to content it has.
fn state(thread: &str, phase: &str, ago_ms: i64) -> Value {
    json!({"machineId": MACHINE, "threadId": thread, "projectTitle": "Project", "threadTitle": "Thread",
           "phase": phase, "headline": "SECRET-HEADLINE", "detail": "SECRET-DETAIL", "modelTitle": "gpt-5.4",
           "updatedAt": crate::auth::dpop_proofs::iso_millis(now_ms() - ago_ms),
           "deepLink": format!("/threads/{MACHINE}/{thread}")})
}

fn renamed(v: &str) -> String {
    v.replace("environmentId", "machineId")
        .replace("T3 Code", "Vekrel")
}

// ---- byte parity with T3 ----

#[tokio::test]
async fn apns_requests_equal_t3() {
    let v = vectors();
    let now_s = vector_now(&v) / 1000;
    let fake = fake_apns().await;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://unused@127.0.0.1:1/x")
        .unwrap();
    let mut config = crate::push::PushConfig::from_lookup(&|k: &str| match k {
        "APNS_TEAM_ID" => Some("TEAM123456".into()),
        "APNS_KEY_ID" => Some("KEY1234567".into()),
        "APNS_BUNDLE_ID" => Some("com.example.vekrel".into()),
        "APNS_PRIVATE_KEY" => Some(apns_pem()),
        "APNS_ENVIRONMENT" => Some("sandbox".into()),
        _ => None,
    })
    .unwrap();
    config.apns_api_base = Some(fake.url.clone());
    let push = Push::new(pool, config);
    let creds = push.config.apns.clone().unwrap();
    let agg =
        |k: &str| -> Aggregate { serde_json::from_value(v["aggregates"][k].clone()).unwrap() };
    let alert = |t: &str, b: &str| Alert {
        title: t.into(),
        body: b.into(),
    };
    let token = "fake-live-activity-token-0001";
    let cases: Vec<(&str, apns::Request)> = vec![
        (
            "la_updateMixed",
            apns::live_activity_request(
                token,
                devices::Kind::LiveActivityUpdate,
                Some(&agg("mixed")),
                None,
                now_s,
            ),
        ),
        (
            "la_updateAlert",
            apns::live_activity_request(
                token,
                devices::Kind::LiveActivityUpdate,
                Some(&agg("many")),
                Some(&alert("Thread", "Approval: Project")),
                now_s,
            ),
        ),
        (
            "la_endWithState",
            apns::live_activity_request(
                token,
                devices::Kind::LiveActivityEnd,
                Some(&agg("terminalPassed")),
                Some(&alert("Thread", "Done: Project")),
                now_s,
            ),
        ),
        (
            "la_endContentless",
            apns::live_activity_request(token, devices::Kind::LiveActivityEnd, None, None, now_s),
        ),
        (
            "push_thread",
            apns::push_notification_request(
                "push-token-0001",
                &serde_json::from_value(v["notifications"]["mixed"].clone()).unwrap(),
            ),
        ),
        (
            "push_noThread",
            apns::push_notification_request(
                "push-token-0002",
                &Notification {
                    title: "T".into(),
                    body: "B".into(),
                    machine_id: MACHINE.into(),
                    thread_id: String::new(),
                    deep_link: "/".into(),
                    phase: None,
                    updated_at: None,
                },
            ),
        ),
    ];
    for (i, (name, r)) in cases.iter().enumerate() {
        let t3 = &v["apns"][name];
        assert_eq!(r.priority, t3["request"]["priority"], "{name}");
        let c = if name.starts_with("push") {
            apns::credentials_for(&creds, None, Some("production"))
        } else {
            creds.clone()
        };
        let id = Uuid::new_v4();
        let o = apns::send(&push, &c, r, Some(id), now_s).await;
        assert!(o.ok, "{name}: {o:?}");
        assert_eq!(o.apns_id.as_deref(), Some(id.to_string().as_str()));
        let seen = &fake.seen()[i];
        assert_eq!(seen.version, Version::HTTP_2, "APNs is HTTP/2");
        let t3_http = &t3["http"];
        assert_eq!(
            seen.body,
            renamed(t3_http["body"].as_str().unwrap()),
            "{name} body"
        );
        let url = t3_http["url"].as_str().unwrap();
        assert_eq!(seen.path, &url[url.find("/3/").unwrap()..], "{name}");
        // T3's provider token, byte for byte (deterministic ES256, quantized iat).
        for h in [
            "authorization",
            "apns-priority",
            "apns-push-type",
            "apns-topic",
            "content-type",
        ] {
            // The fixture splits JWTs with " . " so secret scanners leave it alone.
            let t3_value = t3_http["headers"][h].as_str().unwrap().replace(" . ", ".");
            assert_eq!(seen.headers[h], t3_value.as_str(), "{name} {h}");
        }
        assert_eq!(seen.headers["apns-id"], id.to_string());
    }
    // Sandbox and production hosts as T3 picks them.
    assert!(
        v["apns"]["la_updateMixed"]["http"]["url"]
            .as_str()
            .unwrap()
            .starts_with("https://api.sandbox.push.apple.com/")
    );
    assert!(
        v["apns"]["push_thread"]["http"]["url"]
            .as_str()
            .unwrap()
            .starts_with("https://api.push.apple.com/")
    );
    // One token per 45-minute window.
    let w = apns::APNS_JWT_REUSE_SECONDS;
    let key = apns::signing_key(&apns_pem()).unwrap();
    assert_eq!(apns::quantized_issued_at(w + 10), w);
    assert_eq!(apns::quantized_issued_at(2 * w - 1), w);
    assert_ne!(
        apns::make_jwt(&key, "T", "K", apns::quantized_issued_at(2 * w)),
        apns::make_jwt(&key, "T", "K", w)
    );
}

#[tokio::test]
async fn fcm_requests_equal_t3() {
    let v = vectors();
    let fake = fake_fcm().await;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://unused@127.0.0.1:1/x")
        .unwrap();
    let sa = service_account_json();
    let token_url = format!("{}/token", fake.url);
    let config = crate::push::PushConfig::from_lookup(&|k: &str| match k {
        "FCM_SERVICE_ACCOUNT" => Some(sa.clone()),
        "FCM_API_BASE" => Some(fake.url.clone()),
        "FCM_TOKEN_URL" => Some(token_url.clone()),
        "FCM_PACKAGE_NAMES" => Some("com.example.vekrel".into()),
        _ => None,
    })
    .unwrap();
    let push = Push::new(pool, config);
    let data = |k: &str| -> serde_json::Map<String, Value> {
        serde_json::from_value(v["fcm"][k]["fitted"].clone()).unwrap()
    };
    assert!(
        !fcm::send(
            &push,
            "fcm-token-1",
            "com.example.vekrel",
            &data("mixed"),
            true
        )
        .await
        .unwrap()
    );
    assert!(
        !fcm::send(
            &push,
            "fcm-token-2",
            "com.example.vekrel",
            &data("oneRunning"),
            false
        )
        .await
        .unwrap()
    );
    let seen = fake.seen();
    assert_eq!(seen.len(), 3, "one OAuth exchange, then the cached token");
    let t3 = &v["fcmHttp"];
    let form = &seen[0].body;
    let prefix = t3["oauth"]["body"]
        .as_str()
        .unwrap()
        .replace("<assertion>", "");
    assert!(form.starts_with(&prefix), "{form}");
    let assertion = form_urlencoded::parse(form.as_bytes())
        .find(|(k, _)| k == "assertion")
        .unwrap()
        .1
        .into_owned();
    // T3's header and claims for the same email and iat; the RS256 signature verifies.
    let t3_input = t3["assertionSigningInput"].as_str().unwrap();
    let t3_iat = jws::decode_unverified(&format!("{t3_input}.x")).unwrap()["iat"]
        .as_i64()
        .unwrap();
    let a = push.config.fcm.clone().unwrap();
    let ours = fcm::assertion(&a, t3_iat).unwrap();
    assert_eq!(&ours[..ours.rfind('.').unwrap()], t3_input);
    let parts: Vec<&str> = assertion.split('.').collect();
    let public_pem = {
        use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey};
        rsa::RsaPrivateKey::from_pkcs8_pem(rsa_pem())
            .unwrap()
            .to_public_key()
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap()
    };
    let verifies = jsonwebtoken::crypto::verify(
        parts[2],
        format!("{}.{}", parts[0], parts[1]).as_bytes(),
        &jsonwebtoken::DecodingKey::from_rsa_pem(public_pem.as_bytes()).unwrap(),
        jsonwebtoken::Algorithm::RS256,
    );
    assert!(verifies.unwrap(), "RS256 signature");
    for (i, m) in t3["messages"].as_array().unwrap().iter().enumerate() {
        // T3's second vector has no package; Vekrel always restricts (T3 adds the key last).
        let t3_body = renamed(m["body"].as_str().unwrap()).replace(
            r#""collapse_key":"t3-agent-activity"}"#,
            r#""collapse_key":"t3-agent-activity","restricted_package_name":"com.example.vekrel"}"#,
        );
        assert_eq!(seen[i + 1].body, t3_body, "message {i}");
        assert_eq!(
            seen[i + 1].headers["authorization"],
            "Bearer ya29.fake-fcm-access-token"
        );
        assert_eq!(seen[i + 1].path, "/v1/projects/vekrel-test/messages:send");
    }
}

// ---- flows ----

#[sqlx::test]
async fn publish_queues_jobs_and_workers_deliver_ids_and_titles_only(pool: PgPool) {
    let h = harness(pool).await;
    let u = h.user("a@example.test", &["mobile:registration"]).await;
    let cred = h.link(u.id, true, true).await;
    h.ios(&u, "phone-1", "push-token-ios-1").await;
    let la = h
        .mobile(
            &u,
            "POST",
            "/v1/mobile/live-activities",
            Some(json!({"deviceId": "phone-1", "activityPushToken": "activity-token-1"})),
        )
        .await;
    assert_eq!(la.body, json!({"ok": true}));
    h.android(&u, "pixel-1", "fcm-token-android-1").await;

    // The first update after arming is the baseline (no alert); the next transition alerts.
    h.publish(&cred, "thread-1", Some(&state("thread-1", "running", 2000)))
        .await;
    while h.work().await > 0 {}
    let first = h
        .apns
        .seen()
        .into_iter()
        .find(|s| s.path == "/3/device/activity-token-1")
        .unwrap();
    assert_eq!(first.headers["apns-priority"], "5");
    let s = state("thread-1", "waiting_for_approval", 1000);
    let r = h.publish(&cred, "thread-1", Some(&s)).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(
        r.body,
        json!({"ok": true, "deliveries": [
            {"deviceId": "phone-1", "kind": "live_activity_update", "ok": true, "queued": true, "apnsStatus": null, "apnsReason": null, "apnsId": null},
            {"deviceId": "pixel-1", "kind": "push_notification", "ok": true, "queued": true, "apnsStatus": null, "apnsReason": null, "apnsId": null},
        ]})
    );
    // Replays at registration queued their own jobs; work everything.
    while h.work().await > 0 {}
    assert!(
        h.jobs().await.iter().all(|j| j.1 == "done"),
        "{:?}",
        h.jobs().await
    );

    let apns = h.apns.seen();
    let update = apns
        .iter()
        .rev()
        .find(|s| s.path == "/3/device/activity-token-1")
        .expect("live activity update");
    assert_eq!(update.version, Version::HTTP_2);
    assert_eq!(update.headers["apns-push-type"], "liveactivity");
    assert_eq!(
        update.headers["apns-priority"], "10",
        "attention: alerting update"
    );
    let body: Value = serde_json::from_str(&update.body).unwrap();
    assert_eq!(body["aps"]["event"], "update");
    let props: Value =
        serde_json::from_str(body["aps"]["content-state"]["props"].as_str().unwrap()).unwrap();
    assert_eq!(props["title"], "Vekrel");
    assert_eq!(props["activities"][0]["machineId"], MACHINE);
    assert_eq!(props["activities"][0]["status"], "Approval");
    let fcm = h.fcm.seen();
    let android = fcm
        .iter()
        .rev()
        .find(|s| s.body.contains("fcm-token-android-1"))
        .unwrap();
    let data = &serde_json::from_str::<Value>(&android.body).unwrap()["message"]["data"];
    assert_eq!(data["t3_kind"], "agent_activity");
    assert_eq!(data["user_id"], wire_user_id(u.id));
    assert_eq!(data["alert_title"], "Thread");
    // No content: the state's headline and detail never leave the relay.
    for s in apns.iter().chain(fcm.iter()) {
        assert!(
            !s.body.contains("SECRET-HEADLINE") && !s.body.contains("SECRET-DETAIL"),
            "{}",
            s.body
        );
    }
    let snap = h.mobile(&u, "GET", "/v1/mobile/agent-activity", None).await;
    assert_eq!(
        snap.body["aggregate"]["activities"][0]["threadId"],
        "thread-1"
    );
    assert_eq!(snap.body["aggregate"]["activeCount"], 1);

    // The attempt log has the APNs answer for every APNs job.
    let attempts: Vec<(String, Option<i32>)> = sqlx::query_as(
        "SELECT kind, apns_status FROM relay_delivery_attempts WHERE kind = 'live_activity_update'",
    )
    .fetch_all(&h.pool)
    .await
    .unwrap();
    assert!(attempts.iter().any(|a| a.1 == Some(200)), "{attempts:?}");

    // Completion: the Live Activity ends; a fresh terminal state also rings the phone.
    let done = state("thread-1", "completed", 1000);
    let r = h.publish(&cred, "thread-1", Some(&done)).await;
    assert_eq!(r.status, StatusCode::OK);
    while h.work().await > 0 {}
    let last: Vec<Seen> = h.apns.seen();
    assert!(last.iter().any(|s| s.path == "/3/device/activity-token-1"
        && s.body.contains("\"event\":\"update\"")
        && s.body.contains("Done")));
}

#[sqlx::test]
async fn notification_only_links_get_alert_pushes(pool: PgPool) {
    let h = harness(pool).await;
    let u = h.user("a@example.test", &["mobile:registration"]).await;
    let cred = h.link(u.id, true, false).await;
    h.ios(&u, "phone-1", "push-token-ios-1").await;
    let r = h
        .publish(
            &cred,
            "thread-1",
            Some(&state("thread-1", "waiting_for_input", 1000)),
        )
        .await;
    assert_eq!(
        r.body["deliveries"][0]["kind"], "push_notification",
        "{}",
        r.body
    );
    while h.work().await > 0 {}
    let push = h
        .apns
        .seen()
        .into_iter()
        .find(|s| s.path == "/3/device/push-token-ios-1")
        .unwrap();
    assert_eq!(push.headers["apns-push-type"], "alert");
    assert_eq!(push.headers["apns-topic"], "com.example.vekrel");
    let body: Value = serde_json::from_str(&push.body).unwrap();
    assert_eq!(body["aps"]["thread-id"], format!("{MACHINE}/thread-1"));
    assert_eq!(
        body["body"],
        json!({"machineId": MACHINE, "threadId": "thread-1", "deepLink": format!("/threads/{MACHINE}/thread-1")})
    );
    assert_eq!(
        body["aps"]["alert"],
        json!({"title": "Thread", "body": "Input: Project"})
    );
}

#[sqlx::test]
async fn gone_tokens_are_cleared_and_devices_kept(pool: PgPool) {
    let h = harness(pool).await;
    let u = h.user("a@example.test", &["mobile:registration"]).await;
    let cred = h.link(u.id, true, false).await;
    h.ios(&u, "phone-1", "gone-ios-token").await;
    h.android(&u, "pixel-1", "gone-fcm-token").await;
    h.publish(
        &cred,
        "thread-1",
        Some(&state("thread-1", "waiting_for_input", 1000)),
    )
    .await;
    while h.work().await > 0 {}
    let tokens: Vec<(String, Option<String>)> =
        sqlx::query_as("SELECT device_id, push_token FROM relay_mobile_devices ORDER BY device_id")
            .fetch_all(&h.pool)
            .await
            .unwrap();
    assert_eq!(
        tokens,
        vec![("phone-1".into(), None), ("pixel-1".into(), None)],
        "410 / UNREGISTERED clear the token, the device stays"
    );
    let a: (Option<i32>, Option<String>) = sqlx::query_as("SELECT apns_status, apns_reason FROM relay_delivery_attempts WHERE kind = 'push_notification'")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(a, (Some(410), Some("Unregistered".into())));
    // Nothing more is sent to them.
    let before = h.apns.seen().len() + h.fcm.seen().len();
    h.publish(
        &cred,
        "thread-1",
        Some(&state("thread-1", "waiting_for_approval", 500)),
    )
    .await;
    while h.work().await > 0 {}
    assert_eq!(h.apns.seen().len() + h.fcm.seen().len(), before);
}

#[sqlx::test]
async fn a_crash_between_claim_and_send_resends_after_the_claim_timeout(pool: PgPool) {
    let h = harness(pool).await;
    let u = h.user("a@example.test", &["mobile:registration"]).await;
    let cred = h.link(u.id, true, false).await;
    h.ios(&u, "phone-1", "push-token-ios-1").await;
    while h.work().await > 0 {}
    h.publish(
        &cred,
        "thread-1",
        Some(&state("thread-1", "waiting_for_input", 1000)),
    )
    .await;
    // A worker claims the job and its delivery attempt, then dies before sending.
    let claimed = jobs::claim(&h.pool, &["apns"]).await.unwrap();
    assert_eq!(claimed.len(), 1);
    let job_id = claimed[0].id;
    sqlx::query("INSERT INTO relay_delivery_attempts (id, created_at, kind, source_job_id) VALUES ($1, $2, 'push_notification', $3)")
        .bind(Uuid::new_v4().to_string())
        .bind(crate::machines::now_iso())
        .bind(job_id.to_string())
        .execute(&h.pool)
        .await
        .unwrap();
    // Within the claim timeout nobody else takes it.
    assert_eq!(h.work().await, 0);
    assert!(h.apns.seen().is_empty());
    // The timeout passes.
    let past =
        crate::auth::dpop_proofs::iso_millis(now_ms() - jobs::CLAIM_TIMEOUT_SECONDS * 1000 - 1000);
    sqlx::query("UPDATE relay_push_jobs SET locked_until = now() - interval '1 second'")
        .execute(&h.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE relay_delivery_attempts SET created_at = $1")
        .bind(&past)
        .execute(&h.pool)
        .await
        .unwrap();
    let logs = crate::test_logs::capture_logs(|| {});
    let _ = logs;
    assert_eq!(h.work().await, 1);
    let seen = h.apns.seen();
    assert_eq!(seen.len(), 1, "sent exactly once");
    assert_eq!(
        seen[0].headers["apns-id"],
        job_id.to_string(),
        "the re-send keeps the job's apns-id"
    );
    let job: (String, i32) =
        sqlx::query_as("SELECT status, attempts FROM relay_push_jobs WHERE id = $1")
            .bind(job_id)
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert_eq!(
        job,
        ("done".into(), 2),
        "the attempt count shows the crashed claim"
    );
    let attempt: (Option<i32>, Option<String>) = sqlx::query_as(
        "SELECT apns_status, apns_id FROM relay_delivery_attempts WHERE source_job_id = $1",
    )
    .bind(job_id.to_string())
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_eq!(attempt, (Some(200), Some(job_id.to_string())));
    let logs = crate::test_logs::capture_logs(|| {});
    assert!(
        logs.contains("push job claim timed out; sending again")
            && logs.contains(&job_id.to_string())
    );

    // A worker that lost its claim cannot finish the job afterwards.
    let mut stale = jobs::Claimed {
        id: job_id,
        kind: "apns".into(),
        payload: Value::Null,
        attempts: 1,
    };
    sqlx::query("UPDATE relay_push_jobs SET status = 'running'")
        .execute(&h.pool)
        .await
        .unwrap();
    jobs::finish(&h.pool, &stale, Err(jobs::JobError::fatal("Late")))
        .await
        .unwrap();
    let still: (String, Option<String>) =
        sqlx::query_as("SELECT status, last_error FROM relay_push_jobs WHERE id = $1")
            .bind(job_id)
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert_eq!(still, ("running".into(), None));
    stale.attempts = 2;
    let _ = stale;

    // A crash after the send (attempt recorded, job not finished) sends nothing more.
    sqlx::query(
        "UPDATE relay_push_jobs SET status = 'running', locked_until = now() - interval '1 second'",
    )
    .execute(&h.pool)
    .await
    .unwrap();
    assert_eq!(h.work().await, 1);
    assert_eq!(h.apns.seen().len(), 1, "a completed attempt is a duplicate");
}

#[sqlx::test]
async fn two_workers_never_send_one_job_twice(pool: PgPool) {
    let h = harness(pool).await;
    let u = h.user("a@example.test", &["mobile:registration"]).await;
    let cred = h.link(u.id, true, false).await;
    for i in 0..15 {
        h.ios(&u, &format!("phone-{i}"), &format!("push-token-{i}"))
            .await;
    }
    for t in 0..4 {
        h.publish(
            &cred,
            &format!("thread-{t}"),
            Some(&state(&format!("thread-{t}"), "waiting_for_input", 1000)),
        )
        .await;
    }
    let queued = h.jobs().await.len();
    assert!(queued >= 60, "{queued}");
    // Rows another worker holds are skipped, not waited for and not taken.
    let mut held = h.pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM relay_push_jobs FOR UPDATE")
        .fetch_all(&mut *held)
        .await
        .unwrap();
    let got = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        jobs::claim(&h.pool, &["apns"]),
    )
    .await
    .expect("a claim must not wait for rows another worker holds")
    .unwrap();
    assert!(
        got.is_empty(),
        "claimed {} rows another worker holds",
        got.len()
    );
    held.rollback().await.unwrap();
    // Four workers (separate services, as on separate replicas) start claiming at once.
    let gate = Arc::new(tokio::sync::Barrier::new(4));
    let workers: Vec<_> = (0..4)
        .map(|_| {
            let p = Arc::new(Push::new(h.pool.clone(), h.push.config.clone()));
            let gate = gate.clone();
            tokio::spawn(async move {
                gate.wait().await;
                while jobs::run_once(&p).await.unwrap() > 0 {}
            })
        })
        .collect();
    for w in workers {
        w.await.unwrap();
    }
    let ids: Vec<String> = h
        .apns
        .seen()
        .iter()
        .map(|s| s.headers["apns-id"].to_str().unwrap().to_owned())
        .collect();
    let unique: std::collections::HashSet<&String> = ids.iter().collect();
    assert_eq!(ids.len(), unique.len(), "a job id was sent twice");
    assert_eq!(ids.len(), queued);
    assert!(h.jobs().await.iter().all(|j| j.1 == "done"));
}

#[sqlx::test]
async fn a_stalled_batch_skips_jobs_another_worker_reclaimed(pool: PgPool) {
    let h = harness(pool).await;
    let u = h.user("a@example.test", &["mobile:registration"]).await;
    let cred = h.link(u.id, true, false).await;
    h.android(&u, "pixel-1", "fcm-token-1").await;
    h.android(&u, "pixel-2", "fcm-token-2").await;
    while h.work().await > 0 {}
    let sent_before = h.fcm.seen().len();
    h.publish(
        &cred,
        "thread-1",
        Some(&state("thread-1", "waiting_for_input", 1000)),
    )
    .await;
    // Worker A claims both jobs; the first send stalls past the second job's lease.
    let batch = jobs::claim(&h.pool, &["fcm"]).await.unwrap();
    assert_eq!(batch.len(), 2);
    sqlx::query(
        "UPDATE relay_push_jobs SET locked_until = now() - interval '1 second' WHERE id = $1",
    )
    .bind(batch[1].id)
    .execute(&h.pool)
    .await
    .unwrap();
    // Worker B takes the expired job meanwhile.
    let b = jobs::claim(&h.pool, &["fcm"]).await.unwrap();
    assert_eq!(b.iter().map(|j| j.id).collect::<Vec<_>>(), [batch[1].id]);
    // A gets on with its batch: it sends the job it still holds, and skips the one it lost.
    jobs::process(&h.push, &batch).await.unwrap();
    let sent: Vec<String> = h.fcm.seen()[sent_before..]
        .iter()
        .filter(|s| s.path.ends_with("messages:send"))
        .map(|s| s.body.clone())
        .collect();
    let token = |j: &jobs::Claimed| j.payload["token"].as_str().unwrap().to_owned();
    assert_eq!(sent.len(), 1, "A sent a job B now owns");
    assert!(sent[0].contains(&token(&batch[0])));
    // The job A still held was renewed while it ran: B cannot take it.
    let (status, attempts): (String, i32) =
        sqlx::query_as("SELECT status, attempts FROM relay_push_jobs WHERE id = $1")
            .bind(batch[0].id)
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert_eq!((status.as_str(), attempts), ("done", 1));
}

#[sqlx::test]
async fn a_job_lease_is_renewed_before_its_turn_in_the_batch(pool: PgPool) {
    let h = harness(pool).await;
    let u = h.user("a@example.test", &["mobile:registration"]).await;
    let cred = h.link(u.id, true, false).await;
    h.android(&u, "pixel-1", "fcm-token-1").await;
    while h.work().await > 0 {}
    h.publish(
        &cred,
        "thread-1",
        Some(&state("thread-1", "waiting_for_input", 1000)),
    )
    .await;
    let batch = jobs::claim(&h.pool, &["fcm"]).await.unwrap();
    assert_eq!(batch.len(), 1);
    // The lease ran out while earlier jobs of the batch were sent, but nobody took the job yet.
    sqlx::query("UPDATE relay_push_jobs SET locked_until = now() - interval '1 second'")
        .execute(&h.pool)
        .await
        .unwrap();
    assert!(jobs::renew(&h.pool, &batch[0]).await.unwrap());
    assert!(
        jobs::claim(&h.pool, &["fcm"]).await.unwrap().is_empty(),
        "a renewed lease is not claimable"
    );
    let left: f64 = sqlx::query_scalar(
        "SELECT extract(epoch FROM locked_until - now())::float8 FROM relay_push_jobs WHERE id = $1",
    )
    .bind(batch[0].id)
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert!(left > (jobs::CLAIM_TIMEOUT_SECONDS - 30) as f64, "{left}");
}

#[test]
fn push_tokens_never_show_in_debug() {
    let secret = "push-token-SECRET-0001";
    let reg: devices::Registration = serde_json::from_value(json!({
        "deviceId": "d", "label": "l", "platform": "ios", "iosMajorVersion": 18,
        "pushToken": secret, "pushToStartToken": secret, "preferences": prefs_json()}))
    .unwrap();
    let target = devices::Target {
        user_id: Uuid::nil(),
        device_id: "d".into(),
        platform: "ios".into(),
        bundle_id: None,
        aps_environment: None,
        push_token: Some(secret.into()),
        preferences: None,
        activity_push_token: Some(secret.into()),
        remote_started_at: None,
        last_aggregate: None,
        last_live_activity_delivery_at: None,
    };
    let apns_target = apns::JobTarget {
        user_id: Uuid::nil(),
        device_id: "d".into(),
        token: secret.into(),
        bundle_id: None,
        aps_environment: None,
    };
    let fcm_job = fcm::Job {
        user_id: Uuid::nil(),
        device_id: "d".into(),
        token: secret.into(),
        state: None,
        queued_at: 0,
        replay: None,
    };
    for d in [
        format!("{reg:?}"),
        format!("{target:?}"),
        format!("{apns_target:?}"),
        format!("{fcm_job:?}"),
    ] {
        assert!(!d.contains("SECRET"), "{d}");
    }
    // The wire and job bytes keep the token as a plain string.
    assert_eq!(serde_json::to_value(&fcm_job).unwrap()["token"], secret);
    assert_eq!(serde_json::to_value(&apns_target).unwrap()["token"], secret);
}

#[sqlx::test]
async fn failures_retry_30s_apart_and_die_after_the_last_attempt(pool: PgPool) {
    let h = harness(pool).await;
    let u = h.user("a@example.test", &["mobile:registration"]).await;
    let cred = h.link(u.id, true, false).await;
    h.android(&u, "pixel-1", "fail-fcm-token").await;
    while h.work().await > 0 {}
    sqlx::query("DELETE FROM relay_push_jobs")
        .execute(&h.pool)
        .await
        .unwrap();
    h.publish(
        &cred,
        "thread-1",
        Some(&state("thread-1", "waiting_for_input", 1000)),
    )
    .await;
    assert_eq!(h.work().await, 1);
    let (status, delay, attempts): (String, f64, i32) = sqlx::query_as(
        "SELECT status, extract(epoch FROM run_at - now())::float8, attempts FROM relay_push_jobs",
    )
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_eq!((status.as_str(), attempts), ("pending", 1));
    assert!((20.0..=31.0).contains(&delay), "{delay}");
    assert_eq!(h.work().await, 0, "not due yet");
    // T3: `maxRetries: 5`, so six deliveries in all.
    assert_eq!(jobs::MAX_ATTEMPTS, 6);
    for n in 2..=6 {
        sqlx::query("UPDATE relay_push_jobs SET run_at = now()")
            .execute(&h.pool)
            .await
            .unwrap();
        assert_eq!(h.work().await, 1);
        let j = &h.jobs().await[0];
        assert_eq!(j.2, n);
        assert_eq!(j.1, if n == 6 { "dead" } else { "pending" });
        assert_eq!(j.3.as_deref(), Some("FcmClientError"));
    }
    sqlx::query("UPDATE relay_push_jobs SET run_at = now()")
        .execute(&h.pool)
        .await
        .unwrap();
    assert_eq!(h.work().await, 0, "dead jobs stay dead");
}

#[sqlx::test]
async fn disabled_delivery_keeps_jobs_until_enabled(pool: PgPool) {
    let h = harness_with(
        pool.clone(),
        &[("APNS_ENABLED", "false"), ("FCM_ENABLED", "false")],
    )
    .await;
    let u = h.user("a@example.test", &["mobile:registration"]).await;
    let cred = h.link(u.id, true, false).await;
    h.ios(&u, "phone-1", "push-token-ios-1").await;
    h.android(&u, "pixel-1", "fcm-token-android-1").await;
    let r = h
        .publish(
            &cred,
            "thread-1",
            Some(&state("thread-1", "waiting_for_input", 1000)),
        )
        .await;
    assert_eq!(
        r.body["deliveries"].as_array().unwrap().len(),
        2,
        "{}",
        r.body
    );
    assert_eq!(h.work().await, 0);
    let pending = h.jobs().await;
    assert!(
        pending.len() >= 2 && pending.iter().all(|j| j.1 == "pending"),
        "{pending:?}"
    );
    assert!(h.apns.seen().is_empty() && h.fcm.seen().is_empty());
    // Delivery back on (same database, same jobs).
    let mut config = h.push.config.clone();
    config.apns_enabled = true;
    config.fcm_enabled = true;
    let on = Push::new(pool, config);
    while jobs::run_once(&on).await.unwrap() > 0 {}
    assert!(h.jobs().await.iter().all(|j| j.1 == "done"));
    assert!(
        h.apns
            .seen()
            .iter()
            .any(|s| s.path == "/3/device/push-token-ios-1")
    );
    assert!(
        h.fcm
            .seen()
            .iter()
            .any(|s| s.body.contains("fcm-token-android-1"))
    );
}

#[sqlx::test]
async fn without_credentials_push_is_off_as_in_t3(pool: PgPool) {
    let unset: Vec<(&str, &str)> = [
        "APNS_TEAM_ID",
        "APNS_KEY_ID",
        "APNS_BUNDLE_ID",
        "APNS_PRIVATE_KEY",
        "APNS_ENVIRONMENT",
        "FCM_SERVICE_ACCOUNT",
    ]
    .iter()
    .map(|k| (*k, ""))
    .collect();
    let h = harness_with(pool, &unset).await;
    let u = h.user("a@example.test", &["mobile:registration"]).await;
    let cred = h.link(u.id, true, true).await;
    h.ios(&u, "phone-1", "push-token-ios-1").await;
    h.android(&u, "pixel-1", "fcm-token-android-1").await;
    let r = h
        .publish(
            &cred,
            "thread-1",
            Some(&state("thread-1", "waiting_for_input", 1000)),
        )
        .await;
    assert_eq!(
        r.body["deliveries"],
        json!([{"deviceId": "pixel-1", "kind": "push_notification", "ok": false, "apnsStatus": null, "apnsReason": null, "apnsId": null}])
    );
    assert!(h.jobs().await.is_empty());
}

#[sqlx::test]
async fn publish_proofs_are_checked_as_t3_does(pool: PgPool) {
    let h = harness(pool).await;
    let u = h.user("a@example.test", &["mobile:registration"]).await;
    let cred = h.link(u.id, true, true).await;
    let s = state("thread-1", "running", 1000);
    let tag = |r: &Res| (r.status, r.body["_tag"].clone(), r.body["reason"].clone());
    let invalid = |reason: &str| {
        (
            StatusCode::UNAUTHORIZED,
            json!("RelayAgentActivityPublishProofInvalidError"),
            json!(reason),
        )
    };

    let mut c = proof_claims("thread-1", Some(&s));
    c["exp"] = json!(now_ms() / 1000 - 1);
    let r = h.publish_raw(&cred, "thread-1", Some(&s), c).await;
    assert_eq!(
        tag(&r),
        (
            StatusCode::UNAUTHORIZED,
            json!("RelayAgentActivityPublishProofExpiredError"),
            Value::Null
        )
    );
    assert_eq!(r.body["code"], "agent_activity_publish_proof_expired");

    let other = state("thread-1", "completed", 1000);
    assert_eq!(
        tag(&h
            .publish_raw(
                &cred,
                "thread-1",
                Some(&s),
                proof_claims("thread-1", Some(&other))
            )
            .await),
        invalid("invalid_signature_or_payload")
    );
    assert_eq!(
        tag(&h
            .publish_raw(
                &cred,
                "thread-1",
                Some(&s),
                proof_claims("thread-2", Some(&s))
            )
            .await),
        invalid("invalid_signature_or_payload")
    );
    let s2 = state("thread-2", "running", 1000);
    assert_eq!(
        tag(&h.publish(&cred, "thread-1", Some(&s2)).await),
        invalid("invalid_signature_or_payload"),
        "state for another thread"
    );
    let mut c = proof_claims("thread-1", Some(&s));
    c["aud"] = json!("https://other.example.test");
    assert_eq!(
        tag(&h.publish_raw(&cred, "thread-1", Some(&s), c).await),
        invalid("invalid_signature_or_payload")
    );

    let c = proof_claims("thread-1", Some(&s));
    assert_eq!(
        h.publish_raw(&cred, "thread-1", Some(&s), c.clone())
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(
        tag(&h.publish_raw(&cred, "thread-1", Some(&s), c).await),
        invalid("replayed_nonce")
    );

    // Another machine's path, a bad credential, a body without `state`.
    let r = h
        .send(
            Request::post("/v1/machines/machine-2/threads/t/agent-activity")
                .header(header::AUTHORIZATION, format!("Bearer {cred}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({"state": null, "proof": "x"}).to_string()))
                .unwrap(),
        )
        .await;
    assert_eq!(
        tag(&r),
        (
            StatusCode::UNAUTHORIZED,
            json!("RelayAuthInvalidError"),
            json!("not_authorized")
        )
    );
    let r = h
        .send(
            Request::post(format!("/v1/machines/{MACHINE}/threads/t/agent-activity"))
                .header(header::AUTHORIZATION, "Bearer nope")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({"state": null, "proof": "x"}).to_string()))
                .unwrap(),
        )
        .await;
    assert_eq!(tag(&r).2, json!("not_authorized"));
    let r = h
        .send(
            Request::post(format!("/v1/machines/{MACHINE}/threads/t/agent-activity"))
                .header(header::AUTHORIZATION, format!("Bearer {cred}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({"proof": "x"}).to_string()))
                .unwrap(),
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);

    // A null state removes the row.
    assert_eq!(
        h.publish(&cred, "thread-1", None).await.status,
        StatusCode::OK
    );
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM relay_agent_activity_rows")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(n, 0);
}

#[sqlx::test]
async fn mobile_routes_follow_t3(pool: PgPool) {
    let h = harness(pool).await;
    let u = h.user("a@example.test", &["mobile:registration"]).await;
    // Schema checks: Android may not carry iOS fields; iOS needs its major version >= 18.
    for bad in [
        json!({"deviceId": "d", "label": "x", "platform": "android", "androidApiLevel": 34, "iosMajorVersion": 18, "preferences": prefs_json()}),
        json!({"deviceId": "d", "label": "x", "platform": "ios", "iosMajorVersion": 17, "preferences": prefs_json()}),
        json!({"deviceId": "d", "label": "x", "platform": "ios", "preferences": prefs_json()}),
        json!({"deviceId": " ", "label": "x", "platform": "ios", "iosMajorVersion": 18, "preferences": prefs_json()}),
        json!({"deviceId": "d", "label": "x", "platform": "ios", "iosMajorVersion": 18, "pushToken": null, "preferences": prefs_json()}),
    ] {
        assert_eq!(
            h.mobile(&u, "POST", "/v1/mobile/devices", Some(bad.clone()))
                .await
                .status,
            StatusCode::BAD_REQUEST,
            "{bad}"
        );
    }
    h.ios(&u, "phone-1", "push-token-1").await;
    // A token moves to the device that registers it last.
    h.ios(&u, "phone-2", "push-token-1").await;
    let owners: Vec<(String, Option<String>)> =
        sqlx::query_as("SELECT device_id, push_token FROM relay_mobile_devices ORDER BY device_id")
            .fetch_all(&h.pool)
            .await
            .unwrap();
    assert_eq!(
        owners,
        vec![
            ("phone-1".into(), None),
            ("phone-2".into(), Some("push-token-1".into()))
        ]
    );
    let r = h
        .mobile(&u, "DELETE", "/v1/mobile/devices/phone-1", None)
        .await;
    assert_eq!(r.body, json!({"ok": true}));
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM relay_mobile_devices")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(n, 1);
    assert_eq!(
        h.mobile(&u, "GET", "/v1/mobile/agent-activity", None)
            .await
            .body,
        json!({"aggregate": null})
    );

    // Without `mobile:registration`, or without DPoP, it is a DPoP 401.
    let other = h.user("b@example.test", &["machine:connect"]).await;
    let r = h
        .mobile(&other, "GET", "/v1/mobile/agent-activity", None)
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert_eq!(r.headers[header::WWW_AUTHENTICATE], "DPoP");
    assert_eq!(r.body["reason"], "invalid_dpop");
    let r = h
        .send(
            Request::get("/v1/mobile/agent-activity")
                .header(header::AUTHORIZATION, format!("Bearer {}", u.token))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(
        (r.status, r.body["reason"].clone()),
        (StatusCode::UNAUTHORIZED, json!("invalid_bearer"))
    );
    // A replayed proof is refused.
    let url = format!("{ORIGIN}/v1/mobile/agent-activity");
    let proof = u.dpop.proof("GET", &url, &u.token);
    let call = || {
        Request::get("/v1/mobile/agent-activity")
            .header(header::AUTHORIZATION, format!("DPoP {}", u.token))
            .header("dpop", proof.clone())
            .body(Body::empty())
            .unwrap()
    };
    assert_eq!(h.send(call()).await.status, StatusCode::OK);
    assert_eq!(h.send(call()).await.body["dpopFailureReason"], "replay");
}

#[sqlx::test]
async fn disabling_a_user_removes_their_phones(pool: PgPool) {
    let h = harness(pool).await;
    let u = h.user("a@example.test", &["mobile:registration"]).await;
    h.ios(&u, "phone-1", "push-token-1").await;
    h.android(&u, "pixel-1", "fcm-token-1").await;
    h.mobile(
        &u,
        "POST",
        "/v1/mobile/live-activities",
        Some(json!({"deviceId": "phone-1", "activityPushToken": "la-1"})),
    )
    .await;
    while h.work().await > 0 {}
    let cred = h.link(u.id, true, true).await;
    h.publish(
        &cred,
        "thread-1",
        Some(&state("thread-1", "waiting_for_input", 1000)),
    )
    .await;
    let other = Uuid::new_v4();
    sqlx::query("INSERT INTO relay_push_jobs (kind, payload) VALUES ('fcm', $1)")
        .bind(json!({"userId": other, "deviceId": "x", "token": "t", "state": null, "queuedAt": 0}))
        .execute(&h.pool)
        .await
        .unwrap();
    let pending = |pool: PgPool| async move {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT coalesce(payload->'target'->>'userId', payload->>'userId') FROM relay_push_jobs
             WHERE status IN ('pending', 'running') ORDER BY 1",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        rows.into_iter().map(|r| r.0).collect::<Vec<_>>()
    };
    let before = pending(h.pool.clone()).await;
    assert!(
        before.len() >= 3 && before.contains(&u.id.to_string()),
        "{before:?}"
    );
    let out = crate::admin::run(
        &h.pool,
        crate::admin::Admin::DisableUser {
            email: "a@example.test".into(),
        },
    )
    .await
    .unwrap();
    assert!(out.contains("; removed 2 mobile devices;"), "{out}");
    let n: i64 = sqlx::query_scalar("SELECT (SELECT count(*) FROM relay_mobile_devices) + (SELECT count(*) FROM relay_live_activities)")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(n, 0);
    assert_eq!(
        pending(h.pool.clone()).await,
        [other.to_string()],
        "the user's queued pushes are gone, other users' stay"
    );
}

#[sqlx::test]
async fn admin_push_test_sends_one_alert_per_phone(pool: PgPool) {
    let h = harness(pool).await;
    let u = h.user("a@example.test", &["mobile:registration"]).await;
    h.ios(&u, "phone-1", "push-token-1").await;
    h.android(&u, "pixel-1", "fcm-token-1").await;
    let out = super::push_test(&h.push, "a@example.test").await.unwrap();
    assert_eq!(out, "ios phone-1: APNs 200 \nandroid pixel-1: FCM accepted");
    let apns = h.apns.seen();
    assert_eq!(apns.len(), 1);
    assert!(apns[0].body.contains("\"thread-id\":\"t3-agent-alerts\""));
    assert!(
        super::push_test(&h.push, "nobody@example.test")
            .await
            .is_err()
    );
}

#[sqlx::test]
async fn keys_and_tokens_never_reach_the_logs(pool: PgPool) {
    let h = harness(pool).await;
    let u = h.user("a@example.test", &["mobile:registration"]).await;
    let cred = h.link(u.id, true, true).await;
    h.ios(&u, "phone-1", "push-token-secret-ios-0001").await;
    h.ios(&u, "phone-2", "bad-token-secret-ios-0002").await;
    h.android(&u, "pixel-1", "fail-token-secret-fcm-0003").await;
    h.publish(
        &cred,
        "thread-1",
        Some(&state("thread-1", "waiting_for_input", 1000)),
    )
    .await;
    while h.work().await > 0 {}
    let logs = crate::test_logs::capture_logs(|| {});
    let apns_key = apns_pem();
    let body_line = apns_key.lines().nth(1).unwrap();
    let rsa_line = rsa_pem().lines().nth(1).unwrap();
    let debug = format!("{:?}", h.push.config);
    for secret in [
        body_line,
        rsa_line,
        "ya29.fake-fcm-access-token",
        "push-token-secret-ios-0001",
        "bad-token-secret-ios-0002",
        "fail-token-secret-fcm-0003",
        &u.token,
        &cred,
    ] {
        assert!(!logs.contains(secret), "{secret} in logs");
        assert!(!debug.contains(secret), "{secret} in Debug");
    }
    assert!(
        logs.contains("push job failed"),
        "the failure was logged, without its token"
    );
}

#[sqlx::test]
async fn devices_may_only_route_to_listed_apps(pool: PgPool) {
    let h = harness_with(
        pool,
        &[(
            "APNS_BUNDLE_IDS",
            "com.example.vekrel, com.example.vekrel.dev",
        )],
    )
    .await;
    let u = h.user("a@example.test", &["mobile:registration"]).await;
    let cred = h.link(u.id, true, false).await;
    let reg = |platform: &str, bundle: &str| {
        let mut v = json!({"deviceId": format!("{platform}-{bundle}"), "label": "x", "platform": platform,
            "bundleId": bundle, "pushToken": format!("tok-{platform}-{bundle}"), "preferences": prefs_json()});
        if bundle.is_empty() {
            v.as_object_mut().unwrap().remove("bundleId");
        }
        if platform == "ios" {
            v["iosMajorVersion"] = json!(18)
        } else {
            v["androidApiLevel"] = json!(34)
        }
        v
    };
    for (platform, bundle, ok) in [
        ("ios", "com.example.vekrel.dev", true),
        ("ios", "com.attacker.app", false),
        ("android", "com.example.vekrel", true),
        ("android", "com.attacker.app", false),
        ("android", "", false),
        ("ios", "", true),
    ] {
        let r = h
            .mobile(
                &u,
                "POST",
                "/v1/mobile/devices",
                Some(reg(platform, bundle)),
            )
            .await;
        assert_eq!(
            r.status == StatusCode::OK,
            ok,
            "{platform} {bundle}: {}",
            r.status
        );
    }
    // A value stored before the list existed is never used to send.
    sqlx::query("INSERT INTO relay_mobile_devices (user_id, device_id, platform, ios_major_version, bundle_id, push_token, preferences_json, created_at, updated_at)
                 VALUES ($1, 'old-ios', 'ios', 18, 'com.attacker.app', 'tok-old-ios', $2, 'x', 'x'),
                        ($1, 'old-android', 'android', NULL, 'com.attacker.app', 'tok-old-android', $2, 'x', 'x'),
                        ($1, 'nopkg-android', 'android', NULL, NULL, 'tok-nopkg-android', $2, 'x', 'x')")
        .bind(u.id)
        .bind(prefs_json())
        .execute(&h.pool)
        .await
        .unwrap();
    h.publish(
        &cred,
        "thread-1",
        Some(&state("thread-1", "waiting_for_input", 1000)),
    )
    .await;
    while h.work().await > 0 {}
    let apns: Vec<String> = h.apns.seen().iter().map(|s| s.path.clone()).collect();
    assert!(
        apns.contains(&"/3/device/tok-ios-com.example.vekrel.dev".to_string()),
        "{apns:?}"
    );
    let dev = h
        .apns
        .seen()
        .into_iter()
        .find(|s| s.path.ends_with("com.example.vekrel.dev"))
        .unwrap();
    assert_eq!(dev.headers["apns-topic"], "com.example.vekrel.dev");
    assert!(!apns.iter().any(|p| p.contains("old-ios")), "{apns:?}");
    assert!(
        !h.fcm
            .seen()
            .iter()
            .any(|s| s.body.contains("tok-old-android") || s.body.contains("tok-nopkg-android"))
    );
    assert!(
        h.fcm
            .seen()
            .iter()
            .any(|s| s.body.contains("tok-android-com.example.vekrel"))
    );
}
