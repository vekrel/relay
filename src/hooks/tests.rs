// Webhook forwarding and held hooks through the HTTP routes, against a fake machine on loopback
// (cases follow T3's `HookForwarder.test.ts`, `HookInboxStore.test.ts`, `HeldHooks.test.ts`).
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, Request, StatusCode, header};
use axum::response::{IntoResponse, Response};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

use super::upstream::Hook;
use super::{forwarder, held, inbox};
use crate::accounts::keys::SigningKeys;
use crate::accounts::oauth::AccountsState;
use crate::accounts::tokens::{AccessClaims, sign_access_token};
use crate::config::Config;
use crate::http::client::{MachineState, router as client_router};
use crate::jws::{self, tests::test_only_key};
use crate::machines::provider::NoTunnels;
use crate::machines::{Relay, credentials, now_ms};

const ORIGIN: &str = "https://relay.example.test";
const ZONE: &str = "tunnels.example.test";
const KEY: &str = "0123456789abcdef";

#[derive(Debug, Clone)]
struct Seen {
    method: String,
    uri: String,
    headers: HeaderMap,
    body: Vec<u8>,
}

/// A machine's webhook route: records every request and answers the queued statuses, then 200.
#[derive(Clone, Default)]
struct Machine {
    seen: Arc<Mutex<Vec<Seen>>>,
    statuses: Arc<Mutex<VecDeque<u16>>>,
    fallback: Arc<Mutex<Option<u16>>>,
    /// Revokes every link (without clearing held hooks) when the first request arrives.
    revoke_on_first: Arc<Mutex<Option<PgPool>>>,
    /// Requests in progress now, and the most seen at once.
    inflight: Arc<std::sync::atomic::AtomicUsize>,
    max_inflight: Arc<std::sync::atomic::AtomicUsize>,
    /// Extra time each answer takes, in ms.
    delay_ms: Arc<std::sync::atomic::AtomicU64>,
}

impl Machine {
    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
    fn answer(&self, statuses: &[u16]) {
        self.statuses.lock().unwrap().extend(statuses);
    }
    fn always(&self, status: u16) {
        *self.fallback.lock().unwrap() = Some(status);
    }
}

async fn machine_route(State(m): State<Machine>, req: Request<Body>) -> Response {
    let (parts, body) = req.into_parts();
    let body = body.collect().await.unwrap().to_bytes().to_vec();
    use std::sync::atomic::Ordering::SeqCst;
    let now = m.inflight.fetch_add(1, SeqCst) + 1;
    m.max_inflight.fetch_max(now, SeqCst);
    let revoke = m.revoke_on_first.lock().unwrap().take();
    if let Some(pool) = revoke {
        exec(&pool, "UPDATE relay_machine_links SET revoked_at = 'x'").await;
    }
    m.seen.lock().unwrap().push(Seen {
        method: parts.method.to_string(),
        uri: parts.uri.to_string(),
        headers: parts.headers,
        body,
    });
    let extra = m.delay_ms.load(SeqCst);
    tokio::time::sleep(std::time::Duration::from_millis(20 + extra)).await;
    m.inflight.fetch_sub(1, SeqCst);
    let queued = m.statuses.lock().unwrap().pop_front();
    let status = queued.or(*m.fallback.lock().unwrap()).unwrap_or(200);
    (
        StatusCode::from_u16(status).unwrap(),
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::SET_COOKIE, "s=1"),
            (
                header::HeaderName::from_static("x-vekrel-hook-outcome"),
                "accepted",
            ),
        ],
        r#"{"error":"bad_signature"}"#,
    )
        .into_response()
}

async fn start_machine() -> (Machine, String) {
    let m = Machine::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new().fallback(machine_route).with_state(m.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (m, format!("http://{addr}/"))
}

struct T {
    router: Router,
    relay: Arc<Relay>,
    pool: PgPool,
    machine: Machine,
    user: Uuid,
    keys: Arc<SigningKeys>,
    credential: String,
}

struct Res {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl Res {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }
}

async fn exec(pool: &PgPool, sql: &str) {
    sqlx::query(sqlx::AssertSqlSafe(sql.to_owned()))
        .execute(pool)
        .await
        .unwrap();
}

/// User `a@example.test` links machine `m1` (key `mk`) as a managed endpoint on `prod-<KEY>.<ZONE>`, whose
/// tunnel name ends with `KEY`. `hold`: the link opted in to held webhooks.
async fn setup(pool: PgPool, hold: bool) -> T {
    setup_with(pool, hold, Arc::new(NoTunnels)).await
}

async fn setup_with(
    pool: PgPool,
    hold: bool,
    provider: Arc<dyn crate::machines::provider::ManagedEndpoints>,
) -> T {
    let (machine, url) = start_machine().await;
    let user: Uuid =
        sqlx::query_scalar("INSERT INTO users (email) VALUES ('a@example.test') RETURNING id")
            .fetch_one(&pool)
            .await
            .unwrap();
    add_link(&pool, user, "m1", hold).await;
    let credential = credentials::create(&mut pool.acquire().await.unwrap(), "m1", "mk")
        .await
        .unwrap();
    let mint = test_only_key("relayMint");
    let mut relay = Relay::new(pool.clone(), mint, ORIGIN, Some(ZONE.into()), provider);
    relay.endpoint_override = Some(url);
    let relay = Arc::new(relay);
    let (a, _) = crate::accounts::keys::tests::entry("a", "active");
    let keys = Arc::new(SigningKeys::from_json(&json!([a]).to_string()).unwrap());
    let config = Config::for_tests(&[("RELAY_ORIGIN", ORIGIN)]);
    let accounts = AccountsState::new(pool.clone(), keys.clone(), &config);
    let router = forwarder::router(relay.clone()).merge(client_router(MachineState {
        relay: relay.clone(),
        accounts,
    }));
    T {
        router,
        relay,
        pool,
        machine,
        user,
        keys,
        credential,
    }
}

async fn add_link(pool: &PgPool, user: Uuid, machine_id: &str, hold: bool) {
    add_link_with_key(pool, user, machine_id, hold, KEY).await
}

/// A managed link whose endpoint key is `key`, on `prod-<key>.<ZONE>`.
async fn add_link_with_key(pool: &PgPool, user: Uuid, machine_id: &str, hold: bool, key: &str) {
    let host = format!("prod-{key}.{ZONE}");
    sqlx::query(
        "INSERT INTO relay_machine_links (user_id, machine_id, machine_public_key,
            endpoint_http_base_url, endpoint_ws_base_url, endpoint_provider_kind,
            managed_tunnels_enabled, hold_webhooks_while_offline, created_at, updated_at)
         VALUES ($1, $2, 'mk', $3, $4, 'cloudflare_tunnel', true, $5, 'x', 'x')",
    )
    .bind(user)
    .bind(machine_id)
    .bind(format!("https://{host}/"))
    .bind(format!("wss://{host}/ws"))
    .bind(hold)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO relay_managed_endpoint_allocations (user_id, machine_id, hostname, tunnel_id,
            tunnel_name, dns_record_id, ready_at, created_at, updated_at)
         VALUES ($1, $2, $3, 'tunnel-1', $4, 'dns-1', 'x', 'x', 'x')",
    )
    .bind(user)
    .bind(machine_id)
    .bind(&host)
    .bind(format!("vekrelrelay-managedendpoint-test-{key}"))
    .execute(pool)
    .await
    .unwrap();
}

impl T {
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

    async fn hook(&self, method: &str, path_tail: &str, body: &'static [u8]) -> Res {
        let req = Request::builder()
            .method(method)
            .uri(format!("/v1/hooks/{KEY}/{path_tail}"))
            .body(Body::from(body))
            .unwrap();
        self.send(req).await
    }

    async fn machine_call(&self, path: &str, body: Option<Value>) -> Res {
        let mut b = Request::builder()
            .method("POST")
            .uri(path)
            .header(header::AUTHORIZATION, format!("Bearer {}", self.credential));
        if body.is_some() {
            b = b.header(header::CONTENT_TYPE, "application/json");
        }
        let body = body.map_or_else(Body::empty, |v| Body::from(v.to_string()));
        self.send(b.body(body).unwrap()).await
    }

    async fn held(&self) -> Vec<(String, Vec<u8>)> {
        sqlx::query_as("SELECT id, body FROM relay_held_hooks ORDER BY seq")
            .fetch_all(&self.pool)
            .await
            .unwrap()
    }
}

/// A held request built directly (the inbox tests skip the HTTP path).
fn hook_row(id: &str, hook_key: &str, body: &[u8]) -> Hook {
    Hook {
        id: id.into(),
        received_at: crate::machines::now_iso(),
        method: "POST".into(),
        raw_hook_id: hook_key.into(),
        raw_token: "tok".into(),
        hook_key: hook_key.into(),
        query: String::new(),
        headers: serde_json::Map::new(),
        body: body.to_vec(),
    }
}

const BASE: &str = "https://prod-0123456789abcdef.tunnels.example.test/";

#[sqlx::test]
async fn forward_preserves_method_body_query_and_the_headers_t3_keeps(pool: PgPool) {
    let t = setup(pool, false).await;
    t.machine.answer(&[401]);
    let body: &[u8] = &[0, 255, 10, b'x'];
    let req = Request::builder()
        .method("POST")
        .uri(format!("/v1/hooks/{KEY}/hook-1/tok%2Fen?a=1&b=two%20words"))
        .header("authorization", "Bearer sender-secret")
        .header("x-hub-signature-256", "sha256=abc")
        .header("content-type", "application/octet-stream")
        .header("content-length", body.len().to_string())
        .header("cookie", "c=1")
        .header("x-real-ip", "203.0.113.1")
        .header("x-forwarded-for", "203.0.113.1")
        .header("cf-ray", "r")
        .header("proxy-authorization", "p")
        .header("traceparent", "00-aa-bb-01")
        .header("x-b3-traceid", "t")
        .header("x-vekrel-relay-delivery-id", "forged")
        .header("x-vekrel-relay-received-at", "forged")
        .header("x-vekrel-relay-delivery", "forged")
        .header("connection", "x-hop")
        .header("x-hop", "1")
        .header("x-keep", "2")
        .header("x-multi", "a")
        .header("x-multi", "b")
        .body(Body::from(body))
        .unwrap();
    let r = t.send(req).await;
    // The machine's answer passes through, sandboxed, without its cookies and without CORS.
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert_eq!(r.body, br#"{"error":"bad_signature"}"#);
    assert_eq!(r.headers[header::CONTENT_TYPE], "application/json");
    assert_eq!(r.headers["x-content-type-options"], "nosniff");
    assert_eq!(
        r.headers["content-security-policy"],
        "sandbox; default-src 'none'"
    );
    assert!(r.headers.get(header::SET_COOKIE).is_none());
    assert!(r.headers.get("access-control-allow-origin").is_none());

    let seen = t.machine.seen();
    assert_eq!(seen.len(), 1);
    let s = &seen[0];
    assert_eq!(s.method, "POST");
    assert_eq!(s.uri, "/api/hooks/hook-1/tok%2Fen?a=1&b=two%20words");
    assert_eq!(s.body, body);
    let h = |n: &str| s.headers.get(n).map(|v| v.to_str().unwrap().to_owned());
    assert_eq!(h("authorization").as_deref(), Some("Bearer sender-secret"));
    assert_eq!(h("x-hub-signature-256").as_deref(), Some("sha256=abc"));
    assert_eq!(
        h("content-type").as_deref(),
        Some("application/octet-stream")
    );
    assert_eq!(h("content-length").as_deref(), Some("4"));
    assert_eq!(h("x-keep").as_deref(), Some("2"));
    assert_eq!(h("x-multi").as_deref(), Some("a, b"));
    for dropped in [
        "cookie",
        "x-real-ip",
        "x-forwarded-for",
        "cf-ray",
        "proxy-authorization",
        "traceparent",
        "x-b3-traceid",
        "x-hop",
    ] {
        assert_eq!(h(dropped), None, "{dropped}");
    }
    // The relay sets the delivery headers itself and signs them for the machine.
    let delivery_id = h("x-vekrel-relay-delivery-id").unwrap();
    let received_at = h("x-vekrel-relay-received-at").unwrap();
    assert_ne!(delivery_id, "forged");
    assert!(Uuid::parse_str(&delivery_id).is_ok());
    assert!(crate::machines::parse_iso_ms(&received_at).is_some());
    let proof = h("x-vekrel-relay-delivery").unwrap();
    let claims = jws::verify(
        &test_only_key("relayMint").verifying_key(),
        &proof,
        &jws::Expect {
            typ: "t3-relay-hook-delivery+jwt",
            issuer: ORIGIN,
            audience: "vekrel-machine:m1",
            now_epoch_seconds: now_ms() / 1000,
            max_age_seconds: 25 * 60 * 60,
        },
    )
    .unwrap();
    let keys: Vec<&String> = claims.keys().collect();
    assert_eq!(
        keys,
        [
            "iss",
            "aud",
            "sub",
            "jti",
            "iat",
            "exp",
            "machineId",
            "deliveryId",
            "receivedAt",
            "hookId"
        ]
    );
    assert_eq!(claims["sub"], "m1");
    assert_eq!(claims["machineId"], "m1");
    assert_eq!(claims["deliveryId"], delivery_id.as_str());
    assert_eq!(claims["receivedAt"], received_at.as_str());
    assert_eq!(claims["hookId"], "hook-1");
    assert_eq!(
        claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(),
        25 * 60 * 60
    );

    // GET carries no body; PUT and PATCH keep their method; a body without a type gets
    // Effect's default.
    for method in ["GET", "PUT", "PATCH"] {
        assert_eq!(
            t.hook(method, "hook-1/tok", b"x").await.status,
            StatusCode::OK
        );
    }
    let seen = t.machine.seen();
    assert_eq!(
        (seen[1].method.as_str(), seen[1].body.as_slice()),
        ("GET", &b""[..])
    );
    assert!(seen[1].headers.get("content-type").is_none());
    assert_eq!(
        (seen[2].method.as_str(), seen[2].body.as_slice()),
        ("PUT", &b"x"[..])
    );
    assert_eq!(seen[2].headers["content-type"], "application/octet-stream");
    assert_eq!(seen[3].method, "PATCH");
    assert!(t.held().await.is_empty(), "nothing is stored by default");
}

#[sqlx::test]
async fn offline_without_opt_in_answers_t3s_status_and_stores_nothing(pool: PgPool) {
    let mut t = setup(pool, false).await;
    for status in [530, 502, 503, 504] {
        t.machine.answer(&[status]);
        let r = t.hook("POST", "hook-1/tok", b"{}").await;
        assert_eq!(r.status, StatusCode::SERVICE_UNAVAILABLE, "{status}");
        assert_eq!(r.json(), json!({"error": "environment_unavailable"}));
    }
    // A machine that answers 500 did take the request: it passes through.
    t.machine.answer(&[500]);
    assert_eq!(
        t.hook("POST", "hook-1/tok", b"{}").await.status,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    // Nobody listening at all.
    let mut relay = Relay::new(
        t.pool.clone(),
        test_only_key("relayMint"),
        ORIGIN,
        Some(ZONE.into()),
        Arc::new(NoTunnels),
    );
    relay.endpoint_override = Some("http://127.0.0.1:1/".into());
    t.router = forwarder::router(Arc::new(relay));
    let r = t.hook("POST", "hook-1/tok", b"{}").await;
    assert_eq!(r.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(r.json(), json!({"error": "environment_unavailable"}));
    assert!(t.held().await.is_empty());
}

#[sqlx::test]
async fn offline_with_opt_in_holds_then_replays_once_in_order_after_wake(pool: PgPool) {
    let t = setup(pool, true).await;
    t.machine.always(530);
    for body in [&b"one"[..], b"two", b"three"] {
        let r = t.hook("POST", "hook-1/tok%2Fen?a=1", body).await;
        assert_eq!(r.status, StatusCode::ACCEPTED);
        assert_eq!(r.body, br#"{"queued":true}"#);
    }
    let held = t.held().await;
    assert_eq!(held.len(), 3);
    let first_tries = t.machine.seen();
    assert_eq!(first_tries.len(), 3);
    // Held under the id of the first try, so the machine runs a twice-delivered request once.
    for (s, (id, _)) in first_tries.iter().zip(&held) {
        assert_eq!(s.headers["x-vekrel-relay-delivery-id"], id.as_str());
    }
    // The first retry is 10 s out: nothing is due yet.
    assert_eq!(inbox::run_due(&t.relay).await.unwrap(), 0);

    t.machine.always(200);
    let r = t.machine_call("/v1/machines/m1/hooks/wake", None).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.body, br#"{"pending":true}"#);
    assert_eq!(inbox::run_due(&t.relay).await.unwrap(), 1);
    let replays = t.machine.seen()[3..].to_vec();
    let bodies: Vec<&[u8]> = replays.iter().map(|s| s.body.as_slice()).collect();
    assert_eq!(bodies, [&b"one"[..], b"two", b"three"]);
    for (replay, first) in replays.iter().zip(&first_tries) {
        assert_eq!(replay.uri, "/api/hooks/hook-1/tok%2Fen?a=1");
        for h in [
            "x-vekrel-relay-delivery-id",
            "x-vekrel-relay-received-at",
            "x-vekrel-relay-delivery",
        ] {
            assert_eq!(replay.headers[h], first.headers[h], "{h}");
        }
    }
    assert!(t.held().await.is_empty());
    // Delivered once: nothing more is sent, and a second wake finds nothing.
    assert_eq!(inbox::run_due(&t.relay).await.unwrap(), 0);
    let r = t.machine_call("/v1/machines/m1/hooks/wake", None).await;
    assert_eq!(r.body, br#"{"pending":false}"#);
    assert_eq!(inbox::run_due(&t.relay).await.unwrap(), 0);
    assert_eq!(t.machine.seen().len(), 6);
}

#[sqlx::test]
async fn a_busy_hook_waits_while_others_go_and_unreachable_backs_off(pool: PgPool) {
    let t = setup(pool, true).await;
    for r in [
        hook_row("a1", "hook-a", b"a1"),
        hook_row("a2", "hook-a", b"a2"),
        hook_row("b1", "hook-b", b"b1"),
    ] {
        assert_eq!(
            inbox::hold(&t.pool, KEY, BASE, &r).await.unwrap(),
            inbox::Held::Stored
        );
    }
    // hook-a answers 429 (busy): its next request waits, hook-b's goes through.
    t.machine.answer(&[429, 200]);
    let now = now_ms();
    let next = inbox::deliver_due(&t.relay, KEY, 0).await.unwrap().unwrap();
    assert!((now..now + 5_000).contains(&next), "more is due now");
    let ids: Vec<String> = t.held().await.into_iter().map(|h| h.0).collect();
    assert_eq!(ids, ["a1", "a2"]);
    let sent: Vec<Vec<u8>> = t.machine.seen().into_iter().map(|s| s.body).collect();
    assert_eq!(sent, [b"a1".to_vec(), b"b1".to_vec()]);
    // Only busy hooks left: retry in 30 s.
    t.machine.answer(&[429]);
    let now = now_ms();
    let next = inbox::deliver_due(&t.relay, KEY, 0).await.unwrap().unwrap();
    assert!((now + 30_000..now + 35_000).contains(&next));
    // Unreachable: stop, count the failure, retry in 10 s.
    t.machine.answer(&[530]);
    let now = now_ms();
    let next = inbox::deliver_due(&t.relay, KEY, 0).await.unwrap().unwrap();
    assert!((now + 10_000..now + 15_000).contains(&next));
    let failures: i32 = sqlx::query_scalar("SELECT failures FROM relay_held_hook_targets")
        .fetch_one(&t.pool)
        .await
        .unwrap();
    assert_eq!(failures, 1);
    assert_eq!(t.held().await.len(), 2);
}

#[sqlx::test]
async fn the_61st_call_to_one_url_in_a_minute_is_refused(pool: PgPool) {
    let t = setup(pool, false).await;
    for i in 0..60 {
        assert_eq!(
            t.hook("GET", "hook-1/tok", b"").await.status,
            StatusCode::OK,
            "{i}"
        );
    }
    let r = t.hook("GET", "hook-1/tok", b"").await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(r.headers[header::RETRY_AFTER], "60");
    assert_eq!(r.json(), json!({"error": "rate_limited"}));
    // Another spelling of the same token shares the budget; a wrong token has its own.
    assert_eq!(
        t.hook("GET", "hook-1/%74ok", b"").await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        t.hook("GET", "hook-1/other", b"").await.status,
        StatusCode::OK
    );
    assert_eq!(t.machine.seen().len(), 61);
    // The endpoint's own budget (600/min) covers every URL under it.
    exec(
        &t.pool,
        &format!(
            "INSERT INTO relay_rate_limits (key, window_start, count)
             VALUES ('hook-endpoint:{KEY}', now(), 600)"
        ),
    )
    .await;
    assert_eq!(
        t.hook("GET", "hook-2/fresh", b"").await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(t.machine.seen().len(), 61);
}

#[sqlx::test]
async fn held_hooks_past_the_ttl_are_pruned(pool: PgPool) {
    let t = setup(pool, true).await;
    for (id, age_ms) in [
        ("old", inbox::TTL_MS + 1_000),
        ("fresh", inbox::TTL_MS - 60_000),
    ] {
        let mut h = hook_row(id, "hook-1", b"x");
        h.received_at = crate::auth::dpop_proofs::iso_millis(now_ms() - age_ms);
        assert_eq!(
            inbox::hold(&t.pool, KEY, BASE, &h).await.unwrap(),
            inbox::Held::Stored
        );
    }
    assert_eq!(inbox::prune_expired(&t.pool).await.unwrap(), 1);
    let ids: Vec<String> = t.held().await.into_iter().map(|h| h.0).collect();
    assert_eq!(ids, ["fresh"]);
}

#[sqlx::test]
async fn caps_hold_under_concurrent_requests(pool: PgPool) {
    let t = setup(pool, true).await;
    // Several rounds, each one hook two short of its cap and 40 racing holds: exactly 2 get in.
    // (Without the per-endpoint lock the race lets more in, though not every round.)
    for round in 0..8 {
        let hook_key = if round == 0 {
            "hook-1".to_owned()
        } else {
            format!("hook-r{round}")
        };
        exec(
            &t.pool,
            &format!(
                "INSERT INTO relay_held_hooks (id, endpoint_key, received_at, method, raw_hook_id,
                    raw_token, hook_key, query, headers, body)
                 SELECT 'pre{round}-' || i, '{KEY}', 'x', 'POST', 'h', 't', '{hook_key}', '', '{{}}', 'x'
                 FROM generate_series(1, {}) AS i",
                inbox::MAX_PER_HOOK - 2
            ),
        )
        .await;
        let mut set = tokio::task::JoinSet::new();
        for i in 0..40 {
            let (pool, hook) = (
                t.pool.clone(),
                hook_row(&format!("c{round}-{i}"), &hook_key, b"x"),
            );
            set.spawn(async move {
                inbox::hold(&pool, KEY, BASE, &hook).await.unwrap() == inbox::Held::Stored
            });
        }
        let stored = set.join_all().await.into_iter().filter(|s| *s).count();
        assert_eq!(stored, 2, "round {round}");
    }
    // Another hook still has room; a full hook answers inbox_full.
    assert_eq!(
        inbox::hold(&t.pool, KEY, BASE, &hook_row("other", "hook-2", b"x"))
            .await
            .unwrap(),
        inbox::Held::Stored
    );
    t.machine.always(530);
    let r = t.hook("POST", "hook-1/tok", b"x").await;
    assert_eq!(r.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(r.json(), json!({"error": "inbox_full"}));
    // The byte cap: 50 MiB per endpoint.
    let big = vec![0u8; (inbox::MAX_BYTES / 2) as usize];
    let mut h = hook_row("big1", "hook-3", b"");
    h.body = big.clone();
    assert_eq!(
        inbox::hold(&t.pool, KEY, BASE, &h).await.unwrap(),
        inbox::Held::Stored
    );
    h.id = "big2".into();
    assert_eq!(
        inbox::hold(&t.pool, KEY, BASE, &h).await.unwrap(),
        inbox::Held::Full
    );
}

#[sqlx::test]
async fn unlink_hold_opt_out_and_disable_clear_held_hooks(pool: PgPool) {
    let t = setup(pool, true).await;
    let pool = &t.pool;
    let fill = |id: &'static str| async move {
        assert_eq!(
            inbox::hold(pool, KEY, BASE, &hook_row(id, "hook-1", b"x"))
                .await
                .unwrap(),
            inbox::Held::Stored
        );
    };
    // Turning the hold on keeps them; turning it off clears them.
    fill("h1").await;
    let on = json!({"holdWebhooksWhileOffline": true});
    assert_eq!(
        t.machine_call("/v1/machines/m1/link-preferences", Some(on))
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(t.held().await.len(), 1);
    let off = json!({"holdWebhooksWhileOffline": false});
    let r = t
        .machine_call("/v1/machines/m1/link-preferences", Some(off))
        .await;
    assert_eq!(r.body, br#"{"holdWebhooksWhileOffline":false}"#);
    assert!(t.held().await.is_empty());
    let targets: i64 = sqlx::query_scalar("SELECT count(*) FROM relay_held_hook_targets")
        .fetch_one(&t.pool)
        .await
        .unwrap();
    assert_eq!(targets, 0);

    // Unlinking clears them.
    let on = json!({"holdWebhooksWhileOffline": true});
    t.machine_call("/v1/machines/m1/link-preferences", Some(on))
        .await;
    fill("h2").await;
    let claims = AccessClaims::new(
        ORIGIN,
        t.user,
        Uuid::new_v4(),
        "vekrel-cli",
        "a@example.test",
        crate::accounts::tokens::now_secs(),
    );
    let req = Request::builder()
        .method("DELETE")
        .uri("/v1/client/machine-links/m1")
        .header(
            header::AUTHORIZATION,
            format!("Bearer {}", sign_access_token(&t.keys, &claims)),
        )
        .body(Body::empty())
        .unwrap();
    let r = t.send(req).await;
    assert_eq!(r.body, br#"{"ok":true}"#);
    assert!(t.held().await.is_empty());
}

#[sqlx::test]
async fn disable_user_deletes_only_that_users_held_hooks(pool: PgPool) {
    let t = setup(pool, true).await;
    let other: Uuid =
        sqlx::query_scalar("INSERT INTO users (email) VALUES ('b@example.test') RETURNING id")
            .fetch_one(&t.pool)
            .await
            .unwrap();
    sqlx::query(
        "INSERT INTO relay_managed_endpoint_allocations (user_id, machine_id, hostname,
            tunnel_name, created_at, updated_at)
         VALUES ($1, 'm9', 'other.tunnels.example.test', 'vekrelrelay-x-fedcba9876543210', 'x', 'x')",
    )
    .bind(other)
    .execute(&t.pool)
    .await
    .unwrap();
    let h = hook_row("mine", "hook-1", b"x");
    assert_eq!(
        inbox::hold(&t.pool, KEY, BASE, &h).await.unwrap(),
        inbox::Held::Stored
    );
    exec(
        &t.pool,
        "INSERT INTO relay_held_hooks (id, endpoint_key, received_at, method, raw_hook_id, raw_token,
            hook_key, query, headers, body)
         VALUES ('theirs', 'fedcba9876543210', 'x', 'POST', 'h', 't', 'h', '', '{}', 'x')",
    )
    .await;
    let out = crate::admin::run(
        &t.pool,
        crate::admin::Admin::DisableUser {
            email: "a@example.test".into(),
        },
    )
    .await
    .unwrap();
    assert!(out.ends_with("; deleted 1 held webhooks"), "{out}");
    let ids: Vec<String> = t.held().await.into_iter().map(|h| h.0).collect();
    assert_eq!(ids, ["theirs"]);
}

#[sqlx::test]
async fn forwards_only_to_the_managed_endpoint_of_the_owning_link(pool: PgPool) {
    let t = setup(pool, false).await;
    let resolved = held::resolve_endpoint(&t.relay, KEY)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(resolved.http_base_url, BASE);
    assert_eq!(resolved.machine_id, "m1");
    // A Host header or absolute-form target in the request changes nothing.
    let req = Request::builder()
        .method("POST")
        .uri(format!("http://evil.example/v1/hooks/{KEY}/hook-1/tok"))
        .header(header::HOST, "evil.example")
        .body(Body::from("x"))
        .unwrap();
    assert_eq!(t.send(req).await.status, StatusCode::OK);
    assert_eq!(t.machine.seen()[0].uri, "/api/hooks/hook-1/tok");

    let not_found = |r: Res| {
        assert_eq!(r.status, StatusCode::NOT_FOUND);
        assert_eq!(r.json(), json!({"error": "hook_not_found"}));
    };
    let unknown = Request::builder()
        .method("POST")
        .uri("/v1/hooks/ffffffffffffffff/hook-1/tok")
        .body(Body::empty())
        .unwrap();
    not_found(t.send(unknown).await);
    let upper = Request::builder()
        .method("POST")
        .uri("/v1/hooks/0123456789ABCDEF/hook-1/tok")
        .body(Body::empty())
        .unwrap();
    not_found(t.send(upper).await);
    let sent = t.machine.seen().len();
    // The link's endpoint must be the allocation's managed hostname in the zone.
    // Each case alone, undone afterwards, so one check never hides another.
    for (sql, undo, why) in [
        (
            "UPDATE relay_machine_links SET endpoint_http_base_url = 'https://evil.example/'",
            "UPDATE relay_machine_links SET endpoint_http_base_url = 'https://prod-0123456789abcdef.tunnels.example.test/'",
            "mismatch",
        ),
        (
            "UPDATE relay_managed_endpoint_allocations SET hostname = 'prod-x.evil.example'",
            "UPDATE relay_managed_endpoint_allocations SET hostname = 'prod-0123456789abcdef.tunnels.example.test'",
            "zone",
        ),
        (
            "UPDATE relay_managed_endpoint_allocations SET ready_at = NULL",
            "UPDATE relay_managed_endpoint_allocations SET ready_at = 'x'",
            "unready",
        ),
        (
            "UPDATE relay_machine_links SET revoked_at = 'x'",
            "UPDATE relay_machine_links SET revoked_at = NULL",
            "revoked",
        ),
        (
            "UPDATE users SET disabled_at = now()",
            "UPDATE users SET disabled_at = NULL",
            "disabled",
        ),
    ] {
        exec(&t.pool, sql).await;
        assert_eq!(
            held::resolve_endpoint(&t.relay, KEY).await.unwrap(),
            None,
            "{why}"
        );
        not_found(t.hook("POST", "hook-1/tok", b"").await);
        exec(&t.pool, undo).await;
        assert!(
            held::resolve_endpoint(&t.relay, KEY)
                .await
                .unwrap()
                .is_some(),
            "{why} undone"
        );
    }
    assert_eq!(t.machine.seen().len(), sent, "nothing forwarded");
}

#[sqlx::test]
async fn methods_bodies_and_paths_are_refused_as_t3_refuses_them(pool: PgPool) {
    let t = setup(pool, true).await;
    let head = t.hook("HEAD", "hook-1/tok", b"").await;
    assert_eq!(head.status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(head.headers[header::ALLOW], "GET, POST, PUT, PATCH");
    let delete = t.hook("DELETE", "hook-1/tok", b"").await;
    assert_eq!(
        (delete.status, delete.body.len()),
        (StatusCode::NOT_FOUND, 0)
    );
    // Over 1 MiB, by content-length and while reading.
    let declared = Request::builder()
        .method("POST")
        .uri(format!("/v1/hooks/{KEY}/hook-1/tok"))
        .header(
            header::CONTENT_LENGTH,
            (forwarder::MAX_BODY_BYTES + 1).to_string(),
        )
        .body(Body::empty())
        .unwrap();
    let r = t.send(declared).await;
    assert_eq!(
        (r.status, r.json()),
        (
            StatusCode::PAYLOAD_TOO_LARGE,
            json!({"error": "payload_too_large"})
        )
    );
    let streamed = Request::builder()
        .method("POST")
        .uri(format!("/v1/hooks/{KEY}/hook-1/tok"))
        .body(Body::from(vec![b'x'; forwarder::MAX_BODY_BYTES + 1]))
        .unwrap();
    let r = t.send(streamed).await;
    assert_eq!(
        (r.status, r.json()),
        (
            StatusCode::PAYLOAD_TOO_LARGE,
            json!({"error": "payload_too_large"})
        )
    );
    let bad_escape = t.hook("POST", "hook-1/%zz", b"").await;
    assert_eq!(bad_escape.status, StatusCode::NOT_FOUND);
    assert!(t.machine.seen().is_empty());
    assert!(t.held().await.is_empty());
}

/// Review Focus 4: two workers deliver each held request once; a claim that dies mid-run is
/// picked up after its lease.
#[sqlx::test]
async fn parallel_workers_deliver_once_and_a_crashed_claim_is_retried(pool: PgPool) {
    let t = setup(pool, true).await;
    for id in ["r1", "r2", "r3"] {
        assert_eq!(
            inbox::hold(&t.pool, KEY, BASE, &hook_row(id, "hook-1", id.as_bytes()))
                .await
                .unwrap(),
            inbox::Held::Stored
        );
    }
    assert!(inbox::wake(&t.pool, KEY, BASE).await.unwrap());
    let (a, b) = tokio::join!(inbox::run_due(&t.relay), inbox::run_due(&t.relay));
    assert_eq!(a.unwrap() + b.unwrap(), 1);
    let sent: Vec<Vec<u8>> = t.machine.seen().into_iter().map(|s| s.body).collect();
    assert_eq!(sent, [b"r1".to_vec(), b"r2".to_vec(), b"r3".to_vec()]);

    // A claim taken and never released (the process died mid-run).
    assert_eq!(
        inbox::hold(&t.pool, KEY, BASE, &hook_row("r4", "hook-1", b"r4"))
            .await
            .unwrap(),
        inbox::Held::Stored
    );
    assert!(inbox::wake(&t.pool, KEY, BASE).await.unwrap());
    assert!(inbox::claim(&t.pool).await.unwrap().is_some());
    assert_eq!(inbox::run_due(&t.relay).await.unwrap(), 0, "leased");
    // A wake during the live claim makes it due, but the lease still keeps others out.
    assert!(inbox::wake(&t.pool, KEY, BASE).await.unwrap());
    assert_eq!(inbox::run_due(&t.relay).await.unwrap(), 0, "still leased");
    assert!(t.machine.seen().len() == 3);
    // Claimed again and left to die; once the lease is over, it is due again by itself.
    exec(
        &t.pool,
        "UPDATE relay_held_hook_targets SET locked_until_ms = 1, next_attempt_at_ms = NULL",
    )
    .await;
    exec(
        &t.pool,
        &format!(
            "UPDATE relay_held_hook_targets SET next_attempt_at_ms = {}",
            now_ms()
        ),
    )
    .await;
    assert!(inbox::claim(&t.pool).await.unwrap().is_some());
    exec(
        &t.pool,
        "UPDATE relay_held_hook_targets SET locked_until_ms = locked_until_ms - 600000,
            next_attempt_at_ms = next_attempt_at_ms - 600000",
    )
    .await;
    assert_eq!(inbox::run_due(&t.relay).await.unwrap(), 1);
    assert_eq!(t.machine.seen().len(), 4);
    assert!(t.held().await.is_empty());
}

/// Held hooks keep the token, headers and body in plaintext (replay needs them, as in T3); none of
/// them may reach a log on any path.
#[sqlx::test]
async fn tokens_headers_and_bodies_never_reach_the_logs(pool: PgPool) {
    crate::test_logs::capture_logs(|| ()); // installs the capture before anything logs
    let t = setup(pool, true).await;
    let send = |status: u16| {
        t.machine.answer(&[status]);
        let req = Request::builder()
            .method("POST")
            .uri(format!(
                "/v1/hooks/{KEY}/hook-1/super-secret-token?q=query-secret"
            ))
            .header("x-signature", "header-secret")
            .body(Body::from("body-secret"))
            .unwrap();
        t.send(req)
    };
    let mut statuses = vec![];
    for upstream in [200, 530] {
        statuses.push(send(upstream).await.status);
    }
    assert_eq!(statuses, [StatusCode::OK, StatusCode::ACCEPTED]);
    let stored: String = sqlx::query_scalar("SELECT raw_token FROM relay_held_hooks")
        .fetch_one(&t.pool)
        .await
        .unwrap();
    assert_eq!(stored, "super-secret-token", "held as T3 holds it");
    t.machine.answer(&[530]);
    assert!(inbox::wake(&t.pool, KEY, BASE).await.unwrap());
    inbox::run_due(&t.relay).await.unwrap(); // unreachable: logged, kept
    assert!(inbox::wake(&t.pool, KEY, BASE).await.unwrap());
    inbox::run_due(&t.relay).await.unwrap(); // delivered
    assert!(t.held().await.is_empty());
    let logs = crate::test_logs::capture_logs(|| ());
    assert!(logs.contains("relay.hooks.forward"), "logs are captured");
    assert!(logs.contains("held webhook not delivered yet"));
    for secret in [
        "super-secret-token",
        "query-secret",
        "header-secret",
        "body-secret",
    ] {
        assert!(!logs.contains(secret), "{secret} leaked into logs");
    }
}

/// The hook routes are mounted in the relay's router, under its wrong-method rewrite, which keeps
/// the forwarder's own 405.
#[sqlx::test]
async fn the_relay_router_serves_hooks_as_t3_does(pool: PgPool) {
    use ed25519_dalek::pkcs8::{EncodePrivateKey, spki::der::pem::LineEnding};
    let pem = test_only_key("relayMint")
        .to_pkcs8_pem(LineEnding::LF)
        .unwrap()
        .to_string();
    let config = Config::for_tests(&[("RELAY_ORIGIN", ORIGIN), ("RELAY_MINT_PRIVATE_KEY", &pem)]);
    let (a, _) = crate::accounts::keys::tests::entry("a", "active");
    let keys = Arc::new(SigningKeys::from_json(&json!([a]).to_string()).unwrap());
    let router = crate::http::router(pool, keys, &config);
    let call = |method: &str| {
        let req = Request::builder()
            .method(method)
            .uri(format!("/v1/hooks/{KEY}/hook-1/tok"))
            .body(Body::empty())
            .unwrap();
        router.clone().oneshot(req)
    };
    let head = call("HEAD").await.unwrap();
    assert_eq!(head.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(head.headers()[header::ALLOW], "GET, POST, PUT, PATCH");
    assert!(head.headers().get("access-control-allow-origin").is_none());
    assert_eq!(
        call("DELETE").await.unwrap().status(),
        StatusCode::NOT_FOUND
    );
    let post = call("POST").await.unwrap();
    assert_eq!(post.status(), StatusCode::NOT_FOUND);
    let body = post.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], br#"{"error":"hook_not_found"}"#);
}

/// Dot segments would let a URL climb out of `/api/hooks/` on the machine. T3's runtime normalizes
/// them out of the incoming URL, which then has too few segments: `hook_not_found`.
#[sqlx::test]
async fn dot_segments_in_any_spelling_are_not_hooks(pool: PgPool) {
    let t = setup(pool, false).await;
    for tail in [
        "../tok",
        "hook-1/..",
        "./tok",
        "hook-1/.",
        "%2e%2e/tok",
        "%2E%2e/tok",
        ".%2E/tok",
        "hook-1/%2e",
        "%2E./tok",
    ] {
        let r = t.hook("POST", tail, b"x").await;
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{tail}");
        assert_eq!(r.json(), json!({"error": "hook_not_found"}), "{tail}");
    }
    assert!(t.machine.seen().is_empty());
    // Dots inside a segment are an ordinary hook id.
    assert_eq!(
        t.hook("POST", "a..b/tok", b"x").await.status,
        StatusCode::OK
    );
}

/// A run re-checks that the endpoint may still get its held requests; if not, they are dropped.
#[sqlx::test]
async fn a_delivery_run_drops_what_the_endpoint_may_no_longer_get(pool: PgPool) {
    let t = setup(pool, true).await;
    for (i, sql) in [
        "UPDATE relay_machine_links SET revoked_at = 'x'",
        "UPDATE relay_machine_links SET hold_webhooks_while_offline = false",
        "UPDATE users SET disabled_at = now()",
    ]
    .into_iter()
    .enumerate()
    {
        let id = format!("r{i}");
        assert_eq!(
            inbox::hold(&t.pool, KEY, BASE, &hook_row(&id, "hook-1", b"x"))
                .await
                .unwrap(),
            inbox::Held::Stored
        );
        assert!(inbox::wake(&t.pool, KEY, BASE).await.unwrap());
        exec(&t.pool, sql).await;
        assert_eq!(inbox::run_due(&t.relay).await.unwrap(), 1);
        assert!(t.held().await.is_empty(), "{sql}");
        exec(
            &t.pool,
            "UPDATE relay_machine_links SET revoked_at = NULL, hold_webhooks_while_offline = true",
        )
        .await;
        exec(&t.pool, "UPDATE users SET disabled_at = NULL").await;
    }
    assert!(t.machine.seen().is_empty(), "nothing delivered");
}

/// Hold re-checks the opt-in under the endpoint lock, so a hold racing an unlink, opt-out or
/// disable stores nothing.
#[sqlx::test]
async fn hold_stores_only_for_an_authorized_endpoint(pool: PgPool) {
    let t = setup(pool, true).await;
    for sql in [
        "UPDATE relay_machine_links SET revoked_at = 'x'",
        "UPDATE relay_machine_links SET hold_webhooks_while_offline = false",
        "UPDATE users SET disabled_at = now()",
        "UPDATE relay_machine_links SET endpoint_provider_kind = 'manual'",
    ] {
        exec(&t.pool, sql).await;
        assert_eq!(
            inbox::hold(&t.pool, KEY, BASE, &hook_row("h", "hook-1", b"x"))
                .await
                .unwrap(),
            inbox::Held::NotAllowed,
            "{sql}"
        );
        exec(
            &t.pool,
            "UPDATE relay_machine_links SET revoked_at = NULL, hold_webhooks_while_offline = true,
                endpoint_provider_kind = 'cloudflare_tunnel'",
        )
        .await;
        exec(&t.pool, "UPDATE users SET disabled_at = NULL").await;
    }
    assert!(t.held().await.is_empty());
    assert_eq!(
        inbox::hold(&t.pool, KEY, BASE, &hook_row("h", "hook-1", b"x"))
            .await
            .unwrap(),
        inbox::Held::Stored
    );
}

// ---- Fix round 1 ----

/// The link is revoked (without a clear) while a run is sending: the run stops before the next
/// send and drops what is left.
#[sqlx::test]
async fn a_run_rechecks_authorization_before_each_send(pool: PgPool) {
    let t = setup(pool, true).await;
    for id in ["s1", "s2", "s3"] {
        let h = hook_row(id, "hook-1", id.as_bytes());
        assert_eq!(
            inbox::hold(&t.pool, KEY, BASE, &h).await.unwrap(),
            inbox::Held::Stored
        );
    }
    assert!(inbox::wake(&t.pool, KEY, BASE).await.unwrap());
    *t.machine.revoke_on_first.lock().unwrap() = Some(t.pool.clone());
    assert_eq!(inbox::run_due(&t.relay).await.unwrap(), 1);
    assert_eq!(t.machine.seen().len(), 1, "no send after the revoke");
    assert!(t.held().await.is_empty(), "the rest is dropped");
}

/// Every run prunes its endpoint's expired requests first (T3 `deliverDue`), so none is sent.
#[sqlx::test]
async fn a_run_never_sends_an_expired_request(pool: PgPool) {
    let t = setup(pool, true).await;
    let mut old = hook_row("old", "hook-1", b"old");
    old.received_at = crate::auth::dpop_proofs::iso_millis(now_ms() - inbox::TTL_MS - 1_000);
    assert_eq!(
        inbox::hold(&t.pool, KEY, BASE, &old).await.unwrap(),
        inbox::Held::Stored
    );
    let fresh = hook_row("fresh", "hook-1", b"fresh");
    assert_eq!(
        inbox::hold(&t.pool, KEY, BASE, &fresh).await.unwrap(),
        inbox::Held::Stored
    );
    assert!(inbox::wake(&t.pool, KEY, BASE).await.unwrap());
    assert_eq!(inbox::run_due(&t.relay).await.unwrap(), 1);
    let sent: Vec<Vec<u8>> = t.machine.seen().into_iter().map(|s| s.body).collect();
    assert_eq!(sent, [b"fresh".to_vec()]);
    assert!(t.held().await.is_empty());
}

/// A held request whose machine URL is refused can never be delivered: it is dropped and the
/// queue goes on, instead of counting as an outage.
#[sqlx::test]
async fn an_undeliverable_url_is_dropped_not_retried(pool: PgPool) {
    let t = setup(pool, true).await;
    let mut bad = hook_row("bad", "hook-1", b"bad");
    bad.raw_hook_id = "..".into();
    assert_eq!(
        inbox::hold(&t.pool, KEY, BASE, &bad).await.unwrap(),
        inbox::Held::Stored
    );
    let good = hook_row("good", "hook-1", b"good");
    assert_eq!(
        inbox::hold(&t.pool, KEY, BASE, &good).await.unwrap(),
        inbox::Held::Stored
    );
    assert_eq!(inbox::deliver_due(&t.relay, KEY, 0).await.unwrap(), None);
    let sent: Vec<Vec<u8>> = t.machine.seen().into_iter().map(|s| s.body).collect();
    assert_eq!(sent, [b"good".to_vec()]);
    assert!(t.held().await.is_empty());
    let failures: i32 = sqlx::query_scalar("SELECT failures FROM relay_held_hook_targets")
        .fetch_one(&t.pool)
        .await
        .unwrap();
    assert_eq!(failures, 0);
}

/// Turning the hold off runs on one connection: it works with a pool of one.
#[sqlx::test]
async fn hold_opt_out_needs_one_connection(pool: PgPool) {
    let t = setup(pool, true).await;
    let h = hook_row("h", "hook-1", b"x");
    assert_eq!(
        inbox::hold(&t.pool, KEY, BASE, &h).await.unwrap(),
        inbox::Held::Stored
    );
    let one = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(3))
        .connect_with((*t.pool.connect_options()).clone())
        .await
        .unwrap();
    held::set_hold_while_offline(&one, "m1", "mk", false)
        .await
        .unwrap();
    assert!(t.held().await.is_empty());
}

/// The worker runs at most `MAX_CONCURRENT_RUNS` endpoints at once.
#[sqlx::test]
async fn concurrent_delivery_runs_are_bounded(pool: PgPool) {
    let t = setup(pool, true).await;
    t.machine
        .delay_ms
        .store(300, std::sync::atomic::Ordering::SeqCst);
    let n = inbox::MAX_CONCURRENT_RUNS + 4;
    for i in 0..n {
        let key = format!("{i:016x}");
        let machine = format!("mc{i}");
        add_link_with_key(&t.pool, t.user, &machine, true, &key).await;
        let h = hook_row(&format!("h{i}"), "hook-1", b"x");
        assert_eq!(
            inbox::hold(&t.pool, &key, "unused", &h).await.unwrap(),
            inbox::Held::Stored
        );
        assert!(inbox::wake(&t.pool, &key, "unused").await.unwrap());
    }
    let sem = Arc::new(tokio::sync::Semaphore::new(inbox::MAX_CONCURRENT_RUNS));
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    while t.machine.seen().len() < n && tokio::time::Instant::now() < deadline {
        inbox::dispatch_due(&t.relay, &sem).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(t.machine.seen().len(), n);
    let max = t
        .machine
        .max_inflight
        .load(std::sync::atomic::Ordering::SeqCst);
    assert!(
        (2..=inbox::MAX_CONCURRENT_RUNS).contains(&max),
        "max in flight {max}"
    );
}

use crate::machines::provider::{
    Allocation, BoxFuture, DeprovisionFailed, ManagedEndpoints, OriginSync, ProviderError,
    Provisioned,
};

/// Tunnel teardown that always fails (Cloudflare down); everything else as `NoTunnels`.
struct FailingTeardown;

impl ManagedEndpoints for FailingTeardown {
    fn provision<'a>(
        &'a self,
        u: Uuid,
        m: &'a str,
        o: &'a crate::machines::Origin,
        r: bool,
    ) -> BoxFuture<'a, Result<Provisioned, ProviderError>> {
        NoTunnels.provision(u, m, o, r)
    }
    fn reconcile_origin<'a>(
        &'a self,
        u: Uuid,
        m: &'a str,
        t: &'a str,
        o: &'a crate::machines::Origin,
        e: &'a crate::machines::Endpoint,
    ) -> BoxFuture<'a, Result<OriginSync, ProviderError>> {
        NoTunnels.reconcile_origin(u, m, t, o, e)
    }
    fn prepare_deprovision<'a>(
        &'a self,
        u: Uuid,
        m: &'a str,
    ) -> BoxFuture<'a, Result<Option<Allocation>, DeprovisionFailed>> {
        NoTunnels.prepare_deprovision(u, m)
    }
    fn deprovision<'a>(
        &'a self,
        _: Uuid,
        _: &'a str,
        _: Option<Option<Allocation>>,
    ) -> BoxFuture<'a, Result<bool, DeprovisionFailed>> {
        Box::pin(async {
            Err(DeprovisionFailed {
                stage: "delete-tunnel",
            })
        })
    }
    fn release<'a>(
        &'a self,
        u: Uuid,
        m: &'a str,
        t: Option<&'a str>,
    ) -> BoxFuture<'a, Result<bool, DeprovisionFailed>> {
        NoTunnels.release(u, m, t)
    }
    fn enable_recovery<'a>(
        &'a self,
        u: Uuid,
        m: &'a str,
        t: &'a str,
        k: &'a str,
        o: &'a crate::machines::Origin,
    ) -> BoxFuture<'a, Result<bool, sqlx::Error>> {
        NoTunnels.enable_recovery(u, m, t, k, o)
    }
}

/// Unlink clears held hooks in the revoke transaction, so a failed tunnel teardown cannot leave
/// them behind.
#[sqlx::test]
async fn unlink_clears_held_hooks_even_when_teardown_fails(pool: PgPool) {
    let t = setup_with(pool, true, Arc::new(FailingTeardown)).await;
    let h = hook_row("h", "hook-1", b"x");
    assert_eq!(
        inbox::hold(&t.pool, KEY, BASE, &h).await.unwrap(),
        inbox::Held::Stored
    );
    let claims = AccessClaims::new(
        ORIGIN,
        t.user,
        Uuid::new_v4(),
        "vekrel-cli",
        "a@example.test",
        crate::accounts::tokens::now_secs(),
    );
    let req = Request::builder()
        .method("DELETE")
        .uri("/v1/client/machine-links/m1")
        .header(
            header::AUTHORIZATION,
            format!("Bearer {}", sign_access_token(&t.keys, &claims)),
        )
        .body(Body::empty())
        .unwrap();
    let r = t.send(req).await;
    assert_eq!(
        r.status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "teardown failed"
    );
    assert!(t.held().await.is_empty());
}
