// Tunnel provisioning and the reaper against a fake Cloudflare API (`CLOUDFLARE_API_BASE`). The
// fake keeps tunnels and DNS records in memory and records every request, so tests compare the
// exact request bodies with the ones T3's provider sends (`ManagedEndpointProvider.test.ts`).
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

use super::cloudflare::Cloudflare;
use super::provider::{CloudflareTunnels, ExpectInactive};
use super::{api_pause, reaper};
use crate::auth::dpop_proofs::iso_millis;
use crate::config::{CleanupConfig, CleanupMode, CloudflareConfig, Secret};
use crate::machines::provider::{ManagedEndpoints, OriginSync, ProviderError};
use crate::machines::{Origin, now_ms};

pub const API_TOKEN: &str = "cf-test-api-token-SECRET";
pub const ZONE: &str = "tunnels.example.test";
pub const STAGE: &str = "prod";

#[derive(Debug, Clone)]
pub struct Call {
    pub method: String,
    pub path: String,
    pub query: String,
    pub body: Option<String>,
    pub auth: String,
}

#[derive(Debug, Clone)]
pub struct FakeTunnel {
    pub id: String,
    pub name: String,
    pub status: String,
    pub created_at: String,
    pub conns_inactive_at: Option<String>,
    pub config: Option<Value>,
}

#[derive(Default)]
pub struct FakeState {
    pub tunnels: Vec<FakeTunnel>,
    /// `(id, name, content)`.
    pub records: Vec<(String, String, String)>,
    pub calls: Vec<Call>,
    /// The next N requests answer 429 with this `Retry-After` (seconds).
    pub rate_limit: Option<(u32, u64)>,
    /// Deleting these tunnels fails with "has active connections".
    pub in_use: Vec<String>,
    /// Each list request waits this long (holds a sweep inside its lock).
    pub list_delay: Duration,
    next: u32,
}

#[derive(Clone)]
pub struct Fake(pub Arc<Mutex<FakeState>>);

fn ok(result: Value) -> Response {
    axum::Json(json!({"success": true, "errors": [], "messages": [], "result": result}))
        .into_response()
}

fn err(status: StatusCode, message: &str) -> Response {
    (
        status,
        axum::Json(json!({"success": false, "errors": [{"code": 1000, "message": message}], "messages": [], "result": null})),
    )
        .into_response()
}

fn tunnel_json(t: &FakeTunnel) -> Value {
    json!({"id": t.id, "name": t.name, "status": t.status, "created_at": t.created_at,
           "conns_inactive_at": t.conns_inactive_at, "deleted_at": null})
}

async fn handle(
    State(f): State<Fake>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let delay = {
        let mut s = f.0.lock().unwrap();
        s.calls.push(Call {
            method: method.to_string(),
            path: uri.path().to_owned(),
            query: uri.query().unwrap_or("").to_owned(),
            body: (!body.is_empty()).then(|| String::from_utf8_lossy(&body).into_owned()),
            auth: headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_owned(),
        });
        if let Some((n, secs)) = s.rate_limit {
            s.rate_limit = (n > 1).then_some((n - 1, secs));
            return (
                StatusCode::TOO_MANY_REQUESTS,
                [("retry-after", secs.to_string())],
                axum::Json(json!({"success": false, "errors": [{"code": 10000, "message": "Rate limited"}]})),
            )
                .into_response();
        }
        s.list_delay
    };
    let q: Vec<(String, String)> = form_urlencoded::parse(uri.query().unwrap_or("").as_bytes())
        .into_owned()
        .collect();
    let qv = |k: &str| q.iter().find(|(a, _)| a == k).map(|(_, v)| v.clone());
    let body: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let segs: Vec<&str> = uri.path().trim_start_matches('/').split('/').collect();
    if method == Method::GET && segs.len() == 5 && segs[4] == "cfd_tunnel" {
        tokio::time::sleep(delay).await;
    }
    let mut s = f.0.lock().unwrap();
    match (method.as_str(), &segs[4..]) {
        ("GET", ["cfd_tunnel"]) => {
            assert_eq!(qv("is_deleted").as_deref(), Some("false"));
            let all: Vec<&FakeTunnel> = s
                .tunnels
                .iter()
                .filter(|t| qv("name").is_none_or(|n| t.name == n))
                .filter(|t| qv("include_prefix").is_none_or(|p| t.name.starts_with(&p)))
                .filter(|t| qv("status").is_none_or(|st| t.status == st))
                .collect();
            let per: usize = qv("per_page").map_or(1000, |v| v.parse().unwrap());
            let page: usize = qv("page").map_or(1, |v| v.parse().unwrap());
            let result: Vec<Value> = all
                .iter()
                .skip((page - 1) * per)
                .take(per)
                .map(|t| tunnel_json(t))
                .collect();
            axum::Json(json!({"success": true, "errors": [], "result": result,
                "result_info": {"page": page, "per_page": per, "total_count": all.len()}}))
            .into_response()
        }
        ("POST", ["cfd_tunnel"]) => {
            s.next += 1;
            let t = FakeTunnel {
                id: format!("tun-{}", s.next),
                name: body["name"].as_str().unwrap().to_owned(),
                status: "inactive".into(),
                created_at: iso_millis(now_ms()),
                conns_inactive_at: None,
                config: None,
            };
            s.tunnels.push(t.clone());
            ok(tunnel_json(&t))
        }
        ("GET", ["cfd_tunnel", id]) => match s.tunnels.iter().find(|t| t.id == *id) {
            Some(t) => ok(tunnel_json(t)),
            None => err(StatusCode::NOT_FOUND, "Tunnel not found"),
        },
        ("GET", ["cfd_tunnel", id, "token"]) => match s.tunnels.iter().find(|t| t.id == *id) {
            Some(t) => ok(json!(format!("connector-token-SECRET-{}", t.id))),
            None => err(StatusCode::NOT_FOUND, "Tunnel not found"),
        },
        ("PUT", ["cfd_tunnel", id, "configurations"]) => {
            match s.tunnels.iter_mut().find(|t| t.id == *id) {
                Some(t) => {
                    t.config = Some(body["config"].clone());
                    ok(json!({"tunnel_id": id, "version": 1}))
                }
                None => err(StatusCode::NOT_FOUND, "Tunnel not found"),
            }
        }
        ("DELETE", ["cfd_tunnel", id]) => {
            if s.in_use.iter().any(|t| t == id) {
                return err(
                    StatusCode::BAD_REQUEST,
                    "Cannot delete tunnel because it has active connections",
                );
            }
            let before = s.tunnels.len();
            s.tunnels.retain(|t| t.id != *id);
            if s.tunnels.len() == before {
                err(StatusCode::NOT_FOUND, "Tunnel not found")
            } else {
                ok(json!({"id": id}))
            }
        }
        ("GET", ["dns_records"]) => {
            let search = qv("search").unwrap_or_default();
            let r: Vec<Value> = s
                .records
                .iter()
                .filter(|(_, n, _)| n.contains(&search))
                .map(|(i, n, c)| json!({"id": i, "name": n, "type": "CNAME", "content": c}))
                .collect();
            ok(json!(r))
        }
        ("POST", ["dns_records"]) => {
            s.next += 1;
            let id = format!("dns-{}", s.next);
            let name = body["name"].as_str().unwrap().to_owned();
            let content = body["content"].as_str().unwrap().to_owned();
            s.records.push((id.clone(), name.clone(), content));
            ok(json!({"id": id, "name": name}))
        }
        ("PUT", ["dns_records", id]) => match s.records.iter_mut().find(|r| r.0 == *id) {
            Some(r) => {
                r.2 = body["content"].as_str().unwrap().to_owned();
                ok(json!({"id": id}))
            }
            None => err(StatusCode::NOT_FOUND, "Record not found"),
        },
        ("DELETE", ["dns_records", id]) => {
            let before = s.records.len();
            s.records.retain(|r| r.0 != *id);
            if s.records.len() == before {
                err(StatusCode::NOT_FOUND, "Record not found")
            } else {
                ok(json!({"id": id}))
            }
        }
        _ => err(StatusCode::NOT_FOUND, "no such route"),
    }
}

impl Fake {
    /// Serves the fake on loopback; returns it and its `CLOUDFLARE_API_BASE`.
    pub async fn start() -> (Fake, String) {
        let f = Fake(Arc::new(Mutex::new(FakeState::default())));
        let app = Router::new().fallback(handle).with_state(f.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (f, format!("http://{addr}/client/v4"))
    }

    pub fn calls(&self) -> Vec<Call> {
        self.0.lock().unwrap().calls.clone()
    }

    pub fn clear_calls(&self) {
        self.0.lock().unwrap().calls.clear();
    }

    pub fn set(&self, f: impl FnOnce(&mut FakeState)) {
        f(&mut self.0.lock().unwrap());
    }

    pub fn tunnel(&self, id: &str) -> Option<FakeTunnel> {
        self.0
            .lock()
            .unwrap()
            .tunnels
            .iter()
            .find(|t| t.id == id)
            .cloned()
    }
}

pub fn cf_config(base: &str) -> CloudflareConfig {
    CloudflareConfig {
        account_id: "acct-1".into(),
        zone_id: "zone-1".into(),
        api_token: Secret(API_TOKEN.into()),
        api_base: base.into(),
    }
}

pub fn provider(pool: &PgPool, base: &str) -> CloudflareTunnels {
    CloudflareTunnels {
        cf: Arc::new(Cloudflare::new(cf_config(base), pool.clone())),
        pool: pool.clone(),
        base_domain: Some(ZONE.into()),
        namespace: Some(STAGE.into()),
    }
}

pub fn loopback(port: i64) -> Origin {
    Origin {
        local_http_host: "127.0.0.1".into(),
        local_http_port: port,
    }
}

async fn user(pool: &PgPool, email: &str) -> Uuid {
    sqlx::query_scalar("INSERT INTO users (email) VALUES ($1) RETURNING id")
        .bind(email)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// An active managed link, as linking leaves it.
async fn link(pool: &PgPool, user: Uuid, machine_id: &str, host: &str) {
    sqlx::query(
        "INSERT INTO relay_machine_links (user_id, machine_id, machine_public_key,
             endpoint_http_base_url, endpoint_ws_base_url, endpoint_provider_kind,
             managed_tunnels_enabled, created_at, updated_at)
         VALUES ($1, $2, 'pk', $3, $4, 'cloudflare_tunnel', true, 'x', 'x')",
    )
    .bind(user)
    .bind(machine_id)
    .bind(format!("https://{host}/"))
    .bind(format!("wss://{host}/ws"))
    .execute(pool)
    .await
    .unwrap();
}

/// Provisions and links `machine_id`; returns the hostname and tunnel id.
async fn linked(p: &CloudflareTunnels, user: Uuid, machine_id: &str) -> (String, String) {
    let r = p
        .provision(user, machine_id, &loopback(3773), false)
        .await
        .unwrap();
    let host = r
        .endpoint
        .http_base_url
        .trim_start_matches("https://")
        .trim_end_matches('/')
        .to_owned();
    link(&p.pool, user, machine_id, &host).await;
    (host, r.runtime.tunnel_id.unwrap())
}

async fn allocation_row(
    pool: &PgPool,
    user: Uuid,
    m: &str,
) -> Option<(String, Option<String>, Option<String>, Option<String>)> {
    sqlx::query_as(
        "SELECT hostname, tunnel_id, dns_record_id, ready_at FROM relay_managed_endpoint_allocations
         WHERE user_id = $1 AND machine_id = $2",
    )
    .bind(user)
    .bind(m)
    .fetch_optional(pool)
    .await
    .unwrap()
}

#[sqlx::test]
async fn provisioning_sends_t3s_requests(pool: PgPool) {
    let (fake, base) = Fake::start().await;
    let p = provider(&pool, &base);
    let u = user(&pool, "a@example.test").await;
    let r = p.provision(u, "m1", &loopback(3773), false).await.unwrap();
    let hash = crate::zone::machine_hash(STAGE, &crate::machines::wire_user_id(u), "m1");
    let host = format!("prod-{}.{ZONE}", &hash[..16]);
    let name = format!("vekrelrelay-managedendpoint-prod-{}", &hash[..16]);
    assert_eq!(r.endpoint.http_base_url, format!("https://{host}/"));
    assert_eq!(r.endpoint.ws_base_url, format!("wss://{host}/ws"));
    assert_eq!(
        serde_json::to_string(&r.runtime).unwrap(),
        format!(
            r#"{{"providerKind":"cloudflare_tunnel","connectorToken":"connector-token-SECRET-tun-1","tunnelId":"tun-1","tunnelName":"{name}"}}"#
        )
    );
    let calls: Vec<(String, String, String, Option<String>)> = fake
        .calls()
        .into_iter()
        .map(|c| (c.method, c.path, c.query, c.body))
        .collect();
    let t = "/client/v4/accounts/acct-1/cfd_tunnel";
    let d = "/client/v4/zones/zone-1/dns_records";
    assert_eq!(
        calls,
        vec![
            (
                "GET".into(),
                t.into(),
                format!("is_deleted=false&name={name}"),
                None
            ),
            (
                "POST".into(),
                t.into(),
                "".into(),
                Some(format!(r#"{{"name":"{name}","config_src":"cloudflare"}}"#))
            ),
            (
                "PUT".into(),
                format!("{t}/tun-1/configurations"),
                "".into(),
                Some(format!(
                    r#"{{"config":{{"ingress":[{{"hostname":"{host}","service":"http://127.0.0.1:3773"}},{{"service":"http_status:404"}}]}}}}"#
                ))
            ),
            ("GET".into(), d.into(), format!("search={host}"), None),
            (
                "POST".into(),
                d.into(),
                "".into(),
                Some(format!(
                    r#"{{"type":"CNAME","name":"{host}","content":"tun-1.cfargotunnel.com","ttl":1,"proxied":true}}"#
                ))
            ),
            ("GET".into(), format!("{t}/tun-1/token"), "".into(), None),
        ]
    );
    assert!(
        fake.calls()
            .iter()
            .all(|c| c.auth == format!("Bearer {API_TOKEN}"))
    );
    let (h, tunnel, dns, ready) = allocation_row(&pool, u, "m1").await.unwrap();
    assert_eq!(
        (h.as_str(), tunnel.as_deref(), dns.as_deref()),
        (host.as_str(), Some("tun-1"), Some("dns-2"))
    );
    assert!(ready.is_some());
    // IPv6 loopback is bracketed in the ingress service (T3 `formatOriginService`).
    let v6 = Origin {
        local_http_host: "::1".into(),
        local_http_port: 3773,
    };
    assert_eq!(super::provider::origin_service(&v6), "http://[::1]:3773");
}

#[sqlx::test]
async fn refusals_happen_before_any_cloudflare_call(pool: PgPool) {
    let (fake, base) = Fake::start().await;
    let p = provider(&pool, &base);
    let u = user(&pool, "a@example.test").await;
    for m in ["m1", "m2", "m3"] {
        linked(&p, u, m).await;
    }
    fake.clear_calls();
    assert!(matches!(
        p.provision(u, "m4", &loopback(3773), false).await,
        Err(ProviderError::LimitExceeded { max_tunnels: 3 })
    ));
    let lan = Origin {
        local_http_host: "192.168.1.5".into(),
        local_http_port: 3773,
    };
    assert!(matches!(
        p.provision(u, "m5", &lan, false).await,
        Err(ProviderError::OriginNotAllowed)
    ));
    assert!(fake.calls().is_empty());
    assert!(allocation_row(&pool, u, "m4").await.is_none());
    // Relinking a machine that already has a tunnel stays possible at the limit.
    p.provision(u, "m1", &loopback(3773), false).await.unwrap();
    // Without zone or stage the provider answers as unconfigured.
    let mut unconfigured = provider(&pool, &base);
    unconfigured.namespace = None;
    assert!(matches!(
        unconfigured
            .provision(u, "m1", &loopback(3773), false)
            .await,
        Err(ProviderError::NotConfigured)
    ));
}

#[sqlx::test]
async fn a_429_pauses_every_replica_and_sets_retry_after(pool: PgPool) {
    let (fake, base) = Fake::start().await;
    let p = provider(&pool, &base);
    let u = user(&pool, "a@example.test").await;
    fake.set(|s| s.rate_limit = Some((1, 7)));
    let before = now_ms();
    match p.provision(u, "m1", &loopback(3773), false).await {
        Err(ProviderError::Failed {
            stage: "ensure-tunnel",
            retry_after_ms: Some(7_000),
        }) => {}
        other => panic!("{other:?}"),
    }
    let until = api_pause::paused_until_ms(&pool).await;
    assert!(
        until >= before + 7_000 && until <= now_ms() + 7_000,
        "{until}"
    );
    let sent = fake.calls().len();
    // Later calls wait the pause out: refused without a request, here and on another replica.
    for replica in [&p, &provider(&pool, &base)] {
        match replica.provision(u, "m1", &loopback(3773), false).await {
            Err(ProviderError::Failed {
                stage: "ensure-tunnel",
                retry_after_ms: Some(ms),
            }) => assert!(ms > 0 && ms <= 7_000, "{ms}"),
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(fake.calls().len(), sent);
    // Once the pause is over, provisioning goes through.
    sqlx::query("UPDATE relay_upstream_api_pauses SET paused_until_ms = 0")
        .execute(&pool)
        .await
        .unwrap();
    let fresh = provider(&pool, &base);
    fresh
        .provision(u, "m1", &loopback(3773), false)
        .await
        .unwrap();
}

#[sqlx::test]
async fn recovery_reuses_or_replaces_under_the_same_hostname(pool: PgPool) {
    let (fake, base) = Fake::start().await;
    let p = provider(&pool, &base);
    let u = user(&pool, "a@example.test").await;
    let (host, tun) = linked(&p, u, "m1").await;
    // A ready tunnel for the same origin: two reads, nothing written.
    fake.clear_calls();
    let r = p.provision(u, "m1", &loopback(3773), true).await.unwrap();
    assert_eq!(r.runtime.tunnel_id.as_deref(), Some(tun.as_str()));
    let ops: Vec<_> = fake
        .calls()
        .iter()
        .map(|c| (c.method.clone(), c.path.clone()))
        .collect();
    assert_eq!(ops.len(), 2, "{ops:?}");
    assert!(ops.iter().all(|(m, _)| m == "GET"));
    // The tunnel is gone at Cloudflare: a replacement, same hostname, the DNS record updated.
    fake.set(|s| s.tunnels.clear());
    let r = p.provision(u, "m1", &loopback(3773), true).await.unwrap();
    let new_tun = r.runtime.tunnel_id.unwrap();
    assert_ne!(new_tun, tun);
    assert_eq!(r.endpoint.http_base_url, format!("https://{host}/"));
    let records = fake.0.lock().unwrap().records.clone();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].1, host);
    assert_eq!(records[0].2, format!("{new_tun}.cfargotunnel.com"));
    let (h, t, _, _) = allocation_row(&pool, u, "m1").await.unwrap();
    assert_eq!((h, t), (host, Some(new_tun)));
}

#[sqlx::test]
async fn a_new_port_updates_ingress_once(pool: PgPool) {
    let (fake, base) = Fake::start().await;
    let p = provider(&pool, &base);
    let u = user(&pool, "a@example.test").await;
    let (host, tun) = linked(&p, u, "m1").await;
    let endpoint = crate::machines::connector::endpoint_for_hostname(&host);
    fake.clear_calls();
    let sync = p
        .reconcile_origin(u, "m1", &tun, &loopback(4000), &endpoint)
        .await
        .unwrap();
    assert_eq!(sync, OriginSync::Ready);
    let again = p
        .reconcile_origin(u, "m1", &tun, &loopback(4000), &endpoint)
        .await
        .unwrap();
    assert_eq!(again, OriginSync::Ready);
    let puts = fake.calls().iter().filter(|c| c.method == "PUT").count();
    assert_eq!(puts, 1);
    assert_eq!(
        fake.tunnel(&tun).unwrap().config.unwrap()["ingress"][0]["service"],
        "http://127.0.0.1:4000"
    );
    // A deleted tunnel asks the machine for recovery.
    fake.set(|s| s.tunnels.clear());
    assert_eq!(
        p.reconcile_origin(u, "m1", &tun, &loopback(4000), &endpoint)
            .await
            .unwrap(),
        OriginSync::RecoveryRequired
    );
}

#[sqlx::test]
async fn release_keeps_the_hostname_and_frees_the_connector(pool: PgPool) {
    let (fake, base) = Fake::start().await;
    let p = provider(&pool, &base);
    let u = user(&pool, "a@example.test").await;
    let (host, tun) = linked(&p, u, "m1").await;
    assert!(p.release(u, "m1", None).await.unwrap());
    assert!(fake.tunnel(&tun).is_none(), "tunnel deleted");
    assert_eq!(fake.0.lock().unwrap().records.len(), 1, "DNS record kept");
    let (h, t, dns, _) = allocation_row(&pool, u, "m1").await.unwrap();
    assert_eq!(h, host);
    assert_eq!(t.as_deref(), Some(tun.as_str()));
    assert!(dns.is_some());
    // The next start gets a new tunnel under the same hostname.
    let r = p.provision(u, "m1", &loopback(3773), true).await.unwrap();
    assert_eq!(r.endpoint.http_base_url, format!("https://{host}/"));
    // A stale tunnel id releases nothing.
    assert!(!p.release(u, "m1", Some(&tun)).await.unwrap());
    // A connector still attached keeps the tunnel and reports it as not released.
    let live = r.runtime.tunnel_id.unwrap();
    fake.set(|s| s.in_use.push(live.clone()));
    assert!(!p.release(u, "m1", None).await.unwrap());
    assert!(fake.tunnel(&live).is_some());
}

#[sqlx::test]
async fn unlink_deletes_tunnel_and_dns_record(pool: PgPool) {
    let (fake, base) = Fake::start().await;
    let p = provider(&pool, &base);
    let u = user(&pool, "a@example.test").await;
    let (_, tun) = linked(&p, u, "m1").await;
    let target = p.prepare_deprovision(u, "m1").await.unwrap();
    assert!(p.deprovision(u, "m1", Some(target)).await.unwrap());
    assert!(fake.tunnel(&tun).is_none());
    assert!(fake.0.lock().unwrap().records.is_empty());
    assert!(allocation_row(&pool, u, "m1").await.is_none());
    // Already gone remotely still counts as deprovisioned.
    let (_, _) = linked(&p, u, "m2").await;
    fake.set(|s| {
        s.tunnels.clear();
        s.records.clear();
    });
    assert!(p.deprovision(u, "m2", None).await.unwrap());
    assert!(allocation_row(&pool, u, "m2").await.is_none());
    // A snapshot a relink superseded is left alone.
    let (_, _) = linked(&p, u, "m3").await;
    let stale = p.prepare_deprovision(u, "m3").await.unwrap();
    p.provision(u, "m3", &loopback(3773), false).await.unwrap();
    assert!(!p.deprovision(u, "m3", Some(stale)).await.unwrap());
    assert!(allocation_row(&pool, u, "m3").await.is_some());
}

async fn enable_recovery(pool: &PgPool, user: Uuid, m: &str) {
    sqlx::query(
        "UPDATE relay_managed_endpoint_allocations
         SET recovery_enabled_at = 'x', recovery_machine_public_key = 'pk'
         WHERE user_id = $1 AND machine_id = $2",
    )
    .bind(user)
    .bind(m)
    .execute(pool)
    .await
    .unwrap();
}

fn age(fake: &Fake, tunnel: &str, status: &str, minutes_ago: i64) {
    let at = iso_millis(now_ms() - minutes_ago * 60_000);
    fake.set(|s| {
        let t = s.tunnels.iter_mut().find(|t| t.id == tunnel).unwrap();
        t.status = status.into();
        t.created_at = at.clone();
        t.conns_inactive_at = (status == "down").then_some(at);
    });
}

fn cleanup(mode: CleanupMode) -> CleanupConfig {
    CleanupConfig {
        mode,
        ..Default::default()
    }
}

/// Five tunnels: idle down (recoverable), idle never connected (recoverable), recently down,
/// idle but its machine never registered recovery (legacy), and an orphan with no allocation.
async fn reaper_fixture(
    pool: &PgPool,
    base: &str,
    fake: &Fake,
) -> (CloudflareTunnels, Vec<String>) {
    let p = provider(pool, base);
    let u = user(pool, "a@example.test").await;
    sqlx::query("INSERT INTO relay_managed_tunnel_limits (user_id, max_tunnels, created_at, updated_at) VALUES ($1, 10, 'x', 'x')")
        .bind(u)
        .execute(pool)
        .await
        .unwrap();
    let mut ids = Vec::new();
    for m in ["down", "inactive", "recent", "legacy"] {
        ids.push(linked(&p, u, m).await.1);
        if m != "legacy" {
            enable_recovery(pool, u, m).await;
        }
    }
    age(fake, &ids[0], "down", 10);
    age(fake, &ids[1], "inactive", 120);
    age(fake, &ids[2], "down", 1);
    age(fake, &ids[3], "down", 10);
    let orphan = format!("{}0123456789abcdef", crate::zone::tunnel_name_prefix(STAGE));
    fake.set(|s| {
        s.tunnels.push(FakeTunnel {
            id: "tun-orphan".into(),
            name: orphan,
            status: "down".into(),
            created_at: iso_millis(now_ms() - 3_600_000),
            conns_inactive_at: Some(iso_millis(now_ms() - 3_600_000)),
            config: None,
        })
    });
    ids.push("tun-orphan".into());
    (p, ids)
}

#[sqlx::test]
async fn the_reaper_only_logs_in_dry_run_and_removes_only_idle_owned_tunnels(pool: PgPool) {
    let (fake, base) = Fake::start().await;
    let (p, ids) = reaper_fixture(&pool, &base, &fake).await;
    let off = reaper::sweep(&p, cleanup(CleanupMode::Off)).await.unwrap();
    assert_eq!(off.list_requests, 0);

    fake.clear_calls();
    let logs = crate::test_logs::capture_logs(|| {});
    let r = reaper::sweep(&p, cleanup(CleanupMode::DryRun))
        .await
        .unwrap();
    let after = crate::test_logs::capture_logs(|| {});
    assert_eq!((r.would_delete, r.deleted, r.attempted), (2, 0, 0));
    assert_eq!((r.skipped_orphan, r.skipped_legacy), (1, 1));
    assert!(
        fake.calls().iter().all(|c| c.method == "GET"),
        "dry run changes nothing"
    );
    assert!(ids.iter().all(|id| fake.tunnel(id).is_some()));
    assert!(after[logs.len()..].contains("dry run: would delete an inactive managed tunnel"));

    let r = reaper::sweep(&p, cleanup(CleanupMode::Enabled))
        .await
        .unwrap();
    assert_eq!(
        (r.would_delete, r.attempted, r.deleted, r.failed),
        (2, 2, 2, 0)
    );
    assert!(fake.tunnel(&ids[0]).is_none());
    assert!(fake.tunnel(&ids[1]).is_none());
    for kept in &ids[2..] {
        assert!(fake.tunnel(kept).is_some(), "{kept} kept");
    }
    // The allocations and DNS records stay: the machines recover under the same hostnames.
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM relay_managed_endpoint_allocations")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows, 4);
    assert_eq!(fake.0.lock().unwrap().records.len(), 4);
    // Legacy cleanup takes the legacy tunnel only after its own grace.
    let legacy = CleanupConfig {
        mode: CleanupMode::Off,
        legacy_mode: CleanupMode::Enabled,
        legacy_grace_minutes: None,
    };
    assert_eq!(reaper::sweep(&p, legacy).await.unwrap().deleted, 0);
    // Another stage sees none of these tunnels.
    let mut dev = provider(&pool, &base);
    dev.namespace = Some("dev".into());
    assert_eq!(reaper::sweep(&dev, legacy).await.unwrap().scanned, 0);
    age(&fake, &ids[3], "down", 8 * 24 * 60);
    let r = reaper::sweep(&p, legacy).await.unwrap();
    assert_eq!((r.deleted, r.deleted_legacy), (1, 1));
    assert!(fake.tunnel(&ids[3]).is_none());
}

#[sqlx::test]
async fn a_tunnel_that_reconnects_before_deletion_is_kept(pool: PgPool) {
    let (fake, base) = Fake::start().await;
    let p = provider(&pool, &base);
    let u = user(&pool, "a@example.test").await;
    let (_, tun) = linked(&p, u, "m1").await;
    age(&fake, &tun, "healthy", 10);
    let x = ExpectInactive {
        before_ms: now_ms(),
        status: "down",
    };
    assert!(
        !p.release_with(u, "m1", Some(&tun), Some(x), false)
            .await
            .unwrap()
    );
    assert!(fake.tunnel(&tun).is_some());
}

#[sqlx::test]
async fn two_reapers_in_parallel_act_once(pool: PgPool) {
    let (fake, base) = Fake::start().await;
    let (p, ids) = reaper_fixture(&pool, &base, &fake).await;
    let p2 = provider(&pool, &base);
    fake.set(|s| s.list_delay = Duration::from_millis(300));
    fake.clear_calls();
    let enabled = cleanup(CleanupMode::Enabled);
    let (a, b) = tokio::join!(
        crate::cron::run_once(&pool, Some(&p), enabled),
        crate::cron::run_once(&pool, Some(&p2), enabled)
    );
    let (a, b) = (a.unwrap(), b.unwrap());
    assert!(a ^ b, "exactly one replica runs the pass ({a}, {b})");
    let deletes: Vec<String> = fake
        .calls()
        .into_iter()
        .filter(|c| c.method == "DELETE")
        .map(|c| c.path)
        .collect();
    assert_eq!(deletes.len(), 2, "{deletes:?}");
    assert!(fake.tunnel(&ids[0]).is_none() && fake.tunnel(&ids[1]).is_none());
    // Without the lock (two sweeps at once), the generation claims still delete each tunnel once.
    let (_, ids) = {
        sqlx::query("DELETE FROM relay_managed_endpoint_allocations")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM relay_machine_links")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM relay_managed_tunnel_limits")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users")
            .execute(&pool)
            .await
            .unwrap();
        fake.set(|s| s.tunnels.clear());
        reaper_fixture(&pool, &base, &fake).await
    };
    fake.set(|s| s.list_delay = Duration::ZERO);
    fake.clear_calls();
    let (a, b) = tokio::join!(reaper::sweep(&p, enabled), reaper::sweep(&p2, enabled));
    // A replica that claims after the other deleted finds the tunnel gone and counts it too, but
    // each tunnel gets exactly one DELETE.
    assert!(a.unwrap().deleted + b.unwrap().deleted >= 2);
    let deletes = fake.calls().iter().filter(|c| c.method == "DELETE").count();
    assert_eq!(deletes, 2);
    assert!(fake.tunnel(&ids[0]).is_none() && fake.tunnel(&ids[1]).is_none());
}

#[sqlx::test]
async fn secrets_never_reach_the_logs(pool: PgPool) {
    let (fake, base) = Fake::start().await;
    let p = provider(&pool, &base);
    let u = user(&pool, "a@example.test").await;
    crate::test_logs::capture_logs(|| {});
    let (_, tun) = linked(&p, u, "m1").await;
    fake.set(|s| s.rate_limit = Some((1, 3)));
    let _ = p.release(u, "m1", None).await;
    let logs = crate::test_logs::capture_logs(|| {});
    assert!(logs.contains("cloudflare rate limited"));
    for secret in [API_TOKEN, &format!("connector-token-SECRET-{tun}")] {
        assert!(!logs.contains(secret), "a secret reached the logs");
    }
}

#[sqlx::test]
async fn admin_tunnel_test_creates_and_removes_one_tunnel(pool: PgPool) {
    let (fake, base) = Fake::start().await;
    let config = crate::config::Config::for_tests(&[
        ("CLOUDFLARE_ACCOUNT_ID", "acct-1"),
        ("CLOUDFLARE_TUNNEL_ZONE_ID", "zone-1"),
        ("CLOUDFLARE_API_TOKEN", API_TOKEN),
        ("CLOUDFLARE_API_BASE", &base),
        ("RELAY_TUNNEL_ZONE_NAME", ZONE),
    ]);
    let out = crate::admin::tunnel_test(&pool, &config).await.unwrap();
    assert!(
        out.contains("appears") && out.contains("disappears") && out.contains("tunnel deleted"),
        "{out}"
    );
    assert!(!out.contains("connector-token-SECRET") && !out.contains(API_TOKEN));
    {
        let s = fake.0.lock().unwrap();
        assert!(s.tunnels.is_empty() && s.records.is_empty());
        assert!(
            s.calls
                .iter()
                .any(|c| c.method == "POST" && c.path.ends_with("/dns_records"))
        );
    }
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM relay_managed_endpoint_allocations")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows, 0);
}
