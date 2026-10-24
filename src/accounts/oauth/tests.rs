// End-to-end OAuth tests, driven by a test-only identity provider (`GET /auth/test`).
use super::*;
use axum::body::Body;
use axum::http::Request;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use std::collections::HashMap;
use tower::ServiceExt;

use crate::accounts::keys::tests::entry;

mod device;

const ISS: &str = "https://relay.example.test";
const WEB_ORIGIN: &str = "https://app.example.test";
const CLI: &str = "vekrel-cli";
const CLI_REDIRECT: &str = "http://127.0.0.1:34338/callback";

#[derive(Deserialize)]
pub struct FakeParams {
    sub: String,
    email: String,
}

/// The test identity provider: whatever identity the query names, for the calling browser.
pub async fn fake_provider(
    State(s): State<Arc<AccountsState>>,
    headers: HeaderMap,
    Query(p): Query<FakeParams>,
) -> Response {
    let id = VerifiedIdentity {
        provider: "test",
        subject: p.sub,
        email: p.email,
    };
    complete_sign_in(&s, &headers, id).await
}

struct App {
    router: Router,
    state: Arc<AccountsState>,
}

fn app_with(pool: PgPool, mode: &str) -> App {
    let keys = SigningKeys::from_json(&json!([entry("k1", "active").0]).to_string()).unwrap();
    let config = Config::for_tests(&[
        ("RELAY_ORIGIN", ISS),
        ("SIGNUP_MODE", mode),
        ("WEB_ORIGINS", WEB_ORIGIN),
    ]);
    let state = AccountsState::new(pool, Arc::new(keys), &config);
    App {
        router: router(state.clone()),
        state,
    }
}

fn app(pool: PgPool) -> App {
    app_with(pool, "open")
}

struct Res {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

impl Res {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap()
    }
    /// Query of the `Location` redirect, which must start with `base?`.
    fn redirect_query(&self, base: &str) -> HashMap<String, String> {
        let loc = self.headers[header::LOCATION].to_str().unwrap();
        let q = loc
            .strip_prefix(base)
            .and_then(|r| r.strip_prefix('?'))
            .unwrap_or_else(|| panic!("redirect {loc} not to {base}"));
        form_urlencoded::parse(q.as_bytes()).into_owned().collect()
    }
    fn set_cookies(&self) -> Vec<String> {
        self.headers
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().to_owned())
            .collect()
    }
    fn cookie(&self, name: &str) -> String {
        self.set_cookies()
            .iter()
            .find_map(|c| c.strip_prefix(&format!("{name}="))?.split(';').next())
            .unwrap_or_else(|| panic!("no {name} cookie"))
            .to_owned()
    }
}

/// The socket peer `serve` would attach; a test that layers its own `ConnectInfo` wins.
const TEST_PEER: std::net::SocketAddr = std::net::SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1)),
    4000,
);

impl App {
    async fn send(&self, mut req: Request<Body>) -> Res {
        req.extensions_mut()
            .insert(axum::extract::ConnectInfo(TEST_PEER));
        let res = self.router.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let headers = res.headers().clone();
        let body = res.into_body().collect().await.unwrap().to_bytes();
        Res {
            status,
            headers,
            body: String::from_utf8(body.to_vec()).unwrap(),
        }
    }

    async fn get(&self, uri: &str, cookie: Option<&str>) -> Res {
        let mut r = Request::get(uri);
        if let Some(c) = cookie {
            r = r.header(header::COOKIE, c);
        }
        self.send(r.body(Body::empty()).unwrap()).await
    }

    async fn post(&self, path: &str, form: &[(&str, &str)], extra: &[(&str, &str)]) -> Res {
        let body = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(form)
            .finish();
        let mut r =
            Request::post(path).header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        for (k, v) in extra {
            r = r.header(*k, *v);
        }
        self.send(r.body(Body::from(body)).unwrap()).await
    }

    async fn authorize(&self, client: &str, redirect: &str, challenge: &str) -> Res {
        let q = form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("response_type", "code"),
                ("client_id", client),
                ("redirect_uri", redirect),
                ("code_challenge", challenge),
                ("code_challenge_method", "S256"),
                ("state", "st-1"),
                ("scope", "openid profile email offline_access"),
            ])
            .finish();
        self.get(&format!("/oauth/authorize?{q}"), None).await
    }

    /// Authorize, then sign in through the fake provider; returns the redirect.
    async fn sign_in(&self, client: &str, redirect: &str, challenge: &str, email: &str) -> Res {
        let page = self.authorize(client, redirect, challenge).await;
        assert_eq!(page.status, StatusCode::OK, "{}", page.body);
        let cookie = format!("vekrel_auth_request={}", page.cookie("vekrel_auth_request"));
        self.get(
            &format!("/auth/test?sub=sub-{email}&email={email}"),
            Some(&cookie),
        )
        .await
    }

    /// Code for the CLI client.
    async fn code(&self, challenge: &str, email: &str) -> String {
        let res = self.sign_in(CLI, CLI_REDIRECT, challenge, email).await;
        let q = res.redirect_query(CLI_REDIRECT);
        assert_eq!(q["state"], "st-1");
        q["code"].clone()
    }

    async fn exchange(&self, code: &str, verifier: &str) -> Res {
        self.post(
            "/oauth/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", CLI_REDIRECT),
                ("client_id", CLI),
                ("code_verifier", verifier),
            ],
            &[],
        )
        .await
    }

    async fn refresh(&self, refresh_token: &str) -> Res {
        self.post(
            "/oauth/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
                ("client_id", CLI),
            ],
            &[],
        )
        .await
    }

    /// Full CLI sign-in; returns the token response.
    async fn login(&self, email: &str) -> Value {
        let (v, c) = pkce();
        let code = self.code(&c, email).await;
        let res = self.exchange(&code, &v).await;
        assert_eq!(res.status, StatusCode::OK, "{}", res.body);
        res.json()
    }

    /// Status of a request through the `AccountUser` extractor.
    async fn whoami(&self, access_token: &str) -> StatusCode {
        let r = Router::new()
            .route(
                "/whoami",
                get(|u: AccountUser| async move {
                    format!("{} {} {}", u.user_id, u.email, u.client_id)
                }),
            )
            .with_state(self.state.clone());
        r.oneshot(
            Request::get("/whoami")
                .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
    }
}

fn pkce() -> (String, String) {
    let verifier = random_secret();
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

async fn count(pool: &PgPool, table: &str) -> i64 {
    sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT count(*) FROM {table}")))
        .fetch_one(pool)
        .await
        .unwrap()
}

fn payload(jwt: &str) -> Value {
    serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(jwt.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap()
}

#[sqlx::test]
async fn code_flow_issues_cli_token_file_shape(pool: PgPool) {
    let a = app(pool);
    let t = a.login("a@example.test").await;
    let keys: Vec<&str> = t.as_object().unwrap().keys().map(|k| k.as_str()).collect();
    assert_eq!(
        keys,
        [
            "access_token",
            "token_type",
            "expires_in",
            "refresh_token",
            "id_token"
        ]
    );
    assert_eq!(t["token_type"], "Bearer");
    assert_eq!(t["expires_in"], 600);
    let claims = tokens::verify_access_token(
        &a.state.public_keys,
        ISS,
        t["access_token"].as_str().unwrap(),
    )
    .unwrap();
    assert_eq!(claims.email, "a@example.test");
    assert_eq!(claims.client_id, CLI);
    let id = payload(t["id_token"].as_str().unwrap());
    assert_eq!(id["sub"], claims.sub);
    assert_eq!(id["email"], "a@example.test");
    assert_eq!(id["aud"], CLI);
    assert_eq!(
        a.whoami(t["access_token"].as_str().unwrap()).await,
        StatusCode::OK
    );
    // Only hashes are stored.
    let stored: String = sqlx::query_scalar("SELECT hash FROM refresh_tokens")
        .fetch_one(&a.state.pool)
        .await
        .unwrap();
    assert_eq!(stored, hash(t["refresh_token"].as_str().unwrap()));
}

#[sqlx::test]
async fn s256_is_required(pool: PgPool) {
    let a = app(pool);
    let (_, c) = pkce();
    for method in [Some("plain"), Some("s256"), None] {
        let mut pairs = vec![
            ("response_type", "code"),
            ("client_id", CLI),
            ("redirect_uri", CLI_REDIRECT),
            ("code_challenge", c.as_str()),
            ("state", "st-1"),
        ];
        if let Some(m) = method {
            pairs.push(("code_challenge_method", m));
        }
        let q = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(pairs)
            .finish();
        let res = a.get(&format!("/oauth/authorize?{q}"), None).await;
        assert_eq!(res.status, StatusCode::SEE_OTHER, "{method:?}");
        let q = res.redirect_query(CLI_REDIRECT);
        assert_eq!(q["error"], "invalid_request");
        assert_eq!(q["state"], "st-1");
        assert!(res.headers.get(header::SET_COOKIE).is_none());
    }
    // A challenge that is not a SHA-256 (e.g. a `plain` verifier) is refused too.
    let res = a.authorize(CLI, CLI_REDIRECT, &format!("{c}{c}")).await;
    assert_eq!(res.redirect_query(CLI_REDIRECT)["error"], "invalid_request");
    assert_eq!(count(&a.state.pool, "auth_requests").await, 0);
}

#[sqlx::test]
async fn unlisted_or_prefix_redirect_is_refused_before_any_redirect(pool: PgPool) {
    let a = app(pool);
    let (_, c) = pkce();
    for (client, redirect) in [
        (CLI, "http://127.0.0.1:34338/callback/evil"),
        (CLI, "http://127.0.0.1:34338/callbac"),
        (CLI, "http://127.0.0.1:34338/callback?x=1"),
        (CLI, "https://evil.test/callback"),
        (
            "vekrel-web",
            "https://app.example.test/auth/callback.evil.test",
        ),
        (
            "vekrel-web",
            "https://app.example.test.evil.test/auth/callback",
        ),
        ("vekrel-unknown", CLI_REDIRECT),
    ] {
        let res = a.authorize(client, redirect, &c).await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST, "{client} {redirect}");
        assert!(res.headers.get(header::LOCATION).is_none());
        assert!(res.body.contains("not registered"), "{}", res.body);
    }
    assert_eq!(count(&a.state.pool, "auth_requests").await, 0);
}

#[sqlx::test]
async fn sign_in_page_is_branded_and_hardened(pool: PgPool) {
    let a = app(pool);
    let (_, c) = pkce();
    let res = a.authorize(CLI, CLI_REDIRECT, &c).await;
    assert_eq!(res.status, StatusCode::OK);
    // Provider buttons: sign_in_page_shows_configured_providers_only.
    for text in ["action=\"/auth/email\"", "#FF6A2B"] {
        assert!(res.body.contains(text), "{text}");
    }
    assert_eq!(res.headers[header::X_FRAME_OPTIONS], "DENY");
    assert!(
        res.headers[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .contains("frame-ancestors 'none'")
    );
    let cookie = &res.set_cookies()[0];
    assert!(
        cookie.ends_with("; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=1800"),
        "{cookie}"
    );
}

#[sqlx::test]
async fn wrong_verifier_fails_and_kills_the_code(pool: PgPool) {
    let a = app(pool);
    let (v, c) = pkce();
    let code = a.code(&c, "a@example.test").await;
    let (other, _) = pkce();
    let res = a.exchange(&code, &other).await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    assert_eq!(res.json()["error"], "invalid_grant");
    assert_eq!(a.exchange(&code, &v).await.json()["error"], "invalid_grant");
    // The verifier itself in place of its challenge (a `plain` downgrade) fails too.
    let (v, _) = pkce();
    let code = a.code(&v, "a@example.test").await;
    assert_eq!(a.exchange(&code, &v).await.json()["error"], "invalid_grant");
}

#[sqlx::test]
async fn code_is_single_use_and_replay_revokes_its_tokens(pool: PgPool) {
    let a = app(pool);
    let (v, c) = pkce();
    let code = a.code(&c, "a@example.test").await;
    let first = a.exchange(&code, &v).await.json();
    let replay = a.exchange(&code, &v).await;
    assert_eq!(replay.status, StatusCode::BAD_REQUEST);
    assert_eq!(replay.json()["error"], "invalid_grant");
    let refresh = a.refresh(first["refresh_token"].as_str().unwrap()).await;
    assert_eq!(refresh.json()["error"], "invalid_grant");
    assert_eq!(
        a.whoami(first["access_token"].as_str().unwrap()).await,
        StatusCode::UNAUTHORIZED
    );
}

#[sqlx::test]
async fn code_lives_60_seconds(pool: PgPool) {
    let a = app(pool);
    let (v, c) = pkce();
    let code = a.code(&c, "a@example.test").await;
    let ttl: f64 = sqlx::query_scalar(
        "SELECT extract(epoch FROM expires_at - created_at)::float8 FROM auth_codes",
    )
    .fetch_one(&a.state.pool)
    .await
    .unwrap();
    assert_eq!(ttl, 60.0);
    sqlx::query("UPDATE auth_codes SET expires_at = now() - interval '1 second'")
        .execute(&a.state.pool)
        .await
        .unwrap();
    assert_eq!(a.exchange(&code, &v).await.json()["error"], "invalid_grant");
}

#[sqlx::test]
async fn code_is_bound_to_client_and_redirect_uri(pool: PgPool) {
    let a = app(pool);
    let app_redirect = "vekrel://auth/callback";
    let redeem = |code: String, v: String, client: &'static str, redirect: &'static str| {
        let a = &a;
        async move {
            a.post(
                "/oauth/token",
                &[
                    ("grant_type", "authorization_code"),
                    ("code", &code),
                    ("redirect_uri", redirect),
                    ("client_id", client),
                    ("code_verifier", &v),
                ],
                &[],
            )
            .await
            .json()
        }
    };
    let (v, c) = pkce();
    let code = a.code(&c, "a@example.test").await;
    let res = redeem(code, v, "vekrel-mobile", app_redirect).await;
    assert_eq!(res["error"], "invalid_grant");
    // Desktop and mobile share redirect URIs: the client id alone must not match.
    let (v, c) = pkce();
    let res = a
        .sign_in("vekrel-mobile", app_redirect, &c, "a@example.test")
        .await;
    let code = res.redirect_query(app_redirect)["code"].clone();
    let res = redeem(code, v, "vekrel-desktop", app_redirect).await;
    assert_eq!(res["error"], "invalid_grant");
    // Same client, its other registered redirect URI.
    let (v, c) = pkce();
    let res = a
        .sign_in("vekrel-mobile", app_redirect, &c, "a@example.test")
        .await;
    let code = res.redirect_query(app_redirect)["code"].clone();
    let res = redeem(code, v, "vekrel-mobile", "vekrel-dev://auth/callback").await;
    assert_eq!(res["error"], "invalid_grant");
}

#[sqlx::test]
async fn refresh_rotates_and_reuse_revokes_the_family(pool: PgPool) {
    let a = app(pool);
    let t0 = a.login("a@example.test").await;
    let r0 = t0["refresh_token"].as_str().unwrap();
    let t1 = a.refresh(r0).await;
    assert_eq!(t1.status, StatusCode::OK, "{}", t1.body);
    let t1 = t1.json();
    let r1 = t1["refresh_token"].as_str().unwrap();
    assert_ne!(r0, r1);
    let c0 = payload(t0["access_token"].as_str().unwrap());
    let c1 = payload(t1["access_token"].as_str().unwrap());
    assert_eq!(c0["sid"], c1["sid"], "same family");
    let t2 = a.refresh(r1).await.json();
    let r2 = t2["refresh_token"].as_str().unwrap();
    // A second sign-in is its own family and survives the reuse below.
    let other = a.login("a@example.test").await;

    let reuse = a.refresh(r0).await;
    assert_eq!(reuse.status, StatusCode::BAD_REQUEST);
    assert_eq!(reuse.json()["error"], "invalid_grant");
    assert_eq!(a.refresh(r2).await.json()["error"], "invalid_grant");
    assert_eq!(
        a.whoami(t2["access_token"].as_str().unwrap()).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        a.refresh(other["refresh_token"].as_str().unwrap())
            .await
            .status,
        StatusCode::OK
    );
}

#[sqlx::test]
async fn refresh_is_bound_to_its_client(pool: PgPool) {
    let a = app(pool);
    let t = a.login("a@example.test").await;
    let res = a
        .post(
            "/oauth/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", t["refresh_token"].as_str().unwrap()),
                ("client_id", "vekrel-mobile"),
            ],
            &[],
        )
        .await;
    assert_eq!(res.json()["error"], "invalid_grant");
}

#[sqlx::test]
async fn revoke_ends_the_family(pool: PgPool) {
    let a = app(pool);
    let t = a.login("a@example.test").await;
    let r0 = t["refresh_token"].as_str().unwrap();
    let r1 = a.refresh(r0).await.json()["refresh_token"]
        .as_str()
        .unwrap()
        .to_owned();
    // Revoking an older token of the family ends the newest one too.
    let res = a.post("/oauth/revoke", &[("token", r0)], &[]).await;
    assert_eq!(res.status, StatusCode::OK);
    assert_eq!(a.refresh(&r1).await.json()["error"], "invalid_grant");
    assert_eq!(
        a.whoami(t["access_token"].as_str().unwrap()).await,
        StatusCode::UNAUTHORIZED
    );
    // Unknown tokens: 200 as RFC 7009 says.
    let res = a.post("/oauth/revoke", &[("token", "nope")], &[]).await;
    assert_eq!(res.status, StatusCode::OK);
}

#[sqlx::test]
async fn allowlist_mode_refuses_unlisted_emails(pool: PgPool) {
    let a = app_with(pool.clone(), "allowlist");
    let (_, c) = pkce();
    let res = a.sign_in(CLI, CLI_REDIRECT, &c, "out@example.test").await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);
    assert!(res.body.contains("invite-only"), "{}", res.body);
    assert!(res.headers.get(header::LOCATION).is_none());
    assert_eq!(count(&pool, "users").await, 0);
    assert_eq!(count(&pool, "auth_codes").await, 0);

    crate::admin::run(
        &pool,
        crate::admin::Admin::Allow {
            email: "in@example.test".into(),
            note: None,
        },
    )
    .await
    .unwrap();
    a.login("in@example.test").await;
    assert_eq!(count(&pool, "users").await, 1);
}

#[sqlx::test]
async fn open_mode_signs_up_anyone(pool: PgPool) {
    let a = app_with(pool.clone(), "open");
    a.login("new@example.test").await;
    assert_eq!(count(&pool, "users").await, 1);
}

#[sqlx::test]
async fn disable_user_makes_the_next_access_token_use_401(pool: PgPool) {
    let a = app(pool.clone());
    let t = a.login("a@example.test").await;
    let access = t["access_token"].as_str().unwrap();
    assert_eq!(a.whoami(access).await, StatusCode::OK);
    crate::admin::run(
        &pool,
        crate::admin::Admin::DisableUser {
            email: "a@example.test".into(),
        },
    )
    .await
    .unwrap();
    assert_eq!(a.whoami(access).await, StatusCode::UNAUTHORIZED);
    assert_eq!(
        a.refresh(t["refresh_token"].as_str().unwrap()).await.json()["error"],
        "invalid_grant"
    );
    let (_, c) = pkce();
    let res = a.sign_in(CLI, CLI_REDIRECT, &c, "a@example.test").await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);
    assert!(res.body.contains("Account disabled"));
}

#[sqlx::test]
async fn disabled_user_cannot_use_earlier_codes_or_tokens(pool: PgPool) {
    let a = app(pool.clone());
    let t = a.login("a@example.test").await;
    let (v, c) = pkce();
    let code = a.code(&c, "a@example.test").await;
    // Disabled directly, without the CLI's revocations: `disabled_at` alone is enforced.
    sqlx::query("UPDATE users SET disabled_at = now()")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(a.exchange(&code, &v).await.json()["error"], "invalid_grant");
    assert_eq!(
        a.whoami(t["access_token"].as_str().unwrap()).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        a.refresh(t["refresh_token"].as_str().unwrap()).await.json()["error"],
        "invalid_grant"
    );
}

#[sqlx::test]
async fn bearer_rejects_garbage_and_foreign_tokens(pool: PgPool) {
    let a = app(pool.clone());
    assert_eq!(a.whoami("nope").await, StatusCode::UNAUTHORIZED);
    // Signed by a key the relay does not publish.
    let other = app(pool);
    let t = other.login("a@example.test").await;
    assert_eq!(
        a.whoami(t["access_token"].as_str().unwrap()).await,
        StatusCode::UNAUTHORIZED
    );
}

#[sqlx::test]
async fn auth_request_is_single_use_and_bound_to_the_browser(pool: PgPool) {
    let a = app(pool.clone());
    let (_, c) = pkce();
    let page = a.authorize(CLI, CLI_REDIRECT, &c).await;
    let cookie = format!("vekrel_auth_request={}", page.cookie("vekrel_auth_request"));
    // Another browser (no cookie) cannot finish it.
    let res = a.get("/auth/test?sub=s&email=a@example.test", None).await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    let ok = a
        .get("/auth/test?sub=s&email=a@example.test", Some(&cookie))
        .await;
    assert_eq!(ok.status, StatusCode::SEE_OTHER);
    assert!(
        ok.set_cookies()
            .iter()
            .any(|c| c.starts_with("vekrel_auth_request=;") && c.contains("Max-Age=0"))
    );
    let again = a
        .get("/auth/test?sub=s&email=a@example.test", Some(&cookie))
        .await;
    assert_eq!(again.status, StatusCode::BAD_REQUEST);
    assert_eq!(count(&pool, "auth_codes").await, 1);
    // Expired requests are refused.
    let page = a.authorize(CLI, CLI_REDIRECT, &c).await;
    let cookie = format!("vekrel_auth_request={}", page.cookie("vekrel_auth_request"));
    sqlx::query("UPDATE auth_requests SET expires_at = now() - interval '1 second'")
        .execute(&pool)
        .await
        .unwrap();
    let res = a
        .get("/auth/test?sub=s&email=a@example.test", Some(&cookie))
        .await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
}

#[sqlx::test]
async fn web_refresh_token_lives_only_in_an_httponly_cookie(pool: PgPool) {
    let a = app(pool);
    let redirect = format!("{WEB_ORIGIN}/auth/callback");
    let (v, c) = pkce();
    let res = a
        .sign_in("vekrel-web", &redirect, &c, "a@example.test")
        .await;
    let code = res.redirect_query(&redirect)["code"].clone();
    let origin = [("origin", WEB_ORIGIN)];
    let res = a
        .post(
            "/oauth/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", &redirect),
                ("client_id", "vekrel-web"),
                ("code_verifier", &v),
            ],
            &origin,
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert!(res.json().get("refresh_token").is_none());
    assert_eq!(res.headers[header::ACCESS_CONTROL_ALLOW_ORIGIN], WEB_ORIGIN);
    assert_eq!(
        res.headers[header::ACCESS_CONTROL_ALLOW_CREDENTIALS],
        "true"
    );
    let set = res.set_cookies();
    assert_eq!(set.len(), 1);
    let refresh = res.cookie(REFRESH_COOKIE);
    assert_eq!(
        set[0],
        format!(
            "vekrel_refresh={refresh}; HttpOnly; Secure; SameSite=Lax; Path=/oauth; Max-Age=2592000"
        )
    );
    let jar = format!("vekrel_refresh={refresh}");
    let form = [("grant_type", "refresh_token"), ("client_id", "vekrel-web")];
    // The cookie alone is accepted only from a web origin.
    for headers in [
        vec![("cookie", jar.as_str())],
        vec![("cookie", jar.as_str()), ("origin", "https://evil.test")],
    ] {
        let res = a.post("/oauth/token", &form, &headers).await;
        assert_eq!(res.json()["error"], "invalid_request");
        assert!(
            res.headers
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none()
        );
    }
    let res = a
        .post(
            "/oauth/token",
            &form,
            &[("cookie", jar.as_str()), ("origin", WEB_ORIGIN)],
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let rotated = res.cookie(REFRESH_COOKIE);
    assert_ne!(rotated, refresh);
    // Sign-out with the cookie clears it and ends the family.
    let jar = format!("vekrel_refresh={rotated}");
    let res = a
        .post(
            "/oauth/revoke",
            &[],
            &[("cookie", jar.as_str()), ("origin", WEB_ORIGIN)],
        )
        .await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(
        res.set_cookies()[0]
            .starts_with("vekrel_refresh=; HttpOnly; Secure; SameSite=Lax; Path=/oauth; Max-Age=0")
    );
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM refresh_tokens WHERE revoked_at IS NULL")
        .fetch_one(&a.state.pool)
        .await
        .unwrap();
    assert_eq!(n, 0);
}

#[sqlx::test]
async fn cors_preflight_allows_only_web_origins(pool: PgPool) {
    let a = app(pool);
    for (origin, allowed) in [(WEB_ORIGIN, true), ("https://evil.test", false)] {
        let res = a
            .send(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/oauth/token")
                    .header("origin", origin)
                    .header("access-control-request-method", "POST")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(
            res.headers
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_some(),
            allowed,
            "{origin}"
        );
    }
}

#[sqlx::test]
async fn token_endpoint_errors_are_oauth_json(pool: PgPool) {
    let a = app(pool);
    let cases: [(&[(&str, &str)], &str); 4] = [
        (
            &[("grant_type", "password"), ("client_id", CLI)],
            "unsupported_grant_type",
        ),
        (
            &[("grant_type", "refresh_token"), ("client_id", "x")],
            "invalid_client",
        ),
        (
            &[("grant_type", "authorization_code"), ("client_id", CLI)],
            "invalid_request",
        ),
        (
            &[
                ("grant_type", "refresh_token"),
                ("client_id", CLI),
                ("refresh_token", "nope"),
            ],
            "invalid_grant",
        ),
    ];
    for (form, error) in cases {
        let res = a.post("/oauth/token", form, &[]).await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST);
        assert_eq!(res.json()["error"], error);
        assert_eq!(res.headers[header::CACHE_CONTROL], "no-store");
    }
}

#[sqlx::test]
async fn secrets_never_reach_the_logs(pool: PgPool) {
    crate::test_logs::capture_logs(|| ());
    let a = app(pool);
    let (v, c) = pkce();
    let page = a.authorize(CLI, CLI_REDIRECT, &c).await;
    let request_id = page.cookie("vekrel_auth_request");
    let res = a
        .get(
            "/auth/test?sub=s&email=a@example.test",
            Some(&format!("vekrel_auth_request={request_id}")),
        )
        .await;
    let code = res.redirect_query(CLI_REDIRECT)["code"].clone();
    let t = a.exchange(&code, &v).await.json();
    let replay = a.exchange(&code, &v).await;
    assert_eq!(replay.status, StatusCode::BAD_REQUEST);
    let t2 = a.login("a@example.test").await;
    let r1 = a
        .refresh(t2["refresh_token"].as_str().unwrap())
        .await
        .json();
    a.refresh(t2["refresh_token"].as_str().unwrap()).await; // reuse
    a.post(
        "/oauth/revoke",
        &[("token", r1["refresh_token"].as_str().unwrap())],
        &[],
    )
    .await;
    let logs = crate::test_logs::capture_logs(|| ());
    assert!(logs.contains("sign-in completed"), "{logs}");
    assert!(logs.contains("refresh token reused"), "{logs}");
    let secrets = [
        v,
        code,
        request_id,
        t["access_token"].as_str().unwrap().into(),
        t["refresh_token"].as_str().unwrap().into(),
        t["id_token"].as_str().unwrap().into(),
        t2["refresh_token"].as_str().unwrap().into(),
        r1["refresh_token"].as_str().unwrap().into(),
    ];
    for s in secrets {
        assert!(!logs.contains(&s), "secret in logs: {s}");
    }
}

#[sqlx::test]
async fn concurrent_refreshes_of_one_token_let_exactly_one_win(pool: PgPool) {
    let a = app(pool);
    let t = a.login("a@example.test").await;
    let r0 = t["refresh_token"].as_str().unwrap();
    let (x, y) = tokio::join!(a.refresh(r0), a.refresh(r0));
    let ok: Vec<_> = [&x, &y]
        .into_iter()
        .filter(|r| r.status == StatusCode::OK)
        .collect();
    assert_eq!(ok.len(), 1, "{} / {}", x.body, y.body);
    // The loser is reuse of a rotated token: the whole family, the winner's new head too, is revoked.
    let winner = ok[0].json();
    assert_eq!(
        a.refresh(winner["refresh_token"].as_str().unwrap())
            .await
            .json()["error"],
        "invalid_grant"
    );
    let live: i64 =
        sqlx::query_scalar("SELECT count(*) FROM refresh_tokens WHERE revoked_at IS NULL")
            .fetch_one(&a.state.pool)
            .await
            .unwrap();
    assert_eq!(live, 0);
}

/// The state a revoke racing a rotation leaves (the revoke's snapshot predates the new head): the
/// old token revoked, the new head not. The new head must not refresh, and the family ends revoked.
#[sqlx::test]
async fn refresh_is_refused_when_any_token_of_the_family_is_revoked(pool: PgPool) {
    let a = app(pool);
    let t = a.login("a@example.test").await;
    let r0 = t["refresh_token"].as_str().unwrap();
    let r1 = a.refresh(r0).await.json()["refresh_token"]
        .as_str()
        .unwrap()
        .to_owned();
    sqlx::query("UPDATE refresh_tokens SET revoked_at = now() WHERE hash = $1")
        .bind(hash(r0))
        .execute(&a.state.pool)
        .await
        .unwrap();
    assert_eq!(a.refresh(&r1).await.json()["error"], "invalid_grant");
    let live: i64 =
        sqlx::query_scalar("SELECT count(*) FROM refresh_tokens WHERE revoked_at IS NULL")
            .fetch_one(&a.state.pool)
            .await
            .unwrap();
    assert_eq!(live, 0);
}

/// Revoke and rotate fired together, many times: whatever the interleaving, nothing of the family
/// stays usable afterwards.
#[sqlx::test]
async fn revoke_racing_a_rotation_leaves_nothing_usable(pool: PgPool) {
    let a = app(pool);
    for _ in 0..30 {
        let t = a.login("a@example.test").await;
        let r0 = t["refresh_token"].as_str().unwrap();
        let form = [("token", r0)];
        let (rotated, revoked) = tokio::join!(a.refresh(r0), a.post("/oauth/revoke", &form, &[]));
        assert_eq!(revoked.status, StatusCode::OK);
        if rotated.status == StatusCode::OK {
            let head = rotated.json();
            assert_eq!(
                a.refresh(head["refresh_token"].as_str().unwrap())
                    .await
                    .json()["error"],
                "invalid_grant"
            );
            assert_eq!(
                a.whoami(head["access_token"].as_str().unwrap()).await,
                StatusCode::UNAUTHORIZED
            );
        }
    }
}

#[sqlx::test]
async fn state_postgres_cannot_store_is_a_400_not_a_500(pool: PgPool) {
    let a = app(pool.clone());
    let (_, c) = pkce();
    let q = form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("response_type", "code"),
            ("client_id", CLI),
            ("redirect_uri", CLI_REDIRECT),
            ("code_challenge", c.as_str()),
            ("code_challenge_method", "S256"),
            ("state", "a\0b"),
        ])
        .finish();
    let res = a.get(&format!("/oauth/authorize?{q}"), None).await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST, "{}", res.body);
    assert!(res.headers.get(header::LOCATION).is_none());
    assert_eq!(count(&pool, "auth_requests").await, 0);
}

#[sqlx::test]
async fn cookie_revoke_needs_a_web_origin(pool: PgPool) {
    let a = app(pool);
    let redirect = format!("{WEB_ORIGIN}/auth/callback");
    let (v, c) = pkce();
    let res = a
        .sign_in("vekrel-web", &redirect, &c, "a@example.test")
        .await;
    let code = res.redirect_query(&redirect)["code"].clone();
    let res = a
        .post(
            "/oauth/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", &redirect),
                ("client_id", "vekrel-web"),
                ("code_verifier", &v),
            ],
            &[("origin", WEB_ORIGIN)],
        )
        .await;
    let jar = format!("vekrel_refresh={}", res.cookie(REFRESH_COOKIE));
    // A cross-site form post (or no Origin at all) cannot sign the user out.
    for headers in [
        vec![("cookie", jar.as_str())],
        vec![("cookie", jar.as_str()), ("origin", "https://evil.test")],
    ] {
        let res = a.post("/oauth/revoke", &[], &headers).await;
        assert_eq!(res.status, StatusCode::OK);
        assert!(res.set_cookies().is_empty(), "cookie cleared: {headers:?}");
        let live: i64 =
            sqlx::query_scalar("SELECT count(*) FROM refresh_tokens WHERE revoked_at IS NULL")
                .fetch_one(&a.state.pool)
                .await
                .unwrap();
        assert_eq!(live, 1, "revoked without a web Origin: {headers:?}");
    }
    // A body token needs no Origin (CLI, desktop, mobile).
    let t = a.login("b@example.test").await;
    let res = a
        .post(
            "/oauth/revoke",
            &[("token", t["refresh_token"].as_str().unwrap())],
            &[],
        )
        .await;
    assert_eq!(res.status, StatusCode::OK);
    assert_eq!(
        a.refresh(t["refresh_token"].as_str().unwrap()).await.json()["error"],
        "invalid_grant"
    );
}

/// Only configured providers get a button; the email form is always there.
#[sqlx::test]
async fn sign_in_page_shows_configured_providers_only(pool: PgPool) {
    let keys =
        Arc::new(SigningKeys::from_json(&json!([entry("k1", "active").0]).to_string()).unwrap());
    for (vars, github, google) in [
        (vec![], false, false),
        (
            vec![("GITHUB_CLIENT_ID", "id"), ("GITHUB_CLIENT_SECRET", "s")],
            true,
            false,
        ),
        (
            vec![("GOOGLE_CLIENT_ID", "id"), ("GOOGLE_CLIENT_SECRET", "s")],
            false,
            true,
        ),
    ] {
        let config = Config::for_tests(&vars);
        let a = App {
            router: router(AccountsState::new(pool.clone(), keys.clone(), &config)),
            state: AccountsState::new(pool.clone(), keys.clone(), &config),
        };
        let (_, c) = pkce();
        let page = a.authorize(CLI, CLI_REDIRECT, &c).await;
        assert_eq!(page.status, StatusCode::OK, "{}", page.body);
        assert_eq!(
            page.body.contains(r#"href="/auth/github""#),
            github,
            "{vars:?}"
        );
        assert_eq!(
            page.body.contains(r#"href="/auth/google""#),
            google,
            "{vars:?}"
        );
        assert!(page.body.contains(r#"action="/auth/email""#));
    }
}
