// Magic link end to end through the whole router, with the log transport or a local Resend mock.
use std::collections::HashMap;

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use http_body_util::BodyExt;
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tower::ServiceExt;

use crate::accounts::keys::{SigningKeys, tests::entry};
use crate::accounts::oauth::random_secret;
use crate::config::Config;
use crate::email::mock::{self, Mock};

const ISS: &str = "https://relay.example.test";
const CLI: &str = "vekrel-cli";
const CLI_REDIRECT: &str = "http://127.0.0.1:34338/callback";
const API_KEY: &str = "re_test_k3y_never_logged";

struct App {
    router: axum::Router,
    pool: PgPool,
}

struct Res {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

impl Res {
    fn cookie(&self, name: &str) -> String {
        self.headers
            .get_all(header::SET_COOKIE)
            .iter()
            .find_map(|c| {
                c.to_str()
                    .unwrap()
                    .strip_prefix(&format!("{name}="))?
                    .split(';')
                    .next()
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| panic!("no {name} cookie"))
    }
    /// Query of a redirect to the CLI callback.
    fn redirect_query(&self) -> HashMap<String, String> {
        let loc = self.headers[header::LOCATION].to_str().unwrap();
        let q = loc
            .strip_prefix(CLI_REDIRECT)
            .and_then(|r| r.strip_prefix('?'))
            .unwrap_or_else(|| panic!("redirect {loc}"));
        form_urlencoded::parse(q.as_bytes()).into_owned().collect()
    }
    /// The dev-only link and code the log transport puts on the page.
    fn dev_link(&self) -> (String, String) {
        let pick = |id: &str| {
            let start = self.body.find(&format!("id=\"{id}\">")).expect(id) + id.len() + 6;
            let end = start + self.body[start..].find('<').unwrap();
            self.body[start..end].to_owned()
        };
        (pick("dev-link"), pick("dev-code"))
    }
}

fn app_with(pool: PgPool, vars: &[(&str, &str)]) -> App {
    let keys = SigningKeys::from_json(&json!([entry("k1", "active").0]).to_string()).unwrap();
    let mut all = vec![
        ("RELAY_ORIGIN", ISS),
        ("SIGNUP_MODE", "open"),
        ("TRUST_PROXY_IP_HEADER", "true"),
    ];
    all.extend_from_slice(vars);
    let config = Config::for_tests(&all);
    App {
        router: crate::http::router(pool.clone(), std::sync::Arc::new(keys), &config),
        pool,
    }
}

fn log_app(pool: PgPool) -> App {
    app_with(pool, &[])
}

fn resend_app(pool: PgPool, mock: &Mock, mode: &str) -> App {
    app_with(
        pool,
        &[
            ("SIGNUP_MODE", mode),
            ("MAGIC_LINK_TRANSPORT", "resend"),
            ("RESEND_API_KEY", API_KEY),
            ("MAGIC_LINK_FROM", "Vekrel <signin@example.test>"),
            ("RESEND_BASE_URL", &mock.base_url),
        ],
    )
}

fn challenge() -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(random_secret().as_bytes()))
}

impl App {
    async fn send(&self, req: Request<Body>) -> Res {
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

    async fn post(&self, path: &str, form: &[(&str, &str)], cookie: Option<&str>, ip: &str) -> Res {
        let body = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(form)
            .finish();
        let mut r =
            Request::post(path).header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if !ip.is_empty() {
            r = r.header(crate::rate_limit::CLIENT_IP_HEADER, ip);
        }
        if let Some(c) = cookie {
            r = r.header(header::COOKIE, c);
        }
        self.send(r.body(Body::from(body)).unwrap()).await
    }

    /// A browser that opened `/oauth/authorize`: its auth-request cookie.
    async fn browser(&self) -> String {
        let q = form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("response_type", "code"),
                ("client_id", CLI),
                ("redirect_uri", CLI_REDIRECT),
                ("code_challenge", &challenge()),
                ("code_challenge_method", "S256"),
                ("state", "st-7"),
            ])
            .finish();
        let page = self.get(&format!("/oauth/authorize?{q}"), None).await;
        assert_eq!(page.status, StatusCode::OK, "{}", page.body);
        format!("vekrel_auth_request={}", page.cookie("vekrel_auth_request"))
    }

    async fn request_link(&self, browser: &str, email: &str) -> Res {
        self.post(
            "/auth/email",
            &[("email", email)],
            Some(browser),
            "203.0.113.7",
        )
        .await
    }

    async fn enter_code(&self, browser: &str, code: &str) -> Res {
        self.post(
            "/auth/email/code",
            &[("code", code)],
            Some(browser),
            "203.0.113.7",
        )
        .await
    }

    async fn count(&self, sql: &str) -> i64 {
        sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_owned()))
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }
}

/// Path and query of a link to this relay.
fn path(link: &str) -> &str {
    link.strip_prefix(ISS).unwrap_or_else(|| panic!("{link}"))
}

#[sqlx::test]
async fn link_signs_in_the_same_browser_once(pool: PgPool) {
    let a = log_app(pool);
    let b = a.browser().await;
    let page = a.request_link(&b, "Ann@Example.test").await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    let (link, code) = page.dev_link();
    assert!(
        link.starts_with(&format!("{ISS}/auth/email/verify?t=")),
        "{link}"
    );
    assert_eq!(code.len(), 6);
    // Stored hashed only.
    let token = link.rsplit("t=").next().unwrap();
    assert_eq!(
        a.count(&format!(
            "SELECT count(*) FROM magic_links WHERE token_hash = '{}' AND email = 'ann@example.test'",
            crate::accounts::oauth::hash(token)
        ))
        .await,
        1
    );
    assert_eq!(
        a.count(&format!(
            "SELECT count(*) FROM magic_links WHERE token_hash = '{token}' OR code_hash = '{code}'"
        ))
        .await,
        0
    );
    let res = a.get(path(&link), Some(&b)).await;
    assert_eq!(res.status, StatusCode::SEE_OTHER, "{}", res.body);
    let q = res.redirect_query();
    assert_eq!(q["state"], "st-7");
    assert!(!q["code"].is_empty());
    assert_eq!(
        a.count("SELECT count(*) FROM identities WHERE provider = 'email' AND email = 'ann@example.test'")
            .await,
        1
    );
    // Single use: neither the link nor its code works again, in any browser.
    let again = a.get(path(&link), Some(&b)).await;
    assert_eq!(again.status, StatusCode::BAD_REQUEST);
    assert!(again.body.contains("Sign-in expired"), "{}", again.body);
    assert!(again.headers.get(header::LOCATION).is_none());
    let b2 = a.browser().await;
    assert_eq!(
        a.get(path(&link), Some(&b2)).await.status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        a.enter_code(&b, &code).await.status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(a.count("SELECT count(*) FROM auth_codes").await, 1);
}

#[sqlx::test]
async fn link_expires_after_15_minutes(pool: PgPool) {
    let a = log_app(pool);
    let b = a.browser().await;
    let (link, code) = a.request_link(&b, "ann@example.test").await.dev_link();
    let ttl: f64 = sqlx::query_scalar(
        "SELECT extract(epoch FROM expires_at - created_at)::float8 FROM magic_links",
    )
    .fetch_one(&a.pool)
    .await
    .unwrap();
    assert_eq!(ttl, 900.0);
    sqlx::query("UPDATE magic_links SET expires_at = now() - interval '1 second'")
        .execute(&a.pool)
        .await
        .unwrap();
    let res = a.get(path(&link), Some(&b)).await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    assert!(res.headers.get(header::LOCATION).is_none());
    assert_eq!(
        a.enter_code(&b, &code).await.status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(a.count("SELECT count(*) FROM auth_codes").await, 0);
}

#[sqlx::test]
async fn link_opened_in_another_browser_shows_the_code_and_signs_nobody_in(pool: PgPool) {
    let a = log_app(pool);
    let b = a.browser().await;
    let (link, code) = a.request_link(&b, "ann@example.test").await.dev_link();
    let other = a.browser().await;
    for cookie in [None, Some(other.as_str())] {
        let res = a.get(path(&link), cookie).await;
        assert_eq!(res.status, StatusCode::OK, "{}", res.body);
        assert!(res.headers.get(header::LOCATION).is_none());
        assert!(res.body.contains(&code), "{}", res.body);
        assert!(res.headers.get(header::SET_COOKIE).is_none());
    }
    // The code is bound to the browser that asked for the link.
    assert_eq!(
        a.enter_code(&other, &code).await.status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(a.count("SELECT count(*) FROM auth_codes").await, 0);
    assert_eq!(a.count("SELECT count(*) FROM users").await, 0);
    // The waiting browser types it in (any case, spaces ignored).
    let typed = format!("{} {}", &code[..3], code[3..].to_lowercase());
    let res = a.enter_code(&b, &typed).await;
    assert_eq!(res.status, StatusCode::SEE_OTHER, "{}", res.body);
    assert_eq!(res.redirect_query()["state"], "st-7");
    // Used up: the link is dead too.
    assert_eq!(
        a.get(path(&link), Some(&b)).await.status,
        StatusCode::BAD_REQUEST
    );
}

#[sqlx::test]
async fn four_wrong_codes_still_allow_the_right_one(pool: PgPool) {
    let a = log_app(pool);
    let b = a.browser().await;
    let (_, code) = a.request_link(&b, "ann@example.test").await.dev_link();
    for _ in 0..4 {
        let res = a.enter_code(&b, "ZZZZZZ").await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST);
        assert!(res.body.contains("not right"), "{}", res.body);
    }
    assert_eq!(a.enter_code(&b, &code).await.status, StatusCode::SEE_OTHER);
}

#[sqlx::test]
async fn fifth_wrong_code_kills_the_link(pool: PgPool) {
    let a = log_app(pool);
    let b = a.browser().await;
    let (link, code) = a.request_link(&b, "ann@example.test").await.dev_link();
    for _ in 0..5 {
        assert_eq!(
            a.enter_code(&b, "ZZZZZZ").await.status,
            StatusCode::BAD_REQUEST
        );
    }
    let res = a.enter_code(&b, &code).await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    assert!(res.headers.get(header::LOCATION).is_none());
    assert_eq!(
        a.get(path(&link), Some(&b)).await.status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(a.count("SELECT count(*) FROM auth_codes").await, 0);
}

#[sqlx::test]
async fn fourth_send_to_one_email_in_15_minutes_is_429(pool: PgPool) {
    let a = log_app(pool);
    let b = a.browser().await;
    for email in ["ann@example.test", "ANN@example.test", "ann@EXAMPLE.test"] {
        assert_eq!(a.request_link(&b, email).await.status, StatusCode::OK);
    }
    let res = a.request_link(&b, "Ann@Example.Test").await;
    assert_eq!(res.status, StatusCode::TOO_MANY_REQUESTS, "{}", res.body);
    assert!(!res.body.contains("dev-link"));
    assert_eq!(a.count("SELECT count(*) FROM magic_links").await, 3);
    // Another email is unaffected; the window is 15 minutes.
    assert_eq!(
        a.request_link(&b, "bob@example.test").await.status,
        StatusCode::OK
    );
    sqlx::query(
        "UPDATE relay_rate_limits SET window_start = window_start - interval '901 seconds'",
    )
    .execute(&a.pool)
    .await
    .unwrap();
    assert_eq!(
        a.request_link(&b, "ann@example.test").await.status,
        StatusCode::OK
    );
}

#[sqlx::test]
async fn twenty_first_send_from_one_ip_in_an_hour_is_429(pool: PgPool) {
    let a = log_app(pool);
    let b = a.browser().await;
    let send = |i: usize, ip: &'static str| {
        let (a, b) = (&a, &b);
        async move {
            a.post(
                "/auth/email",
                &[("email", &format!("u{i}@example.test"))],
                Some(b),
                ip,
            )
            .await
            .status
        }
    };
    for i in 0..20 {
        assert_eq!(send(i, "198.51.100.1").await, StatusCode::OK);
    }
    assert_eq!(
        send(20, "198.51.100.1").await,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(send(21, "198.51.100.2").await, StatusCode::OK);
    sqlx::query(
        "UPDATE relay_rate_limits SET window_start = window_start - interval '3601 seconds'",
    )
    .execute(&a.pool)
    .await
    .unwrap();
    assert_eq!(send(22, "198.51.100.1").await, StatusCode::OK);
}

#[sqlx::test]
async fn sending_needs_a_pending_sign_in_and_a_valid_email(pool: PgPool) {
    let mock = mock::start(StatusCode::OK).await;
    let a = resend_app(pool, &mock, "open");
    let none = a
        .post(
            "/auth/email",
            &[("email", "ann@example.test")],
            None,
            "203.0.113.7",
        )
        .await;
    assert_eq!(none.status, StatusCode::BAD_REQUEST);
    assert!(none.body.contains("Sign-in expired"));
    let b = a.browser().await;
    for bad in [
        "",
        "ann",
        "@example.test",
        "ann@",
        "a b@example.test",
        "a@b@c",
        "<a@b>",
    ] {
        let res = a.request_link(&b, bad).await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST, "{bad}");
    }
    assert!(mock.requests().is_empty());
    assert_eq!(a.count("SELECT count(*) FROM magic_links").await, 0);
}

#[sqlx::test]
async fn resend_gets_the_link_and_the_page_does_not(pool: PgPool) {
    let mock = mock::start(StatusCode::OK).await;
    let a = resend_app(pool, &mock, "open");
    let b = a.browser().await;
    let page = a.request_link(&b, "ann@example.test").await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(!page.body.contains("dev-link"));
    assert!(!page.body.contains("/auth/email/verify"));
    let reqs = mock.requests();
    assert_eq!(reqs.len(), 1);
    let r = &reqs[0];
    assert_eq!((r.method.as_str(), r.path.as_str()), ("POST", "/emails"));
    assert_eq!(r.headers["authorization"], format!("Bearer {API_KEY}"));
    assert_eq!(r.headers["content-type"], "application/json");
    let body = r.body.as_object().unwrap();
    assert_eq!(
        body.keys().collect::<Vec<_>>(),
        ["from", "to", "subject", "html", "text"]
    );
    assert_eq!(body["from"], "Vekrel <signin@example.test>");
    assert_eq!(body["to"], json!(["ann@example.test"]));
    assert_eq!(body["subject"], "Sign in to Vekrel");
    let text = body["text"].as_str().unwrap();
    let html = body["html"].as_str().unwrap();
    let link = text
        .split_whitespace()
        .find(|w| w.starts_with(ISS))
        .unwrap()
        .to_owned();
    assert!(html.contains(&format!("href=\"{link}\"")), "{html}");
    let code = text
        .split_whitespace()
        .find(|w| {
            w.len() == 6
                && w.chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
        })
        .unwrap()
        .to_owned();
    assert!(html.contains(&code));
    assert!(!page.body.contains(&code));
    let res = a.get(path(&link), Some(&b)).await;
    assert_eq!(res.status, StatusCode::SEE_OTHER, "{}", res.body);
}

#[sqlx::test]
async fn resend_failure_is_503_and_says_nothing_about_the_account(pool: PgPool) {
    let mock = mock::start(StatusCode::INTERNAL_SERVER_ERROR).await;
    let a = resend_app(pool, &mock, "open");
    let b = a.browser().await;
    let res = a.request_link(&b, "ann@example.test").await;
    assert_eq!(res.status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(res.body.contains("try again"), "{}", res.body);
}

/// Review Focus 5 and no account enumeration: the reply to `POST /auth/email` is the same for an
/// existing user, an allowlisted email and an unknown one; only signup.rs decides, after the link.
#[sqlx::test]
async fn same_reply_for_every_email_and_allowlist_decides_after_the_link(pool: PgPool) {
    let mock = mock::start(StatusCode::OK).await;
    let a = resend_app(pool, &mock, "allowlist");
    sqlx::query("INSERT INTO users (id, email) VALUES (gen_random_uuid(), 'old@example.test')")
        .execute(&a.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO signup_allowlist (email) VALUES ('invited@example.test')")
        .execute(&a.pool)
        .await
        .unwrap();
    let emails = [
        "old@example.test",
        "invited@example.test",
        "stranger@example.test",
    ];
    let mut replies = Vec::new();
    let mut browsers = Vec::new();
    for e in emails {
        let b = a.browser().await;
        let r = a.request_link(&b, e).await;
        replies.push((r.status, r.body));
        browsers.push(b);
    }
    assert!(replies.iter().all(|r| *r == replies[0]), "{replies:?}");
    assert_eq!(replies[0].0, StatusCode::OK);
    let reqs = mock.requests();
    assert_eq!(reqs.len(), 3, "every address gets an email");
    let link = |i: usize| {
        reqs[i].body["text"]
            .as_str()
            .unwrap()
            .split_whitespace()
            .find(|w| w.starts_with(ISS))
            .unwrap()
            .to_owned()
    };
    for (i, want) in [
        (0, StatusCode::SEE_OTHER),
        (1, StatusCode::SEE_OTHER),
        (2, StatusCode::FORBIDDEN),
    ] {
        let res = a.get(path(&link(i)), Some(&browsers[i])).await;
        assert_eq!(res.status, want, "{}: {}", emails[i], res.body);
    }
    assert_eq!(
        a.count("SELECT count(*) FROM users WHERE email = 'stranger@example.test'")
            .await,
        0
    );
    assert_eq!(a.count("SELECT count(*) FROM users").await, 2);
}

#[sqlx::test]
async fn link_token_code_and_api_key_never_reach_the_logs(pool: PgPool) {
    crate::test_logs::capture_logs(|| ());
    let mock = mock::start(StatusCode::OK).await;
    let a = resend_app(pool.clone(), &mock, "open");
    let b = a.browser().await;
    a.request_link(&b, "logcheck-ann@example.test").await;
    let text = mock.requests()[0].body["text"].as_str().unwrap().to_owned();
    let link = text
        .split_whitespace()
        .find(|w| w.starts_with(ISS))
        .unwrap();
    let token = link.rsplit("t=").next().unwrap().to_owned();
    a.get(path(link), None).await; // other browser: shows the code
    a.enter_code(&b, "ZZZZZZ").await;
    a.get(path(link), Some(&b)).await; // signs in
    // Log transport too.
    let l = log_app(pool);
    let lb = l.browser().await;
    let (llink, lcode) = l.request_link(&lb, "bob@example.test").await.dev_link();
    l.get(path(&llink), None).await;
    let logs = crate::test_logs::capture_logs(|| ());
    assert!(logs.contains("magic link sent"), "{logs}");
    assert!(logs.contains("sign-in completed"), "{logs}");
    let ltoken = llink.rsplit("t=").next().unwrap().to_owned();
    for s in [
        token,
        ltoken,
        lcode,
        API_KEY.to_owned(),
        "logcheck-ann@example.test".into(),
    ] {
        assert!(!logs.contains(&s), "secret in logs: {s}");
    }
}

#[sqlx::test]
async fn parallel_sends_to_one_email_never_pass_the_limit(pool: PgPool) {
    let a = std::sync::Arc::new(log_app(pool));
    let b = a.browser().await;
    let mut set = tokio::task::JoinSet::new();
    for i in 0..10 {
        let (a, b) = (a.clone(), b.clone());
        let ip = format!("198.51.100.{i}");
        set.spawn(async move {
            a.post(
                "/auth/email",
                &[("email", "ann@example.test")],
                Some(&b),
                &ip,
            )
            .await
            .status
        });
    }
    let statuses = set.join_all().await;
    assert_eq!(
        statuses.iter().filter(|s| **s == StatusCode::OK).count(),
        3,
        "{statuses:?}"
    );
    assert_eq!(a.count("SELECT count(*) FROM magic_links").await, 3);
}

/// Without the edge header the socket peer is the key: one client cannot use up a shared bucket.
#[sqlx::test]
async fn without_the_edge_header_each_peer_has_its_own_limit(pool: PgPool) {
    use axum::extract::ConnectInfo;
    let base = log_app(pool.clone());
    let b = base.browser().await;
    let peer = |last: u8| App {
        router: base
            .router
            .clone()
            // What `into_make_service_with_connect_info` attaches in `serve`.
            .layer(axum::Extension(ConnectInfo(std::net::SocketAddr::from((
                [192, 0, 2, last],
                40000,
            ))))),
        pool: pool.clone(),
    };
    let (p1, p2) = (peer(1), peer(2));
    for i in 0..20 {
        let r = p1
            .post(
                "/auth/email",
                &[("email", &format!("u{i}@example.test"))],
                Some(&b),
                "",
            )
            .await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    }
    let late = p1
        .post(
            "/auth/email",
            &[("email", "late@example.test")],
            Some(&b),
            "",
        )
        .await;
    assert_eq!(late.status, StatusCode::TOO_MANY_REQUESTS);
    let other = p2
        .post(
            "/auth/email",
            &[("email", "other@example.test")],
            Some(&b),
            "",
        )
        .await;
    assert_eq!(other.status, StatusCode::OK);
}

#[sqlx::test]
async fn global_send_cap_is_a_backstop(pool: PgPool) {
    let a = log_app(pool);
    let b = a.browser().await;
    sqlx::query(
        "INSERT INTO relay_rate_limits (key, window_start, count) VALUES ('magic_link:global', now(), 200)",
    )
    .execute(&a.pool)
    .await
    .unwrap();
    let res = a.request_link(&b, "ann@example.test").await;
    assert_eq!(res.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(a.count("SELECT count(*) FROM magic_links").await, 0);
    assert_eq!(
        a.count("SELECT count(*) FROM relay_rate_limits WHERE key <> 'magic_link:global'")
            .await,
        0,
        "a refused send records nothing"
    );
}

/// The code is compared and the try counted in one statement. Two links of one sign-in, one try
/// left on each; a wrong guess is in flight (blocked on link A) when the right code for link B
/// arrives. The wrong guess is the fifth try, so link B must be dead too.
#[sqlx::test]
async fn a_guess_in_flight_counts_before_a_later_right_code(pool: PgPool) {
    let a = std::sync::Arc::new(log_app(pool.clone()));
    let b = a.browser().await;
    let (link_a, _) = a.request_link(&b, "ann@example.test").await.dev_link();
    let (_, code_b) = a.request_link(&b, "ann@example.test").await.dev_link();
    sqlx::query("UPDATE magic_links SET code_attempts = 4")
        .execute(&pool)
        .await
        .unwrap();
    let token_a = link_a.rsplit("t=").next().unwrap().to_owned();
    let mut lock = pool.begin().await.unwrap();
    sqlx::query("SELECT 1 FROM magic_links WHERE token_hash = $1 FOR UPDATE")
        .bind(crate::accounts::oauth::hash(&token_a))
        .execute(&mut *lock)
        .await
        .unwrap();
    let waiting = || async {
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM pg_stat_activity
             WHERE datname = current_database() AND wait_event_type = 'Lock'",
        )
        .fetch_one(&pool)
        .await
        .unwrap()
    };
    let until = |n: i64, task: &tokio::task::JoinHandle<Res>| {
        let done = task.is_finished();
        async move {
            for _ in 0..200 {
                if done || waiting().await >= n {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
            panic!("no request waited on the row lock");
        }
    };
    let (a1, b1) = (a.clone(), b.clone());
    let wrong = tokio::spawn(async move { a1.enter_code(&b1, "ZZZZZZ").await });
    until(1, &wrong).await;
    let (a2, b2) = (a.clone(), b.clone());
    let right = tokio::spawn(async move { a2.enter_code(&b2, &code_b).await });
    for _ in 0..200 {
        if right.is_finished() || waiting().await >= 2 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    lock.commit().await.unwrap();
    let (wrong, right) = (wrong.await.unwrap(), right.await.unwrap());
    assert_eq!(wrong.status, StatusCode::BAD_REQUEST);
    assert_eq!(right.status, StatusCode::BAD_REQUEST, "{}", right.body);
    assert!(right.headers.get(header::LOCATION).is_none());
    assert_eq!(a.count("SELECT count(*) FROM auth_codes").await, 0);
}

/// `TRUST_PROXY_IP_HEADER` unset: the peer is the key, and a client-sent `X-Real-IP` changes nothing.
#[sqlx::test]
async fn spoofed_ip_header_is_ignored_unless_trusted(pool: PgPool) {
    use axum::extract::ConnectInfo;
    let base = app_with(pool.clone(), &[("TRUST_PROXY_IP_HEADER", "false")]);
    let b = base.browser().await;
    let a = App {
        router: base.router.clone().layer(axum::Extension(ConnectInfo(
            std::net::SocketAddr::from(([192, 0, 2, 50], 40000)),
        ))),
        pool: pool.clone(),
    };
    for i in 0..20 {
        let spoofed = format!("198.51.100.{i}");
        let r = a
            .post(
                "/auth/email",
                &[("email", &format!("u{i}@example.test"))],
                Some(&b),
                &spoofed,
            )
            .await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    }
    let r = a
        .post(
            "/auth/email",
            &[("email", "late@example.test")],
            Some(&b),
            "203.0.113.99",
        )
        .await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        a.count("SELECT count(*) FROM relay_rate_limits WHERE key LIKE 'magic_link:ip:%' AND key <> 'magic_link:ip:192.0.2.50'")
            .await,
        0
    );
}
