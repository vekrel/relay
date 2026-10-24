// GitHub and Google sign-in against local fake providers (axum on 127.0.0.1:0).
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use axum::body::Body;
use axum::extract::Form;
use axum::http::{Request, header};
use axum::routing::post;
use axum::{Json, Router};
use http_body_util::BodyExt;
use jsonwebtoken::{EncodingKey, Header};
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::traits::PublicKeyParts;
use serde_json::{Value, json};
use sqlx::PgPool;
use tower::ServiceExt;

use super::*;
use crate::accounts::keys::{SigningKeys, tests::entry};

const CLI: &str = "vekrel-cli";
const CLI_REDIRECT: &str = "http://127.0.0.1:34338/callback";
const ISS: &str = "https://relay.example.test";
const GH_SECRET: &str = "gh-client-secret-TEST";
const G_CLIENT: &str = "g-client.apps.googleusercontent.test";
const G_SECRET: &str = "g-client-secret-TEST";
const GH_TOKEN: &str = "gho_fake_provider_access_token";
const G_ACCESS: &str = "ya29.fake_google_access_token";

/// Two RS256 keys: `good` is in the fake JWKS, `rogue` is not.
struct Keys {
    good: rsa::RsaPrivateKey,
    rogue: rsa::RsaPrivateKey,
}

fn keys() -> &'static Keys {
    static K: OnceLock<Keys> = OnceLock::new();
    K.get_or_init(|| {
        let mut rng = rand::rngs::OsRng;
        Keys {
            good: rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap(),
            rogue: rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap(),
        }
    })
}

fn sign_rs256(key: &rsa::RsaPrivateKey, claims: &Value) -> String {
    let mut h = Header::new(jsonwebtoken::Algorithm::RS256);
    h.kid = Some("g1".into());
    let der = key.to_pkcs1_der().unwrap();
    jsonwebtoken::encode(&h, claims, &EncodingKey::from_rsa_der(der.as_bytes())).unwrap()
}

/// What the fake providers answer, and what they were sent.
struct Mock {
    gh_id: u64,
    gh_emails: Value,
    /// Google ID token claims; `None` means "the standard good claims for the nonce sent".
    g_claims: Option<Value>,
    g_rogue_key: bool,
    /// Token endpoint form bodies, in order.
    token_forms: Vec<HashMap<String, String>>,
    /// The nonce the relay sent to the fake Google authorize URL.
    g_nonce: String,
    /// The last ID token issued (for the log grep).
    g_id_token: String,
}

type M = Arc<Mutex<Mock>>;

fn bearer_ok(h: &HeaderMap) -> bool {
    h.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok())
        == Some(&format!("Bearer {GH_TOKEN}"))
        && h.get(header::USER_AGENT).is_some()
}

fn now() -> u64 {
    crate::accounts::tokens::now_secs()
}

fn fake_providers(m: M) -> Router {
    Router::new()
        .route(
            "/gh/token",
            post(
                |State(m): State<M>, Form(f): Form<HashMap<String, String>>| async move {
                    let ok = f.get("code").map(String::as_str) == Some("gh-code");
                    m.lock().unwrap().token_forms.push(f);
                    if ok {
                        Json(json!({"access_token": GH_TOKEN, "token_type": "bearer", "scope": "read:user,user:email"}))
                    } else {
                        Json(json!({"error": "bad_verification_code"}))
                    }
                },
            ),
        )
        .route(
            "/gh/user",
            get(|State(m): State<M>, h: HeaderMap| async move {
                if !bearer_ok(&h) {
                    return StatusCode::UNAUTHORIZED.into_response();
                }
                Json(json!({"login": "octo", "id": m.lock().unwrap().gh_id})).into_response()
            }),
        )
        .route(
            "/gh/user/emails",
            get(|State(m): State<M>, h: HeaderMap| async move {
                if !bearer_ok(&h) {
                    return StatusCode::UNAUTHORIZED.into_response();
                }
                Json(m.lock().unwrap().gh_emails.clone()).into_response()
            }),
        )
        .route(
            "/g/token",
            post(
                |State(m): State<M>, Form(f): Form<HashMap<String, String>>| async move {
                    let mut m = m.lock().unwrap();
                    let ok = f.get("code").map(String::as_str) == Some("g-code");
                    m.token_forms.push(f);
                    if !ok {
                        return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid_grant"})))
                            .into_response();
                    }
                    let claims = m.g_claims.clone().unwrap_or_else(|| {
                        google_claims(&m.g_nonce, "g-sub-1", "g@example.test", true)
                    });
                    let k = keys();
                    let id_token =
                        sign_rs256(if m.g_rogue_key { &k.rogue } else { &k.good }, &claims);
                    m.g_id_token = id_token.clone();
                    Json(json!({"access_token": G_ACCESS, "expires_in": 3599, "token_type": "Bearer", "id_token": id_token}))
                        .into_response()
                },
            ),
        )
        .route(
            "/g/certs",
            get(|| async {
                let pk = keys().good.to_public_key();
                let b = |v: rsa::BigUint| URL_SAFE_NO_PAD.encode(v.to_bytes_be());
                Json(json!({"keys": [{"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "g1",
                    "n": b(pk.n().clone()), "e": b(pk.e().clone())}]}))
            }),
        )
        .with_state(m)
}

fn google_claims(nonce: &str, sub: &str, email: &str, verified: bool) -> Value {
    json!({"iss": "https://accounts.google.com", "azp": G_CLIENT, "aud": G_CLIENT, "sub": sub,
        "email": email, "email_verified": verified, "nonce": nonce,
        "iat": now(), "exp": now() + 3600})
}

struct T {
    router: Router,
    pool: PgPool,
    mock: M,
    fake: String,
}

struct Res {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

impl Res {
    fn location(&self) -> &str {
        self.headers[header::LOCATION].to_str().unwrap()
    }
    fn query_after(&self, base: &str) -> HashMap<String, String> {
        let loc = self.location();
        let q = loc
            .strip_prefix(base)
            .and_then(|r| r.strip_prefix('?'))
            .unwrap_or_else(|| panic!("redirect {loc} not to {base}"));
        form_urlencoded::parse(q.as_bytes()).into_owned().collect()
    }
}

async fn setup(pool: PgPool, mode: &str) -> T {
    // RSA key generation is slow in debug builds; do it before any request can time out on it.
    keys();
    let mock: M = Arc::new(Mutex::new(Mock {
        gh_id: 4242,
        gh_emails: json!([
            {"email": "gh@example.test", "primary": true, "verified": true, "visibility": "private"},
            {"email": "other@example.test", "primary": false, "verified": true, "visibility": null}
        ]),
        g_claims: None,
        g_rogue_key: false,
        token_forms: vec![],
        g_nonce: String::new(),
        g_id_token: String::new(),
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let fake = format!("http://{}", listener.local_addr().unwrap());
    let app = fake_providers(mock.clone());
    // Ends with the test's runtime.
    tokio::spawn(async move { axum::serve(listener, app).await });
    let keys = SigningKeys::from_json(&json!([entry("k1", "active").0]).to_string()).unwrap();
    let u = |p: &str| format!("{fake}{p}");
    let config = Config::for_tests(&[
        ("RELAY_ORIGIN", ISS),
        ("SIGNUP_MODE", mode),
        ("GITHUB_CLIENT_ID", "gh-client"),
        ("GITHUB_CLIENT_SECRET", GH_SECRET),
        ("GITHUB_AUTHORIZE_URL", &u("/gh/authorize")),
        ("GITHUB_TOKEN_URL", &u("/gh/token")),
        ("GITHUB_API_URL", &u("/gh")),
        ("GOOGLE_CLIENT_ID", G_CLIENT),
        ("GOOGLE_CLIENT_SECRET", G_SECRET),
        ("GOOGLE_AUTHORIZE_URL", &u("/g/authorize")),
        ("GOOGLE_TOKEN_URL", &u("/g/token")),
        ("GOOGLE_JWKS_URL", &u("/g/certs")),
    ]);
    let accounts = AccountsState::new(pool.clone(), Arc::new(keys), &config);
    let router = oauth::router(accounts.clone()).merge(router(accounts, &config));
    T {
        router,
        pool,
        mock,
        fake,
    }
}

impl T {
    async fn get(&self, uri: &str, cookie: Option<&str>) -> Res {
        let mut r = Request::get(uri);
        if let Some(c) = cookie {
            r = r.header(header::COOKIE, c);
        }
        let res = self
            .router
            .clone()
            .oneshot(r.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = res.status();
        let headers = res.headers().clone();
        let body = res.into_body().collect().await.unwrap().to_bytes();
        Res {
            status,
            headers,
            body: String::from_utf8(body.to_vec()).unwrap(),
        }
    }

    /// `/oauth/authorize` for the CLI, then `/auth/<p>`: the browser cookie and the query the
    /// relay sent to the provider's authorize URL.
    async fn begin(&self, p: &str) -> (String, HashMap<String, String>) {
        let q = form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("response_type", "code"),
                ("client_id", CLI),
                ("redirect_uri", CLI_REDIRECT),
                ("code_challenge", &"A".repeat(43)),
                ("code_challenge_method", "S256"),
                ("state", "client-state"),
            ])
            .finish();
        let page = self.get(&format!("/oauth/authorize?{q}"), None).await;
        assert_eq!(page.status, StatusCode::OK, "{}", page.body);
        let set = page.headers[header::SET_COOKIE].to_str().unwrap();
        let cookie = set.split(';').next().unwrap().to_owned();
        let res = self.get(&format!("/auth/{p}"), Some(&cookie)).await;
        assert_eq!(res.status, StatusCode::SEE_OTHER, "{}", res.body);
        let short = if p == "github" { "gh" } else { "g" };
        let sent = res.query_after(&format!("{}/{short}/authorize", self.fake));
        if p == "google" {
            self.mock.lock().unwrap().g_nonce = sent["nonce"].clone();
        }
        (cookie, sent)
    }

    async fn callback(&self, p: &str, cookie: &str, code: &str, state: &str) -> Res {
        let q = form_urlencoded::Serializer::new(String::new())
            .extend_pairs([("code", code), ("state", state)])
            .finish();
        self.get(&format!("/auth/{p}/callback?{q}"), Some(cookie))
            .await
    }

    /// Full browser round trip through provider `p` with the code the fake accepts.
    async fn sign_in(&self, p: &str) -> Res {
        let (cookie, sent) = self.begin(p).await;
        let code = if p == "github" { "gh-code" } else { "g-code" };
        self.callback(p, &cookie, code, &sent["state"]).await
    }

    async fn count(&self, sql: &str) -> i64 {
        sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_owned()))
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }

    fn token_calls(&self) -> usize {
        self.mock.lock().unwrap().token_forms.len()
    }
}

/// The sign-in reached the client with a code and its own state.
fn assert_signed_in(res: &Res) {
    assert_eq!(res.status, StatusCode::SEE_OTHER, "{}", res.body);
    let q = res.query_after(CLI_REDIRECT);
    assert_eq!(q["state"], "client-state");
    assert!(!q["code"].is_empty());
}

#[sqlx::test]
async fn github_signs_in_with_the_primary_verified_email(pool: PgPool) {
    let t = setup(pool, "open").await;
    let (cookie, sent) = t.begin("github").await;
    assert_eq!(sent["client_id"], "gh-client");
    assert_eq!(sent["scope"], "read:user user:email");
    assert_eq!(sent["redirect_uri"], format!("{ISS}/auth/github/callback"));
    assert_eq!(sent["code_challenge_method"], "S256");
    let res = t
        .callback("github", &cookie, "gh-code", &sent["state"])
        .await;
    assert_signed_in(&res);
    let form = t.mock.lock().unwrap().token_forms[0].clone();
    assert_eq!(form["client_secret"], GH_SECRET);
    assert_eq!(form["redirect_uri"], sent["redirect_uri"]);
    // The verifier the relay sends back matches the challenge it sent first.
    let verifier = &form["code_verifier"];
    assert_eq!(
        URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())),
        sent["code_challenge"]
    );
    let row: (String, String) = sqlx::query_as(
        "SELECT i.provider_user_id, u.email::text FROM identities i JOIN users u ON u.id = i.user_id
         WHERE i.provider = 'github'",
    )
    .fetch_one(&t.pool)
    .await
    .unwrap();
    assert_eq!(row, ("4242".into(), "gh@example.test".into()));
}

#[sqlx::test]
async fn github_refuses_unverified_or_non_primary_emails(pool: PgPool) {
    let t = setup(pool, "open").await;
    for emails in [
        json!([{"email": "gh@example.test", "primary": true, "verified": false}]),
        json!([
            {"email": "gh@example.test", "primary": true, "verified": false},
            {"email": "other@example.test", "primary": false, "verified": true}
        ]),
        json!([]),
    ] {
        t.mock.lock().unwrap().gh_emails = emails;
        let res = t.sign_in("github").await;
        assert_eq!(res.status, StatusCode::FORBIDDEN);
        assert!(res.body.contains("Email not verified"), "{}", res.body);
    }
    assert_eq!(t.count("SELECT count(*) FROM users").await, 0);
    assert_eq!(t.count("SELECT count(*) FROM auth_codes").await, 0);
}

#[sqlx::test]
async fn github_links_to_the_existing_user_by_verified_email(pool: PgPool) {
    let t = setup(pool, "allowlist").await;
    let user: uuid::Uuid =
        sqlx::query_scalar("INSERT INTO users (email) VALUES ('GH@example.test') RETURNING id")
            .fetch_one(&t.pool)
            .await
            .unwrap();
    assert_signed_in(&t.sign_in("github").await);
    let linked: uuid::Uuid =
        sqlx::query_scalar("SELECT user_id FROM identities WHERE provider = 'github'")
            .fetch_one(&t.pool)
            .await
            .unwrap();
    assert_eq!(linked, user);
    assert_eq!(t.count("SELECT count(*) FROM users").await, 1);
}

#[sqlx::test]
async fn second_github_account_with_another_email_is_a_second_user(pool: PgPool) {
    let t = setup(pool, "open").await;
    assert_signed_in(&t.sign_in("github").await);
    {
        let mut m = t.mock.lock().unwrap();
        m.gh_id = 777;
        m.gh_emails = json!([{"email": "second@example.test", "primary": true, "verified": true}]);
    }
    assert_signed_in(&t.sign_in("github").await);
    assert_eq!(t.count("SELECT count(*) FROM users").await, 2);
    assert_eq!(
        t.count("SELECT count(DISTINCT user_id) FROM identities")
            .await,
        2
    );
}

#[sqlx::test]
async fn allowlist_mode_refuses_an_unlisted_provider_email(pool: PgPool) {
    let t = setup(pool, "allowlist").await;
    for p in ["github", "google"] {
        let res = t.sign_in(p).await;
        assert_eq!(res.status, StatusCode::FORBIDDEN, "{p}");
        assert!(res.body.contains("invite-only"), "{}", res.body);
    }
    assert_eq!(t.count("SELECT count(*) FROM users").await, 0);
}

#[sqlx::test]
async fn tampered_or_foreign_state_is_refused_before_any_exchange(pool: PgPool) {
    let t = setup(pool, "open").await;
    let (cookie, sent) = t.begin("github").await;
    let (other_cookie, other_sent) = t.begin("github").await;
    let mut tampered = sent["state"].clone();
    tampered.replace_range(0..1, if tampered.starts_with('0') { "1" } else { "0" });
    for (c, st) in [
        (&cookie, tampered.as_str()),
        (&cookie, ""),
        // A state from another browser's sign-in (login CSRF / session swap).
        (&cookie, other_sent["state"].as_str()),
        (&other_cookie, sent["state"].as_str()),
    ] {
        let res = t.callback("github", c, "gh-code", st).await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST, "{st}");
        assert!(res.body.contains("did not start in this browser"));
    }
    let res = t
        .get("/auth/github/callback?code=gh-code", Some(&cookie))
        .await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    assert_eq!(t.token_calls(), 0, "no code exchange on a bad state");
    // No cookie at all: the sign-in is gone.
    let q = format!("code=gh-code&state={}", sent["state"]);
    let res = t.get(&format!("/auth/github/callback?{q}"), None).await;
    assert!(res.body.contains("Sign-in expired"));
    assert_eq!(t.count("SELECT count(*) FROM users").await, 0);
    // The real state still works afterwards.
    assert_signed_in(
        &t.callback("github", &cookie, "gh-code", &sent["state"])
            .await,
    );
}

#[sqlx::test]
async fn provider_error_or_refused_code_signs_nobody_in(pool: PgPool) {
    let t = setup(pool, "open").await;
    let (cookie, sent) = t.begin("github").await;
    // An error wins even if a code rides along.
    for extra in ["", "&code=gh-code"] {
        let q = format!("error=access_denied&state={}{extra}", sent["state"]);
        let res = t
            .get(&format!("/auth/github/callback?{q}"), Some(&cookie))
            .await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST);
        assert!(res.body.contains("Sign-in cancelled"));
    }
    assert_eq!(t.token_calls(), 0);
    for p in ["github", "google"] {
        let (cookie, sent) = t.begin(p).await;
        let res = t.callback(p, &cookie, "wrong-code", &sent["state"]).await;
        assert_eq!(res.status, StatusCode::BAD_GATEWAY, "{p}");
    }
    assert_eq!(t.count("SELECT count(*) FROM users").await, 0);
}

#[sqlx::test]
async fn google_signs_in_with_a_verified_id_token(pool: PgPool) {
    let t = setup(pool, "open").await;
    let (cookie, sent) = t.begin("google").await;
    assert_eq!(sent["scope"], "openid email profile");
    assert_eq!(sent["client_id"], G_CLIENT);
    assert_eq!(sent["redirect_uri"], format!("{ISS}/auth/google/callback"));
    assert_eq!(sent["nonce"].len(), 64);
    assert_ne!(sent["nonce"], sent["state"]);
    let res = t
        .callback("google", &cookie, "g-code", &sent["state"])
        .await;
    assert_signed_in(&res);
    let form = t.mock.lock().unwrap().token_forms[0].clone();
    assert_eq!(form["grant_type"], "authorization_code");
    assert_eq!(form["client_secret"], G_SECRET);
    assert_eq!(
        URL_SAFE_NO_PAD.encode(Sha256::digest(form["code_verifier"].as_bytes())),
        sent["code_challenge"]
    );
    let row: (String, String) = sqlx::query_as(
        "SELECT provider_user_id, email::text FROM identities WHERE provider = 'google'",
    )
    .fetch_one(&t.pool)
    .await
    .unwrap();
    assert_eq!(row, ("g-sub-1".into(), "g@example.test".into()));
}

impl T {
    /// Google sign-in with `email` and optional `hd`, for an existing user with that email.
    async fn google_as(&self, sub: &str, email: &str, hd: Option<&str>) -> Res {
        let (cookie, sent) = self.begin("google").await;
        let mut c = google_claims(&sent["nonce"], sub, email, true);
        if let Some(hd) = hd {
            c["hd"] = json!(hd);
        }
        self.mock.lock().unwrap().g_claims = Some(c);
        self.callback("google", &cookie, "g-code", &sent["state"])
            .await
    }
}

#[sqlx::test]
async fn google_links_by_email_only_where_it_is_authoritative(pool: PgPool) {
    let t = setup(pool, "open").await;
    assert_signed_in(&t.sign_in("github").await); // user gh@example.test
    for email in [
        "ws@corp.test",
        "Someone@Gmail.com",
        "old@googlemail.com",
        "plain@example.test",
        "other-hd@corp.test",
        "empty-hd@corp.test",
    ] {
        sqlx::query("INSERT INTO users (email) VALUES ($1)")
            .bind(email.to_lowercase())
            .execute(&t.pool)
            .await
            .unwrap();
    }
    let linked = [
        ("ws@corp.test", Some("corp.test")),
        ("Someone@Gmail.com", None),
        ("old@googlemail.com", None),
        ("GH@example.test", Some("EXAMPLE.test")),
    ];
    for (i, (email, hd)) in linked.into_iter().enumerate() {
        assert_signed_in(&t.google_as(&format!("link-{i}"), email, hd).await);
    }
    let refused = [
        ("plain@example.test", None),
        ("other-hd@corp.test", Some("elsewhere.test")),
        ("empty-hd@corp.test", Some("")),
        ("gh@example.test", None),
    ];
    for (i, (email, hd)) in refused.into_iter().enumerate() {
        let res = t.google_as(&format!("nolink-{i}"), email, hd).await;
        assert_eq!(res.status, StatusCode::FORBIDDEN, "{email}");
        assert!(
            res.body.contains("already has a Vekrel account"),
            "{}",
            res.body
        );
    }
    assert_eq!(t.count("SELECT count(*) FROM users").await, 7);
    assert_eq!(
        t.count("SELECT count(*) FROM identities WHERE provider = 'google'")
            .await,
        4
    );
    assert_eq!(
        t.count("SELECT count(*) FROM identities WHERE provider_user_id LIKE 'nolink-%'")
            .await,
        0
    );
}

#[sqlx::test]
async fn google_non_authoritative_email_signs_up_and_returns(pool: PgPool) {
    let t = setup(pool, "open").await;
    assert_signed_in(&t.google_as("g-new", "fresh@example.test", None).await);
    // The same Google account (sub) signs back in although its email now has a user.
    assert_signed_in(&t.google_as("g-new", "fresh@example.test", None).await);
    assert_eq!(t.count("SELECT count(*) FROM users").await, 1);
    // A second Google account claiming that email may not take it over.
    let res = t.google_as("g-other", "fresh@example.test", None).await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);
    assert_eq!(t.count("SELECT count(*) FROM identities").await, 1);
}

#[sqlx::test]
async fn google_refuses_bad_id_tokens(pool: PgPool) {
    let t = setup(pool, "open").await;
    type Edit = fn(&mut Value);
    let cases: [(&str, Edit, StatusCode); 8] = [
        (
            "unverified",
            |c| c["email_verified"] = json!(false),
            StatusCode::FORBIDDEN,
        ),
        (
            "no email_verified",
            |c| {
                c.as_object_mut().unwrap().remove("email_verified");
            },
            StatusCode::FORBIDDEN,
        ),
        (
            "no email",
            |c| {
                c.as_object_mut().unwrap().remove("email");
            },
            StatusCode::FORBIDDEN,
        ),
        (
            "wrong nonce",
            |c| c["nonce"] = json!("0".repeat(64)),
            StatusCode::BAD_GATEWAY,
        ),
        (
            "no nonce",
            |c| {
                c.as_object_mut().unwrap().remove("nonce");
            },
            StatusCode::BAD_GATEWAY,
        ),
        (
            "wrong aud",
            |c| c["aud"] = json!("someone-else.apps.googleusercontent.test"),
            StatusCode::BAD_GATEWAY,
        ),
        (
            "wrong iss",
            |c| c["iss"] = json!("https://evil.example.test"),
            StatusCode::BAD_GATEWAY,
        ),
        (
            "expired",
            |c| {
                c["exp"] = json!(now() - 600);
                c["iat"] = json!(now() - 4200);
            },
            StatusCode::BAD_GATEWAY,
        ),
    ];
    for (name, edit, status) in cases {
        let (cookie, sent) = t.begin("google").await;
        let mut c = google_claims(&sent["nonce"], "g-sub-1", "g@example.test", true);
        edit(&mut c);
        t.mock.lock().unwrap().g_claims = Some(c);
        let res = t
            .callback("google", &cookie, "g-code", &sent["state"])
            .await;
        assert_eq!(res.status, status, "{name}: {}", res.body);
    }
    // Signed by a key Google's JWKS does not have.
    {
        let mut m = t.mock.lock().unwrap();
        m.g_claims = None;
        m.g_rogue_key = true;
    }
    let res = t.sign_in("google").await;
    assert_eq!(res.status, StatusCode::BAD_GATEWAY, "rogue key");
    assert_eq!(t.count("SELECT count(*) FROM users").await, 0);
    // `accounts.google.com` without the scheme is a documented Google issuer.
    t.mock.lock().unwrap().g_rogue_key = false;
    let (cookie, sent) = t.begin("google").await;
    let mut c = google_claims(&sent["nonce"], "g-sub-1", "g@example.test", true);
    c["iss"] = json!("accounts.google.com");
    t.mock.lock().unwrap().g_claims = Some(c);
    assert_signed_in(
        &t.callback("google", &cookie, "g-code", &sent["state"])
            .await,
    );
}

#[sqlx::test]
async fn unconfigured_provider_is_unavailable(pool: PgPool) {
    let keys = SigningKeys::from_json(&json!([entry("k1", "active").0]).to_string()).unwrap();
    let config = Config::for_tests(&[("RELAY_ORIGIN", ISS)]);
    let accounts = AccountsState::new(pool, Arc::new(keys), &config);
    let r = router(accounts, &config);
    for uri in ["/auth/github", "/auth/google/callback?code=x&state=y"] {
        let res = r
            .clone()
            .oneshot(Request::get(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE, "{uri}");
    }
}

#[sqlx::test]
async fn provider_secrets_never_reach_the_logs(pool: PgPool) {
    crate::test_logs::capture_logs(|| ());
    let t = setup(pool, "open").await;
    let (cookie, gh) = t.begin("github").await;
    let gh_res = t.callback("github", &cookie, "gh-code", &gh["state"]).await;
    let (cookie, g) = t.begin("google").await;
    let g_res = t.callback("google", &cookie, "g-code", &g["state"]).await;
    // Failure paths log too.
    t.mock.lock().unwrap().gh_emails = json!([]);
    t.sign_in("github").await;
    let (cookie, bad) = t.begin("google").await;
    t.callback("google", &cookie, "g-code", "tampered").await;
    t.callback("google", &cookie, "wrong-code", &bad["state"])
        .await;
    let logs = crate::test_logs::capture_logs(|| ());
    assert!(logs.contains("sign-in completed"), "{logs}");
    assert!(logs.contains("no verified email"), "{logs}");
    assert!(logs.contains("provider sign-in failed"), "{logs}");
    let (gh_verifier, g_verifier, g_id_token) = {
        let m = t.mock.lock().unwrap();
        (
            m.token_forms[0]["code_verifier"].clone(),
            m.token_forms[1]["code_verifier"].clone(),
            m.g_id_token.clone(),
        )
    };
    let mut secrets = vec![
        GH_SECRET.to_owned(),
        G_SECRET.to_owned(),
        GH_TOKEN.to_owned(),
        G_ACCESS.to_owned(),
        g_id_token,
        gh_verifier,
        g_verifier,
        gh["state"].clone(),
        g["nonce"].clone(),
        cookie.split('=').nth(1).unwrap().to_owned(),
    ];
    for r in [&gh_res, &g_res] {
        secrets.push(r.query_after(CLI_REDIRECT)["code"].clone());
    }
    for s in secrets {
        assert!(!s.is_empty());
        assert!(!logs.contains(&s), "secret in logs: {s}");
    }
    // Provider codes are short in the fake; check them as query values.
    assert!(
        !logs.contains("gh-code") && !logs.contains("g-code"),
        "{logs}"
    );
}
