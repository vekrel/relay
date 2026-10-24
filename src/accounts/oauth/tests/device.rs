// RFC 8628 device grant end to end (plan 6A Task 8), with the test identity provider.
use super::*;

const UA: &str = "vekrel-engine 1.0 (test host)";
const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

fn device_app(pool: PgPool, mode: &str) -> App {
    let mut a = app_with(pool, mode);
    a.router = a
        .router
        .merge(crate::accounts::device::router(a.state.clone()));
    a
}

impl App {
    async fn device_start(&self) -> Value {
        let res = self
            .post(
                "/oauth/device_authorization",
                &[
                    ("client_id", CLI),
                    ("scope", "openid profile email offline_access"),
                ],
                &[("user-agent", UA)],
            )
            .await;
        assert_eq!(res.status, StatusCode::OK, "{}", res.body);
        res.json()
    }

    async fn poll(&self, device_code: &str) -> Res {
        self.post(
            "/oauth/token",
            &[
                ("grant_type", DEVICE_GRANT),
                ("device_code", device_code),
                ("client_id", CLI),
            ],
            &[],
        )
        .await
    }

    /// Lets the next poll through the interval check.
    async fn wait_interval(&self) {
        sqlx::query(
            "UPDATE device_codes SET last_polled_at = last_polled_at - interval '1 minute'",
        )
        .execute(&self.state.pool)
        .await
        .unwrap();
    }

    /// `/device?user_code=…`, sign-in through the test provider, back to `/device/callback`.
    async fn device_sign_in(&self, user_code: &str, email: &str) -> Res {
        let page = self
            .get(&format!("/device?user_code={user_code}"), None)
            .await;
        assert_eq!(page.status, StatusCode::OK, "{}", page.body);
        assert!(page.body.contains("Sign in to Vekrel"));
        let verifier = page.cookie("vekrel_device_verifier");
        let request = page.cookie("vekrel_auth_request");
        let back = self
            .get(
                &format!("/auth/test?sub=sub-{email}&email={email}"),
                Some(&format!("vekrel_auth_request={request}")),
            )
            .await;
        if back.status != StatusCode::SEE_OTHER {
            return back;
        }
        let q = back.redirect_query(&format!("{ISS}/device/callback"));
        let query = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(&q)
            .finish();
        self.get(
            &format!("/device/callback?{query}"),
            Some(&format!("vekrel_device_verifier={verifier}")),
        )
        .await
    }

    async fn answer(&self, approval: &str, action: &str) -> Res {
        self.post(
            "/device/confirm",
            &[("approval", approval), ("action", action)],
            &[],
        )
        .await
    }

    /// Signs in and answers; returns the confirm page's response.
    async fn device_answer(&self, user_code: &str, email: &str, action: &str) -> Res {
        let page = self.device_sign_in(user_code, email).await;
        assert_eq!(page.status, StatusCode::OK, "{}", page.body);
        self.answer(&approval_of(&page), action).await
    }
}

fn approval_of(page: &Res) -> String {
    page.body
        .split(r#"name="approval" value=""#)
        .nth(1)
        .and_then(|r| r.split('"').next())
        .unwrap_or_else(|| panic!("no approval in {}", page.body))
        .to_owned()
}

fn s(v: &Value, k: &str) -> String {
    v[k].as_str().unwrap().to_owned()
}

async fn status(pool: &PgPool) -> String {
    sqlx::query_scalar("SELECT status FROM device_codes")
        .fetch_one(pool)
        .await
        .unwrap()
}

#[sqlx::test]
async fn authorization_response_follows_rfc_8628(pool: PgPool) {
    let a = device_app(pool, "open");
    let res = a
        .post(
            "/oauth/device_authorization",
            &[("client_id", CLI), ("scope", "openid")],
            &[("user-agent", UA)],
        )
        .await;
    assert_eq!(res.headers[header::CACHE_CONTROL], "no-store");
    let d = res.json();
    let keys: Vec<&str> = d.as_object().unwrap().keys().map(|k| k.as_str()).collect();
    assert_eq!(
        keys,
        [
            "device_code",
            "user_code",
            "verification_uri",
            "verification_uri_complete",
            "expires_in",
            "interval"
        ]
    );
    let user_code = s(&d, "user_code");
    let (left, right) = user_code.split_once('-').unwrap();
    for half in [left, right] {
        assert_eq!(half.len(), 4);
        assert!(half.bytes().all(|b| b"BCDFGHJKLMNPQRSTVWXZ".contains(&b)));
    }
    assert_eq!(d["verification_uri"], format!("{ISS}/device"));
    assert_eq!(
        d["verification_uri_complete"],
        format!("{ISS}/device?user_code={user_code}")
    );
    assert_eq!(d["expires_in"], 600);
    assert_eq!(d["interval"], 5);
    // Only the hash is stored; the row lives 10 min and keeps the user agent for the prompt.
    let (stored, ttl, ua): (String, f64, String) = sqlx::query_as(
        "SELECT device_code_hash, extract(epoch FROM expires_at - created_at)::float8, user_agent
         FROM device_codes",
    )
    .fetch_one(&a.state.pool)
    .await
    .unwrap();
    assert_eq!(stored, hash(&s(&d, "device_code")));
    assert_eq!(ttl, 600.0);
    assert_eq!(ua, UA);
}

#[sqlx::test]
async fn only_the_cli_client_may_start(pool: PgPool) {
    let a = device_app(pool, "open");
    for (client, error) in [
        ("vekrel-web", "unauthorized_client"),
        ("vekrel-mobile", "unauthorized_client"),
        ("vekrel-device", "invalid_client"),
        ("nope", "invalid_client"),
    ] {
        let res = a
            .post("/oauth/device_authorization", &[("client_id", client)], &[])
            .await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST);
        assert_eq!(res.json()["error"], error, "{client}");
    }
    assert_eq!(count(&a.state.pool, "device_codes").await, 0);
}

#[sqlx::test]
async fn approve_issues_tokens_once(pool: PgPool) {
    let a = device_app(pool, "open");
    let d = a.device_start().await;
    let dc = s(&d, "device_code");
    assert_eq!(a.poll(&dc).await.json()["error"], "authorization_pending");
    // Typed in lower case without the dash; it still matches.
    let typed = s(&d, "user_code").replace('-', "").to_lowercase();
    let page = a.device_sign_in(&typed, "a@example.test").await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    assert!(
        page.body
            .contains("<h1>Approve sign-in for Vekrel CLI?</h1>"),
        "{}",
        page.body
    );
    assert!(
        page.body
            .contains("Check this matches the code in your terminal")
    );
    let requested: String = sqlx::query_scalar(
        "SELECT to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI') FROM device_codes",
    )
    .fetch_one(&a.state.pool)
    .await
    .unwrap();
    assert!(
        page.body.contains(&format!("Requested {requested} UTC")),
        "{}",
        page.body
    );
    assert!(
        page.body
            .contains("Reported by the device (unverified): vekrel-engine 1.0 (test host)"),
        "{}",
        page.body
    );
    assert!(page.body.contains("a@example.test"));
    assert!(page.body.contains(&s(&d, "user_code")));
    // Signing in alone approves nothing.
    a.wait_interval().await;
    assert_eq!(a.poll(&dc).await.json()["error"], "authorization_pending");
    let done = a.answer(&approval_of(&page), "approve").await;
    assert_eq!(done.status, StatusCode::OK);
    assert!(done.body.contains("Sign-in approved"));
    a.wait_interval().await;
    let t = a.poll(&dc).await;
    assert_eq!(t.status, StatusCode::OK, "{}", t.body);
    assert_eq!(t.headers[header::CACHE_CONTROL], "no-store");
    let t = t.json();
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
    let claims = payload(t["access_token"].as_str().unwrap());
    assert_eq!(claims["client_id"], CLI);
    assert_eq!(claims["email"], "a@example.test");
    assert_eq!(
        a.whoami(t["access_token"].as_str().unwrap()).await,
        StatusCode::OK
    );
    assert_eq!(
        a.refresh(t["refresh_token"].as_str().unwrap()).await.status,
        StatusCode::OK
    );
    // Redeemed once: the next poll, slow or not, gets invalid_grant.
    a.wait_interval().await;
    assert_eq!(a.poll(&dc).await.json()["error"], "invalid_grant");
    assert_eq!(a.poll(&dc).await.json()["error"], "invalid_grant");
    // The answer cannot be replayed onto the used code.
    let again = a.answer(&approval_of(&page), "approve").await;
    assert_eq!(again.status, StatusCode::BAD_REQUEST);
    assert_eq!(status(&a.state.pool).await, "consumed");
}

#[sqlx::test]
async fn concurrent_polls_issue_tokens_once(pool: PgPool) {
    let a = device_app(pool, "open");
    let d = a.device_start().await;
    let dc = s(&d, "device_code");
    a.device_answer(&s(&d, "user_code"), "a@example.test", "approve")
        .await;
    let rs = tokio::join!(
        a.poll(&dc),
        a.poll(&dc),
        a.poll(&dc),
        a.poll(&dc),
        a.poll(&dc),
        a.poll(&dc)
    );
    let rs = [rs.0, rs.1, rs.2, rs.3, rs.4, rs.5];
    let ok = rs.iter().filter(|r| r.status == StatusCode::OK).count();
    assert_eq!(ok, 1);
    assert_eq!(count(&a.state.pool, "refresh_tokens").await, 1);
}

#[sqlx::test]
async fn polling_too_fast_gets_slow_down_and_a_longer_interval(pool: PgPool) {
    let a = device_app(pool, "open");
    let dc = s(&a.device_start().await, "device_code");
    assert_eq!(a.poll(&dc).await.json()["error"], "authorization_pending");
    assert_eq!(a.poll(&dc).await.json()["error"], "slow_down");
    let interval: i32 = sqlx::query_scalar("SELECT interval_seconds FROM device_codes")
        .fetch_one(&a.state.pool)
        .await
        .unwrap();
    assert_eq!(interval, 10);
    // 6 s later is fine for the old 5 s interval but not the new 10 s one.
    sqlx::query("UPDATE device_codes SET last_polled_at = now() - interval '6 seconds'")
        .execute(&a.state.pool)
        .await
        .unwrap();
    assert_eq!(a.poll(&dc).await.json()["error"], "slow_down");
    sqlx::query("UPDATE device_codes SET last_polled_at = now() - interval '16 seconds'")
        .execute(&a.state.pool)
        .await
        .unwrap();
    assert_eq!(a.poll(&dc).await.json()["error"], "authorization_pending");
}

#[sqlx::test]
async fn expired_code_gets_expired_token(pool: PgPool) {
    let a = device_app(pool, "open");
    let d = a.device_start().await;
    let dc = s(&d, "device_code");
    let page = a
        .device_sign_in(&s(&d, "user_code"), "a@example.test")
        .await;
    sqlx::query("UPDATE device_codes SET expires_at = now() - interval '1 second'")
        .execute(&a.state.pool)
        .await
        .unwrap();
    assert_eq!(a.poll(&dc).await.json()["error"], "expired_token");
    // An expired code is not offered for approval, and an earlier prompt cannot approve it.
    let fresh = a
        .device_sign_in(&s(&d, "user_code"), "a@example.test")
        .await;
    assert_eq!(fresh.status, StatusCode::BAD_REQUEST);
    assert!(fresh.body.contains("Code not valid"));
    let late = a.answer(&approval_of(&page), "approve").await;
    assert_eq!(late.status, StatusCode::BAD_REQUEST);
    assert_eq!(a.poll(&dc).await.json()["error"], "expired_token");
}

#[sqlx::test]
async fn deny_gets_access_denied(pool: PgPool) {
    let a = device_app(pool, "open");
    let d = a.device_start().await;
    let dc = s(&d, "device_code");
    let res = a
        .device_answer(&s(&d, "user_code"), "a@example.test", "deny")
        .await;
    assert!(res.body.contains("Sign-in denied"));
    assert_eq!(a.poll(&dc).await.json()["error"], "access_denied");
    a.wait_interval().await;
    assert_eq!(a.poll(&dc).await.json()["error"], "access_denied");
    assert_eq!(count(&a.state.pool, "refresh_tokens").await, 0);
}

#[sqlx::test]
async fn unknown_or_foreign_device_code_is_invalid_grant(pool: PgPool) {
    let a = device_app(pool, "open");
    let dc = s(&a.device_start().await, "device_code");
    assert_eq!(a.poll("not-a-code").await.json()["error"], "invalid_grant");
    let other = a
        .post(
            "/oauth/token",
            &[
                ("grant_type", DEVICE_GRANT),
                ("device_code", &dc),
                ("client_id", "vekrel-mobile"),
            ],
            &[],
        )
        .await;
    assert_eq!(other.json()["error"], "invalid_grant");
    let missing = a
        .post(
            "/oauth/token",
            &[("grant_type", DEVICE_GRANT), ("client_id", CLI)],
            &[],
        )
        .await;
    assert_eq!(missing.json()["error"], "invalid_request");
}

#[sqlx::test]
async fn approval_needs_a_signed_in_user_and_a_real_confirm(pool: PgPool) {
    let a = device_app(pool, "open");
    let d = a.device_start().await;
    let dc = s(&d, "device_code");
    let user_code = s(&d, "user_code");
    // No approval, a forged one, and an account access token in its place.
    let t = a.login("b@example.test").await;
    for forged in ["", "x.y.z", t["access_token"].as_str().unwrap()] {
        let res = a.answer(forged, "approve").await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST, "{forged}");
    }
    // An approval from a key the relay does not hold.
    let foreign = SigningKeys::from_json(&json!([entry("k1", "active").0]).to_string()).unwrap();
    let now = tokens::now_secs();
    let forged = tokens::sign(
        &foreign,
        "vekrel-device-approval+jwt",
        &json!({"iss": ISS, "aud": "vekrel-device", "sub": Uuid::new_v4().to_string(),
                "user_code": user_code.replace('-', ""), "iat": now, "exp": now + 300}),
    );
    assert_eq!(
        a.answer(&forged, "approve").await.status,
        StatusCode::BAD_REQUEST
    );
    // Signed in, but no explicit action.
    let page = a.device_sign_in(&user_code, "a@example.test").await;
    for action in ["", "yes"] {
        assert_eq!(
            a.answer(&approval_of(&page), action).await.status,
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(status(&a.state.pool).await, "pending");
    a.wait_interval().await;
    assert_eq!(a.poll(&dc).await.json()["error"], "authorization_pending");
}

#[sqlx::test]
async fn callback_needs_this_browsers_verifier(pool: PgPool) {
    let a = device_app(pool, "open");
    let d = a.device_start().await;
    let page = a
        .get(&format!("/device?user_code={}", s(&d, "user_code")), None)
        .await;
    let request = page.cookie("vekrel_auth_request");
    let back = a
        .get(
            "/auth/test?sub=s&email=a@example.test",
            Some(&format!("vekrel_auth_request={request}")),
        )
        .await;
    let loc = back.headers[header::LOCATION].to_str().unwrap();
    let path = loc.strip_prefix(ISS).unwrap();
    for cookie in [None, Some("vekrel_device_verifier=someone-elses-verifier")] {
        let res = a.get(path, cookie).await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST);
        assert!(res.body.contains("Sign-in expired"));
        assert!(!res.body.contains("approval"));
    }
    // The browser leg's code is not an OAuth code for any client.
    let code = back.redirect_query(&format!("{ISS}/device/callback"))["code"].clone();
    for client in ["vekrel-device", CLI] {
        let res = a
            .post(
                "/oauth/token",
                &[
                    ("grant_type", "authorization_code"),
                    ("code", &code),
                    ("redirect_uri", &format!("{ISS}/device/callback")),
                    ("client_id", client),
                    ("code_verifier", &random_secret()),
                ],
                &[],
            )
            .await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST);
    }
    let (_, c) = pkce();
    let res = a
        .authorize("vekrel-device", &format!("{ISS}/device/callback"), &c)
        .await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    assert!(res.headers.get(header::LOCATION).is_none());
}

#[sqlx::test]
async fn allowlist_and_disabled_checks_apply(pool: PgPool) {
    let a = device_app(pool, "allowlist");
    let d = a.device_start().await;
    let res = a
        .device_sign_in(&s(&d, "user_code"), "stranger@example.test")
        .await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);
    assert!(res.body.contains("invite-only"));
    assert_eq!(count(&a.state.pool, "users").await, 0);
    assert_eq!(status(&a.state.pool).await, "pending");

    sqlx::query("INSERT INTO signup_allowlist (email) VALUES ('friend@example.test')")
        .execute(&a.state.pool)
        .await
        .unwrap();
    let dc = s(&d, "device_code");
    a.device_answer(&s(&d, "user_code"), "friend@example.test", "approve")
        .await;
    // Disabled between approval and the poll: no tokens.
    sqlx::query("UPDATE users SET disabled_at = now()")
        .execute(&a.state.pool)
        .await
        .unwrap();
    let res = a.poll(&dc).await;
    assert_eq!(res.json()["error"], "invalid_grant");
    assert_eq!(count(&a.state.pool, "refresh_tokens").await, 0);
    // A disabled user cannot sign in to approve a new code.
    let d2 = a.device_start().await;
    let res = a
        .device_sign_in(&s(&d2, "user_code"), "friend@example.test")
        .await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);
    assert!(res.body.contains("Account disabled"));
}

#[sqlx::test]
async fn code_guessing_is_bounded(pool: PgPool) {
    let a = device_app(pool, "open");
    // Malformed codes never reach sign-in.
    for bad in ["AAAA-AAAA", "BCDF", "BCDF-GHJK-L", "<script>"] {
        let q = form_urlencoded::Serializer::new(String::new())
            .append_pair("user_code", bad)
            .finish();
        let res = a.get(&format!("/device?{q}"), None).await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST, "{bad}");
        assert!(res.body.contains("not valid"));
        assert!(res.set_cookies().is_empty());
    }
    assert_eq!(count(&a.state.pool, "auth_requests").await, 0);
    // A wrong code costs a sign-in, and one account gets 10 lookups per 15 min.
    let d = a.device_start().await;
    let wrong = if s(&d, "user_code") == "BCDF-GHJK" {
        "BCDF-GHJL"
    } else {
        "BCDF-GHJK"
    };
    for _ in 0..10 {
        let res = a.device_sign_in(wrong, "guesser@example.test").await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST);
        assert!(res.body.contains("Code not valid"));
    }
    let res = a
        .device_sign_in(&s(&d, "user_code"), "guesser@example.test")
        .await;
    assert_eq!(res.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(!res.body.contains("approval"));
    // Another account is not affected.
    let res = a
        .device_sign_in(&s(&d, "user_code"), "owner@example.test")
        .await;
    assert_eq!(res.status, StatusCode::OK);
}

#[sqlx::test]
async fn entry_page_and_prompt_are_hardened(pool: PgPool) {
    let a = device_app(pool, "open");
    let page = a.get("/device", None).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.body.contains(r#"name="user_code""#));
    assert_eq!(page.headers[header::X_FRAME_OPTIONS], "DENY");
    assert_eq!(page.headers[header::CACHE_CONTROL], "no-store");
    // The user agent is the CLI's to choose: never in the heading, labelled, escaped, cut short.
    let ua = format!(
        "Vekrel Official <b>x</b><script>alert(1)</script>{}",
        "z".repeat(100)
    );
    let res = a
        .post(
            "/oauth/device_authorization",
            &[("client_id", CLI)],
            &[("user-agent", &ua)],
        )
        .await
        .json();
    let prompt = a
        .device_sign_in(&s(&res, "user_code"), "a@example.test")
        .await;
    let heading = prompt
        .body
        .split("<h1>")
        .nth(1)
        .and_then(|r| r.split("</h1>").next())
        .unwrap();
    assert_eq!(heading, "Approve sign-in for Vekrel CLI?");
    assert!(!prompt.body.contains("<script>"));
    assert!(!prompt.body.contains("<b>"));
    let shown = prompt
        .body
        .split("Reported by the device (unverified): ")
        .nth(1)
        .and_then(|r| r.split("</p>").next())
        .unwrap_or_else(|| panic!("no unverified label in {}", prompt.body));
    assert!(shown.starts_with("Vekrel Official "), "{shown}");
    assert!(shown.contains("alert(1)"), "{shown}");
    assert!(
        !shown.contains("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"),
        "{shown}"
    );
    assert_eq!(prompt.headers[header::X_FRAME_OPTIONS], "DENY");
    assert!(
        prompt.headers[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .contains("frame-ancestors 'none'")
    );
}

#[sqlx::test]
async fn device_secrets_never_reach_the_logs(pool: PgPool) {
    crate::test_logs::capture_logs(|| ());
    let a = device_app(pool, "open");
    let d = a.device_start().await;
    let dc = s(&d, "device_code");
    let page = a
        .device_sign_in(&s(&d, "user_code"), "a@example.test")
        .await;
    let approval = approval_of(&page);
    a.answer(&approval, "approve").await;
    let t = a.poll(&dc).await.json();
    let logs = crate::test_logs::capture_logs(|| ());
    assert!(logs.contains("device sign-in completed"), "{logs}");
    for secret in [
        dc,
        s(&d, "user_code"),
        s(&d, "user_code").replace('-', ""),
        approval,
        s(&t, "access_token"),
        s(&t, "refresh_token"),
    ] {
        assert!(!logs.contains(&secret), "secret in logs: {secret}");
    }
}

/// Fills `key`'s window as if `n` hits had just happened.
async fn fill(pool: &PgPool, key: &str, n: i32) {
    sqlx::query("INSERT INTO relay_rate_limits (key, window_start, count) VALUES ($1, now(), $2)")
        .bind(key)
        .bind(n)
        .execute(pool)
        .await
        .unwrap();
}

/// Per-IP limits on sign-in starts (`/oauth/authorize`, `/device`), `/oauth/token` and
/// `/oauth/device_authorization`; another address is not affected.
#[sqlx::test]
async fn sign_in_token_and_device_start_are_limited_per_ip(pool: PgPool) {
    let a = device_app(pool, "open");
    let p = &a.state.pool;
    let ip = TEST_PEER.ip();
    fill(p, &format!("authorize:ip:{ip}"), 60).await;
    fill(p, &format!("token:ip:{ip}"), 300).await;
    fill(p, &format!("device_authorization:ip:{ip}"), 10).await;
    let (_, c) = pkce();
    let res = a.authorize(CLI, CLI_REDIRECT, &c).await;
    assert_eq!(res.status, StatusCode::TOO_MANY_REQUESTS, "{}", res.body);
    let res = a.get("/device?user_code=BCDF-GHJK", None).await;
    assert_eq!(res.status, StatusCode::TOO_MANY_REQUESTS, "{}", res.body);
    let res = a.poll("whatever").await;
    assert_eq!(res.status, StatusCode::TOO_MANY_REQUESTS, "{}", res.body);
    // CliTokenManager backs off on slow_down (device polls) and treats 429 as transient (refresh).
    assert_eq!(res.json()["error"], "slow_down");
    let res = a
        .post("/oauth/device_authorization", &[("client_id", CLI)], &[])
        .await;
    assert_eq!(res.status, StatusCode::TOO_MANY_REQUESTS, "{}", res.body);
    assert_eq!(res.json()["error"], "slow_down");
    assert_eq!(count(p, "device_codes").await, 0);
    assert_eq!(count(p, "auth_requests").await, 0);
    // Another client address still gets through.
    let other = App {
        router: a
            .router
            .clone()
            .layer(axum::Extension(axum::extract::ConnectInfo(
                std::net::SocketAddr::from(([198, 51, 100, 7], 4000)),
            ))),
        state: a.state.clone(),
    };
    assert_eq!(
        other.authorize(CLI, CLI_REDIRECT, &c).await.status,
        StatusCode::OK
    );
    other.device_start().await;
    assert_eq!(
        other.poll("whatever").await.json()["error"],
        "invalid_grant"
    );
}

/// User-code lookups (`/device/callback`) are limited per IP as well as per user.
#[sqlx::test]
async fn device_code_lookups_are_limited_per_ip(pool: PgPool) {
    let a = device_app(pool, "open");
    let d = a.device_start().await;
    fill(
        &a.state.pool,
        &format!("device_lookup:ip:{}", TEST_PEER.ip()),
        20,
    )
    .await;
    let res = a
        .device_sign_in(&s(&d, "user_code"), "a@example.test")
        .await;
    assert_eq!(res.status, StatusCode::TOO_MANY_REQUESTS, "{}", res.body);
    assert!(!res.body.contains("approval"));
    // Refused before the browser leg's code is redeemed.
    let unused: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_codes WHERE used_at IS NULL")
        .fetch_one(&a.state.pool)
        .await
        .unwrap();
    assert_eq!(unused, 1);
}

/// The callback's `state` is the user code the sign-in started with; another one is refused.
#[sqlx::test]
async fn callback_state_is_bound_to_the_started_sign_in(pool: PgPool) {
    let a = device_app(pool, "open");
    let first = s(&a.device_start().await, "user_code");
    let second = s(&a.device_start().await, "user_code");
    let page = a.get(&format!("/device?user_code={first}"), None).await;
    let verifier = page.cookie("vekrel_device_verifier");
    let request = page.cookie("vekrel_auth_request");
    let back = a
        .get(
            "/auth/test?sub=s&email=a@example.test",
            Some(&format!("vekrel_auth_request={request}")),
        )
        .await;
    let mut q = back.redirect_query(&format!("{ISS}/device/callback"));
    q.insert("state".into(), second.replace('-', ""));
    let query = form_urlencoded::Serializer::new(String::new())
        .extend_pairs(&q)
        .finish();
    let res = a
        .get(
            &format!("/device/callback?{query}"),
            Some(&format!("vekrel_device_verifier={verifier}")),
        )
        .await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST, "{}", res.body);
    assert!(!res.body.contains("approval"), "{}", res.body);
}

/// A user disabled between the prompt and the answer cannot approve.
#[sqlx::test]
async fn confirm_refuses_a_user_disabled_after_the_prompt(pool: PgPool) {
    let a = device_app(pool, "open");
    let d = a.device_start().await;
    let page = a
        .device_sign_in(&s(&d, "user_code"), "a@example.test")
        .await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    sqlx::query("UPDATE users SET disabled_at = now()")
        .execute(&a.state.pool)
        .await
        .unwrap();
    let res = a.answer(&approval_of(&page), "approve").await;
    assert_eq!(res.status, StatusCode::FORBIDDEN, "{}", res.body);
    assert_eq!(status(&a.state.pool).await, "pending");
}
