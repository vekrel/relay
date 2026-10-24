// Outgoing email (plan 6A Task 7, owner decision 4: Resend in production, nothing sent in dev).
// Our own layer: T3 used Clerk for email sign-in. Callers build an `Email`; a `Mailer` sends it.
// Neither mailer logs the message body or the recipient (the body carries a sign-in secret).
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use serde::Serialize;

use crate::config::{MagicLinkTransport, Secret};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Email {
    pub to: String,
    pub subject: String,
    pub text: String,
    pub html: String,
}

pub type SendFuture<'a> = Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;

pub trait Mailer: Send + Sync {
    /// The error is safe to log: it never contains the message.
    fn send<'a>(&'a self, email: &'a Email) -> SendFuture<'a>;
}

pub fn from_transport(t: &MagicLinkTransport) -> Box<dyn Mailer> {
    match t {
        MagicLinkTransport::Log => Box::new(LogMailer),
        MagicLinkTransport::Resend {
            api_key,
            from,
            base_url,
        } => Box::new(ResendMailer::new(api_key.clone(), from, base_url)),
    }
}

/// Dev and staging: sends nothing. The sign-in page shows the link instead (`magic_link.rs`).
pub struct LogMailer;

impl Mailer for LogMailer {
    fn send<'a>(&'a self, email: &'a Email) -> SendFuture<'a> {
        tracing::info!(
            subject = %email.subject,
            "email not sent (MAGIC_LINK_TRANSPORT=log)"
        );
        Box::pin(async { Ok(()) })
    }
}

/// `POST {base_url}/emails` (https://resend.com/docs/api-reference/emails/send-email).
pub struct ResendMailer {
    client: reqwest::Client,
    api_key: Secret,
    from: String,
    endpoint: String,
}

#[derive(Serialize)]
struct ResendBody<'a> {
    from: &'a str,
    to: [&'a str; 1],
    subject: &'a str,
    html: &'a str,
    text: &'a str,
}

/// Inside the 9 s request deadline (`http::REQUEST_DEADLINE_MS`), so a slow send fails cleanly.
const SEND_TIMEOUT: Duration = Duration::from_secs(6);

impl ResendMailer {
    pub fn new(api_key: Secret, from: &str, base_url: &str) -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(SEND_TIMEOUT)
                // Resend refuses requests without a User-Agent.
                .user_agent(concat!("vekrel-relay/", env!("CARGO_PKG_VERSION")))
                .build()
                .expect("HTTP client"),
            api_key,
            from: from.to_owned(),
            endpoint: format!("{}/emails", base_url.trim_end_matches('/')),
        }
    }
}

impl Mailer for ResendMailer {
    fn send<'a>(&'a self, email: &'a Email) -> SendFuture<'a> {
        Box::pin(async move {
            let res = self
                .client
                .post(&self.endpoint)
                .bearer_auth(&self.api_key.0)
                .json(&ResendBody {
                    from: &self.from,
                    to: [&email.to],
                    subject: &email.subject,
                    html: &email.html,
                    text: &email.text,
                })
                .send()
                .await
                // without_url: the error text stays free of anything but the failure kind.
                .map_err(|e| format!("resend: {}", e.without_url()))?;
            if res.status().is_success() {
                Ok(())
            } else {
                // The response body is not logged: Resend may echo request fields back.
                Err(format!("resend: HTTP {}", res.status().as_u16()))
            }
        })
    }
}

/// A local stand-in for Resend: records each request, answers with a fixed status.
#[cfg(test)]
pub mod mock {
    use std::sync::{Arc, Mutex};

    use axum::Router;
    use axum::body::Bytes;
    use axum::extract::State;
    use axum::http::{HeaderMap, Method, StatusCode, Uri};
    use axum::routing::any;

    #[derive(Debug, Clone)]
    pub struct Captured {
        pub method: Method,
        pub path: String,
        pub headers: HeaderMap,
        pub body: serde_json::Value,
    }

    #[derive(Clone)]
    pub struct Mock {
        pub base_url: String,
        pub requests: Arc<Mutex<Vec<Captured>>>,
    }

    impl Mock {
        pub fn requests(&self) -> Vec<Captured> {
            self.requests.lock().unwrap().clone()
        }
    }

    pub async fn start(status: StatusCode) -> Mock {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new()
            .fallback(any(
                |State((reqs, status)): State<(Arc<Mutex<Vec<Captured>>>, StatusCode)>,
                 method: Method,
                 uri: Uri,
                 headers: HeaderMap,
                 body: Bytes| async move {
                    reqs.lock().unwrap().push(Captured {
                        method,
                        path: uri.path().to_owned(),
                        headers,
                        body: serde_json::from_slice(&body).unwrap_or_default(),
                    });
                    (status, r#"{"id":"49a3999c-0ce1-4ea6-ab68-afcd6dc2e794"}"#)
                },
            ))
            .with_state((requests.clone(), status));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Mock { base_url, requests }
    }
}

#[cfg(test)]
mod tests {
    /// A slow Resend must fail inside the relay's 9 s request deadline, not be cut off by it.
    #[test]
    fn send_timeout_is_inside_the_request_deadline() {
        assert!(
            super::SEND_TIMEOUT.as_millis() < u128::from(crate::http::REQUEST_DEADLINE_MS) - 2000
        );
    }
    use super::*;
    use axum::http::StatusCode;

    fn email() -> Email {
        Email {
            to: "someone@example.test".into(),
            subject: "Sign in to Vekrel".into(),
            text: "text body".into(),
            html: "<p>html body</p>".into(),
        }
    }

    #[tokio::test]
    async fn resend_request_matches_resend_api() {
        let mock = mock::start(StatusCode::OK).await;
        let m = ResendMailer::new(
            Secret("re_test_key".into()),
            "Vekrel <signin@example.test>",
            &format!("{}/", mock.base_url),
        );
        m.send(&email()).await.unwrap();
        let reqs = mock.requests();
        assert_eq!(reqs.len(), 1);
        let r = &reqs[0];
        assert_eq!(r.method, "POST");
        assert_eq!(r.path, "/emails");
        assert_eq!(r.headers["authorization"], "Bearer re_test_key");
        assert_eq!(r.headers["content-type"], "application/json");
        assert!(
            r.headers["user-agent"]
                .to_str()
                .unwrap()
                .starts_with("vekrel-relay/")
        );
        assert_eq!(
            r.body,
            serde_json::json!({
                "from": "Vekrel <signin@example.test>",
                "to": ["someone@example.test"],
                "subject": "Sign in to Vekrel",
                "html": "<p>html body</p>",
                "text": "text body",
            })
        );
    }

    #[tokio::test]
    async fn resend_error_status_is_an_error_without_the_message() {
        let mock = mock::start(StatusCode::UNPROCESSABLE_ENTITY).await;
        let m = ResendMailer::new(Secret("k".into()), "a@example.test", &mock.base_url);
        let err = m.send(&email()).await.unwrap_err();
        assert_eq!(err, "resend: HTTP 422");
    }

    #[tokio::test]
    async fn resend_unreachable_is_an_error() {
        let m = ResendMailer::new(Secret("k".into()), "a@example.test", "http://127.0.0.1:1");
        let err = m.send(&email()).await.unwrap_err();
        assert!(err.starts_with("resend: "), "{err}");
        assert!(!err.contains("127.0.0.1"), "{err}");
    }
}
