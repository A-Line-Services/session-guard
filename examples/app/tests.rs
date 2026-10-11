//! End-to-end tests of the example app, on the in-memory store.

use std::{net::SocketAddr, time::Duration};

use axum::{
    Router,
    body::Body,
    extract::ConnectInfo,
    http::{HeaderMap, Request, StatusCode, header},
    response::Response,
};
use chrono::{TimeZone, Utc};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use session_guard::{IpInfo, ManualClock, MemoryStore};
use tower::ServiceExt;

use crate::app::{config, router};

const CHROME_WIN: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";
const HOME: &str = "203.0.113.7";
/// Another network: a step-up on the strict routes, nothing on the others. (A country change
/// would revoke the session there outright.)
const ABROAD: &str = "198.51.100.20";
const LOGIN: &str = r#"{"username":"demo","password":"demo-password"}"#;

struct App {
    router: Router,
    clock: ManualClock,
}

fn app() -> App {
    let clock = ManualClock::new(Utc.with_ymd_and_hms(2026, 3, 1, 12, 0, 0).unwrap());
    let guard = config::builder(MemoryStore::new())
        .expect("valid configuration")
        .ip_intel(|_ip: std::net::IpAddr| IpInfo::new(Some("US".into()), None))
        .clock(clock.clone())
        .build();
    App {
        router: router(&guard),
        clock,
    }
}

struct Call {
    method: &'static str,
    path: String,
    body: Option<&'static str>,
    cookie: Option<String>,
    bearer: Option<&'static str>,
    peer: &'static str,
}

fn call(method: &'static str, path: &str) -> Call {
    Call {
        method,
        path: path.to_owned(),
        body: None,
        cookie: None,
        bearer: None,
        peer: HOME,
    }
}

impl Call {
    fn json(mut self, body: &'static str) -> Self {
        self.body = Some(body);
        self
    }
    fn cookie(mut self, pair: &str) -> Self {
        self.cookie = Some(pair.to_owned());
        self
    }
    fn bearer(mut self, token: &'static str) -> Self {
        self.bearer = Some(token);
        self
    }
    fn from(mut self, peer: &'static str) -> Self {
        self.peer = peer;
        self
    }
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

impl Reply {
    /// The `name=value` pair of the last `Set-Cookie`, if any.
    fn cookie_pair(&self) -> Option<String> {
        self.headers
            .get_all(header::SET_COOKIE)
            .iter()
            .next_back()
            .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_owned())
    }
    fn clears_cookie(&self) -> bool {
        self.headers
            .get_all(header::SET_COOKIE)
            .iter()
            .any(|v| v.to_str().unwrap().contains("Max-Age=0"))
    }
}

async fn send(app: &App, call: Call) -> Reply {
    let mut builder = Request::builder()
        .method(call.method)
        .uri(&call.path)
        .header(header::USER_AGENT, CHROME_WIN)
        .header("sec-ch-ua-platform", "\"Windows\"")
        .header("sec-ch-ua-mobile", "?0")
        .header(header::ACCEPT_LANGUAGE, "en-US");
    if let Some(cookie) = &call.cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    if let Some(token) = call.bearer {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    if call.body.is_some() {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
    }
    let mut request = builder.body(Body::from(call.body.unwrap_or_default())).unwrap();
    let addr = SocketAddr::new(call.peer.parse().unwrap(), 50_000);
    request.extensions_mut().insert(ConnectInfo(addr));

    let response: Response = app.router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    Reply {
        status,
        headers,
        body: String::from_utf8(bytes.to_vec()).unwrap(),
    }
}

async fn login(app: &App) -> String {
    let reply = send(app, call("POST", "/login").json(LOGIN)).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    reply.cookie_pair().expect("login sets the session cookie")
}

#[tokio::test]
async fn login_cookie_protected_route_logout() {
    let app = app();

    // Wrong password: the app's own check fails, no session, no cookie.
    let bad = send(
        &app,
        call("POST", "/login").json(r#"{"username":"demo","password":"nope"}"#),
    )
    .await;
    assert_eq!(bad.status, StatusCode::UNAUTHORIZED);
    assert_eq!(bad.body, r#"{"error":"invalid_credentials"}"#);
    assert_eq!(bad.cookie_pair(), None);

    // No cookie, no access.
    let anonymous = send(&app, call("GET", "/me")).await;
    assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);
    assert_eq!(anonymous.body, r#"{"error":"not_authenticated"}"#);

    let cookie = login(&app).await;
    assert!(cookie.starts_with("sid=sess_"), "{cookie}");
    let me = send(&app, call("GET", "/me").cookie(&cookie)).await;
    assert_eq!(me.status, StatusCode::OK);
    assert!(me.body.contains("00000000-0000-0000-0000-000000000001"), "{}", me.body);

    let out = send(&app, call("POST", "/logout").cookie(&cookie)).await;
    assert_eq!(out.status, StatusCode::OK);
    assert!(out.clears_cookie());

    let after = send(&app, call("GET", "/me").cookie(&cookie)).await;
    assert_eq!(after.status, StatusCode::UNAUTHORIZED);
    assert_eq!(after.body, r#"{"error":"not_authenticated"}"#);
}

#[tokio::test]
async fn login_replaces_the_presented_session() {
    let app = app();
    let first = login(&app).await;

    let reply = send(&app, call("POST", "/login").cookie(&first).json(LOGIN)).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);

    let old = send(&app, call("GET", "/me").cookie(&first)).await;
    assert_eq!(old.status, StatusCode::UNAUTHORIZED, "the old session is revoked");
}

#[tokio::test]
async fn risky_client_must_step_up_before_sensitive_route() {
    let app = app();
    let cookie = login(&app).await;

    let blocked = send(&app, call("POST", "/transfer").cookie(&cookie).from(ABROAD)).await;
    assert_eq!(blocked.status, StatusCode::UNAUTHORIZED);
    assert_eq!(blocked.body, r#"{"error":"step_up_required"}"#);
    assert!(!blocked.clears_cookie(), "the cookie survives a step-up");

    // Re-verification with the wrong password does not help.
    let wrong = send(
        &app,
        call("POST", "/step-up")
            .cookie(&cookie)
            .from(ABROAD)
            .json(r#"{"username":"demo","password":"nope"}"#),
    )
    .await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    assert_eq!(wrong.body, r#"{"error":"invalid_credentials"}"#);

    let done = send(&app, call("POST", "/step-up").cookie(&cookie).from(ABROAD).json(LOGIN)).await;
    assert_eq!(done.status, StatusCode::OK, "{}", done.body);
    let fresh = done.cookie_pair().expect("step-up issues a new token");
    assert_ne!(fresh, cookie);

    let allowed = send(&app, call("POST", "/transfer").cookie(&fresh).from(ABROAD)).await;
    assert_eq!(allowed.status, StatusCode::OK, "{}", allowed.body);
}

#[tokio::test]
async fn step_up_without_a_session_is_refused() {
    let app = app();
    let reply = send(&app, call("POST", "/step-up").json(LOGIN)).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_eq!(reply.body, r#"{"error":"not_authenticated"}"#);
}

#[tokio::test]
async fn stale_login_must_step_up_for_sensitive_route_only() {
    let app = app();
    let cookie = login(&app).await;
    app.clock.advance(Duration::from_mins(16));

    // Ordinary routes keep working (and may rotate the token).
    let me = send(&app, call("GET", "/me").cookie(&cookie)).await;
    assert_eq!(me.status, StatusCode::OK);
    let cookie = me.cookie_pair().unwrap_or(cookie);

    let blocked = send(&app, call("POST", "/transfer").cookie(&cookie)).await;
    assert_eq!(blocked.status, StatusCode::UNAUTHORIZED);
    assert_eq!(blocked.body, r#"{"error":"step_up_required"}"#);

    let done = send(&app, call("POST", "/step-up").cookie(&cookie).json(LOGIN)).await;
    assert_eq!(done.status, StatusCode::OK, "{}", done.body);
    let fresh = done.cookie_pair().unwrap();
    let allowed = send(&app, call("POST", "/transfer").cookie(&fresh)).await;
    assert_eq!(allowed.status, StatusCode::OK);
}

#[tokio::test]
async fn api_key_prefixes_bypass_the_guard() {
    let app = app();

    let ok = send(&app, call("GET", "/api/ping").bearer("pat_demo-key")).await;
    assert_eq!(ok.status, StatusCode::OK);
    assert_eq!(ok.body, r#"{"auth":"api_key"}"#);
    assert!(!ok.headers.contains_key(header::SET_COOKIE));

    // The app-side handler judges the key; the guard stays out of it.
    let bad = send(&app, call("GET", "/api/ping").bearer("pat_wrong")).await;
    assert_eq!(bad.status, StatusCode::UNAUTHORIZED);
    assert_eq!(bad.body, r#"{"error":"invalid_api_key"}"#);

    // A key is not a session: session-only routes still refuse it.
    let me = send(&app, call("GET", "/me").bearer("pat_demo-key")).await;
    assert_eq!(me.status, StatusCode::UNAUTHORIZED);
    assert_eq!(me.body, r#"{"error":"not_authenticated"}"#);

    // Other bearer tokens are not bypassed: the guard rejects them.
    let other = send(&app, call("GET", "/api/ping").bearer("zzz_unknown")).await;
    assert_eq!(other.status, StatusCode::UNAUTHORIZED);
    assert_eq!(other.body, r#"{"error":"not_authenticated"}"#);
}

#[tokio::test]
async fn sessions_can_be_listed_and_revoked() {
    let app = app();
    let first = login(&app).await;
    let second = login(&app).await;

    let list = send(&app, call("GET", "/sessions").cookie(&first)).await;
    assert_eq!(list.status, StatusCode::OK);
    let sessions: Value = serde_json::from_str(&list.body).unwrap();
    let sessions = sessions.as_array().unwrap();
    assert_eq!(sessions.len(), 2);
    assert!(sessions.iter().any(|s| s["current"] == true));
    let other = sessions.iter().find(|s| s["current"] == false).unwrap();
    let id = other["session_id"].as_str().unwrap();

    let unknown = send(
        &app,
        call("DELETE", "/sessions/6f1c1b52-9c7a-4a1e-9b52-0a7f2f0d1c11").cookie(&first),
    )
    .await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);
    assert_eq!(unknown.body, r#"{"error":"not_found"}"#);

    let revoked = send(&app, call("DELETE", &format!("/sessions/{id}")).cookie(&first)).await;
    assert_eq!(revoked.status, StatusCode::OK, "{}", revoked.body);

    let gone = send(&app, call("GET", "/me").cookie(&second)).await;
    assert_eq!(gone.status, StatusCode::UNAUTHORIZED);
    let still = send(&app, call("GET", "/me").cookie(&first)).await;
    assert_eq!(still.status, StatusCode::OK);
}

#[tokio::test]
async fn swagger_ui_and_spec_document_the_routes() {
    let app = app();
    let ui = send(&app, call("GET", "/swagger")).await;
    assert_eq!(ui.status, StatusCode::OK);
    let spec = send(&app, call("GET", "/api.json")).await;
    assert_eq!(spec.status, StatusCode::OK);
    let spec: Value = serde_json::from_str(&spec.body).unwrap();
    assert_eq!(spec["info"]["title"], "session-guard example");
    assert_eq!(spec["info"]["description"], "Log in with demo / demo-password.");

    let paths = &spec["paths"];
    for path in [
        "/login",
        "/logout",
        "/step-up",
        "/me",
        "/sessions",
        "/sessions/{id}",
        "/transfer",
        "/api/ping",
    ] {
        assert!(paths[path].is_object(), "{path} missing from the spec");
    }

    let schemes = &spec["components"]["securitySchemes"];
    assert_eq!(schemes["session_cookie"]["type"], "apiKey");
    assert_eq!(schemes["session_cookie"]["in"], "cookie");
    assert_eq!(schemes["session_cookie"]["name"], "sid");
    assert_eq!(schemes["bearer"]["type"], "http");
    assert_eq!(schemes["bearer"]["scheme"], "bearer");

    // `AuthSession` marks its routes; rovo's `@security bearer` marks the API route.
    let cookie = json!([{ "session_cookie": [] }]);
    assert_eq!(paths["/me"]["get"]["security"], cookie);
    assert_eq!(paths["/sessions"]["get"]["security"], cookie);
    assert_eq!(paths["/transfer"]["post"]["security"], cookie);
    assert_eq!(paths["/api/ping"]["get"]["security"], json!([{ "bearer": [] }]));
    for (path, method) in [("/login", "post"), ("/logout", "post"), ("/step-up", "post")] {
        assert!(paths[path][method].get("security").is_none(), "{path} is public");
    }

    // The layer's 401 and the app's own errors are documented.
    assert!(paths["/me"]["get"]["responses"]["401"].is_object());
    assert!(paths["/login"]["post"]["responses"]["401"].is_object());
    assert!(paths["/step-up"]["post"]["responses"]["403"].is_object());
    assert!(paths["/sessions/{id}"]["delete"]["responses"]["404"].is_object());
}
