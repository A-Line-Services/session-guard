//! The axum layer, extractors and helpers.

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use axum::{
    Router,
    body::Body,
    extract::ConnectInfo,
    http::{HeaderMap, Request, StatusCode, header},
    response::Response,
    routing::get,
};
use chrono::{DateTime, TimeZone, Utc};
use http_body_util::BodyExt;
use session_guard::{
    AuthSession, Checks, ClientContext, Guard, GuardConfig, GuardLayer, IpInfo, ManualClock, MemoryStore, Rejection,
    SessionEvent, SessionRecord, SessionStore, StoreError, TokenHash, TokenLookup,
};
use tower::ServiceExt;
use uuid::Uuid;

const CHROME_WIN: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";
const HOME: &str = "203.0.113.7";

fn start() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 3, 1, 12, 0, 0).unwrap()
}

fn intel(ip: IpAddr) -> IpInfo {
    let country = match ip {
        IpAddr::V4(v4) if v4.octets()[..3] == [198, 51, 100] => "DE",
        _ => "US",
    };
    IpInfo::new(Some(country.into()), None)
}

struct Harness {
    guard: Guard<Arc<MemoryStore>>,
    clock: ManualClock,
}

fn harness() -> Harness {
    let clock = ManualClock::new(start());
    let guard = Guard::builder(Arc::new(MemoryStore::new()), GuardConfig::default())
        .ip_intel(intel)
        .clock(clock.clone())
        .build();
    Harness { guard, clock }
}

fn ctx(ip: &str) -> ClientContext {
    ClientContext::new(ip.parse().unwrap())
        .with_user_agent(CHROME_WIN)
        .with_ch_platform("\"Windows\"")
        .with_ch_mobile(false)
        .with_accept_language("en-US")
}

/// `name=value` from a `Set-Cookie` value.
fn cookie_pair(set_cookie: &str) -> String {
    set_cookie.split(';').next().unwrap().to_owned()
}

async fn login(h: &Harness, user: Uuid) -> String {
    let session = h.guard.login(&user, &ctx(HOME), None).await.unwrap();
    cookie_pair(session.token.set_cookie())
}

async fn whoami(session: AuthSession<Uuid>) -> String {
    session.subject.to_string()
}

async fn optional(session: Option<AuthSession<Uuid>>) -> String {
    session.map_or_else(|| "anonymous".to_owned(), |s| s.subject.to_string())
}

/// Reports whether the guard ran: an `AuthSession` extension is present.
async fn probe(session: Option<AuthSession<Uuid>>) -> String {
    if session.is_some() { "guarded" } else { "bypassed" }.to_owned()
}

fn app(layer: GuardLayer<Arc<MemoryStore>, Uuid>) -> Router {
    Router::new()
        .route("/me", get(whoami))
        .route("/probe", get(probe))
        .route(
            "/cached",
            get(|| async { ([(header::CACHE_CONTROL, "max-age=3600")], "hi") }),
        )
        .layer(layer)
}

struct Req {
    builder: axum::http::request::Builder,
    peer: Option<&'static str>,
}

fn req(path: &str) -> Req {
    Req {
        builder: Request::get(path)
            .header(header::USER_AGENT, CHROME_WIN)
            .header("sec-ch-ua-platform", "\"Windows\"")
            .header("sec-ch-ua-mobile", "?0")
            .header(header::ACCEPT_LANGUAGE, "en-US"),
        peer: Some(HOME),
    }
}

impl Req {
    fn cookie(mut self, pair: &str) -> Self {
        self.builder = self.builder.header(header::COOKIE, pair);
        self
    }

    fn header(mut self, name: &str, value: &str) -> Self {
        self.builder = self.builder.header(name, value);
        self
    }

    fn from(mut self, peer: &'static str) -> Self {
        self.peer = Some(peer);
        self
    }

    fn no_connect_info(mut self) -> Self {
        self.peer = None;
        self
    }

    fn build(self) -> Request<Body> {
        let mut request = self.builder.body(Body::empty()).unwrap();
        if let Some(peer) = self.peer {
            let addr = SocketAddr::new(peer.parse().unwrap(), 50_000);
            request.extensions_mut().insert(ConnectInfo(addr));
        }
        request
    }
}

async fn send(router: &Router, request: Req) -> Response {
    router.clone().oneshot(request.build()).await.unwrap()
}

async fn body(response: Response) -> String {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).map(|v| v.to_str().unwrap())
}

fn set_cookies(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().to_owned())
        .collect()
}

/// Asserts the 401 contract and returns the `Set-Cookie` values.
async fn assert_rejected(response: Response, error: &str) -> (Vec<String>, Option<String>) {
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let headers = response.headers().clone();
    assert_eq!(header_str(&headers, "content-type"), Some("application/json"));
    assert_eq!(header_str(&headers, "cache-control"), Some("no-store"));
    let clear_site = header_str(&headers, "clear-site-data").map(str::to_owned);
    assert_eq!(body(response).await, format!(r#"{{"error":"{error}"}}"#));
    (set_cookies(&headers), clear_site)
}

fn is_clearing(set_cookie: &str) -> bool {
    set_cookie.contains("Max-Age=0")
}

// --- happy path ---

#[tokio::test]
async fn authenticated_request_reaches_handler_with_session() {
    let h = harness();
    let user = Uuid::new_v4();
    let cookie = login(&h, user).await;
    let router = app(h.guard.layer());

    let response = send(&router, req("/me").cookie(&cookie)).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(header_str(response.headers(), "cache-control"), Some("no-store"));
    assert_eq!(set_cookies(response.headers()), Vec::<String>::new());
    assert_eq!(body(response).await, user.to_string());
}

#[tokio::test]
async fn handler_cache_control_is_overwritten() {
    let h = harness();
    let cookie = login(&h, Uuid::new_v4()).await;
    let router = app(h.guard.layer());

    let response = send(&router, req("/cached").cookie(&cookie)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let values: Vec<_> = response.headers().get_all(header::CACHE_CONTROL).iter().collect();
    assert_eq!(values, ["no-store"]);
}

#[tokio::test]
async fn rotation_appends_set_cookie() {
    let h = harness();
    let user = Uuid::new_v4();
    let cookie = login(&h, user).await;
    let router = app(h.guard.layer());

    h.clock.advance(Duration::from_mins(11));
    let response = send(&router, req("/me").cookie(&cookie)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let cookies = set_cookies(response.headers());
    assert_eq!(cookies.len(), 1);
    let rotated = cookie_pair(&cookies[0]);
    assert_ne!(rotated, cookie);
    assert!(!is_clearing(&cookies[0]));

    let response = send(&router, req("/me").cookie(&rotated)).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body(response).await, user.to_string());
}

// --- rejections ---

#[tokio::test]
async fn missing_cookie_is_not_authenticated() {
    let h = harness();
    let router = app(h.guard.layer());
    let (cookies, clear_site) = assert_rejected(send(&router, req("/me")).await, "not_authenticated").await;
    assert_eq!(cookies.len(), 1);
    assert!(is_clearing(&cookies[0]));
    assert_eq!(clear_site, None);
}

#[tokio::test]
async fn unknown_token_is_not_authenticated_and_clears_cookie() {
    let h = harness();
    let cookie = login(&h, Uuid::new_v4()).await;
    let name = cookie.split('=').next().unwrap();
    let router = app(h.guard.layer());
    let bogus = format!("{name}={}", "A".repeat(43));
    let (cookies, clear_site) =
        assert_rejected(send(&router, req("/me").cookie(&bogus)).await, "not_authenticated").await;
    assert_eq!(cookies, [h.guard.clear_cookie()]);
    assert_eq!(clear_site, None);
}

#[tokio::test]
async fn expired_session_clears_cookie() {
    let h = harness();
    let cookie = login(&h, Uuid::new_v4()).await;
    let router = app(h.guard.layer());
    h.clock.advance(Duration::from_hours(24 * 400));
    let (cookies, clear_site) =
        assert_rejected(send(&router, req("/me").cookie(&cookie)).await, "session_expired").await;
    assert_eq!(cookies, [h.guard.clear_cookie()]);
    assert_eq!(clear_site, None);
}

#[tokio::test]
async fn token_reuse_revokes_and_clears_site_data() {
    let h = harness();
    let t0 = login(&h, Uuid::new_v4()).await;
    let router = app(h.guard.layer());

    h.clock.advance(Duration::from_mins(11));
    let response = send(&router, req("/me").cookie(&t0)).await;
    let t1 = cookie_pair(&set_cookies(response.headers())[0]);
    assert_eq!(send(&router, req("/me").cookie(&t1)).await.status(), StatusCode::OK);

    h.clock.advance(Duration::from_mins(1));
    let (cookies, clear_site) = assert_rejected(send(&router, req("/me").cookie(&t0)).await, "session_revoked").await;
    assert_eq!(cookies, [h.guard.clear_cookie()]);
    assert_eq!(clear_site.as_deref(), Some("\"cookies\""));
}

#[tokio::test]
async fn risky_client_gets_step_up_and_keeps_cookie() {
    let h = harness();
    let cookie = login(&h, Uuid::new_v4()).await;
    let router = app(h.guard.layer());
    // Another country and network: step-up under the default checks.
    let (cookies, clear_site) = assert_rejected(
        send(&router, req("/me").cookie(&cookie).from("198.51.100.20")).await,
        "step_up_required",
    )
    .await;
    assert_eq!(cookies, Vec::<String>::new());
    assert_eq!(clear_site, None);
}

#[tokio::test]
async fn strict_checks_are_passed_through() {
    let h = harness();
    // Same country, other /24: 10 points by default, 40 (step-up) under strict.
    let lenient = app(h.guard.layer());
    let cookie = login(&h, Uuid::new_v4()).await;
    let response = send(&lenient, req("/me").cookie(&cookie).from("203.0.114.9")).await;
    assert_eq!(response.status(), StatusCode::OK);

    let strict = app(h.guard.layer().with(Checks::strict()));
    let cookie = login(&h, Uuid::new_v4()).await;
    let (cookies, _) = assert_rejected(
        send(&strict, req("/me").cookie(&cookie).from("203.0.114.9")).await,
        "step_up_required",
    )
    .await;
    assert_eq!(cookies, Vec::<String>::new());
}

// --- connect info ---

#[tokio::test]
async fn missing_connect_info_fails_closed() {
    let h = harness();
    let cookie = login(&h, Uuid::new_v4()).await;
    let router = app(h.guard.layer());
    let response = send(&router, req("/me").cookie(&cookie).no_connect_info()).await;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(header_str(response.headers(), "cache-control"), Some("no-store"));
    assert_eq!(header_str(response.headers(), "content-type"), Some("application/json"));
    assert_eq!(body(response).await, r#"{"error":"internal"}"#);
}

// --- bypass ---

#[tokio::test]
async fn bearer_prefix_bypasses_the_guard() {
    let h = harness();
    let router = app(h.guard.layer().bypass_bearer_prefixes(["alc_", "als_"]));
    for token in ["alc_abc", "als_xyz"] {
        let response = send(
            &router,
            req("/probe")
                .header("authorization", &format!("Bearer {token}"))
                .no_connect_info(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get(header::CACHE_CONTROL).is_none());
        assert!(response.headers().get(header::SET_COOKIE).is_none());
        assert_eq!(body(response).await, "bypassed");
    }
}

#[tokio::test]
async fn bypass_ignores_a_valid_cookie() {
    let h = harness();
    let cookie = login(&h, Uuid::new_v4()).await;
    let router = app(h.guard.layer().bypass_bearer_prefixes(["alc_"]));
    let response = send(
        &router,
        req("/probe").cookie(&cookie).header("authorization", "Bearer alc_abc"),
    )
    .await;
    assert_eq!(body(response).await, "bypassed");
}

#[tokio::test]
async fn non_matching_bearer_is_still_guarded() {
    let h = harness();
    let router = app(h.guard.layer().bypass_bearer_prefixes(["alc_", "als_"]));
    for auth in ["Bearer alb_abc", "Basic alc_abc", "Bearer", "alc_abc"] {
        let response = send(&router, req("/probe").header("authorization", auth)).await;
        assert_rejected(response, "not_authenticated").await;
    }
}

#[tokio::test]
async fn bearer_scheme_is_case_insensitive() {
    let h = harness();
    let router = app(h.guard.layer().bypass_bearer_prefixes(["alc_"]));
    let response = send(&router, req("/probe").header("authorization", "bearer alc_abc")).await;
    assert_eq!(body(response).await, "bypassed");
}

#[tokio::test]
async fn empty_prefix_bypasses_nothing() {
    let h = harness();
    let router = app(h.guard.layer().bypass_bearer_prefixes([""]));
    let response = send(&router, req("/probe").header("authorization", "Bearer anything")).await;
    assert_rejected(response, "not_authenticated").await;
}

#[tokio::test]
async fn bypass_when_predicate() {
    let h = harness();
    let router = app(h
        .guard
        .layer()
        .bypass_when(|headers: &HeaderMap| headers.contains_key("x-internal")));
    let response = send(&router, req("/probe").header("x-internal", "1")).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get(header::CACHE_CONTROL).is_none());
    assert_eq!(body(response).await, "bypassed");

    assert_rejected(send(&router, req("/probe")).await, "not_authenticated").await;
}

// --- recent auth ---

#[tokio::test]
async fn require_recent_auth() {
    let h = harness();
    let cookie = login(&h, Uuid::new_v4()).await;
    let router = app(h.guard.layer().require_recent_auth(Duration::from_mins(15)));

    h.clock.advance(Duration::from_mins(5));
    assert_eq!(send(&router, req("/me").cookie(&cookie)).await.status(), StatusCode::OK);

    h.clock.advance(Duration::from_mins(11));
    let response = send(&router, req("/me").cookie(&cookie)).await;
    let (cookies, clear_site) = assert_rejected(response, "step_up_required").await;
    assert_eq!(clear_site, None);
    // The token was due for rotation: the replacement is still delivered, nothing clears.
    assert_eq!(cookies.len(), 1);
    assert!(!is_clearing(&cookies[0]));
    let rotated = cookie_pair(&cookies[0]);

    // The session itself is untouched: a layer without the requirement still accepts it.
    let relaxed = app(h.guard.layer());
    assert_eq!(
        send(&relaxed, req("/me").cookie(&rotated)).await.status(),
        StatusCode::OK
    );
}

// --- route_layer ---

#[tokio::test]
async fn works_as_route_layer() {
    let h = harness();
    let user = Uuid::new_v4();
    let cookie = login(&h, user).await;
    let router = Router::new()
        .route("/me", get(whoami))
        .route_layer(h.guard.layer())
        .route("/public", get(|| async { "public" }));

    assert_eq!(body(send(&router, req("/public")).await).await, "public");
    assert_eq!(
        body(send(&router, req("/me").cookie(&cookie)).await).await,
        user.to_string()
    );
    assert_rejected(send(&router, req("/me")).await, "not_authenticated").await;
}

// --- extractors and helpers ---

#[tokio::test]
async fn extractor_without_layer_is_401() {
    let router = Router::new()
        .route("/me", get(whoami))
        .route("/optional", get(optional));
    assert_rejected(send(&router, req("/me")).await, "not_authenticated").await;
    assert_eq!(body(send(&router, req("/optional")).await).await, "anonymous");
}

#[tokio::test]
async fn optional_extractor_with_layer() {
    let h = harness();
    let user = Uuid::new_v4();
    let cookie = login(&h, user).await;
    let router = Router::new().route("/optional", get(optional)).layer(h.guard.layer());
    assert_eq!(
        body(send(&router, req("/optional").cookie(&cookie)).await).await,
        user.to_string()
    );
}

#[tokio::test]
async fn rejection_response_matches_layer_contract() {
    let h = harness();
    let (cookies, clear_site) = assert_rejected(
        session_guard::axum::rejection_response(Rejection::Revoked, &h.guard),
        "session_revoked",
    )
    .await;
    assert_eq!(cookies, [h.guard.clear_cookie()]);
    assert_eq!(clear_site.as_deref(), Some("\"cookies\""));

    let (cookies, clear_site) = assert_rejected(
        session_guard::axum::rejection_response(Rejection::StepUpRequired, &h.guard),
        "step_up_required",
    )
    .await;
    assert_eq!(cookies, Vec::<String>::new());
    assert_eq!(clear_site, None);
}

#[tokio::test]
async fn client_context_helper() {
    let h = harness();
    let (parts, _) = req("/login").build().into_parts();
    let ctx = session_guard::axum::client_context(&h.guard, &parts).unwrap();
    assert_eq!(ctx.ip, HOME.parse::<IpAddr>().unwrap());
    assert_eq!(ctx.user_agent.as_deref(), Some(CHROME_WIN));

    let (parts, _) = req("/login").no_connect_info().build().into_parts();
    let missing = session_guard::axum::client_context(&h.guard, &parts).unwrap_err();
    let response = axum::response::IntoResponse::into_response(missing);
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body(response).await, r#"{"error":"internal"}"#);
}

// --- store failures ---

#[derive(Clone, Copy)]
struct FailingStore;

fn fail<T>() -> Result<T, StoreError> {
    Err("connection refused: secret-host:5432".into())
}

#[allow(clippy::unused_async_trait_impl)]
impl SessionStore for FailingStore {
    async fn insert_session(&self, _: &SessionRecord, _: &TokenHash) -> Result<(), StoreError> {
        fail()
    }
    async fn find_by_token(&self, _: &TokenHash) -> Result<Option<TokenLookup>, StoreError> {
        fail()
    }
    async fn apply(&self, _: &session_guard::SessionUpdate) -> Result<bool, StoreError> {
        fail()
    }
    async fn delete_session(&self, _: Uuid) -> Result<bool, StoreError> {
        fail()
    }
    async fn delete_subject_sessions(&self, _: &str) -> Result<u64, StoreError> {
        fail()
    }
    async fn list_subject_sessions(&self, _: &str) -> Result<Vec<SessionRecord>, StoreError> {
        fail()
    }
    async fn delete_expired(&self, _: DateTime<Utc>, _: DateTime<Utc>) -> Result<u64, StoreError> {
        fail()
    }
    async fn record_event(&self, _: &SessionEvent) -> Result<(), StoreError> {
        fail()
    }
    async fn delete_events_before(&self, _: DateTime<Utc>) -> Result<u64, StoreError> {
        fail()
    }
}

#[tokio::test]
async fn store_error_is_500_without_details() {
    let h = harness();
    let cookie = login(&h, Uuid::new_v4()).await;
    let guard = Guard::new(FailingStore);
    let router = Router::new().route("/me", get(whoami)).layer(guard.layer());
    let response = send(&router, req("/me").cookie(&cookie)).await;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(header_str(response.headers(), "cache-control"), Some("no-store"));
    assert!(response.headers().get(header::SET_COOKIE).is_none());
    let text = body(response).await;
    assert_eq!(text, r#"{"error":"internal"}"#);
    assert!(!text.contains("secret-host"));
}
