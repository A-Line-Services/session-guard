//! End-to-end tests: a real axum server on a loopback socket, driven over HTTP with reqwest,
//! against both the Postgres and the Valkey store.
//!
//! The guard shares a [`ManualClock`] with the test, started at the real time because Valkey key
//! TTLs follow the wall clock. The databases are shared with other test processes, so every
//! scenario uses fresh random subjects and never assumes empty storage.

mod support;

use std::{
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header, request::Parts},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use reqwest::{Method, RequestBuilder};
use session_guard::{
    AuthSession, EventKind, Guard, GuardConfig, GuardConfigBuilder, IpInfo, ManualClock, Mode, PgStore, Rejection,
    SessionEvent, SessionStore, StepUpOutcome, ValkeyStore,
    axum::{client_context, rejection_response},
};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

const CHROME_WIN: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";
const CHROME_MAC: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) \
                          Chrome/126.0.0.0 Safari/537.36";
/// An address `intel` places in another country.
const ABROAD: &str = "198.51.100.20";
const COOKIE_NAME: &str = "__Host-sid";

// --- stores ---

async fn pg_store() -> PgStore {
    let url = support::postgres_url().await;
    let mut last = None;
    for _ in 0..100 {
        match PgPoolOptions::new().max_connections(4).connect(url).await {
            Ok(pool) => match sqlx::query("SELECT 1").execute(&pool).await {
                Ok(_) => return PgStore::migrated(pool).await.expect("migrations"),
                Err(e) => last = Some(e),
            },
            Err(e) => last = Some(e),
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("postgres never became ready: {last:?}");
}

async fn valkey_store() -> ValkeyStore {
    ValkeyStore::connect(support::valkey_url().await)
        .await
        .expect("connect to valkey")
        .key_prefix(format!("sgtest:e2e:{}:", Uuid::new_v4().simple()))
}

// --- the app under test ---

/// Country by network: 198.51.100.0/24 is abroad, everything else is home.
fn intel(ip: IpAddr) -> IpInfo {
    let country = match ip {
        IpAddr::V4(v4) if v4.octets()[..3] == [198, 51, 100] => "DE",
        _ => "US",
    };
    IpInfo::new(Some(country.into()), None)
}

/// Defaults for the tests: a `sess_` token prefix and nothing else changed.
fn config() -> GuardConfigBuilder {
    GuardConfig::builder().token_prefix("sess_")
}

async fn login_route<St: SessionStore>(
    State(guard): State<Guard<St>>,
    Path(user): Path<Uuid>,
    parts: Parts,
) -> Response {
    let ctx = match client_context(&guard, &parts) {
        Ok(ctx) => ctx,
        Err(missing) => return missing.into_response(),
    };
    let previous = guard.cookie_token(&parts.headers);
    match guard.login(&user, &ctx, previous).await {
        Ok(session) => ([(header::SET_COOKIE, session.token.set_cookie().to_owned())], "welcome").into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn step_up_route<St: SessionStore>(
    State(guard): State<Guard<St>>,
    Path(user): Path<Uuid>,
    parts: Parts,
) -> Response {
    let ctx = match client_context(&guard, &parts) {
        Ok(ctx) => ctx,
        Err(missing) => return missing.into_response(),
    };
    let Some(token) = guard.cookie_token(&parts.headers) else {
        return rejection_response(Rejection::NotAuthenticated, &guard);
    };
    match guard.complete_step_up(token, &ctx, &user).await {
        Ok(StepUpOutcome::Completed(issued)) => {
            ([(header::SET_COOKIE, issued.set_cookie().to_owned())], "stepped up").into_response()
        }
        Ok(StepUpOutcome::Rejected(rejection)) => rejection_response(rejection, &guard),
        Ok(_) => StatusCode::FORBIDDEN.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn logout_route<St: SessionStore>(State(guard): State<Guard<St>>, parts: Parts) -> Response {
    let ctx = match client_context(&guard, &parts) {
        Ok(ctx) => ctx,
        Err(missing) => return missing.into_response(),
    };
    if let Some(token) = guard.cookie_token(&parts.headers) {
        let _ = guard.logout(token, &ctx).await;
    }
    ([(header::SET_COOKIE, guard.clear_cookie())], "bye").into_response()
}

async fn me(session: AuthSession<Uuid>) -> String {
    session.subject.to_string()
}

/// Whether the guard ran: an `AuthSession` extension is present.
async fn probe(session: Option<AuthSession<Uuid>>) -> &'static str {
    if session.is_some() { "guarded" } else { "bypassed" }
}

fn router<St: SessionStore>(guard: &Guard<St>) -> Router {
    let browser = Router::new()
        .route("/me", get(me))
        .route("/api/ping", get(probe))
        .layer(guard.layer().bypass_bearer_prefixes(["pat_", "svc_"]));
    let sensitive = Router::new()
        .route("/sensitive/me", get(me))
        .layer(guard.layer().require_recent_auth(Duration::from_mins(15)));
    Router::new()
        .route("/login/{user}", post(login_route::<St>))
        .route("/step-up/{user}", post(step_up_route::<St>))
        .route("/logout", post(logout_route::<St>))
        .merge(browser)
        .merge(sensitive)
        .with_state(guard.clone())
}

// --- harness ---

struct Env<St: SessionStore> {
    base: String,
    guard: Guard<St>,
    clock: ManualClock,
    events: Arc<Mutex<Vec<SessionEvent>>>,
    http: reqwest::Client,
}

async fn spawn<St: SessionStore>(store: St, config: GuardConfigBuilder) -> Env<St> {
    let clock = ManualClock::default();
    let events = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&events);
    let guard = Guard::builder(store, config.build().expect("valid config"))
        .ip_intel(intel)
        .clock(clock.clone())
        .on_event(move |event| sink.lock().unwrap().push(event.clone()))
        .build();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = router(&guard).into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move { axum::serve(listener, app).await });
    Env {
        base: format!("http://{addr}"),
        guard,
        clock,
        events,
        http: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap(),
    }
}

/// A response with the pieces the tests look at.
struct Resp {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

impl Resp {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(|v| v.to_str().unwrap())
    }

    fn set_cookies(&self) -> Vec<String> {
        self.headers
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().to_owned())
            .collect()
    }

    /// The `name=value` of the one non-clearing `Set-Cookie`, if the response delivers a token.
    fn new_cookie(&self) -> Option<String> {
        let mut issued = self.set_cookies().into_iter().filter(|c| !is_clearing(c));
        let first = issued.next()?;
        assert!(issued.next().is_none(), "more than one token cookie");
        Some(cookie_pair(&first))
    }
}

fn cookie_pair(set_cookie: &str) -> String {
    set_cookie.split(';').next().unwrap().to_owned()
}

fn is_clearing(set_cookie: &str) -> bool {
    set_cookie.contains("Max-Age=0")
}

/// Replaces a header (`RequestBuilder::header` appends, so defaults would win).
fn set(request: RequestBuilder, name: &str, value: &str) -> RequestBuilder {
    let (client, request) = request.build_split();
    let mut request = request.expect("request");
    request.headers_mut().insert(
        header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
        header::HeaderValue::from_str(value).unwrap(),
    );
    RequestBuilder::from_parts(client, request)
}

async fn send(request: RequestBuilder) -> Resp {
    let response = request.send().await.expect("request");
    Resp {
        status: response.status(),
        headers: response.headers().clone(),
        body: response.text().await.expect("body"),
    }
}

/// The 401 contract: JSON error code, `no-store`; returns the response for further checks.
fn assert_rejected(resp: &Resp, error: &str) {
    assert_eq!(resp.status, StatusCode::UNAUTHORIZED, "body: {}", resp.body);
    assert_eq!(resp.header("content-type"), Some("application/json"));
    assert_eq!(resp.header("cache-control"), Some("no-store"));
    assert_eq!(resp.body, format!(r#"{{"error":"{error}"}}"#));
}

/// A rejection that ends the session: the cookie is cleared, and for a revocation so is the
/// rest of the site data.
fn assert_cookie_cleared(resp: &Resp, site_data: bool) {
    let cookies = resp.set_cookies();
    assert_eq!(cookies.len(), 1, "{cookies:?}");
    assert!(cookies[0].starts_with(&format!("{COOKIE_NAME}=;")), "{}", cookies[0]);
    assert!(is_clearing(&cookies[0]));
    assert_eq!(resp.header("clear-site-data"), site_data.then_some("\"cookies\""));
}

impl<St: SessionStore> Env<St> {
    fn req(&self, method: Method, path: &str) -> RequestBuilder {
        self.http
            .request(method, format!("{}{path}", self.base))
            .header(header::USER_AGENT, CHROME_WIN)
            .header("sec-ch-ua-platform", "\"Windows\"")
            .header("sec-ch-ua-mobile", "?0")
            .header(header::ACCEPT_LANGUAGE, "en-US")
    }

    /// A GET carrying `cookie` (a `name=value` pair).
    fn get(&self, path: &str, cookie: &str) -> RequestBuilder {
        self.req(Method::GET, path).header(header::COOKIE, cookie)
    }

    async fn login_resp(&self, user: Uuid, previous: Option<&str>) -> Resp {
        let mut request = self.req(Method::POST, &format!("/login/{user}"));
        if let Some(previous) = previous {
            request = request.header(header::COOKIE, previous);
        }
        send(request).await
    }

    /// Logs `user` in and returns the cookie pair.
    async fn login(&self, user: Uuid) -> String {
        let resp = self.login_resp(user, None).await;
        assert_eq!(resp.status, StatusCode::OK);
        resp.new_cookie().expect("login sets the cookie")
    }

    async fn step_up(&self, user: Uuid, cookie: &str, extra: &[(&str, &str)]) -> Resp {
        let mut request = self
            .req(Method::POST, &format!("/step-up/{user}"))
            .header(header::COOKIE, cookie);
        for (name, value) in extra {
            request = set(request, name, value);
        }
        send(request).await
    }

    fn advance(&self, by: Duration) {
        self.clock.advance(by);
    }

    fn events_of(&self, kind: EventKind) -> Vec<SessionEvent> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.kind == kind)
            .cloned()
            .collect()
    }

    /// Requests `/me`, expecting 200 and the subject in the body.
    async fn assert_me(&self, cookie: &str, user: Uuid) -> Resp {
        let resp = send(self.get("/me", cookie)).await;
        assert_eq!(resp.status, StatusCode::OK, "body: {}", resp.body);
        assert_eq!(resp.body, user.to_string());
        resp
    }
}

fn mac(request: RequestBuilder) -> RequestBuilder {
    set(
        set(request, "user-agent", CHROME_MAC),
        "sec-ch-ua-platform",
        "\"macOS\"",
    )
}

/// The token value (without cookie name) of a pair.
fn pair_value(pair: &str) -> &str {
    pair.split_once('=').unwrap().1
}

// --- scenarios ---

/// Scenario 1: Login sets the hardened cookie; the protected route answers with the subject.
async fn login_sets_hardened_cookie<St: SessionStore>(store: St) {
    let env = spawn(store, config()).await;
    let user = Uuid::new_v4();
    let resp = env.login_resp(user, None).await;
    assert_eq!(resp.status, StatusCode::OK);
    let set_cookie = &resp.set_cookies()[0];
    assert!(set_cookie.starts_with("__Host-sid=sess_"), "{set_cookie}");
    for attribute in ["Path=/", "HttpOnly", "Secure", "SameSite=Lax", "Max-Age="] {
        assert!(set_cookie.contains(attribute), "{attribute} missing in {set_cookie}");
    }
    assert!(!set_cookie.contains("Domain"), "{set_cookie}");

    let cookie = cookie_pair(set_cookie);
    let resp = env.assert_me(&cookie, user).await;
    assert_eq!(resp.header("cache-control"), Some("no-store"));
    assert_eq!(resp.set_cookies().len(), 0);
}

/// Scenario 2: After the rotation interval the response carries a new cookie; both tokens work within
/// the grace window.
async fn rotation_issues_new_cookie_and_grace_keeps_old<St: SessionStore>(store: St) {
    let env = spawn(store, config()).await;
    let user = Uuid::new_v4();
    let old = env.login(user).await;

    env.advance(Duration::from_mins(5));
    assert_eq!(env.assert_me(&old, user).await.set_cookies().len(), 0);

    env.advance(Duration::from_mins(6));
    let resp = env.assert_me(&old, user).await;
    let new = resp.new_cookie().expect("rotation delivers a cookie");
    assert_ne!(new, old);
    assert!(resp.set_cookies()[0].contains("HttpOnly"));

    env.advance(Duration::from_secs(5));
    assert_eq!(env.assert_me(&new, user).await.set_cookies().len(), 0);
    // A request that raced the rotation still presents the old token.
    let resp = env.assert_me(&old, user).await;
    assert_eq!(resp.set_cookies().len(), 0, "grace does not rotate again");
}

/// Scenario 3: A stolen, superseded token replayed past grace revokes the session for both parties.
async fn stolen_token_replay_revokes_session<St: SessionStore>(store: St) {
    let env = spawn(store, config()).await;
    let user = Uuid::new_v4();
    let stolen = env.login(user).await;

    env.advance(Duration::from_mins(11));
    let victim = env.assert_me(&stolen, user).await.new_cookie().unwrap();
    // The victim carries on with the new token.
    env.advance(Duration::from_secs(60));
    env.assert_me(&victim, user).await;

    let resp = send(env.get("/me", &stolen)).await;
    assert_rejected(&resp, "session_revoked");
    assert_cookie_cleared(&resp, true);

    let resp = send(env.get("/me", &victim)).await;
    assert_rejected(&resp, "not_authenticated");

    let reuse = env.events_of(EventKind::TokenReuse);
    assert_eq!(reuse.len(), 1);
    assert!(reuse[0].enforced);
    assert_eq!(reuse[0].subject::<Uuid>(), Some(user));
    assert_eq!(env.guard.list_sessions(&user).await.unwrap().len(), 0);
}

/// Scenario 4: A medium-risk change asks for a step-up; completing it resets the baseline.
async fn country_change_steps_up_and_completion_resets_baseline<St: SessionStore>(store: St) {
    let env = spawn(store, config().trusted_proxies(["127.0.0.1/32"]).unwrap()).await;
    let user = Uuid::new_v4();
    let cookie = env.login(user).await;
    let abroad = |path: &str, cookie: &str| env.get(path, cookie).header("x-forwarded-for", ABROAD);

    // Another country alone scores 40: step-up, cookie kept.
    let resp = send(abroad("/me", &cookie)).await;
    assert_rejected(&resp, "step_up_required");
    assert_eq!(resp.set_cookies().len(), 0);
    assert_eq!(resp.header("clear-site-data"), None);
    assert_eq!(env.events_of(EventKind::StepUpRequired).len(), 1);

    // The flag sticks: even the original context is asked now.
    assert_rejected(&send(env.get("/me", &cookie)).await, "step_up_required");

    let resp = env.step_up(user, &cookie, &[("x-forwarded-for", ABROAD)]).await;
    assert_eq!(resp.status, StatusCode::OK, "body: {}", resp.body);
    let cookie = resp.new_cookie().expect("step-up issues a new token");
    assert_eq!(env.events_of(EventKind::StepUpCompleted).len(), 1);

    let resp = send(abroad("/me", &cookie)).await;
    assert_eq!(
        resp.status,
        StatusCode::OK,
        "new context is the baseline: {}",
        resp.body
    );
    assert_eq!(resp.body, user.to_string());
    assert_eq!(env.events_of(EventKind::StepUpRequired).len(), 1);
}

/// 4b. The same flow driven by a User-Agent client hint instead of the network.
async fn mobile_hint_flip_steps_up<St: SessionStore>(store: St) {
    let env = spawn(store, config()).await;
    let user = Uuid::new_v4();
    let cookie = env.login(user).await;

    // The mobile hint flipping alone scores 50.
    let resp = send(set(env.get("/me", &cookie), "sec-ch-ua-mobile", "?1")).await;
    assert_rejected(&resp, "step_up_required");
    assert_eq!(resp.set_cookies().len(), 0);

    let resp = env.step_up(user, &cookie, &[("sec-ch-ua-mobile", "?1")]).await;
    assert_eq!(resp.status, StatusCode::OK);
    let cookie = resp.new_cookie().unwrap();
    let resp = send(set(env.get("/me", &cookie), "sec-ch-ua-mobile", "?1")).await;
    assert_eq!(resp.status, StatusCode::OK);
}

/// Scenario 5: A drastic change (another operating system) revokes the session.
async fn os_change_revokes_session<St: SessionStore>(store: St) {
    let env = spawn(store, config()).await;
    let user = Uuid::new_v4();
    let cookie = env.login(user).await;

    let resp = send(mac(env.get("/me", &cookie))).await;
    assert_rejected(&resp, "session_revoked");
    assert_cookie_cleared(&resp, true);
    let events = env.events_of(EventKind::RiskRevoked);
    assert_eq!(events.len(), 1);
    assert!(events[0].enforced);

    // The real owner is out too.
    assert_rejected(&send(env.get("/me", &cookie)).await, "not_authenticated");
}

/// Scenario 6: Logout clears the cookie and kills the token.
async fn logout_kills_the_token<St: SessionStore>(store: St) {
    let env = spawn(store, config()).await;
    let user = Uuid::new_v4();
    let cookie = env.login(user).await;
    env.assert_me(&cookie, user).await;

    let resp = send(env.req(Method::POST, "/logout").header(header::COOKIE, &cookie)).await;
    assert_eq!(resp.status, StatusCode::OK);
    let cookies = resp.set_cookies();
    assert_eq!(cookies.len(), 1);
    assert!(is_clearing(&cookies[0]));
    assert!(cookies[0].starts_with("__Host-sid=;"));

    let resp = send(env.get("/me", &cookie)).await;
    assert_rejected(&resp, "not_authenticated");
    assert_eq!(env.events_of(EventKind::Logout).len(), 1);
}

/// Scenario 7: API-key bearers bypass the guard untouched; a browser token needs the `sess_` prefix.
async fn bearer_bypass_and_token_prefix<St: SessionStore>(store: St) {
    let env = spawn(store, config()).await;
    let user = Uuid::new_v4();

    for token in ["pat_whatever", "svc_other"] {
        let resp = send(
            env.req(Method::GET, "/api/ping")
                .header(header::AUTHORIZATION, format!("Bearer {token}")),
        )
        .await;
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(resp.body, "bypassed");
        assert_eq!(resp.set_cookies().len(), 0);
        assert_eq!(resp.header("cache-control"), None);
    }
    // Other bearers, and none at all, are not bypassed.
    for request in [
        env.req(Method::GET, "/api/ping")
            .header(header::AUTHORIZATION, "Bearer xyz_whatever"),
        env.req(Method::GET, "/api/ping"),
    ] {
        assert_rejected(&send(request).await, "not_authenticated");
    }

    let cookie = env.login(user).await;
    let resp = send(env.get("/api/ping", &cookie)).await;
    assert_eq!(resp.body, "guarded");

    // The bare token, without the configured prefix, is not a session token.
    let bare = format!("{COOKIE_NAME}={}", pair_value(&cookie).strip_prefix("sess_").unwrap());
    assert!(!env.guard.is_session_token(pair_value(&bare)));
    let resp = send(env.get("/me", &bare)).await;
    assert_rejected(&resp, "not_authenticated");
    // And a session cookie is not mistaken for a bypass.
    env.assert_me(&cookie, user).await;
}

/// 8a. With a trusted proxy, `X-Forwarded-For` is the client IP used for scoring.
async fn trusted_proxy_forwarded_for_is_scored<St: SessionStore>(store: St) {
    let env = spawn(store, config().trusted_proxies(["127.0.0.1/32"]).unwrap()).await;
    let user = Uuid::new_v4();
    let cookie = env.login(user).await;

    let resp = send(env.get("/me", &cookie).header("x-forwarded-for", ABROAD)).await;
    assert_rejected(&resp, "step_up_required");
    let events = env.events_of(EventKind::StepUpRequired);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].ip, ABROAD.parse::<IpAddr>().unwrap());
}

/// 8b. Without trusted proxies the header is ignored.
async fn untrusted_forwarded_for_is_ignored<St: SessionStore>(store: St) {
    let env = spawn(store, config()).await;
    let user = Uuid::new_v4();
    let cookie = env.login(user).await;

    let resp = send(env.get("/me", &cookie).header("x-forwarded-for", ABROAD)).await;
    assert_eq!(resp.status, StatusCode::OK, "body: {}", resp.body);
    assert_eq!(env.events_of(EventKind::StepUpRequired).len(), 0);
}

/// 9a. A session idle for longer than the idle timeout expires; activity keeps it alive.
async fn idle_timeout_expires_session<St: SessionStore>(store: St) {
    let env = spawn(store, config().idle_timeout(Duration::from_mins(30))).await;
    let user = Uuid::new_v4();
    let mut cookie = env.login(user).await;

    for _ in 0..3 {
        env.advance(Duration::from_mins(20));
        let resp = env.assert_me(&cookie, user).await;
        if let Some(rotated) = resp.new_cookie() {
            cookie = rotated;
        }
    }

    env.advance(Duration::from_mins(31));
    let resp = send(env.get("/me", &cookie)).await;
    assert_rejected(&resp, "session_expired");
    assert_cookie_cleared(&resp, false);
    assert_rejected(&send(env.get("/me", &cookie)).await, "not_authenticated");
}

/// 9b. The absolute lifetime ends a session however active it is.
async fn absolute_lifetime_expires_session<St: SessionStore>(store: St) {
    let env = spawn(store, config().session_lifetime(Duration::from_hours(2))).await;
    let user = Uuid::new_v4();
    let mut cookie = env.login(user).await;

    for _ in 0..4 {
        env.advance(Duration::from_mins(25));
        let resp = env.assert_me(&cookie, user).await;
        if let Some(rotated) = resp.new_cookie() {
            cookie = rotated;
        }
    }

    env.advance(Duration::from_mins(25));
    let resp = send(env.get("/me", &cookie)).await;
    assert_rejected(&resp, "session_expired");
    assert_cookie_cleared(&resp, false);
}

/// Scenario 10: Shadow mode lets risky requests through and records unenforced events; reuse is still
/// enforced.
async fn shadow_mode_records_but_allows<St: SessionStore>(store: St) {
    let env = spawn(store, config().mode(Mode::Shadow)).await;
    let user = Uuid::new_v4();
    let cookie = env.login(user).await;

    let resp = send(set(env.get("/me", &cookie), "sec-ch-ua-mobile", "?1")).await;
    assert_eq!(resp.status, StatusCode::OK, "body: {}", resp.body);
    let steps = env.events_of(EventKind::StepUpRequired);
    assert_eq!(steps.len(), 1);
    assert!(!steps[0].enforced);

    let resp = send(mac(env.get("/me", &cookie))).await;
    assert_eq!(resp.status, StatusCode::OK, "body: {}", resp.body);
    let revokes = env.events_of(EventKind::RiskRevoked);
    assert_eq!(revokes.len(), 1);
    assert!(!revokes[0].enforced);
    assert_eq!(env.guard.list_sessions(&user).await.unwrap().len(), 1);

    // Reuse is not a risk decision: always enforced.
    env.advance(Duration::from_mins(11));
    let new = env.assert_me(&cookie, user).await.new_cookie().unwrap();
    env.advance(Duration::from_secs(60));
    env.assert_me(&new, user).await;
    let resp = send(env.get("/me", &cookie)).await;
    assert_rejected(&resp, "session_revoked");
    assert_eq!(env.events_of(EventKind::TokenReuse).len(), 1);
}

/// Scenario 11: Parallel requests with the same cookie at rotation time all succeed; one rotates.
async fn parallel_requests_at_rotation_do_not_trip_reuse<St: SessionStore>(store: St) {
    let env = spawn(store, config()).await;
    let user = Uuid::new_v4();
    let old = env.login(user).await;
    env.advance(Duration::from_mins(11));

    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..24 {
        tasks.spawn(send(env.get("/me", &old)));
    }
    let mut rotated = Vec::new();
    while let Some(resp) = tasks.join_next().await {
        let resp = resp.unwrap();
        assert_eq!(resp.status, StatusCode::OK, "body: {}", resp.body);
        assert_eq!(resp.body, user.to_string());
        rotated.extend(resp.new_cookie());
    }
    assert_eq!(rotated.len(), 1, "exactly one request wins the rotation");

    assert_eq!(env.events_of(EventKind::TokenReuse).len(), 0);
    env.assert_me(&rotated[0], user).await;
    env.assert_me(&old, user).await;
}

/// Scenario 12: Logging in while presenting an old session cookie revokes that session.
async fn login_with_old_cookie_revokes_it<St: SessionStore>(store: St) {
    let env = spawn(store, config()).await;
    let user = Uuid::new_v4();
    let old = env.login(user).await;
    env.assert_me(&old, user).await;

    let resp = env.login_resp(user, Some(&old)).await;
    assert_eq!(resp.status, StatusCode::OK);
    let new = resp.new_cookie().unwrap();
    assert_ne!(new, old);

    assert_rejected(&send(env.get("/me", &old)).await, "not_authenticated");
    env.assert_me(&new, user).await;
    assert_eq!(env.guard.list_sessions(&user).await.unwrap().len(), 1);
}

/// Scenario 13: A sensitive group demands recent authentication; a step-up refreshes it.
async fn sensitive_group_requires_recent_auth<St: SessionStore>(store: St) {
    let env = spawn(store, config()).await;
    let user = Uuid::new_v4();
    let cookie = env.login(user).await;

    let resp = send(env.get("/sensitive/me", &cookie)).await;
    assert_eq!(resp.status, StatusCode::OK);

    env.advance(Duration::from_mins(20));
    let resp = send(env.get("/sensitive/me", &cookie)).await;
    assert_rejected(&resp, "step_up_required");
    assert_eq!(resp.header("clear-site-data"), None);
    // The rotation this request caused is still delivered, and the session is intact.
    let rotated = resp.new_cookie().expect("rotated token delivered with the 401");
    env.assert_me(&rotated, user).await;

    let resp = env.step_up(user, &rotated, &[]).await;
    assert_eq!(resp.status, StatusCode::OK);
    let fresh = resp.new_cookie().unwrap();
    let resp = send(env.get("/sensitive/me", &fresh)).await;
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(resp.body, user.to_string());
}

macro_rules! scenarios {
    ($($name:ident),* $(,)?) => {
        mod postgres {
            $(
                #[tokio::test(flavor = "multi_thread")]
                async fn $name() {
                    super::$name(super::pg_store().await).await;
                }
            )*
        }

        mod valkey {
            $(
                #[tokio::test(flavor = "multi_thread")]
                async fn $name() {
                    super::$name(super::valkey_store().await).await;
                }
            )*
        }
    };
}

scenarios!(
    login_sets_hardened_cookie,
    rotation_issues_new_cookie_and_grace_keeps_old,
    stolen_token_replay_revokes_session,
    country_change_steps_up_and_completion_resets_baseline,
    mobile_hint_flip_steps_up,
    os_change_revokes_session,
    logout_kills_the_token,
    bearer_bypass_and_token_prefix,
    trusted_proxy_forwarded_for_is_scored,
    untrusted_forwarded_for_is_ignored,
    idle_timeout_expires_session,
    absolute_lifetime_expires_session,
    shadow_mode_records_but_allows,
    parallel_requests_at_rotation_do_not_trip_reuse,
    login_with_old_cookie_revokes_it,
    sensitive_group_requires_recent_auth,
);
