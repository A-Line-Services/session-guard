//! The HTTP app shared by the `axum_postgres` and `axum_valkey` examples.
//!
//! Read it top to bottom. It has two halves with a hard boundary between them:
//!
//! * `yours`: what your application owns. Routes, handlers, and the credential check.
//!   session-guard does not log users in, verify passwords or rate-limit anything.
//! * `session`: the session-guard wiring. Configuration, the guard, the layers, the step-up
//!   endpoint, and the background purge.
//!
//! The HTTP layer is built with `rovo` (handlers documented by their doc comments, served with
//! a Swagger UI).

use std::net::SocketAddr;

use axum::Router;
use chrono::{DateTime, TimeDelta, Utc};
use rovo::aide::openapi::OpenApi;
use session_guard::{
    EventKind, Guard, MemoryStore, SessionEvent, SessionRecord, SessionStore, SessionUpdate, StoreError, TokenHash,
    TokenLookup,
};
use uuid::Uuid;

/// One concrete store type for the handlers (`#[rovo]` handlers cannot be generic).
///
/// `SessionStore` is not dyn-compatible, so an enum is the simplest way to pick the backend at
/// runtime. An app with a single backend would just use that store directly.
#[allow(dead_code, reason = "each example constructs one backend")]
pub enum AnyStore {
    /// In-process, for tests and the `core_only` example.
    Memory(MemoryStore),
    /// Postgres.
    #[cfg(feature = "postgres")]
    Postgres(session_guard::PgStore),
    /// Valkey.
    #[cfg(feature = "valkey")]
    Valkey(session_guard::ValkeyStore),
}

impl From<MemoryStore> for AnyStore {
    fn from(store: MemoryStore) -> Self {
        AnyStore::Memory(store)
    }
}

/// Forwards one `SessionStore` method to whichever backend is inside.
macro_rules! forward {
    ($self:ident.$method:ident($($arg:expr),*)) => {
        match $self {
            AnyStore::Memory(s) => s.$method($($arg),*).await,
            #[cfg(feature = "postgres")]
            AnyStore::Postgres(s) => s.$method($($arg),*).await,
            #[cfg(feature = "valkey")]
            AnyStore::Valkey(s) => s.$method($($arg),*).await,
        }
    };
}

impl SessionStore for AnyStore {
    async fn insert_session(&self, session: &SessionRecord, token: &TokenHash) -> Result<(), StoreError> {
        forward!(self.insert_session(session, token))
    }

    async fn find_by_token(&self, token: &TokenHash) -> Result<Option<TokenLookup>, StoreError> {
        forward!(self.find_by_token(token))
    }

    async fn apply(&self, update: &SessionUpdate) -> Result<bool, StoreError> {
        forward!(self.apply(update))
    }

    async fn delete_session(&self, session_id: Uuid) -> Result<bool, StoreError> {
        forward!(self.delete_session(session_id))
    }

    async fn delete_subject_sessions(&self, subject: &str) -> Result<u64, StoreError> {
        forward!(self.delete_subject_sessions(subject))
    }

    async fn list_subject_sessions(&self, subject: &str) -> Result<Vec<SessionRecord>, StoreError> {
        forward!(self.list_subject_sessions(subject))
    }

    async fn delete_expired(&self, now: DateTime<Utc>, idle_cutoff: DateTime<Utc>) -> Result<u64, StoreError> {
        forward!(self.delete_expired(now, idle_cutoff))
    }

    async fn record_event(&self, event: &SessionEvent) -> Result<(), StoreError> {
        forward!(self.record_event(event))
    }

    async fn delete_events_before(&self, cutoff: DateTime<Utc>) -> Result<u64, StoreError> {
        forward!(self.delete_events_before(cutoff))
    }

    async fn claim_event(
        &self,
        session_id: Uuid,
        kind: EventKind,
        now: DateTime<Utc>,
        window: TimeDelta,
    ) -> Result<bool, StoreError> {
        forward!(self.claim_event(session_id, kind, now, window))
    }
}

/// What every handler can reach: the guard, and in a real app your database and so on.
#[derive(Clone)]
pub struct AppState {
    guard: Guard<AnyStore>,
}

// =============================================================================================
// YOUR APP. Nothing in here is session-guard's job.
// =============================================================================================

/// Routes, handlers and the credential check.
mod yours {
    use axum::{
        http::{HeaderMap, StatusCode, header, request::Parts},
        response::{IntoResponse, Response},
    };
    use rovo::{
        aide::NoApi,
        extract::{Path, State},
        response::Json,
        routing::{delete, get, post},
        rovo,
        schemars::JsonSchema,
    };
    use serde::{Deserialize, Serialize};
    use session_guard::{AuthSession, axum::client_context};
    use uuid::Uuid;

    use super::AppState;

    /// The one demo user. Replace this with your user table.
    pub const DEMO_USER: Uuid = Uuid::from_u128(1);
    const DEMO_USERNAME: &str = "demo";
    const DEMO_PASSWORD: &str = "demo-password";

    /// An API key the app-side handler accepts, standing in for your key lookup.
    const DEMO_API_KEY: &str = "pat_demo-key";

    /// What the client sends to log in, and again to step up.
    #[derive(Deserialize, JsonSchema)]
    pub struct Credentials {
        /// Account name.
        pub username: String,
        /// Account password.
        pub password: String,
    }

    /// Toy credential check against a hardcoded user.
    ///
    /// Replace with your real authentication (password hash, SSO, passkey, ...), and
    /// rate-limit every route that calls it. session-guard does neither.
    pub fn verify(credentials: &Credentials) -> Option<Uuid> {
        (credentials.username == DEMO_USERNAME && credentials.password == DEMO_PASSWORD).then_some(DEMO_USER)
    }

    /// An error response body.
    #[derive(Serialize, JsonSchema)]
    pub struct ErrorBody {
        /// Machine-readable error code.
        pub error: String,
    }

    /// A JSON error response with `code` as its `error`.
    pub fn error(status: StatusCode, code: &str) -> Response {
        (status, Json(ErrorBody { error: code.to_owned() })).into_response()
    }

    /// The 500 for failures the client cannot fix. The details go to the log, not the client.
    pub fn internal(error: &dyn std::fmt::Display) -> Response {
        tracing::error!(%error, "request failed");
        self::error(StatusCode::INTERNAL_SERVER_ERROR, "internal")
    }

    /// The session that was just created.
    #[derive(Serialize, JsonSchema)]
    pub struct LoggedIn {
        /// The new session's id.
        pub session_id: Uuid,
    }

    /// Log in.
    ///
    /// Checks the credentials, then asks session-guard for a session and sets its cookie.
    /// Passing the cookie the client already holds makes session-guard revoke that old session
    /// first, which defeats session fixation.
    ///
    /// # Responses
    ///
    /// 200: Json<LoggedIn> - Logged in; the session cookie is set
    /// 401: Json<ErrorBody> - Wrong username or password
    /// 500: Json<ErrorBody> - Internal error
    ///
    /// # Metadata
    ///
    /// @tag auth
    #[rovo]
    pub async fn login(State(state): State<AppState>, parts: Parts, Json(credentials): Json<Credentials>) -> Response {
        // Your job: check who this is (and rate-limit this route).
        let Some(user) = verify(&credentials) else {
            return error(StatusCode::UNAUTHORIZED, "invalid_credentials");
        };
        // The guard's job: create the session.
        let ctx = match client_context(&state.guard, &parts) {
            Ok(ctx) => ctx,
            Err(missing) => return missing.into_response(),
        };
        let previous = state.guard.cookie_token(&parts.headers);
        match state.guard.login(&user, &ctx, previous).await {
            Ok(session) => (
                [(header::SET_COOKIE, session.token.set_cookie().to_owned())],
                Json(LoggedIn {
                    session_id: session.session_id,
                }),
            )
                .into_response(),
            Err(e) => internal(&e),
        }
    }

    /// Acknowledgement of an action.
    #[derive(Serialize, JsonSchema)]
    pub struct Done {
        /// Always `true`.
        pub ok: bool,
    }

    /// Log out.
    ///
    /// Deletes the session behind the cookie and clears the cookie. It sits outside the
    /// layers, so it also works for a session that is waiting for step-up.
    ///
    /// # Responses
    ///
    /// 200: Json<Done> - Logged out; the cookie is cleared
    /// 500: Json<ErrorBody> - Internal error
    ///
    /// # Metadata
    ///
    /// @tag auth
    #[rovo]
    pub async fn logout(State(state): State<AppState>, parts: Parts) -> Response {
        let ctx = match client_context(&state.guard, &parts) {
            Ok(ctx) => ctx,
            Err(missing) => return missing.into_response(),
        };
        if let Some(token) = state.guard.cookie_token(&parts.headers)
            && let Err(e) = state.guard.logout(token, &ctx).await
        {
            return internal(&e);
        }
        (
            [(header::SET_COOKIE, state.guard.clear_cookie())],
            Json(Done { ok: true }),
        )
            .into_response()
    }

    /// Who is signed in.
    #[derive(Serialize, JsonSchema)]
    pub struct Me {
        /// The session's subject, the id you passed to `login`.
        pub subject: Uuid,
        /// This session's id.
        pub session_id: Uuid,
        /// When the user last proved who they are (login or step-up), RFC 3339.
        pub authenticated_at: String,
        /// When the session expires, RFC 3339.
        pub expires_at: String,
    }

    /// The signed-in user.
    ///
    /// `AuthSession` is the session the layer authenticated. Without a valid session this
    /// handler is never reached: the extractor answers 401 `not_authenticated`.
    ///
    /// # Responses
    ///
    /// 200: Json<Me> - The current session
    /// 401: Json<ErrorBody> - No valid session
    ///
    /// # Metadata
    ///
    /// @tag account
    #[rovo]
    pub async fn me(NoApi(session): NoApi<AuthSession<Uuid>>) -> Json<Me> {
        Json(Me {
            subject: session.subject,
            session_id: session.session_id,
            authenticated_at: session.authenticated_at.to_rfc3339(),
            expires_at: session.expires_at.to_rfc3339(),
        })
    }

    /// One of the user's sessions ("your devices").
    #[derive(Serialize, JsonSchema)]
    pub struct SessionView {
        /// Session id, what `DELETE /sessions/{id}` takes.
        pub session_id: Uuid,
        /// Whether this is the session making the request.
        pub current: bool,
        /// When it was created, RFC 3339.
        pub created_at: String,
        /// When it was last seen, RFC 3339.
        pub last_seen_at: String,
        /// Browser family, if known.
        pub browser: Option<String>,
        /// Operating system family, if known.
        pub os: Option<String>,
        /// Country, if an IP intelligence source is configured.
        pub country: Option<String>,
    }

    /// List the user's sessions.
    ///
    /// # Responses
    ///
    /// 200: Json<Vec<SessionView>> - Every live session of the signed-in user
    /// 401: Json<ErrorBody> - No valid session
    /// 500: Json<ErrorBody> - Internal error
    ///
    /// # Metadata
    ///
    /// @tag account
    #[rovo]
    pub async fn list_sessions(State(state): State<AppState>, NoApi(session): NoApi<AuthSession<Uuid>>) -> Response {
        match state.guard.list_sessions(&session.subject).await {
            Ok(sessions) => Json(
                sessions
                    .into_iter()
                    .map(|s| SessionView {
                        session_id: s.session_id,
                        current: s.session_id == session.session_id,
                        created_at: s.created_at.to_rfc3339(),
                        last_seen_at: s.last_seen_at.to_rfc3339(),
                        browser: s.browser,
                        os: s.os,
                        country: s.country,
                    })
                    .collect::<Vec<_>>(),
            )
            .into_response(),
            Err(e) => internal(&e),
        }
    }

    /// Revoke one of the user's sessions.
    ///
    /// # Path Parameters
    ///
    /// id: The session to revoke
    ///
    /// # Responses
    ///
    /// 200: Json<Done> - The session is gone
    /// 401: Json<ErrorBody> - No valid session
    /// 404: Json<ErrorBody> - The user has no such session
    /// 500: Json<ErrorBody> - Internal error
    ///
    /// # Metadata
    ///
    /// @tag account
    #[rovo]
    pub async fn revoke_session(
        State(state): State<AppState>,
        NoApi(session): NoApi<AuthSession<Uuid>>,
        Path(id): Path<Uuid>,
    ) -> Response {
        // `revoke_session` takes any id, so check ownership first: otherwise a user could
        // revoke someone else's session.
        let owned = match state.guard.list_sessions(&session.subject).await {
            Ok(sessions) => sessions.iter().any(|s| s.session_id == id),
            Err(e) => return internal(&e),
        };
        if !owned {
            return error(StatusCode::NOT_FOUND, "not_found");
        }
        match state.guard.revoke_session(id).await {
            Ok(_) => Json(Done { ok: true }).into_response(),
            Err(e) => internal(&e),
        }
    }

    /// The outcome of the sensitive action.
    #[derive(Serialize, JsonSchema)]
    pub struct Transferred {
        /// Always `transferred`.
        pub status: String,
    }

    /// A sensitive action.
    ///
    /// This route sits behind the strict layer: a risky client or a login older than 15
    /// minutes gets 401 `step_up_required` and must `POST /step-up` first.
    ///
    /// # Responses
    ///
    /// 200: Json<Transferred> - Done
    /// 401: Json<ErrorBody> - No valid session, or `step_up_required`
    ///
    /// # Metadata
    ///
    /// @tag account
    #[rovo]
    pub async fn transfer(NoApi(_session): NoApi<AuthSession<Uuid>>) -> Json<Transferred> {
        Json(Transferred {
            status: "transferred".to_owned(),
        })
    }

    /// Which credential an API request used.
    #[derive(Serialize, JsonSchema)]
    pub struct Pong {
        /// Always `api_key`.
        pub auth: String,
    }

    /// Ping with an API key.
    ///
    /// Keys starting with `pat_` or `svc_` skip session-guard entirely (see the layer's
    /// `bypass_bearer_prefixes`), so this handler is the only thing judging them.
    ///
    /// # Responses
    ///
    /// 200: Json<Pong> - The key is valid
    /// 401: Json<ErrorBody> - Unknown key
    ///
    /// # Metadata
    ///
    /// @tag api
    #[rovo]
    pub async fn ping(headers: HeaderMap) -> Response {
        let key = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));
        // Your job: look the key up in your own table.
        if key == Some(DEMO_API_KEY) {
            Json(Pong {
                auth: "api_key".to_owned(),
            })
            .into_response()
        } else {
            error(StatusCode::UNAUTHORIZED, "invalid_api_key")
        }
    }

    /// Routes that need no session: log in and out.
    pub fn public_routes() -> rovo::Router<AppState> {
        rovo::Router::<AppState>::new()
            .route("/login", post(login))
            .route("/logout", post(logout))
    }

    /// Routes for signed-in users that use the app state, behind the standard layer.
    pub fn account_routes() -> rovo::Router<AppState> {
        rovo::Router::<AppState>::new()
            .route("/sessions", get(list_sessions))
            .route("/sessions/{id}", delete(revoke_session))
    }

    /// Routes for signed-in users that need no app state, behind the standard layer.
    ///
    /// (A rovo handler without a `State` extractor is a stateless route, so it lives in its own
    /// router.)
    pub fn account_stateless_routes() -> rovo::Router {
        rovo::Router::new().route("/me", get(me)).route("/api/ping", get(ping))
    }

    /// Routes that need a recent, low-risk login, behind the strict layer.
    pub fn sensitive_routes() -> rovo::Router {
        rovo::Router::new().route("/transfer", post(transfer))
    }
}

// =============================================================================================
// SESSION-GUARD. Everything below is the library wiring.
// =============================================================================================

/// Configuration, the guard, the layers, the step-up endpoint and the purge task.
pub mod session {
    use std::time::Duration;

    use axum::{
        http::{StatusCode, header, request::Parts},
        response::{IntoResponse, Response},
    };
    use rovo::{extract::State, response::Json, routing::post, rovo};
    use session_guard::{
        Checks, ConfigError, CookieConfig, Guard, GuardBuilder, GuardConfig, GuardLayer, SessionEvent, StepUpOutcome,
        axum::{client_context, rejection_response},
    };
    use uuid::Uuid;

    use super::{
        AnyStore, AppState,
        yours::{Credentials, Done, ErrorBody, error, internal, verify},
    };

    /// How recent a login must be for the sensitive routes.
    pub const RECENT_AUTH: Duration = Duration::from_mins(15);

    /// How often expired sessions and old events are deleted.
    pub const PURGE_EVERY: Duration = Duration::from_mins(10);

    /// The guard configuration.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] for an invalid proxy range or cookie.
    pub fn config() -> Result<GuardConfig, ConfigError> {
        GuardConfig::builder()
            // Plain-HTTP localhost needs a non-`Secure`, non-`__Host-` cookie. In production keep
            // the default (`__Host-sid`, `Secure`) and serve over HTTPS.
            .cookie(CookieConfig::named("sid").secure(false))
            // Only these proxies may set `X-Forwarded-For`. Without any, the TCP peer is the
            // client, which is right when nothing sits in front of the app.
            .trusted_proxies(["10.0.0.0/8", "172.16.0.0/12"])?
            // A recognizable prefix lets secret scanners find leaked session tokens.
            .token_prefix("sess_")
            .build()
    }

    /// The guard builder, before the clock and IP intelligence (tests set those).
    ///
    /// # Errors
    ///
    /// [`ConfigError`] from [`config`].
    pub fn builder(store: AnyStore) -> Result<GuardBuilder<AnyStore>, ConfigError> {
        Ok(Guard::builder(store, config()?))
    }

    /// The finished guard: [`builder`] plus event logging.
    ///
    /// Add `.ip_intel(MaxMindIntel::open(..))` (feature `maxmind`) for country and ASN signals.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] from [`config`].
    pub fn guard(store: AnyStore) -> Result<Guard<AnyStore>, ConfigError> {
        Ok(builder(store)?.on_event(log_event).build())
    }

    /// Logs every security event. Ship these to your SIEM instead if you have one.
    fn log_event(event: &SessionEvent) {
        let kind = event.kind.as_str();
        if event.kind.is_security_relevant() {
            tracing::warn!(session = %event.session_id, kind, enforced = event.enforced, score = ?event.score, ip = %event.ip, "session event");
        } else {
            tracing::info!(session = %event.session_id, kind, ip = %event.ip, "session event");
        }
    }

    /// The layer for ordinary signed-in routes.
    ///
    /// API keys with these prefixes belong to an app-side handler, so the guard lets them
    /// through untouched (they get no `AuthSession`).
    pub fn layer(guard: &Guard<AnyStore>) -> GuardLayer<AnyStore, Uuid> {
        guard.layer().bypass_bearer_prefixes(["pat_", "svc_"])
    }

    /// The layer for sensitive routes: strict risk checks, and a login no older than
    /// [`RECENT_AUTH`]. Failing either gives 401 `step_up_required`, with the cookie kept.
    pub fn sensitive_layer(guard: &Guard<AnyStore>) -> GuardLayer<AnyStore, Uuid> {
        guard.layer().with(Checks::strict()).require_recent_auth(RECENT_AUTH)
    }

    /// Step up.
    ///
    /// The answer to a 401 `step_up_required`. The user proves who they are again (here with
    /// the password, in your app a passkey or MFA), then session-guard marks the session
    /// trusted from the current client and issues a fresh token. This route must sit outside
    /// the layer that answers `step_up_required`, or it could never be reached.
    ///
    /// # Responses
    ///
    /// 200: Json<Done> - Trusted again; the new cookie is set
    /// 401: Json<ErrorBody> - Wrong credentials, or no valid session
    /// 403: Json<ErrorBody> - The credentials belong to a different user
    /// 500: Json<ErrorBody> - Internal error
    ///
    /// # Metadata
    ///
    /// @tag auth
    #[rovo]
    pub async fn step_up(
        State(state): State<AppState>,
        parts: Parts,
        Json(credentials): Json<Credentials>,
    ) -> Response {
        // Your job: re-verify the user (and rate-limit this route).
        let Some(verified) = verify(&credentials) else {
            return error(StatusCode::UNAUTHORIZED, "invalid_credentials");
        };
        // The guard's job: refuse unless the verified user owns this session.
        let Some(token) = state.guard.cookie_token(&parts.headers) else {
            return error(StatusCode::UNAUTHORIZED, "not_authenticated");
        };
        let ctx = match client_context(&state.guard, &parts) {
            Ok(ctx) => ctx,
            Err(missing) => return missing.into_response(),
        };
        match state.guard.complete_step_up(token, &ctx, &verified).await {
            Ok(StepUpOutcome::Completed(fresh)) => (
                [(header::SET_COOKIE, fresh.set_cookie().to_owned())],
                Json(Done { ok: true }),
            )
                .into_response(),
            Ok(StepUpOutcome::SubjectMismatch) => error(StatusCode::FORBIDDEN, "subject_mismatch"),
            Ok(StepUpOutcome::Rejected(rejection)) => rejection_response(rejection, &state.guard),
            Err(e) => internal(&e),
        }
    }

    /// The step-up route.
    pub fn step_up_routes() -> rovo::Router<AppState> {
        rovo::Router::<AppState>::new().route("/step-up", post(step_up))
    }

    /// Deletes expired sessions and old events now and then. Run it once per deployment or on
    /// every instance; it is safe either way.
    pub fn spawn_purge(guard: Guard<AnyStore>, every: Duration) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(every);
            loop {
                ticker.tick().await;
                match guard.purge_expired().await {
                    Ok(report) => {
                        tracing::info!(sessions = report.sessions, events = report.events, "purged");
                    }
                    Err(error) => tracing::warn!(%error, "purge failed"),
                }
            }
        })
    }
}

// =============================================================================================
// Joining the two
// =============================================================================================

/// Builds the whole app, ready for `into_make_service_with_connect_info::<SocketAddr>()`
/// (the layer needs the peer address).
pub fn router(guard: &Guard<AnyStore>) -> Router {
    let mut api = OpenApi::default();
    "session-guard example".clone_into(&mut api.info.title);
    api.info.description = Some("Log in with demo / demo-password.".to_owned());

    // Each group is finished into the shared spec, then layered on its own. A layer wraps only
    // the routes of the router it is applied to, so the groups get different rules.
    let state = AppState { guard: guard.clone() };
    let public = yours::public_routes().finish_api(&mut api).with_state(state.clone());
    let step_up = session::step_up_routes().finish_api(&mut api).with_state(state.clone());
    let account = yours::account_routes()
        .finish_api(&mut api)
        .with_state(state)
        .merge(yours::account_stateless_routes().finish_api(&mut api))
        .layer(session::layer(guard));
    let sensitive = yours::sensitive_routes()
        .finish_api(&mut api)
        .layer(session::sensitive_layer(guard));

    let docs = rovo::Router::new().with_oas(api).with_swagger("/swagger").finish();

    Router::new()
        .merge(public)
        .merge(step_up)
        .merge(account)
        .merge(sensitive)
        .merge(docs)
}

/// Runs the app on `LISTEN` (default `127.0.0.1:3000`) until it stops.
///
/// # Errors
///
/// Configuration errors, or failing to bind or serve.
pub async fn serve(store: AnyStore) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let guard = session::guard(store)?;
    session::spawn_purge(guard.clone(), session::PURGE_EVERY);

    let listen = std::env::var("LISTEN").unwrap_or_else(|_| "127.0.0.1:3000".to_owned());
    let listener = tokio::net::TcpListener::bind(&listen).await?;
    let addr = listener.local_addr()?;
    println!("listening on http://{addr}");
    println!("swagger UI:  http://{addr}/swagger");
    println!("log in:      curl -i -c jar -H 'content-type: application/json' \\");
    println!("               -d '{{\"username\":\"demo\",\"password\":\"demo-password\"}}' http://{addr}/login");

    axum::serve(
        listener,
        router(&guard).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
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
    use session_guard::{IpInfo, ManualClock, MemoryStore};
    use tower::ServiceExt;

    use super::{AnyStore, router, session};

    const CHROME_WIN: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";
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
        let guard = session::builder(AnyStore::from(MemoryStore::new()))
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
                .last()
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
        let sessions: serde_json::Value = serde_json::from_str(&list.body).unwrap();
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
        for path in ["/login", "/me", "/transfer", "/step-up", "/sessions", "/api/ping"] {
            assert!(
                spec.body.contains(&format!("\"{path}\"")),
                "{path} missing from the spec"
            );
        }
    }
}
