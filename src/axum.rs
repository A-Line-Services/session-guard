//! axum 0.8 integration: a tower layer that authenticates requests, the [`AuthSession`]
//! extractor, and helpers for routes outside the layer.
//!
//! The layer reads the TCP peer address from [`ConnectInfo<SocketAddr>`], so the app must be
//! served with [`into_make_service_with_connect_info`](::axum::Router::into_make_service_with_connect_info).
//! Without it every guarded request fails closed with 500.
//!
//! ```no_run
//! use std::net::SocketAddr;
//!
//! use axum::{Router, routing::get};
//! use session_guard::{AuthSession, Guard, MemoryStore};
//! use uuid::Uuid;
//!
//! async fn me(session: AuthSession<Uuid>) -> String {
//!     session.subject.to_string()
//! }
//!
//! # async fn run() -> std::io::Result<()> {
//! let guard = Guard::new(MemoryStore::new());
//! let app = Router::new().route("/me", get(me)).layer(guard.layer());
//!
//! let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
//! axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await
//! # }
//! ```
//!
//! # Responses
//!
//! Every rejection is a 401 with `Content-Type: application/json`, `Cache-Control: no-store`
//! and the body `{"error":"<code>"}`, where the code is [`Rejection::as_str`]. Rejections
//! that end the session also delete the cookie; a revoked session additionally sends
//! `Clear-Site-Data: "cookies"`. Guard errors (store failures) are a 500 with
//! `{"error":"internal"}`; the error itself is only logged.

use std::{
    convert::Infallible,
    fmt,
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use ::axum::{
    body::Body,
    extract::{ConnectInfo, FromRef, FromRequestParts, OptionalFromRequestParts},
    response::{IntoResponse, IntoResponseParts, Response, ResponseParts},
};
use http::{Extensions, HeaderMap, HeaderValue, Request, StatusCode, header, request::Parts};
use secrecy::{ExposeSecret, SecretString};
use tower_layer::Layer;
use tower_service::Service;
use uuid::Uuid;

use crate::{
    AuthSession, Checks, ClientContext, Guard, GuardError, IssuedToken, NewSession, Outcome, Rejection, StepUpOutcome,
    store::SessionStore, subject::Subject,
};

type Predicate = Arc<dyn Fn(&HeaderMap) -> bool + Send + Sync>;

impl<St: SessionStore, S: Subject> Guard<St, S> {
    /// A tower layer that authenticates every request through this guard.
    ///
    /// See [`GuardLayer`] for what it does per request and how to configure it.
    ///
    /// ```no_run
    /// use std::{net::SocketAddr, time::Duration};
    ///
    /// use axum::{Router, http::HeaderMap, routing::post};
    /// use session_guard::{AuthSession, Checks, Guard, MemoryStore};
    /// use uuid::Uuid;
    ///
    /// async fn transfer(session: AuthSession<Uuid>) -> &'static str {
    ///     "done"
    /// }
    ///
    /// # async fn run() -> std::io::Result<()> {
    /// let guard = Guard::new(MemoryStore::new());
    /// let layer = guard
    ///     .layer()
    ///     .with(Checks::strict())
    ///     .require_recent_auth(Duration::from_mins(15))
    ///     .bypass_bearer_prefixes(["pat_", "svc_"])
    ///     .bypass_when(|headers: &HeaderMap| headers.contains_key("x-internal-probe"));
    /// let app = Router::new().route("/transfer", post(transfer)).layer(layer);
    ///
    /// let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    /// axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await
    /// # }
    /// ```
    pub fn layer(&self) -> GuardLayer<St, S> {
        GuardLayer {
            shared: Arc::new(Shared {
                guard: self.clone(),
                checks: None,
                recent_auth: None,
                bearer_prefixes: Vec::new(),
                predicates: Vec::new(),
            }),
        }
    }
}

/// Settings shared by a layer and every service it creates.
struct Shared<St, S> {
    guard: Guard<St, S>,
    checks: Option<Checks>,
    recent_auth: Option<Duration>,
    bearer_prefixes: Vec<String>,
    predicates: Vec<Predicate>,
}

impl<St, S> Clone for Shared<St, S> {
    fn clone(&self) -> Self {
        Self {
            guard: self.guard.clone(),
            checks: self.checks,
            recent_auth: self.recent_auth,
            bearer_prefixes: self.bearer_prefixes.clone(),
            predicates: self.predicates.clone(),
        }
    }
}

impl<St, S> Shared<St, S> {
    fn bypassed(&self, headers: &HeaderMap) -> bool {
        bearer_token(headers).is_some_and(|token| self.bearer_prefixes.iter().any(|p| token.starts_with(p.as_str())))
            || self.predicates.iter().any(|p| p(headers))
    }
}

/// The token of an `Authorization: Bearer <token>` header (scheme case-insensitive).
fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?.trim();
    let (scheme, token) = value.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then(|| token.trim_start())
}

/// Tower layer that authenticates requests with a [`Guard`]. Create it with
/// [`Guard::layer`].
///
/// Per request, the service:
///
/// 1. Passes the request to the inner service untouched when a bypass matches
///    ([`bypass_bearer_prefixes`](Self::bypass_bearer_prefixes),
///    [`bypass_when`](Self::bypass_when)): no authentication, no [`AuthSession`], no added
///    headers.
/// 2. Reads the peer address from [`ConnectInfo<SocketAddr>`]. When it is missing the request
///    fails closed with 500, because the app was not served with
///    `into_make_service_with_connect_info::<SocketAddr>()`.
/// 3. Builds the [`ClientContext`] with [`Guard::client_context`] and authenticates the
///    session cookie. A missing cookie is `not_authenticated`.
/// 4. On success, inserts the [`AuthSession`] into the request extensions, calls the inner
///    service, appends the rotated token's `Set-Cookie` when the token was rotated, and sets
///    `Cache-Control: no-store`, **replacing** any `Cache-Control` the handler set:
///    authenticated responses must never be cached by shared caches or the browser.
/// 5. On rejection, answers with [`rejection_response`]; on a guard error, with 500
///    `{"error":"internal"}`.
///
/// Works with both [`Router::layer`](::axum::Router::layer) and
/// [`Router::route_layer`](::axum::Router::route_layer). Cheap to clone.
pub struct GuardLayer<St, S> {
    shared: Arc<Shared<St, S>>,
}

impl<St, S> Clone for GuardLayer<St, S> {
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<St, S> fmt::Debug for GuardLayer<St, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GuardLayer")
            .field("checks", &self.shared.checks)
            .field("recent_auth", &self.shared.recent_auth)
            .field("bearer_prefixes", &self.shared.bearer_prefixes)
            .field("predicates", &self.shared.predicates.len())
            .finish_non_exhaustive()
    }
}

impl<St, S> GuardLayer<St, S> {
    fn update(mut self, f: impl FnOnce(&mut Shared<St, S>)) -> Self {
        f(Arc::make_mut(&mut self.shared));
        self
    }

    /// Authenticates with `checks` through [`Guard::authenticate_with`] instead of the guard's
    /// configured checks, e.g. [`Checks::strict`] for sensitive routes. The session's baseline
    /// learns only the signals `checks` scored.
    ///
    /// Without this, the layer calls [`Guard::authenticate`] with the configured checks.
    #[must_use]
    pub fn with(self, checks: Checks) -> Self {
        self.update(|s| s.checks = Some(checks))
    }

    /// Rejects authenticated requests whose subject last proved who they are more than
    /// `max_age` ago with 401 `step_up_required` (see [`Guard::requires_reauth`]).
    ///
    /// The session is not changed and the cookie is kept; a token rotated by the same request
    /// is still delivered. Complete the step-up with
    /// [`Guard::complete_step_up`](crate::Guard::complete_step_up) to refresh
    /// `authenticated_at`.
    ///
    /// The window must leave room for the retry after the step-up: with a zero `max_age` that
    /// retry is already too late, so the route can never be reached. To confirm every single
    /// action (deleting an account, say), verify the credential in that request's handler
    /// instead, or use a short window such as two minutes.
    #[must_use]
    pub fn require_recent_auth(self, max_age: Duration) -> Self {
        self.update(|s| s.recent_auth = Some(max_age))
    }

    /// Passes requests whose `Authorization: Bearer <token>` starts with one of `prefixes` to
    /// the inner service untouched, for API keys handled by other middleware. Empty prefixes
    /// are ignored. Calls add to the list.
    #[must_use]
    pub fn bypass_bearer_prefixes<I, P>(self, prefixes: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: Into<String>,
    {
        let prefixes: Vec<String> = prefixes.into_iter().map(Into::into).filter(|p| !p.is_empty()).collect();
        self.update(|s| s.bearer_prefixes.extend(prefixes))
    }

    /// Passes requests for which `predicate` returns `true` to the inner service untouched.
    /// Calls add predicates; any match bypasses.
    #[must_use]
    pub fn bypass_when<F>(self, predicate: F) -> Self
    where
        F: Fn(&HeaderMap) -> bool + Send + Sync + 'static,
    {
        self.update(|s| s.predicates.push(Arc::new(predicate)))
    }
}

impl<I, St, S> Layer<I> for GuardLayer<St, S> {
    type Service = GuardService<I, St, S>;

    fn layer(&self, inner: I) -> Self::Service {
        GuardService {
            inner,
            shared: Arc::clone(&self.shared),
        }
    }
}

/// The service [`GuardLayer`] wraps around the inner service.
pub struct GuardService<I, St, S> {
    inner: I,
    shared: Arc<Shared<St, S>>,
}

impl<I: Clone, St, S> Clone for GuardService<I, St, S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<I: fmt::Debug, St, S> fmt::Debug for GuardService<I, St, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GuardService")
            .field("inner", &self.inner)
            .finish_non_exhaustive()
    }
}

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

impl<I, B, St, S> Service<Request<B>> for GuardService<I, St, S>
where
    I: Service<Request<B>, Response = Response> + Clone + Send + 'static,
    I::Future: Send + 'static,
    B: Send + 'static,
    St: SessionStore,
    S: Subject,
{
    type Response = Response;
    type Error = I::Error;
    type Future = BoxFuture<Result<Response, I::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<B>) -> Self::Future {
        // The clone may not be ready; keep the one `poll_ready` drove and leave the clone.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let shared = Arc::clone(&self.shared);
        Box::pin(async move {
            if shared.bypassed(req.headers()) {
                return inner.call(req).await;
            }
            let guard = &shared.guard;
            let Some(peer) = peer_ip(req.extensions()) else {
                return Ok(missing_connect_info());
            };
            let ctx = guard.client_context(peer, req.headers());
            let Some(token) = guard.cookie_token(req.headers()) else {
                return Ok(rejection_response(Rejection::NotAuthenticated, guard));
            };
            let outcome = match &shared.checks {
                Some(checks) => guard.authenticate_with(token, &ctx, checks).await,
                None => guard.authenticate(token, &ctx).await,
            };
            let auth = match outcome {
                Ok(Outcome::Authenticated(auth)) => auth,
                Ok(Outcome::Rejected(rejection)) => return Ok(rejection_response(rejection, guard)),
                Err(error) => return Ok(guard_error(&error)),
            };
            let rotated = auth.rotated.as_ref().map(crate::IssuedToken::set_cookie);
            if let Some(max_age) = shared.recent_auth
                && guard.requires_reauth(&auth.session, max_age)
            {
                let mut response = rejection_response(Rejection::StepUpRequired, guard);
                append_set_cookie(response.headers_mut(), rotated);
                return Ok(response);
            }
            req.extensions_mut().insert(auth.session.clone());
            let mut response = inner.call(req).await?;
            let headers = response.headers_mut();
            append_set_cookie(headers, rotated);
            headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            Ok(response)
        })
    }
}

fn peer_ip(extensions: &Extensions) -> Option<IpAddr> {
    extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip())
}

fn append_set_cookie(headers: &mut HeaderMap, set_cookie: Option<&str>) {
    let Some(set_cookie) = set_cookie else { return };
    if let Ok(value) = HeaderValue::from_str(set_cookie) {
        headers.append(header::SET_COOKIE, value);
    } else {
        tracing::error!("session cookie is not a valid header value; not sent");
    }
}

fn json_response(status: StatusCode, error: &str) -> Response {
    let mut response = Response::new(Body::from(format!(r#"{{"error":"{error}"}}"#)));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn internal_error() -> Response {
    json_response(StatusCode::INTERNAL_SERVER_ERROR, "internal")
}

fn missing_connect_info() -> Response {
    log_missing_connect_info();
    internal_error()
}

fn log_missing_connect_info() {
    tracing::error!(
        "session-guard: no ConnectInfo<SocketAddr> in request extensions; serve the app with \
         `into_make_service_with_connect_info::<SocketAddr>()`. Failing the request closed."
    );
}

fn guard_error(error: &GuardError) -> Response {
    tracing::error!(%error, "session-guard: authentication failed");
    internal_error()
}

/// The 401 response for `rejection`, identical to the one the layer sends.
///
/// Use it where the app talks to the guard itself, e.g. when
/// [`Guard::complete_step_up`](crate::Guard::complete_step_up) returns
/// [`StepUpOutcome::Rejected`]. The body is
/// `{"error":"<code>"}` with `Content-Type: application/json` and `Cache-Control: no-store`;
/// `Set-Cookie` deletes the cookie when [`Rejection::clears_cookie`], and
/// `Clear-Site-Data: "cookies"` is added when [`Rejection::clears_site_data`].
///
/// ```
/// use session_guard::{Guard, MemoryStore, Rejection, axum::rejection_response};
///
/// let guard = Guard::new(MemoryStore::new());
/// let response = rejection_response(Rejection::Revoked, &guard);
/// assert_eq!(response.status(), 401);
/// assert!(response.headers().contains_key("clear-site-data"));
/// ```
pub fn rejection_response<St, S>(rejection: Rejection, guard: &Guard<St, S>) -> Response
where
    St: SessionStore,
    S: Subject,
{
    rejection_with(rejection, &guard.clear_cookie())
}

fn rejection_with(rejection: Rejection, clear_cookie: &str) -> Response {
    let mut response = json_response(StatusCode::UNAUTHORIZED, rejection.as_str());
    let headers = response.headers_mut();
    if rejection.clears_cookie() {
        append_set_cookie(headers, Some(clear_cookie));
    }
    if rejection.clears_site_data() {
        headers.insert("clear-site-data", HeaderValue::from_static("\"cookies\""));
    }
    response
}

/// The [`ClientContext`] of a request, for handlers outside the layer (login, step-up,
/// logout) that call the guard themselves.
///
/// Like the layer, it needs [`ConnectInfo<SocketAddr>`] and fails closed without it: the
/// error is logged and converts into the same 500 `{"error":"internal"}` response.
///
/// ```no_run
/// use std::net::SocketAddr;
///
/// use axum::{
///     Router,
///     extract::State,
///     http::{StatusCode, header, request::Parts},
///     response::{IntoResponse, Response},
///     routing::post,
/// };
/// use session_guard::{Guard, MemoryStore, axum::client_context};
/// use uuid::Uuid;
///
/// async fn login(State(guard): State<Guard<MemoryStore>>, parts: Parts) -> Response {
///     let ctx = match client_context(&guard, &parts) {
///         Ok(ctx) => ctx,
///         Err(missing) => return missing.into_response(),
///     };
///     // Verify the credentials here; that, and rate limiting, is the app's job.
///     let user = Uuid::new_v4();
///     let previous = guard.cookie_token(&parts.headers);
///     match guard.login(&user, &ctx, previous).await {
///         Ok(session) => ([(header::SET_COOKIE, session.token.set_cookie())], "welcome").into_response(),
///         Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
///     }
/// }
///
/// # async fn run() -> std::io::Result<()> {
/// let guard = Guard::new(MemoryStore::new());
/// let app = Router::new().route("/login", post(login)).with_state(guard);
/// let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
/// axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await
/// # }
/// ```
///
/// # Errors
///
/// [`MissingConnectInfo`] when the request has no [`ConnectInfo<SocketAddr>`].
pub fn client_context<St, S>(guard: &Guard<St, S>, parts: &Parts) -> Result<ClientContext, MissingConnectInfo>
where
    St: SessionStore,
    S: Subject,
{
    let Some(peer) = peer_ip(&parts.extensions) else {
        log_missing_connect_info();
        return Err(MissingConnectInfo);
    };
    Ok(guard.client_context(peer, &parts.headers))
}

/// The request carries no [`ConnectInfo<SocketAddr>`]: the app was not served with
/// `into_make_service_with_connect_info::<SocketAddr>()`. Responds with 500
/// `{"error":"internal"}` and `Cache-Control: no-store`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MissingConnectInfo;

impl fmt::Display for MissingConnectInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("no ConnectInfo<SocketAddr> in request extensions")
    }
}

impl std::error::Error for MissingConnectInfo {}

impl IntoResponse for MissingConnectInfo {
    fn into_response(self) -> Response {
        internal_error()
    }
}

/// Extracts the session the [`GuardLayer`] authenticated. Without the layer (or for a
/// bypassed request) it rejects with 401 `{"error":"not_authenticated"}`.
///
/// `S` must match the guard's subject type.
impl<A, S> FromRequestParts<A> for AuthSession<S>
where
    A: Send + Sync,
    S: Clone + Send + Sync + 'static,
{
    type Rejection = Response;

    fn from_request_parts(parts: &mut Parts, _state: &A) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(
            parts
                .extensions
                .get::<AuthSession<S>>()
                .cloned()
                .ok_or_else(|| json_response(StatusCode::UNAUTHORIZED, Rejection::NotAuthenticated.as_str())),
        )
    }
}

/// `Option<AuthSession<S>>`: `None` when the layer did not authenticate the request, for
/// handlers that serve both anonymous and signed-in clients.
impl<A, S> OptionalFromRequestParts<A> for AuthSession<S>
where
    A: Send + Sync,
    S: Clone + Send + Sync + 'static,
{
    type Rejection = std::convert::Infallible;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &A,
    ) -> impl Future<Output = Result<Option<Self>, Self::Rejection>> + Send {
        std::future::ready(Ok(parts.extensions.get::<AuthSession<S>>().cloned()))
    }
}

/// Responses that set or delete the session cookie: append `Set-Cookie` and forbid caching.
fn cookie_parts(mut parts: ResponseParts, set_cookie: &str) -> ResponseParts {
    let headers = parts.headers_mut();
    append_set_cookie(headers, Some(set_cookie));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    parts
}

/// Sends the token: appends its `Set-Cookie` and `Cache-Control: no-store`.
///
/// ```
/// # use axum::http::StatusCode;
/// # use session_guard::IssuedToken;
/// fn respond(token: IssuedToken) -> impl axum::response::IntoResponse {
///     (token, StatusCode::NO_CONTENT)
/// }
/// ```
impl IntoResponseParts for IssuedToken {
    type Error = Infallible;

    fn into_response_parts(self, parts: ResponseParts) -> Result<ResponseParts, Self::Error> {
        Ok(cookie_parts(parts, self.set_cookie()))
    }
}

/// Sends the session's first token, like [`IssuedToken`].
impl IntoResponseParts for NewSession {
    type Error = Infallible;

    fn into_response_parts(self, parts: ResponseParts) -> Result<ResponseParts, Self::Error> {
        self.token.into_response_parts(parts)
    }
}

/// A 500 with `{"error":"internal"}` and `Cache-Control: no-store`. The error itself is only
/// logged, so store details never reach the client.
impl IntoResponse for GuardError {
    fn into_response(self) -> Response {
        guard_error(&self)
    }
}

/// Login, logout and step-up for handlers: the guard, the request's [`ClientContext`] and the
/// session cookie it carries, in one extractor.
///
/// It takes the guard from the router state (anything with [`FromRef`] for
/// [`Guard<St, S>`](Guard), including the guard itself) and needs
/// [`ConnectInfo<SocketAddr>`] like the layer; without it the request fails closed with
/// [`MissingConnectInfo`]. It does not authenticate anything, so put step-up routes outside the
/// [`GuardLayer`]: the layer would answer `step_up_required` before the handler runs.
///
/// Every result converts into a response: [`NewSession`] and [`IssuedToken`] set the cookie,
/// [`LoggedOut`] deletes it, and [`GuardError`] and [`StepUpError`] become the matching error.
/// Verifying credentials, and rate limiting the routes that do, stays with the app.
///
/// ```no_run
/// use std::net::SocketAddr;
///
/// use axum::{Router, http::StatusCode, routing::post};
/// use session_guard::{
///     Guard, GuardError, IssuedToken, MemoryStore, NewSession,
///     axum::{LoggedOut, Sessions, StepUpError},
/// };
/// use uuid::Uuid;
///
/// // Stands in for the app's own credential check.
/// async fn verify() -> Uuid {
///     Uuid::nil()
/// }
///
/// async fn login(sessions: Sessions<MemoryStore>) -> Result<(NewSession, StatusCode), GuardError> {
///     let user = verify().await;
///     Ok((sessions.login(&user).await?, StatusCode::NO_CONTENT))
/// }
///
/// async fn step_up(sessions: Sessions<MemoryStore>) -> Result<(IssuedToken, StatusCode), StepUpError> {
///     let user = verify().await;
///     Ok((sessions.complete_step_up(&user).await?, StatusCode::NO_CONTENT))
/// }
///
/// async fn logout(sessions: Sessions<MemoryStore>) -> Result<(LoggedOut, StatusCode), GuardError> {
///     Ok((sessions.logout().await?, StatusCode::NO_CONTENT))
/// }
///
/// # async fn run() -> std::io::Result<()> {
/// let guard = Guard::new(MemoryStore::new());
/// let app = Router::new()
///     .route("/login", post(login))
///     .route("/step-up", post(step_up))
///     .route("/logout", post(logout))
///     .with_state(guard);
/// let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
/// axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await
/// # }
/// ```
pub struct Sessions<St, S = Uuid> {
    guard: Guard<St, S>,
    client: ClientContext,
    token: Option<SecretString>,
}

impl<St, S> fmt::Debug for Sessions<St, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sessions")
            .field("client", &self.client)
            .field("token", &self.token.as_ref().map(|_| "<redacted>"))
            .finish_non_exhaustive()
    }
}

impl<St: SessionStore, S: Subject> Sessions<St, S> {
    /// [`Guard::login`] for `subject`, revoking the session the request presented, if any.
    /// Call it only after verifying the subject's credentials.
    ///
    /// # Errors
    ///
    /// As [`Guard::login`].
    pub async fn login(&self, subject: &S) -> Result<NewSession, GuardError> {
        self.guard.login(subject, &self.client, self.token()).await
    }

    /// [`Guard::logout`] for the presented session. The result deletes the cookie even when
    /// there was no session to revoke.
    ///
    /// # Errors
    ///
    /// As [`Guard::logout`].
    pub async fn logout(&self) -> Result<LoggedOut, GuardError> {
        let revoked = match self.token() {
            Some(token) => self.guard.logout(token, &self.client).await?,
            None => false,
        };
        Ok(LoggedOut {
            revoked,
            clear_cookie: self.guard.clear_cookie(),
        })
    }

    /// [`Guard::complete_step_up`] for the presented session, once the app has verified
    /// `verified_subject`'s credentials again.
    ///
    /// # Errors
    ///
    /// A [`StepUpError`]: the subject does not own the session, there is no live session
    /// (including no cookie at all), or the guard failed.
    pub async fn complete_step_up(&self, verified_subject: &S) -> Result<IssuedToken, StepUpError> {
        let failure = match self.token() {
            None => StepUpFailure::Rejected(Rejection::NotAuthenticated),
            Some(token) => match self.guard.complete_step_up(token, &self.client, verified_subject).await {
                Ok(StepUpOutcome::Completed(token)) => return Ok(token),
                Ok(StepUpOutcome::SubjectMismatch) => StepUpFailure::SubjectMismatch,
                Ok(StepUpOutcome::Rejected(rejection)) => StepUpFailure::Rejected(rejection),
                Err(error) => StepUpFailure::Guard(error),
            },
        };
        Err(StepUpError {
            failure,
            clear_cookie: self.guard.clear_cookie(),
        })
    }

    /// The guard, for anything else (listing or revoking sessions).
    pub fn guard(&self) -> &Guard<St, S> {
        &self.guard
    }

    /// The request's client context.
    pub fn client(&self) -> &ClientContext {
        &self.client
    }

    /// The session cookie's value, if the request carried one. Not validated.
    pub fn token(&self) -> Option<&str> {
        self.token.as_ref().map(ExposeSecret::expose_secret)
    }
}

impl<T, St, S> FromRequestParts<T> for Sessions<St, S>
where
    T: Send + Sync,
    Guard<St, S>: FromRef<T>,
    St: SessionStore,
    S: Subject,
{
    type Rejection = MissingConnectInfo;

    fn from_request_parts(parts: &mut Parts, state: &T) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        let guard = Guard::from_ref(state);
        let sessions = client_context(&guard, parts).map(|client| {
            let token = guard
                .cookie_token(&parts.headers)
                .map(|token| SecretString::from(token.to_owned()));
            Self { guard, client, token }
        });
        std::future::ready(sessions)
    }
}

/// Result of [`Sessions::logout`]. As response parts it deletes the cookie and sets
/// `Cache-Control: no-store`.
#[derive(Clone, Debug)]
pub struct LoggedOut {
    revoked: bool,
    clear_cookie: String,
}

impl LoggedOut {
    /// Whether a session was revoked; `false` when the request had none.
    pub fn revoked(&self) -> bool {
        self.revoked
    }
}

impl IntoResponseParts for LoggedOut {
    type Error = Infallible;

    fn into_response_parts(self, parts: ResponseParts) -> Result<ResponseParts, Self::Error> {
        Ok(cookie_parts(parts, &self.clear_cookie))
    }
}

/// Why [`Sessions::complete_step_up`] failed. As a response:
///
/// - [`StepUpFailure::SubjectMismatch`]: 403 `{"error":"subject_mismatch"}`, cookie kept.
/// - [`StepUpFailure::Rejected`]: the layer's 401 for that rejection (see
///   [`rejection_response`]).
/// - [`StepUpFailure::Guard`]: 500 `{"error":"internal"}`, the error only logged.
#[derive(Debug)]
pub struct StepUpError {
    failure: StepUpFailure,
    clear_cookie: String,
}

/// The cause of a [`StepUpError`].
#[derive(Debug)]
#[non_exhaustive]
pub enum StepUpFailure {
    /// The verified subject does not own the session. Nothing changed.
    SubjectMismatch,
    /// There is no live session to step up.
    Rejected(Rejection),
    /// The guard failed.
    Guard(GuardError),
}

impl StepUpError {
    /// What went wrong.
    pub fn failure(&self) -> &StepUpFailure {
        &self.failure
    }

    /// What went wrong, by value.
    pub fn into_failure(self) -> StepUpFailure {
        self.failure
    }
}

impl fmt::Display for StepUpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.failure {
            StepUpFailure::SubjectMismatch => f.write_str("verified subject does not own the session"),
            StepUpFailure::Rejected(rejection) => write!(f, "step-up rejected: {rejection}"),
            StepUpFailure::Guard(_) => f.write_str("step-up failed"),
        }
    }
}

impl std::error::Error for StepUpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.failure {
            StepUpFailure::Guard(error) => Some(error),
            _ => None,
        }
    }
}

impl IntoResponse for StepUpError {
    fn into_response(self) -> Response {
        match self.failure {
            StepUpFailure::SubjectMismatch => json_response(StatusCode::FORBIDDEN, "subject_mismatch"),
            StepUpFailure::Rejected(rejection) => rejection_with(rejection, &self.clear_cookie),
            StepUpFailure::Guard(error) => guard_error(&error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(auth: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::AUTHORIZATION, HeaderValue::from_str(auth).unwrap());
        h
    }

    #[test]
    fn bearer_parsing() {
        assert_eq!(bearer_token(&headers("Bearer abc")), Some("abc"));
        assert_eq!(bearer_token(&headers("BEARER  abc")), Some("abc"));
        assert_eq!(bearer_token(&headers("Basic abc")), None);
        assert_eq!(bearer_token(&headers("Bearer")), None);
        assert_eq!(bearer_token(&HeaderMap::new()), None);
    }

    #[test]
    fn json_body_is_exact() {
        let response = json_response(StatusCode::UNAUTHORIZED, "session_expired");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    }
}
