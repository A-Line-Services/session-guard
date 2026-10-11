//! The smallest axum app with session-guard: log in, see who you are, log out.
//!
//! ```sh
//! cargo run -p examples --bin axum_simple
//!
//! curl -i -c jar -H 'content-type: application/json' \
//!   -d '{"username":"demo","password":"demo-password"}' http://127.0.0.1:3000/login
//! curl -b jar http://127.0.0.1:3000/me
//! curl -i -b jar -X POST http://127.0.0.1:3000/logout
//! ```
//!
//! For OpenAPI, step-up, API keys and the Postgres and Valkey stores, see `axum_memory`.

use std::net::SocketAddr;

use axum::{
    Json, Router,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use session_guard::{
    AuthSession, ConfigError, CookieConfig, Guard, GuardConfig, GuardError, MemoryStore, Sessions, axum::LoggedOut,
};
use uuid::Uuid;

const DEMO_USER: Uuid = Uuid::from_u128(1);

#[derive(Deserialize)]
struct Credentials {
    username: String,
    password: String,
}

async fn login(sessions: Sessions<MemoryStore>, Json(creds): Json<Credentials>) -> Response {
    // A real app checks a password hash here and rate limits attempts.
    if creds.username != "demo" || creds.password != "demo-password" {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    match sessions.login(&DEMO_USER).await {
        // `NewSession` sets the session cookie.
        Ok(session) => (session, "signed in\n").into_response(),
        Err(err) => err.into_response(),
    }
}

/// Only reachable with a valid session: the layer answers 401 otherwise.
async fn me(session: AuthSession<Uuid>) -> String {
    format!("signed in as {}\n", session.subject)
}

async fn logout(sessions: Sessions<MemoryStore>) -> Result<(LoggedOut, &'static str), GuardError> {
    // `LoggedOut` deletes the cookie.
    Ok((sessions.logout().await?, "signed out\n"))
}

fn guard() -> Result<Guard<MemoryStore>, ConfigError> {
    let config = GuardConfig::builder()
        // Plain-HTTP localhost needs a non-`Secure` cookie. In production keep the default
        // (`__Host-sid`, `Secure`) and serve over HTTPS.
        .cookie(CookieConfig::named("sid").secure(false))
        .build()?;
    Ok(Guard::builder(MemoryStore::new(), config).build())
}

fn app(guard: Guard<MemoryStore>) -> Router {
    Router::new()
        .route("/me", get(me))
        // The layer wraps only the routes added before it.
        .layer(guard.layer())
        .route("/login", post(login))
        .route("/logout", post(logout))
        .with_state(guard)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    println!("listening on http://{}", listener.local_addr()?);
    // The layer needs the peer address.
    let service = app(guard()?).into_make_service_with_connect_info::<SocketAddr>();
    axum::serve(listener, service).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        extract::ConnectInfo,
        http::{Request, header},
    };
    use tower::ServiceExt;

    use super::*;

    async fn send(app: &Router, method: &str, path: &str, cookie: Option<&str>, body: &str) -> Response {
        let mut req = Request::builder()
            .method(method)
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(cookie) = cookie {
            req = req.header(header::COOKIE, cookie);
        }
        let mut req = req.body(Body::from(body.to_owned())).unwrap();
        // `into_make_service_with_connect_info` sets this in `main`.
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 4000))));
        app.clone().oneshot(req).await.unwrap()
    }

    /// The `name=value` part of the response's `Set-Cookie`.
    fn cookie(response: &Response) -> String {
        let set_cookie = response.headers()[header::SET_COOKIE].to_str().unwrap();
        set_cookie.split(';').next().unwrap().to_owned()
    }

    const DEMO: &str = r#"{"username":"demo","password":"demo-password"}"#;

    #[tokio::test]
    async fn login_me_logout() {
        let app = app(guard().unwrap());

        let anonymous = send(&app, "GET", "/me", None, "").await;
        assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);

        let login = send(&app, "POST", "/login", None, DEMO).await;
        assert_eq!(login.status(), StatusCode::OK);
        let session = cookie(&login);

        let me = send(&app, "GET", "/me", Some(&session), "").await;
        assert_eq!(me.status(), StatusCode::OK);

        let logout = send(&app, "POST", "/logout", Some(&session), "").await;
        assert_eq!(logout.status(), StatusCode::OK);
        let after = send(&app, "GET", "/me", Some(&session), "").await;
        assert_eq!(after.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn wrong_password_gets_no_session() {
        let app = app(guard().unwrap());
        let body = r#"{"username":"demo","password":"guess"}"#;
        let login = send(&app, "POST", "/login", None, body).await;
        assert_eq!(login.status(), StatusCode::UNAUTHORIZED);
        assert!(login.headers().get(header::SET_COOKIE).is_none());
    }
}
