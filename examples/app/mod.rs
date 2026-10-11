//! The HTTP app shared by the `axum_memory`, `axum_postgres` and `axum_valkey` examples.
//!
//! Each binary defines `type Store`; everything here is written against that alias.
//!
//! * [`config`]: the session-guard wiring (configuration and the two layers).
//! * [`routes`]: which handler sits behind which layer.
//! * [`handlers`]: the endpoints, documented for rovo by their doc comments.
//! * [`users`]: the credential and API key checks. These are your app's job, not the guard's.
//! * [`models`], [`errors`], [`state`]: request and response types, and what handlers share.

pub mod config;
pub mod errors;
pub mod handlers;
pub mod models;
pub mod routes;
pub mod state;
pub mod users;

use std::net::SocketAddr;

use rovo::aide::{
    axum::ApiRouter,
    openapi::{OpenApi, SecurityScheme},
};
use session_guard::{
    Guard,
    aide::{SECURITY_SCHEME, security_scheme},
};
use tracing_subscriber::EnvFilter;

use self::state::AppState;
use crate::Store;

/// Builds the whole app, ready for `into_make_service_with_connect_info::<SocketAddr>()`
/// (the layer needs the peer address).
pub fn router(guard: &Guard<Store>) -> axum::Router {
    let mut api = OpenApi::default();
    // A layer wraps only the routes merged before it, so each group gets its own.
    let app = ApiRouter::new()
        .merge(routes::public().into_inner())
        .merge(routes::account().into_inner().layer(config::layer(guard)))
        .merge(routes::sensitive().into_inner().layer(config::sensitive_layer(guard)))
        .finish_api_with(&mut api, |api| {
            api.title("session-guard example")
                .description("Log in with demo / demo-password.")
                // The schemes the routes' security requirements refer to.
                .security_scheme(SECURITY_SCHEME, security_scheme(guard))
                .security_scheme("bearer", bearer_scheme())
        })
        .with_state(AppState { guard: guard.clone() });

    let docs = rovo::Router::new().with_oas(api).with_swagger("/swagger").finish();
    app.merge(docs)
}

/// The scheme behind `@security bearer`: an API key the app checks itself.
#[expect(clippy::default_trait_access, reason = "aide does not re-export IndexMap")]
fn bearer_scheme() -> SecurityScheme {
    SecurityScheme::Http {
        scheme: "bearer".to_owned(),
        bearer_format: None,
        description: Some("API key (`pat_…` or `svc_…`), checked by the app.".to_owned()),
        extensions: Default::default(),
    }
}

/// Logs to stdout, filtered by `RUST_LOG` (default `info`). Call it first in `main`, so the
/// store's connection logs show up too.
pub fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
}

/// Runs the app on `LISTEN` (default `127.0.0.1:3000`) until it stops.
///
/// # Errors
///
/// Configuration errors, or failing to bind or serve.
pub async fn serve(store: Store) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let guard = config::guard(store)?;
    // Deletes expired sessions and old events. Safe to run on every instance.
    let _purge = guard.spawn_purge(config::PURGE_EVERY);

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
