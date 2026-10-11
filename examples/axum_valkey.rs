//! A session-guard app on axum, rovo and Valkey (or Redis).
//!
//! Needs a Valkey, for example:
//!
//! ```text
//! docker run --rm -p 6379:6379 valkey/valkey:8-alpine
//! cargo run --example axum_valkey --features axum,valkey
//! ```
//!
//! Environment:
//!
//! * `VALKEY_URL`: default `redis://localhost:6379`
//! * `LISTEN`: address to bind, default `127.0.0.1:3000`
//!
//! The routes, the credential check and the session wiring are in `shared/app.rs`, which the
//! Postgres example reuses. Only the store differs here.

#[path = "shared/app.rs"]
mod app;

use app::AnyStore;
use session_guard::ValkeyStore;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let url = std::env::var("VALKEY_URL").unwrap_or_else(|_| "redis://localhost:6379".to_owned());
    let store = ValkeyStore::connect(&url).await?;

    app::serve(AnyStore::Valkey(store)).await
}
