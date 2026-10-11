//! The example app on Valkey (or Redis).
//!
//! Needs a Valkey, for example:
//!
//! ```text
//! docker run --rm -p 6379:6379 valkey/valkey:8-alpine
//! cargo run -p examples --bin axum_valkey
//! ```
//!
//! Environment:
//!
//! * `VALKEY_URL`: default `redis://localhost:6379`
//! * `LISTEN`: address to bind, default `127.0.0.1:3000`
//!
//! The app itself is in `app/`, shared by the three examples.

#[path = "app/mod.rs"]
mod app;

/// The store behind every session. `app/` uses this alias, so it is the only line that changes
/// between the examples.
type Store = session_guard::ValkeyStore;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    app::init_tracing();
    let url = std::env::var("VALKEY_URL").unwrap_or_else(|_| "redis://localhost:6379".to_owned());
    let store = Store::connect(&url).await?;

    app::serve(store).await
}
