//! A session-guard app on axum and rovo, with the in-memory store: nothing to install.
//!
//! ```text
//! cargo run -p examples --bin axum_memory
//! ```
//!
//! Then open <http://127.0.0.1:3000/swagger> and log in with `demo` / `demo-password`.
//! Sessions are lost on restart; `axum_postgres` and `axum_valkey` run the same app on a real
//! store.
//!
//! Environment:
//!
//! * `LISTEN`: address to bind, default `127.0.0.1:3000`
//!
//! The app itself is in `app/`, shared by the three examples.

#[path = "app/mod.rs"]
mod app;
#[cfg(test)]
#[path = "app/tests.rs"]
mod tests;

/// The store behind every session. `app/` uses this alias, so it is the only line that changes
/// between the examples.
type Store = session_guard::MemoryStore;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    app::init_tracing();
    app::serve(Store::new()).await
}
