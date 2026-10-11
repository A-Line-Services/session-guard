//! The example app on Postgres.
//!
//! Needs a Postgres, for example:
//!
//! ```text
//! docker run --rm -p 5432:5432 -e POSTGRES_PASSWORD=postgres postgres:18-alpine
//! cargo run -p examples --bin axum_postgres
//! ```
//!
//! Environment:
//!
//! * `DATABASE_URL`: default `postgres://postgres:postgres@localhost:5432/postgres`
//! * `LISTEN`: address to bind, default `127.0.0.1:3000`
//!
//! The app itself is in `app/`, shared by the three examples.

#[path = "app/mod.rs"]
mod app;

/// The store behind every session. `app/` uses this alias, so it is the only line that changes
/// between the examples.
type Store = session_guard::PgStore;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    app::init_tracing();
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/postgres".to_owned());
    let pool = sqlx::PgPool::connect(&url).await?;
    // Creates the session tables on first run and checks them on every run.
    let store = Store::migrated(pool).await?;

    app::serve(store).await
}
