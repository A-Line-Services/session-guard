//! A session-guard app on axum, rovo and Postgres.
//!
//! Needs a Postgres, for example:
//!
//! ```text
//! docker run --rm -p 5432:5432 -e POSTGRES_PASSWORD=postgres postgres:18-alpine
//! cargo run --example axum_postgres --features axum,postgres
//! ```
//!
//! Environment:
//!
//! * `DATABASE_URL`: default `postgres://postgres:postgres@localhost:5432/postgres`
//! * `LISTEN`: address to bind, default `127.0.0.1:3000`
//!
//! The routes, the credential check and the session wiring are in `shared/app.rs`, which the
//! Valkey example reuses. Only the store differs here.

#[path = "shared/app.rs"]
mod app;

use app::AnyStore;
use session_guard::PgStore;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/postgres".to_owned());
    let pool = sqlx::PgPool::connect(&url).await?;
    // Creates the session tables on first run and checks them on every run.
    let store = PgStore::migrated(pool).await?;

    app::serve(AnyStore::Postgres(store)).await
}
