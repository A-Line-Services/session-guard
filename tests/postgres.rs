//! `PgStore` against a real Postgres started with testcontainers (needs Docker).
//!
//! All tests share one reusable container (see `tests/support`); the conformance suite is safe
//! on a shared database.

mod support;

use std::time::Duration;

use chrono::TimeDelta;
use session_guard::{ClaimScope, EventKind, PgStore, Rotation, SessionStore, SessionUpdate, Supersede, testing};
use sqlx::{PgPool, postgres::PgPoolOptions};
use support::postgres_url;
use uuid::Uuid;

/// Connects to the shared container, retrying while Postgres finishes starting up. The image
/// prints the ready message once for its init server (unix socket only) and once for the real
/// one, so a successful TCP query means the real server is up.
async fn pool() -> PgPool {
    let url = postgres_url().await;
    let mut last = None;
    for _ in 0..100 {
        // Small pools: nextest runs many test processes against the one server.
        match PgPoolOptions::new().max_connections(4).connect(url).await {
            Ok(pool) => match sqlx::query("SELECT 1").execute(&pool).await {
                Ok(_) => return pool,
                Err(e) => last = Some(e),
            },
            Err(e) => last = Some(e),
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("postgres never became ready: {last:?}");
}

async fn store() -> PgStore {
    PgStore::migrated(pool().await).await.expect("migrations")
}

session_guard::store_conformance!(store);

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_apply_from_tasks_has_one_winner() {
    let store = store().await;
    let store = store.clone();
    let now = testing::now_secs();
    let session = testing::sample_session(now);
    let first = testing::random_hash();
    store.insert_session(&session, &first).await.unwrap();

    let tasks: Vec<_> = (0..32)
        .map(|_| {
            let store = store.clone();
            let candidate = testing::random_hash();
            let update = SessionUpdate {
                rotation: Some(Rotation {
                    new_token: candidate,
                    supersede: Supersede::Exact(first),
                    prune_superseded_before: now,
                }),
                mark_used: Some(first),
                ..SessionUpdate::touch(session.id, now + TimeDelta::seconds(1))
            };
            tokio::spawn(async move { (candidate, store.apply(&update).await.unwrap()) })
        })
        .collect();
    let mut winners = Vec::new();
    for task in tasks {
        let (candidate, won) = task.await.unwrap();
        if won {
            winners.push(candidate);
        }
    }
    assert_eq!(winners.len(), 1, "exactly one rotation wins");
    let current = store.find_by_token(&winners[0]).await.unwrap().unwrap();
    assert_eq!(current.token.superseded_at, None);
    let old = store.find_by_token(&first).await.unwrap().unwrap();
    assert!(old.token.superseded_at.is_some());
    assert!(old.token.first_used_at.is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn migrated_is_idempotent() {
    let pool = pool().await;
    PgStore::migrated(pool.clone()).await.unwrap();
    PgStore::migrated(pool.clone()).await.unwrap();
    PgStore::migrator().run(&pool).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn claims_dedupe_across_store_instances() {
    let store = store().await;
    let other = PgStore::new(pool().await);
    let now = testing::now_secs();
    let window = TimeDelta::seconds(600);
    let scope = ClaimScope::Session(Uuid::new_v4());
    assert!(
        store
            .claim_event(scope, EventKind::StepUpRequired, now, window)
            .await
            .unwrap()
    );
    assert!(
        !other
            .claim_event(scope, EventKind::StepUpRequired, now + TimeDelta::seconds(5), window)
            .await
            .unwrap()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_claims_have_one_winner() {
    let store = store().await;
    let now = testing::now_secs();
    let scope = ClaimScope::Session(Uuid::new_v4());
    let tasks: Vec<_> = (0..16)
        .map(|_| {
            let store = store.clone();
            tokio::spawn(async move {
                store
                    .claim_event(scope, EventKind::RiskRevoked, now, TimeDelta::seconds(600))
                    .await
                    .unwrap()
            })
        })
        .collect();
    let mut won = 0;
    for task in tasks {
        won += usize::from(task.await.unwrap());
    }
    assert_eq!(won, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn schema_allows_one_current_token_per_session() {
    let store = store().await;
    let pool = pool().await;
    let now = testing::now_secs();
    let session = testing::sample_session(now);
    store.insert_session(&session, &testing::random_hash()).await.unwrap();
    let second = sqlx::query("INSERT INTO session_guard_tokens (hash, session_id, issued_at) VALUES ($1, $2, $3)")
        .bind(&testing::random_hash().as_bytes()[..])
        .bind(session.id)
        .bind(now)
        .execute(&pool)
        .await;
    assert!(second.is_err(), "a second current token is rejected");
}

#[tokio::test(flavor = "multi_thread")]
async fn corrupt_rows_are_errors_not_panics() {
    let store = store().await;
    let pool = pool().await;
    let now = testing::now_secs();
    let session = testing::sample_session(now);
    let token = testing::random_hash();
    store.insert_session(&session, &token).await.unwrap();
    sqlx::query("UPDATE session_guard_sessions SET baseline = '[1, 2]' WHERE id = $1")
        .bind(session.id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(store.find_by_token(&token).await.is_err());
    assert!(store.list_subject_sessions(&session.subject).await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn debug_does_not_leak_connection_details() {
    let store = store().await;
    let debug = format!("{store:?}");
    assert!(debug.starts_with("PgStore"));
    assert!(!debug.contains("postgres:postgres"), "{debug}");
    assert!(!debug.contains("password"), "{debug}");
}
