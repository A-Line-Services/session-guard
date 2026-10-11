//! `ValkeyStore` against a real Valkey in Docker (testcontainers).
//!
//! All tests share one container (see `support`); every store gets a random key prefix so tests
//! never see each other's data.

use std::sync::Arc;

use chrono::TimeDelta;
use session_guard::{EventKind, Rotation, SessionStore, SessionUpdate, Supersede, ValkeyStore, testing};
use uuid::Uuid;

mod support;

use support::valkey_url;

fn random_prefix() -> String {
    format!("sgtest:{}:", Uuid::new_v4().simple())
}

async fn store_with_prefix(prefix: &str) -> ValkeyStore {
    ValkeyStore::connect(valkey_url().await)
        .await
        .expect("connect to valkey")
        .key_prefix(prefix)
}

async fn store() -> ValkeyStore {
    store_with_prefix(&random_prefix()).await
}

session_guard::store_conformance!(store);

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_rotation_across_tasks_has_one_winner() {
    let store = Arc::new(store().await);
    let now = testing::now_secs();
    let session = testing::sample_session(now);
    let first = testing::random_hash();
    store.insert_session(&session, &first).await.unwrap();

    let mut handles = Vec::new();
    for _ in 0..64 {
        let store = Arc::clone(&store);
        handles.push(tokio::spawn(async move {
            let candidate = testing::random_hash();
            let update = SessionUpdate {
                rotation: Some(Rotation {
                    new_token: candidate,
                    supersede: Supersede::Exact(first),
                    prune_superseded_before: now,
                }),
                ..SessionUpdate::touch(session.id, now + TimeDelta::seconds(1))
            };
            (candidate, store.apply(&update).await.unwrap())
        }));
    }
    let mut winners = Vec::new();
    for handle in handles {
        let (candidate, won) = handle.await.unwrap();
        if won {
            winners.push(candidate);
        }
    }
    assert_eq!(winners.len(), 1, "exactly one rotation wins");
    let current = store.find_by_token(&winners[0]).await.unwrap().unwrap();
    assert_eq!(current.token.superseded_at, None);
    let old = store.find_by_token(&first).await.unwrap().unwrap();
    assert_eq!(old.token.superseded_at, Some(now + TimeDelta::seconds(1)));
}

#[tokio::test(flavor = "multi_thread")]
async fn claims_dedupe_across_store_instances() {
    let prefix = random_prefix();
    let a = store_with_prefix(&prefix).await;
    let b = store_with_prefix(&prefix).await;
    let now = testing::now_secs();
    let window = TimeDelta::seconds(600);
    let session = Uuid::new_v4();
    assert!(
        a.claim_event(session, EventKind::RiskRevoked, now, window)
            .await
            .unwrap()
    );
    assert!(
        !b.claim_event(session, EventKind::RiskRevoked, now + TimeDelta::seconds(5), window)
            .await
            .unwrap()
    );
    assert!(
        b.claim_event(session, EventKind::RiskRevoked, now + window, window)
            .await
            .unwrap()
    );
    assert!(
        !a.claim_event(session, EventKind::RiskRevoked, now + window, window)
            .await
            .unwrap()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn claims_older_than_cutoff_are_purged() {
    let store = store().await;
    let now = testing::now_secs();
    let window = TimeDelta::seconds(600);
    let session = Uuid::new_v4();
    assert!(
        store
            .claim_event(session, EventKind::RiskRevoked, now, window)
            .await
            .unwrap()
    );
    assert_eq!(
        store.delete_events_before(now + TimeDelta::seconds(1)).await.unwrap(),
        0
    );
    assert!(
        store
            .claim_event(session, EventKind::RiskRevoked, now + TimeDelta::seconds(1), window)
            .await
            .unwrap(),
        "the purged claim no longer blocks"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn key_prefixes_isolate_stores() {
    let a = store().await;
    let b = store().await;
    let now = testing::now_secs();
    let subject = format!("\"shared-{}\"", Uuid::new_v4());
    let session = testing::sample_session_for(&subject, now);
    let token = testing::random_hash();
    a.insert_session(&session, &token).await.unwrap();

    assert!(a.find_by_token(&token).await.unwrap().is_some());
    assert!(b.find_by_token(&token).await.unwrap().is_none());
    assert_eq!(b.list_subject_sessions(&subject).await.unwrap(), vec![]);
    assert_eq!(b.delete_subject_sessions(&subject).await.unwrap(), 0);
    assert!(!b.delete_session(session.id).await.unwrap());
    assert!(!b.apply(&SessionUpdate::touch(session.id, now)).await.unwrap());
    assert_eq!(a.list_subject_sessions(&subject).await.unwrap(), vec![session]);
}

#[tokio::test(flavor = "multi_thread")]
async fn subjects_with_lua_metacharacters_are_opaque() {
    let store = store().await;
    let now = testing::now_secs();
    let subject = format!("\"x']]..redis.call('FLUSHALL')--{}\"", Uuid::new_v4());
    let session = testing::sample_session_for(&subject, now);
    store.insert_session(&session, &testing::random_hash()).await.unwrap();
    assert_eq!(store.list_subject_sessions(&subject).await.unwrap(), vec![session]);
    assert_eq!(store.delete_subject_sessions(&subject).await.unwrap(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn debug_hides_connection_details() {
    let store = store().await;
    let debug = format!("{store:?}");
    assert!(debug.contains("ValkeyStore"));
    assert!(!debug.contains("redis://"));
}
