//! `ValkeyStore` against a real Valkey Cluster in Docker (testcontainers).
//!
//! Runs the same conformance suite as `tests/valkey.rs`, plus checks that only a cluster can
//! fail: every script must stay inside one hash slot.

use session_guard::ValkeyStore;
use uuid::Uuid;

mod support;

use support::valkey_cluster_url;

fn random_prefix() -> String {
    format!("sgtest:{}:", Uuid::new_v4().simple())
}

async fn store() -> ValkeyStore {
    ValkeyStore::connect_cluster([valkey_cluster_url().await])
        .await
        .expect("connect to valkey cluster")
        .key_prefix(random_prefix())
}

session_guard::store_conformance!(store);

// --- sharding ---

use std::{collections::HashSet, sync::Arc};

use session_guard::{
    Rotation, SessionRecord, SessionStore, SessionUpdate, Supersede, TokenHash, testing, token_bucket,
};
use sha2::{Digest, Sha256};

/// A session of `subject` in `bucket`, with a token in the same bucket.
fn in_bucket(subject: &str, bucket: u8) -> (SessionRecord, TokenHash) {
    let mut session = testing::sample_session_for(subject, testing::now_secs());
    let mut id = *session.id.as_bytes();
    id[15] = bucket;
    session.id = Uuid::from_bytes(id);
    (session, token_in_bucket(bucket))
}

fn token_in_bucket(bucket: u8) -> TokenHash {
    let mut bytes = *testing::random_hash().as_bytes();
    bytes[0] = bucket;
    TokenHash::from_bytes(bytes)
}

fn unique_subject() -> String {
    format!("\"cluster-{}\"", Uuid::new_v4())
}

/// A raw connection, to plant or inspect keys the store would not expose.
async fn raw() -> redis::cluster_async::ClusterConnection {
    redis::cluster::ClusterClient::new([valkey_cluster_url().await])
        .unwrap()
        .get_async_connection()
        .await
        .unwrap()
}

/// The index key of `kind` (`u` or `ur`) for `subject`, mirroring the documented layout.
fn index_key(prefix: &str, kind: &str, subject: &str) -> String {
    format!(
        "{prefix}{{{:02x}}}:{kind}:{subject}",
        Sha256::digest(subject.as_bytes())[0]
    )
}

#[tokio::test]
async fn one_subject_spans_many_buckets() {
    let store = store().await;
    let subject = unique_subject();
    let mut ids = HashSet::new();
    let mut tokens = Vec::new();
    for bucket in (0..=255).step_by(17) {
        let (session, token) = in_bucket(&subject, bucket);
        store.insert_session(&session, &token).await.unwrap();
        ids.insert(session.id);
        tokens.push(token);
    }
    let (bystander, bystander_token) = in_bucket(&unique_subject(), 3);
    store.insert_session(&bystander, &bystander_token).await.unwrap();

    let listed: HashSet<_> = store
        .list_subject_sessions(&subject)
        .await
        .unwrap()
        .into_iter()
        .map(|s| s.id)
        .collect();
    assert_eq!(listed, ids);

    let deleted: HashSet<_> = store
        .delete_subject_sessions(&subject)
        .await
        .unwrap()
        .into_iter()
        .collect();
    assert_eq!(deleted, ids);
    for token in &tokens {
        assert!(store.find_by_token(token).await.unwrap().is_none());
    }
    assert_eq!(store.list_subject_sessions(&subject).await.unwrap().len(), 0);
    assert!(store.find_by_token(&bystander_token).await.unwrap().is_some());
}

#[tokio::test]
async fn writes_across_buckets_are_rejected() {
    let store = store().await;
    let (session, _) = in_bucket(&unique_subject(), 1);
    let other = token_in_bucket(2);
    assert_ne!(token_bucket(&other), 1);
    assert!(store.insert_session(&session, &other).await.is_err());

    let aligned = token_in_bucket(1);
    store.insert_session(&session, &aligned).await.unwrap();
    let now = testing::now_secs();
    let update = SessionUpdate {
        rotation: Some(Rotation {
            new_token: other,
            supersede: Supersede::Current,
            prune_superseded_before: now,
        }),
        ..SessionUpdate::touch(session.id, now)
    };
    assert!(store.apply(&update).await.is_err());
    let mark = SessionUpdate {
        mark_used: Some(other),
        ..SessionUpdate::touch(session.id, now)
    };
    assert!(store.apply(&mark).await.is_err());
}

#[tokio::test]
async fn a_crashed_revoke_is_finished_by_the_next_one() {
    let prefix = random_prefix();
    let store = ValkeyStore::connect_cluster([valkey_cluster_url().await])
        .await
        .unwrap()
        .key_prefix(&prefix);
    let subject = unique_subject();
    let (a, a_token) = in_bucket(&subject, 10);
    let (b, b_token) = in_bucket(&subject, 200);
    store.insert_session(&a, &a_token).await.unwrap();
    store.insert_session(&b, &b_token).await.unwrap();

    // The first phase of a revoke ran and the process died: the ids sit in the revoking set.
    let _: () = redis::cmd("RENAME")
        .arg(index_key(&prefix, "u", &subject))
        .arg(index_key(&prefix, "ur", &subject))
        .query_async(&mut raw().await)
        .await
        .unwrap();
    assert_eq!(store.list_subject_sessions(&subject).await.unwrap().len(), 2);

    let deleted: HashSet<_> = store
        .delete_subject_sessions(&subject)
        .await
        .unwrap()
        .into_iter()
        .collect();
    assert_eq!(deleted, HashSet::from([a.id, b.id]));
    assert!(store.find_by_token(&a_token).await.unwrap().is_none());
    assert_eq!(store.list_subject_sessions(&subject).await.unwrap().len(), 0);
}

#[tokio::test]
async fn revoke_never_deletes_a_session_of_another_subject() {
    let prefix = random_prefix();
    let store = ValkeyStore::connect_cluster([valkey_cluster_url().await])
        .await
        .unwrap()
        .key_prefix(&prefix);
    let subject = unique_subject();
    let (foreign, foreign_token) = in_bucket(&unique_subject(), 77);
    store.insert_session(&foreign, &foreign_token).await.unwrap();
    // A stale or corrupt index entry pointing at someone else's session.
    let _: i64 = redis::cmd("SADD")
        .arg(index_key(&prefix, "u", &subject))
        .arg(foreign.id.to_string())
        .query_async(&mut raw().await)
        .await
        .unwrap();

    assert_eq!(store.delete_subject_sessions(&subject).await.unwrap().len(), 0);
    assert!(store.find_by_token(&foreign_token).await.unwrap().is_some());
    assert_eq!(store.list_subject_sessions(&subject).await.unwrap().len(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn logins_racing_a_revoke_are_revoked_or_rejected() {
    let store = Arc::new(store().await);
    let subject = unique_subject();

    let mut creators = Vec::new();
    for i in 0..48_u8 {
        let store = Arc::clone(&store);
        let subject = subject.clone();
        creators.push(tokio::spawn(async move {
            let (session, token) = in_bucket(&subject, i.wrapping_mul(5));
            // Rejected or not, the session must not outlive the revoke. A rejected login may
            // still be reported deleted: the revoke and the creator both clean up, either first.
            let _ = store.insert_session(&session, &token).await;
            (session.id, token)
        }));
    }
    let revoker = {
        let store = Arc::clone(&store);
        let subject = subject.clone();
        tokio::spawn(async move {
            for _ in 0..8 {
                store.delete_subject_sessions(&subject).await.unwrap();
            }
        })
    };
    let mut created = Vec::new();
    for creator in creators {
        created.push(creator.await.unwrap());
    }
    revoker.await.unwrap();

    // Whatever survived the race is still reachable from the index, so a last revoke gets it.
    store.delete_subject_sessions(&subject).await.unwrap();
    for (id, token) in created {
        assert!(
            store.find_by_token(&token).await.unwrap().is_none(),
            "{id} outlived the revoke"
        );
    }
    assert_eq!(store.list_subject_sessions(&subject).await.unwrap().len(), 0);
}

#[tokio::test]
#[should_panic(expected = "key prefix")]
async fn key_prefixes_with_braces_are_rejected() {
    let _ = store().await.key_prefix("sg:{tenant}:");
}

#[tokio::test]
async fn listing_prunes_ids_of_sessions_that_are_gone() {
    let prefix = random_prefix();
    let store = ValkeyStore::connect_cluster([valkey_cluster_url().await])
        .await
        .unwrap()
        .key_prefix(&prefix);
    let subject = unique_subject();
    let (live, live_token) = in_bucket(&subject, 4);
    store.insert_session(&live, &live_token).await.unwrap();
    let ghost = in_bucket(&subject, 9).0.id;
    let u = index_key(&prefix, "u", &subject);
    let _: i64 = redis::cmd("SADD")
        .arg(&u)
        .arg(ghost.to_string())
        .query_async(&mut raw().await)
        .await
        .unwrap();

    let listed = store.list_subject_sessions(&subject).await.unwrap();
    assert_eq!(listed.iter().map(|s| s.id).collect::<Vec<_>>(), [live.id]);
    let members: HashSet<String> = redis::cmd("SMEMBERS")
        .arg(&u)
        .query_async(&mut raw().await)
        .await
        .unwrap();
    assert_eq!(members, HashSet::from([live.id.to_string()]));
}

#[tokio::test]
async fn malformed_index_members_do_not_block_revoke_or_listing() {
    let prefix = random_prefix();
    let store = ValkeyStore::connect_cluster([valkey_cluster_url().await])
        .await
        .unwrap()
        .key_prefix(&prefix);
    let subject = unique_subject();
    let (session, token) = in_bucket(&subject, 4);
    store.insert_session(&session, &token).await.unwrap();
    let u = index_key(&prefix, "u", &subject);
    let _: i64 = redis::cmd("SADD")
        .arg(&u)
        .arg("not-a-uuid")
        .query_async(&mut raw().await)
        .await
        .unwrap();

    assert_eq!(store.list_subject_sessions(&subject).await.unwrap().len(), 1);
    assert_eq!(store.delete_subject_sessions(&subject).await.unwrap(), [session.id]);
    let left: i64 = redis::cmd("EXISTS")
        .arg(&u)
        .arg(index_key(&prefix, "ur", &subject))
        .query_async(&mut raw().await)
        .await
        .unwrap();
    assert_eq!(left, 0);
}

#[tokio::test]
async fn revoke_covers_an_index_set_without_expiry() {
    let prefix = random_prefix();
    let store = ValkeyStore::connect_cluster([valkey_cluster_url().await])
        .await
        .unwrap()
        .key_prefix(&prefix);
    let subject = unique_subject();
    let (session, token) = in_bucket(&subject, 4);
    store.insert_session(&session, &token).await.unwrap();
    let _: i64 = redis::cmd("PERSIST")
        .arg(index_key(&prefix, "u", &subject))
        .query_async(&mut raw().await)
        .await
        .unwrap();

    assert_eq!(store.delete_subject_sessions(&subject).await.unwrap(), [session.id]);
    assert!(store.find_by_token(&token).await.unwrap().is_none());
}

#[tokio::test]
async fn duplicate_session_ids_and_tokens_are_rejected() {
    use session_guard::SessionStore;
    let store = store().await;
    let now = testing::now_secs();
    let session = testing::sample_session(now);
    let token = testing::random_hash();
    store.insert_session(&session, &token).await.unwrap();
    assert!(store.insert_session(&session, &testing::random_hash()).await.is_err());
    assert!(
        store
            .insert_session(&testing::sample_session(now), &token)
            .await
            .is_err()
    );
}
