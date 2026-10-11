//! `PgStore` against a real Postgres started with testcontainers (needs Docker).
//!
//! All tests share one container. It lives as long as some test holds a [`Held`] store and is
//! removed when the last one finishes, so neither `cargo test` nor `cargo nextest` leaks it.

use std::{
    sync::{Arc, Mutex, PoisonError, Weak, mpsc},
    thread::JoinHandle,
    time::Duration,
};

use chrono::{DateTime, TimeDelta, Utc};
use session_guard::{
    EventKind, PgStore, Rotation, SessionEvent, SessionRecord, SessionStore, SessionUpdate, StoreError, Supersede,
    TokenHash, TokenLookup, testing,
};
use sqlx::{PgPool, postgres::PgPoolOptions};
use testcontainers::{
    GenericImage, ImageExt,
    core::{IntoContainerPort, WaitFor},
    runners::AsyncRunner,
};
use uuid::Uuid;

/// A running container, owned by a dedicated thread so it is created and removed on one runtime.
struct Postgres {
    url: String,
    stop: Option<mpsc::Sender<()>>,
    owner: Option<JoinHandle<()>>,
}

impl Drop for Postgres {
    fn drop(&mut self) {
        // Closing the channel tells the owner thread to remove the container; wait for it so
        // the process cannot exit first.
        drop(self.stop.take());
        if let Some(owner) = self.owner.take() {
            let _ = owner.join();
        }
    }
}

static SHARED: Mutex<Weak<Postgres>> = Mutex::new(Weak::new());

fn postgres() -> Arc<Postgres> {
    let mut shared = SHARED.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(running) = shared.upgrade() {
        return running;
    }
    let (url_tx, url_rx) = mpsc::channel();
    let (stop, stop_rx) = mpsc::channel::<()>();
    let owner = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("owner runtime");
        let container = runtime.block_on(async {
            GenericImage::new("postgres", "18-alpine")
                .with_wait_for(WaitFor::message_on_stderr(
                    "database system is ready to accept connections",
                ))
                .with_exposed_port(5432.tcp())
                .with_env_var("POSTGRES_PASSWORD", "postgres")
                .start()
                .await
                .expect("start postgres container")
        });
        let url = runtime.block_on(async {
            let host = container.get_host().await.expect("container host");
            let port = container.get_host_port_ipv4(5432.tcp()).await.expect("container port");
            format!("postgres://postgres:postgres@{host}:{port}/postgres")
        });
        url_tx.send(url).expect("send url");
        let _ = stop_rx.recv();
        runtime.block_on(async move { drop(container) });
    });
    let url = url_rx.recv().expect("postgres container started");
    let running = Arc::new(Postgres {
        url,
        stop: Some(stop),
        owner: Some(owner),
    });
    *shared = Arc::downgrade(&running);
    running
}

/// Connects to the shared container, retrying while Postgres finishes starting up. The image
/// prints the ready message once for its init server (unix socket only) and once for the real
/// one, so a successful TCP query means the real server is up.
async fn pool(pg: &Postgres) -> PgPool {
    let mut last = None;
    for _ in 0..100 {
        match PgPoolOptions::new().max_connections(20).connect(&pg.url).await {
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

/// A store that keeps the shared container alive while the test uses it.
struct Held {
    store: PgStore,
    pg: Arc<Postgres>,
}

impl std::ops::Deref for Held {
    type Target = PgStore;

    fn deref(&self) -> &PgStore {
        &self.store
    }
}

async fn held() -> Held {
    let pg = tokio::task::spawn_blocking(postgres).await.expect("start postgres");
    let pool = pool(&pg).await;
    Held {
        store: PgStore::migrated(pool).await.expect("migrations"),
        pg,
    }
}

impl SessionStore for Held {
    async fn insert_session(&self, session: &SessionRecord, token: &TokenHash) -> Result<(), StoreError> {
        self.store.insert_session(session, token).await
    }

    async fn find_by_token(&self, token: &TokenHash) -> Result<Option<TokenLookup>, StoreError> {
        self.store.find_by_token(token).await
    }

    async fn apply(&self, update: &SessionUpdate) -> Result<bool, StoreError> {
        self.store.apply(update).await
    }

    async fn delete_session(&self, session_id: Uuid) -> Result<bool, StoreError> {
        self.store.delete_session(session_id).await
    }

    async fn delete_subject_sessions(&self, subject: &str) -> Result<u64, StoreError> {
        self.store.delete_subject_sessions(subject).await
    }

    async fn list_subject_sessions(&self, subject: &str) -> Result<Vec<SessionRecord>, StoreError> {
        self.store.list_subject_sessions(subject).await
    }

    async fn delete_expired(&self, now: DateTime<Utc>, idle_cutoff: DateTime<Utc>) -> Result<u64, StoreError> {
        self.store.delete_expired(now, idle_cutoff).await
    }

    async fn record_event(&self, event: &SessionEvent) -> Result<(), StoreError> {
        self.store.record_event(event).await
    }

    async fn delete_events_before(&self, cutoff: DateTime<Utc>) -> Result<u64, StoreError> {
        self.store.delete_events_before(cutoff).await
    }

    async fn claim_event(
        &self,
        session_id: Uuid,
        kind: EventKind,
        now: DateTime<Utc>,
        window: TimeDelta,
    ) -> Result<bool, StoreError> {
        self.store.claim_event(session_id, kind, now, window).await
    }
}

session_guard::store_conformance!(held);

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_apply_from_tasks_has_one_winner() {
    let held = held().await;
    let store = held.store.clone();
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
    let held = held().await;
    let pool = pool(&held.pg).await;
    PgStore::migrated(pool.clone()).await.unwrap();
    PgStore::migrated(pool.clone()).await.unwrap();
    PgStore::migrator().run(&pool).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn claims_dedupe_across_store_instances() {
    let held = held().await;
    let other = PgStore::new(pool(&held.pg).await);
    let now = testing::now_secs();
    let window = TimeDelta::seconds(600);
    let session = Uuid::new_v4();
    assert!(
        held.claim_event(session, EventKind::StepUpRequired, now, window)
            .await
            .unwrap()
    );
    assert!(
        !other
            .claim_event(session, EventKind::StepUpRequired, now + TimeDelta::seconds(5), window)
            .await
            .unwrap()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_claims_have_one_winner() {
    let held = held().await;
    let now = testing::now_secs();
    let session = Uuid::new_v4();
    let tasks: Vec<_> = (0..16)
        .map(|_| {
            let store = held.store.clone();
            tokio::spawn(async move {
                store
                    .claim_event(session, EventKind::RiskRevoked, now, TimeDelta::seconds(600))
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
    let held = held().await;
    let pool = pool(&held.pg).await;
    let now = testing::now_secs();
    let session = testing::sample_session(now);
    held.insert_session(&session, &testing::random_hash()).await.unwrap();
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
    let held = held().await;
    let pool = pool(&held.pg).await;
    let now = testing::now_secs();
    let session = testing::sample_session(now);
    let token = testing::random_hash();
    held.insert_session(&session, &token).await.unwrap();
    sqlx::query("UPDATE session_guard_sessions SET baseline = '[1, 2]' WHERE id = $1")
        .bind(session.id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(held.find_by_token(&token).await.is_err());
    assert!(held.list_subject_sessions(&session.subject).await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn debug_does_not_leak_connection_details() {
    let held = held().await;
    let debug = format!("{:?}", held.store);
    assert!(debug.starts_with("PgStore"));
    assert!(!debug.contains("postgres:postgres"), "{debug}");
    assert!(!debug.contains("password"), "{debug}");
}
