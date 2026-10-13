//! PostgreSQL store on sqlx.

use std::{fmt, sync::LazyLock};

use chrono::{DateTime, TimeDelta, Utc};
use sqlx::{
    PgPool, Postgres, Row, Transaction,
    migrate::{MigrateError, Migrator},
    postgres::PgRow,
    types::Json,
};
use uuid::Uuid;

use super::{ClaimScope, SessionRecord, SessionStore, SessionUpdate, Supersede, TokenLookup, TokenRecord};
use crate::{
    error::StoreError,
    event::{EventKind, SessionEvent, SessionOrigin},
    fingerprint::Baseline,
    token::TokenHash,
};

/// Table that records which session-guard migrations ran, kept apart from the app's
/// `_sqlx_migrations` so the two migration sets never see each other as missing.
const MIGRATIONS_TABLE: &str = "_session_guard_migrations";

static MIGRATOR: LazyLock<Migrator> = LazyLock::new(|| {
    let mut migrator = sqlx::migrate!();
    migrator.dangerous_set_table_name(MIGRATIONS_TABLE);
    migrator
});

/// Partial unique index allowing one current token per session.
const CURRENT_TOKEN_INDEX: &str = "session_guard_tokens_current_idx";

/// Stores sessions in PostgreSQL through a sqlx [`PgPool`]. Shared safely by any number of
/// processes; rotations are single transactions with a conditional update, and a partial unique
/// index guarantees at most one current token per session.
///
/// Tables are named `session_guard_*`. Create them with [`PgStore::migrated`], or run
/// [`PgStore::migrator`] in your own deployment pipeline. Applied migrations are tracked in
/// `_session_guard_migrations`, separate from your app's `_sqlx_migrations`.
///
/// ```no_run
/// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
/// use session_guard::{Guard, PgStore};
///
/// let pool = sqlx::PgPool::connect("postgres://localhost/app").await?;
/// let guard = Guard::new(PgStore::migrated(pool).await?);
/// # let _ = guard;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct PgStore {
    pool: PgPool,
}

impl fmt::Debug for PgStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The pool's own Debug prints connect options; keep credentials out of logs.
        f.debug_struct("PgStore")
            .field("connections", &self.pool.size())
            .finish_non_exhaustive()
    }
}

impl PgStore {
    /// Wraps `pool` without touching the schema. Run [`PgStore::migrator`] first.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Runs the embedded migrations, then wraps `pool`. Safe to call from many processes at
    /// once and on every start: applied migrations are skipped.
    ///
    /// # Errors
    ///
    /// If a migration fails or the applied migrations do not match the embedded ones.
    pub async fn migrated(pool: PgPool) -> Result<Self, MigrateError> {
        MIGRATOR.run(&pool).await?;
        Ok(Self::new(pool))
    }

    /// The embedded migrations, for running them in your own pipeline:
    /// `PgStore::migrator().run(&pool).await?`.
    pub fn migrator() -> &'static Migrator {
        &MIGRATOR
    }

    /// The underlying pool.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    async fn rotate(
        tx: &mut Transaction<'static, Postgres>,
        update: &SessionUpdate,
        rotation: &super::Rotation,
    ) -> Result<bool, sqlx::Error> {
        let (exact, issued_before) = match rotation.supersede {
            Supersede::Exact(hash) => (Some(hash.as_bytes().to_vec()), None),
            Supersede::CurrentIssuedBefore(at) => (None, Some(at)),
            Supersede::Current => (None, None),
        };
        // The row lock on the current token makes concurrent callers wait; they re-check the
        // condition against the committed row and find it superseded.
        let superseded: Option<Vec<u8>> = sqlx::query_scalar(
            "UPDATE session_guard_tokens SET superseded_at = $2
             WHERE session_id = $1 AND superseded_at IS NULL
               AND ($3::bytea IS NULL OR hash = $3)
               AND ($4::timestamptz IS NULL OR issued_at < $4)
             RETURNING hash",
        )
        .bind(update.session_id)
        .bind(update.now)
        .bind(exact)
        .bind(issued_before)
        .fetch_optional(&mut **tx)
        .await?;
        let Some(superseded) = superseded else {
            return Ok(false);
        };
        let inserted = sqlx::query(
            "INSERT INTO session_guard_tokens (hash, session_id, issued_at) VALUES ($1, $2, $3)
             ON CONFLICT (hash) DO NOTHING",
        )
        .bind(&rotation.new_token.as_bytes()[..])
        .bind(update.session_id)
        .bind(update.now)
        .execute(&mut **tx)
        .await?;
        if inserted.rows_affected() == 0 {
            // The new hash already exists somewhere: keep the old token current.
            sqlx::query("UPDATE session_guard_tokens SET superseded_at = NULL WHERE hash = $1")
                .bind(superseded)
                .execute(&mut **tx)
                .await?;
            return Ok(false);
        }
        sqlx::query("DELETE FROM session_guard_tokens WHERE session_id = $1 AND superseded_at < $2")
            .bind(update.session_id)
            .bind(rotation.prune_superseded_before)
            .execute(&mut **tx)
            .await?;
        Ok(true)
    }

    async fn apply_in(tx: &mut Transaction<'static, Postgres>, update: &SessionUpdate) -> Result<bool, sqlx::Error> {
        // Serialize updates of one session; also keeps a concurrent delete from racing the
        // token insert.
        let exists = sqlx::query("SELECT 1 FROM session_guard_sessions WHERE id = $1 FOR NO KEY UPDATE")
            .bind(update.session_id)
            .fetch_optional(&mut **tx)
            .await?
            .is_some();
        if !exists {
            return Ok(false);
        }
        let rotated = match &update.rotation {
            Some(rotation) => Self::rotate(tx, update, rotation).await?,
            None => false,
        };
        if let Some(hash) = update.mark_used {
            sqlx::query(
                "UPDATE session_guard_tokens SET first_used_at = $3
                 WHERE hash = $1 AND session_id = $2 AND first_used_at IS NULL",
            )
            .bind(&hash.as_bytes()[..])
            .bind(update.session_id)
            .bind(update.now)
            .execute(&mut **tx)
            .await?;
        }
        sqlx::query(
            "UPDATE session_guard_sessions SET
                 last_seen_at = $2,
                 baseline = COALESCE($3, baseline),
                 step_up_required = COALESCE($4, step_up_required),
                 authenticated_at = COALESCE($5, authenticated_at)
             WHERE id = $1",
        )
        .bind(update.session_id)
        .bind(update.now)
        .bind(update.baseline.as_ref().map(Json))
        .bind(update.step_up_required)
        .bind(update.authenticated_at)
        .execute(&mut **tx)
        .await?;
        Ok(rotated)
    }
}

fn is_current_token_conflict(error: &sqlx::Error) -> bool {
    matches!(error, sqlx::Error::Database(db) if db.constraint() == Some(CURRENT_TOKEN_INDEX))
}

fn decode_hash(bytes: &[u8]) -> Result<TokenHash, sqlx::Error> {
    <[u8; 32]>::try_from(bytes)
        .map(TokenHash::from_bytes)
        .map_err(|_| sqlx::Error::Decode(format!("token hash has {} bytes, expected 32", bytes.len()).into()))
}

fn session_from_row(row: &PgRow) -> Result<SessionRecord, sqlx::Error> {
    let Json(baseline): Json<Baseline> = row.try_get("baseline")?;
    let origin: Option<Json<SessionOrigin>> = row.try_get("origin")?;
    Ok(SessionRecord {
        id: row.try_get("id")?,
        subject: row.try_get("subject")?,
        created_at: row.try_get("created_at")?,
        authenticated_at: row.try_get("authenticated_at")?,
        last_seen_at: row.try_get("last_seen_at")?,
        expires_at: row.try_get("expires_at")?,
        step_up_required: row.try_get("step_up_required")?,
        baseline,
        origin: origin.map(|Json(origin)| origin),
    })
}

fn lookup_from_row(row: &PgRow) -> Result<TokenLookup, sqlx::Error> {
    let hash: Vec<u8> = row.try_get("hash")?;
    Ok(TokenLookup {
        session: session_from_row(row)?,
        token: TokenRecord {
            hash: decode_hash(&hash)?,
            issued_at: row.try_get("issued_at")?,
            first_used_at: row.try_get("first_used_at")?,
            superseded_at: row.try_get("superseded_at")?,
        },
        newer_token_used: row.try_get("newer_token_used")?,
    })
}

impl SessionStore for PgStore {
    async fn insert_session(&self, session: &SessionRecord, token: &TokenHash) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO session_guard_sessions
                 (id, subject, created_at, authenticated_at, last_seen_at, expires_at, step_up_required, baseline,
                  origin)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(session.id)
        .bind(&session.subject)
        .bind(session.created_at)
        .bind(session.authenticated_at)
        .bind(session.last_seen_at)
        .bind(session.expires_at)
        .bind(session.step_up_required)
        .bind(Json(&session.baseline))
        .bind(session.origin.as_ref().map(Json))
        .execute(&mut *tx)
        .await?;
        sqlx::query("INSERT INTO session_guard_tokens (hash, session_id, issued_at) VALUES ($1, $2, $3)")
            .bind(&token.as_bytes()[..])
            .bind(session.id)
            .bind(session.created_at)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn find_by_token(&self, token: &TokenHash) -> Result<Option<TokenLookup>, StoreError> {
        let row = sqlx::query(
            "SELECT s.id, s.subject, s.created_at, s.authenticated_at, s.last_seen_at, s.expires_at,
                    s.step_up_required, s.baseline, s.origin,
                    t.hash, t.issued_at, t.first_used_at, t.superseded_at,
                    EXISTS (
                        SELECT 1 FROM session_guard_tokens n
                        WHERE n.session_id = t.session_id AND n.seq > t.seq AND n.first_used_at IS NOT NULL
                    ) AS newer_token_used
             FROM session_guard_tokens t
             JOIN session_guard_sessions s ON s.id = t.session_id
             WHERE t.hash = $1",
        )
        .bind(&token.as_bytes()[..])
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.as_ref().map(lookup_from_row).transpose()?)
    }

    async fn apply(&self, update: &SessionUpdate) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin().await?;
        match Self::apply_in(&mut tx, update).await {
            Ok(rotated) => {
                tx.commit().await?;
                Ok(rotated)
            }
            // Backstop: another writer made a token current first. Unreachable while every
            // writer takes the session lock, but never let it surface as a second current token.
            Err(e) if is_current_token_conflict(&e) => {
                tx.rollback().await?;
                Ok(false)
            }
            Err(e) => Err(e.into()),
        }
    }

    async fn delete_session(&self, session_id: Uuid) -> Result<bool, StoreError> {
        let done = sqlx::query("DELETE FROM session_guard_sessions WHERE id = $1")
            .bind(session_id)
            .execute(&self.pool)
            .await?;
        Ok(done.rows_affected() > 0)
    }

    async fn delete_subject_sessions(&self, subject: &str) -> Result<Vec<Uuid>, StoreError> {
        let ids = sqlx::query_scalar("DELETE FROM session_guard_sessions WHERE subject = $1 RETURNING id")
            .bind(subject)
            .fetch_all(&self.pool)
            .await?;
        Ok(ids)
    }

    async fn list_subject_sessions(&self, subject: &str) -> Result<Vec<SessionRecord>, StoreError> {
        let rows = sqlx::query(
            "SELECT s.id, s.subject, s.created_at, s.authenticated_at, s.last_seen_at, s.expires_at,
                    s.step_up_required, s.baseline, s.origin
             FROM session_guard_sessions s
             WHERE s.subject = $1",
        )
        .bind(subject)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.iter().map(session_from_row).collect::<Result<_, _>>()?)
    }

    async fn delete_expired(&self, now: DateTime<Utc>, idle_cutoff: DateTime<Utc>) -> Result<u64, StoreError> {
        let done = sqlx::query("DELETE FROM session_guard_sessions WHERE expires_at <= $1 OR last_seen_at <= $2")
            .bind(now)
            .bind(idle_cutoff)
            .execute(&self.pool)
            .await?;
        Ok(done.rows_affected())
    }

    async fn record_event(&self, event: &SessionEvent) -> Result<(), StoreError> {
        let signals: Vec<&str> = event.signals.iter().map(|c| c.as_str()).collect();
        sqlx::query(
            "INSERT INTO session_guard_events
                 (session_id, subject, kind, enforced, score, signals, ip, user_agent, client, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(event.session_id)
        .bind(&event.subject)
        .bind(event.kind.as_str())
        .bind(event.enforced)
        .bind(event.score.map(i64::from))
        .bind(signals)
        .bind(event.ip)
        .bind(event.user_agent.as_deref())
        .bind(sqlx::types::Json(&event.client))
        .bind(event.at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn delete_events_before(&self, cutoff: DateTime<Utc>) -> Result<u64, StoreError> {
        let done = sqlx::query(
            "WITH claims AS (DELETE FROM session_guard_event_claims WHERE claimed_at < $1),
                  subject_claims AS (DELETE FROM session_guard_subject_claims WHERE claimed_at < $1)
             DELETE FROM session_guard_events WHERE created_at < $1",
        )
        .bind(cutoff)
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected())
    }

    async fn claim_event(
        &self,
        scope: ClaimScope<'_>,
        kind: EventKind,
        now: DateTime<Utc>,
        window: TimeDelta,
    ) -> Result<bool, StoreError> {
        // A claim at or before `now - window` has lapsed. If that instant does not exist, no
        // stored claim can have lapsed; NULL never compares true.
        let lapsed_at = now.checked_sub_signed(window);
        let query = match scope {
            ClaimScope::Session(session_id) => sqlx::query(
                "INSERT INTO session_guard_event_claims (session_id, kind, claimed_at) VALUES ($1, $2, $3)
                 ON CONFLICT (session_id, kind) DO UPDATE SET claimed_at = EXCLUDED.claimed_at
                 WHERE session_guard_event_claims.claimed_at <= $4
                 RETURNING 1",
            )
            .bind(session_id),
            ClaimScope::Subject(subject) => sqlx::query(
                "INSERT INTO session_guard_subject_claims (subject, kind, claimed_at) VALUES ($1, $2, $3)
                 ON CONFLICT (subject, kind) DO UPDATE SET claimed_at = EXCLUDED.claimed_at
                 WHERE session_guard_subject_claims.claimed_at <= $4
                 RETURNING 1",
            )
            .bind(subject),
        };
        let claimed = query
            .bind(kind.as_str())
            .bind(now)
            .bind(lapsed_at)
            .fetch_optional(&self.pool)
            .await?;
        Ok(claimed.is_some())
    }
}
