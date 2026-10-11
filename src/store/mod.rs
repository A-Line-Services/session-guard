//! The storage contract and the built-in stores.
//!
//! The guard holds all security logic; a store only persists records and performs two
//! operations atomically: [`SessionStore::apply`] (rotate, mark used, update) and the lookups.
//! Implement [`SessionStore`] for your own backend and run the
//! `store_conformance!` (feature `testing`) suite against it.

mod memory;

use std::future::Future;

use chrono::{DateTime, TimeDelta, Utc};
use uuid::Uuid;

pub use memory::MemoryStore;

use crate::{
    error::StoreError,
    event::{EventKind, SessionEvent},
    fingerprint::Baseline,
    token::TokenHash,
};

/// A stored session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionRecord {
    /// Session id. Safe to show and log; key your own per-session data by it.
    pub id: Uuid,
    /// The subject in canonical JSON form (see [`Subject`](crate::Subject)).
    pub subject: String,
    /// When the session was created.
    pub created_at: DateTime<Utc>,
    /// When the subject last proved who they are (login or completed step-up).
    pub authenticated_at: DateTime<Utc>,
    /// Last request, written at most once per
    /// [`last_seen_write_interval`](crate::GuardConfig::last_seen_write_interval).
    pub last_seen_at: DateTime<Utc>,
    /// Absolute expiry.
    pub expires_at: DateTime<Utc>,
    /// Requests are rejected until step-up completes.
    pub step_up_required: bool,
    /// What the session's client looks like.
    pub baseline: Baseline,
}

/// A stored token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TokenRecord {
    /// SHA-256 of the token.
    pub hash: TokenHash,
    /// When it was issued.
    pub issued_at: DateTime<Utc>,
    /// When a client first presented it. `None` means its response may never have arrived.
    pub first_used_at: Option<DateTime<Utc>>,
    /// When a newer token replaced it. `None` for the session's current token.
    pub superseded_at: Option<DateTime<Utc>>,
}

/// Result of [`SessionStore::find_by_token`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenLookup {
    /// The session the token belongs to.
    pub session: SessionRecord,
    /// The token itself.
    pub token: TokenRecord,
    /// Whether any token issued after this one in the same session has been presented
    /// (`first_used_at` set).
    pub newer_token_used: bool,
}

/// Which token a [`Rotation`] replaces. Each variant is a condition evaluated atomically
/// against the session's current token; if it does not hold, nothing rotates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Supersede {
    /// Only if this exact token is still current. Two concurrent requests with the same token
    /// both ask for this; exactly one wins.
    Exact(TokenHash),
    /// Only if the current token was issued strictly before this instant.
    CurrentIssuedBefore(DateTime<Utc>),
    /// Whatever token is current.
    Current,
}

/// Replace the current token with a new one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rotation {
    /// Hash of the new token; becomes current with `issued_at = now`.
    pub new_token: TokenHash,
    /// Which token is replaced (its `superseded_at` becomes `now`).
    pub supersede: Supersede,
    /// Delete this session's tokens superseded strictly before this instant.
    pub prune_superseded_before: DateTime<Utc>,
}

/// Everything one request changes, applied atomically by [`SessionStore::apply`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionUpdate {
    /// The session to update.
    pub session_id: Uuid,
    /// The request time; `last_seen_at` becomes this.
    pub now: DateTime<Utc>,
    /// Set this token's `first_used_at` to `now` if it is still unset.
    pub mark_used: Option<TokenHash>,
    /// Replace the baseline.
    pub baseline: Option<Baseline>,
    /// Set the step-up flag.
    pub step_up_required: Option<bool>,
    /// Set `authenticated_at`.
    pub authenticated_at: Option<DateTime<Utc>>,
    /// Rotate the token.
    pub rotation: Option<Rotation>,
}

impl SessionUpdate {
    /// An update that only touches `last_seen_at`.
    pub fn touch(session_id: Uuid, now: DateTime<Utc>) -> Self {
        Self {
            session_id,
            now,
            mark_used: None,
            baseline: None,
            step_up_required: None,
            authenticated_at: None,
            rotation: None,
        }
    }
}

/// Session persistence.
///
/// Every method must be safe to call concurrently from many processes. Each returned future
/// must be `Send`. Timestamps may be stored at microsecond precision.
pub trait SessionStore: Send + Sync + 'static {
    /// Stores a new session with `token` as its current token (`issued_at = created_at`,
    /// unused, not superseded).
    fn insert_session(
        &self,
        session: &SessionRecord,
        token: &TokenHash,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Finds the session holding `token`, current or superseded.
    fn find_by_token(&self, token: &TokenHash) -> impl Future<Output = Result<Option<TokenLookup>, StoreError>> + Send;

    /// Applies `update` atomically, in this order:
    ///
    /// 1. If `rotation` is set and its [`Supersede`] condition holds for the current token:
    ///    supersede it, insert the new token as current, prune old superseded tokens.
    /// 2. Mark `mark_used` used if it belongs to the session and is unused.
    /// 3. Set `last_seen_at = now` and every `Some` field.
    ///
    /// A session must never have more than one current token. Returns whether the rotation
    /// happened; a missing session is not an error and returns `false`.
    fn apply(&self, update: &SessionUpdate) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// Deletes a session and its tokens. Returns whether it existed.
    fn delete_session(&self, session_id: Uuid) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// Deletes every session of `subject` (canonical JSON). Returns how many.
    fn delete_subject_sessions(&self, subject: &str) -> impl Future<Output = Result<u64, StoreError>> + Send;

    /// Every session of `subject` (canonical JSON), including expired ones not yet purged.
    fn list_subject_sessions(
        &self,
        subject: &str,
    ) -> impl Future<Output = Result<Vec<SessionRecord>, StoreError>> + Send;

    /// Deletes sessions with `expires_at <= now` or `last_seen_at <= idle_cutoff`. Returns how
    /// many.
    fn delete_expired(
        &self,
        now: DateTime<Utc>,
        idle_cutoff: DateTime<Utc>,
    ) -> impl Future<Output = Result<u64, StoreError>> + Send;

    /// Appends a security event. Stores without an event log may discard it.
    fn record_event(&self, event: &SessionEvent) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Deletes events with `at < cutoff`. Returns how many. Also deletes event claims older
    /// than `cutoff`.
    fn delete_events_before(&self, cutoff: DateTime<Utc>) -> impl Future<Output = Result<u64, StoreError>> + Send;

    /// Claims the right to record an unenforced `kind` event for a session, for shadow-mode
    /// deduplication across processes. Succeeds (`true`) unless a claim for the same session
    /// and kind was made after `now - window`, and records `now` as the new claim when it
    /// does. Must be atomic across processes.
    ///
    /// The default always succeeds, which leaves deduplication to each process.
    fn claim_event(
        &self,
        session_id: Uuid,
        kind: EventKind,
        now: DateTime<Utc>,
        window: TimeDelta,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send {
        let _ = (session_id, kind, now, window);
        std::future::ready(Ok(true))
    }
}

impl<T: SessionStore> SessionStore for std::sync::Arc<T> {
    fn insert_session(
        &self,
        session: &SessionRecord,
        token: &TokenHash,
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        (**self).insert_session(session, token)
    }

    fn find_by_token(&self, token: &TokenHash) -> impl Future<Output = Result<Option<TokenLookup>, StoreError>> + Send {
        (**self).find_by_token(token)
    }

    fn apply(&self, update: &SessionUpdate) -> impl Future<Output = Result<bool, StoreError>> + Send {
        (**self).apply(update)
    }

    fn delete_session(&self, session_id: Uuid) -> impl Future<Output = Result<bool, StoreError>> + Send {
        (**self).delete_session(session_id)
    }

    fn delete_subject_sessions(&self, subject: &str) -> impl Future<Output = Result<u64, StoreError>> + Send {
        (**self).delete_subject_sessions(subject)
    }

    fn list_subject_sessions(
        &self,
        subject: &str,
    ) -> impl Future<Output = Result<Vec<SessionRecord>, StoreError>> + Send {
        (**self).list_subject_sessions(subject)
    }

    fn delete_expired(
        &self,
        now: DateTime<Utc>,
        idle_cutoff: DateTime<Utc>,
    ) -> impl Future<Output = Result<u64, StoreError>> + Send {
        (**self).delete_expired(now, idle_cutoff)
    }

    fn record_event(&self, event: &SessionEvent) -> impl Future<Output = Result<(), StoreError>> + Send {
        (**self).record_event(event)
    }

    fn delete_events_before(&self, cutoff: DateTime<Utc>) -> impl Future<Output = Result<u64, StoreError>> + Send {
        (**self).delete_events_before(cutoff)
    }

    fn claim_event(
        &self,
        session_id: Uuid,
        kind: EventKind,
        now: DateTime<Utc>,
        window: TimeDelta,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send {
        (**self).claim_event(session_id, kind, now, window)
    }
}
