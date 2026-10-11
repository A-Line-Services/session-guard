//! In-process store for tests, development and single-instance apps.

use std::{
    collections::HashMap,
    future::{Future, Ready, ready},
    sync::{Mutex, MutexGuard, PoisonError},
};

use chrono::{DateTime, TimeDelta, Utc};
use uuid::Uuid;

use super::{SessionRecord, SessionStore, SessionUpdate, Supersede, TokenLookup, TokenRecord};
use crate::{
    error::StoreError,
    event::{EventKind, SessionEvent},
    token::TokenHash,
};

/// Keeps everything in memory behind one mutex. Nothing survives a restart and nothing is shared
/// between processes, so use it for tests, development and single-instance apps only.
#[derive(Debug, Default)]
pub struct MemoryStore {
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    sessions: HashMap<Uuid, Entry>,
    token_index: HashMap<TokenHash, Uuid>,
    events: Vec<SessionEvent>,
    claims: HashMap<(Uuid, EventKind), DateTime<Utc>>,
}

#[derive(Debug)]
struct Entry {
    record: SessionRecord,
    /// In issue order; the last one is current.
    tokens: Vec<TokenRecord>,
}

impl State {
    fn remove(&mut self, id: Uuid) -> bool {
        let Some(entry) = self.sessions.remove(&id) else {
            return false;
        };
        for token in entry.tokens {
            self.token_index.remove(&token.hash);
        }
        true
    }

    fn apply(&mut self, update: &SessionUpdate) -> bool {
        let Some(entry) = self.sessions.get_mut(&update.session_id) else {
            return false;
        };
        let now = update.now;
        let mut rotated = false;
        if let Some(rotation) = &update.rotation
            && let Some(current) = entry.tokens.last_mut()
            && current.superseded_at.is_none()
        {
            let holds = match rotation.supersede {
                Supersede::Exact(hash) => current.hash == hash,
                Supersede::CurrentIssuedBefore(cutoff) => current.issued_at < cutoff,
                Supersede::Current => true,
            };
            if holds && !self.token_index.contains_key(&rotation.new_token) {
                current.superseded_at = Some(now);
                entry.tokens.push(TokenRecord {
                    hash: rotation.new_token,
                    issued_at: now,
                    first_used_at: None,
                    superseded_at: None,
                });
                self.token_index.insert(rotation.new_token, update.session_id);
                let cutoff = rotation.prune_superseded_before;
                let index = &mut self.token_index;
                entry.tokens.retain(|t| match t.superseded_at {
                    Some(at) if at < cutoff => {
                        index.remove(&t.hash);
                        false
                    }
                    _ => true,
                });
                rotated = true;
            }
        }
        if let Some(hash) = update.mark_used
            && let Some(token) = entry.tokens.iter_mut().find(|t| t.hash == hash)
            && token.first_used_at.is_none()
        {
            token.first_used_at = Some(now);
        }
        let record = &mut entry.record;
        record.last_seen_at = now;
        if let Some(baseline) = &update.baseline {
            record.baseline.clone_from(baseline);
        }
        if let Some(flag) = update.step_up_required {
            record.step_up_required = flag;
        }
        if let Some(at) = update.authenticated_at {
            record.authenticated_at = at;
        }
        rotated
    }
}

impl MemoryStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Every recorded event, oldest first.
    pub fn events(&self) -> Vec<SessionEvent> {
        self.lock().events.clone()
    }

    /// Number of stored sessions, including expired ones not yet purged.
    pub fn session_count(&self) -> usize {
        self.lock().sessions.len()
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        // A panic while holding the lock cannot leave State half-updated in a way that breaks
        // invariants worse than the panic itself, so keep serving.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn with<T>(&self, f: impl FnOnce(&mut State) -> T) -> Ready<Result<T, StoreError>> {
        ready(Ok(f(&mut self.lock())))
    }
}

impl SessionStore for MemoryStore {
    fn insert_session(
        &self,
        session: &SessionRecord,
        token: &TokenHash,
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        let result = {
            let mut state = self.lock();
            if state.token_index.contains_key(token) || state.sessions.contains_key(&session.id) {
                Err("duplicate session id or token".into())
            } else {
                state.token_index.insert(*token, session.id);
                state.sessions.insert(
                    session.id,
                    Entry {
                        record: session.clone(),
                        tokens: vec![TokenRecord {
                            hash: *token,
                            issued_at: session.created_at,
                            first_used_at: None,
                            superseded_at: None,
                        }],
                    },
                );
                Ok(())
            }
        };
        ready(result)
    }

    fn find_by_token(&self, token: &TokenHash) -> impl Future<Output = Result<Option<TokenLookup>, StoreError>> + Send {
        self.with(|state| {
            let id = state.token_index.get(token)?;
            let entry = state.sessions.get(id)?;
            let position = entry.tokens.iter().position(|t| t.hash == *token)?;
            Some(TokenLookup {
                session: entry.record.clone(),
                token: entry.tokens[position],
                newer_token_used: entry.tokens[position + 1..].iter().any(|t| t.first_used_at.is_some()),
            })
        })
    }

    fn apply(&self, update: &SessionUpdate) -> impl Future<Output = Result<bool, StoreError>> + Send {
        self.with(|state| state.apply(update))
    }

    fn delete_session(&self, session_id: Uuid) -> impl Future<Output = Result<bool, StoreError>> + Send {
        self.with(|state| state.remove(session_id))
    }

    fn delete_subject_sessions(&self, subject: &str) -> impl Future<Output = Result<u64, StoreError>> + Send {
        self.with(|state| {
            let ids: Vec<Uuid> = state
                .sessions
                .values()
                .filter(|e| e.record.subject == subject)
                .map(|e| e.record.id)
                .collect();
            ids.into_iter().filter(|id| state.remove(*id)).count() as u64
        })
    }

    fn list_subject_sessions(
        &self,
        subject: &str,
    ) -> impl Future<Output = Result<Vec<SessionRecord>, StoreError>> + Send {
        self.with(|state| {
            state
                .sessions
                .values()
                .filter(|e| e.record.subject == subject)
                .map(|e| e.record.clone())
                .collect()
        })
    }

    fn delete_expired(
        &self,
        now: DateTime<Utc>,
        idle_cutoff: DateTime<Utc>,
    ) -> impl Future<Output = Result<u64, StoreError>> + Send {
        self.with(|state| {
            let ids: Vec<Uuid> = state
                .sessions
                .values()
                .filter(|e| e.record.expires_at <= now || e.record.last_seen_at <= idle_cutoff)
                .map(|e| e.record.id)
                .collect();
            ids.into_iter().filter(|id| state.remove(*id)).count() as u64
        })
    }

    fn record_event(&self, event: &SessionEvent) -> impl Future<Output = Result<(), StoreError>> + Send {
        self.with(|state| state.events.push(event.clone()))
    }

    fn delete_events_before(&self, cutoff: DateTime<Utc>) -> impl Future<Output = Result<u64, StoreError>> + Send {
        self.with(|state| {
            let before = state.events.len();
            state.events.retain(|e| e.at >= cutoff);
            state.claims.retain(|_, at| *at >= cutoff);
            (before - state.events.len()) as u64
        })
    }

    fn claim_event(
        &self,
        session_id: Uuid,
        kind: EventKind,
        now: DateTime<Utc>,
        window: TimeDelta,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send {
        self.with(|state| match state.claims.get(&(session_id, kind)) {
            Some(at) if now - *at < window => false,
            _ => {
                state.claims.insert((session_id, kind), now);
                true
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::MemoryStore;

    crate::store_conformance!(|| async { MemoryStore::new() });

    #[tokio::test]
    async fn duplicate_token_is_rejected() {
        use crate::{store::SessionStore, testing};
        let store = MemoryStore::new();
        let now = testing::now_secs();
        let token = testing::random_hash();
        store
            .insert_session(&testing::sample_session(now), &token)
            .await
            .unwrap();
        assert!(
            store
                .insert_session(&testing::sample_session(now), &token)
                .await
                .is_err()
        );
        assert_eq!(store.session_count(), 1);
    }
}
