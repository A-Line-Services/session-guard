//! The guard: issues, checks, rotates and revokes sessions.

mod outcome;
#[cfg(test)]
mod tests;

use std::{
    collections::HashMap,
    marker::PhantomData,
    net::IpAddr,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use chrono::{DateTime, TimeDelta, Utc};
use uuid::Uuid;

pub use outcome::{
    AuthSession, Authenticated, IssuedToken, NewSession, Outcome, PurgeReport, Rejection, SessionInfo, StepUpOutcome,
};

use crate::{
    checks::{Checks, Decision},
    client::{ClientContext, HeaderSource, resolve_client_ip},
    clock::{Clock, SystemClock},
    config::{GuardConfig, Mode, StepUpPolicy},
    error::GuardError,
    event::{EventKind, SessionEvent},
    fingerprint::{Baseline, Fingerprint, UaCache},
    intel::{IpIntel, NoIpIntel},
    store::{Rotation, SessionRecord, SessionStore, SessionUpdate, Supersede},
    subject::Subject,
    token::{SessionToken, TokenHash},
};

use secrecy::SecretString;

type Hook = Arc<dyn Fn(&SessionEvent) + Send + Sync>;

/// Issues, checks, rotates and revokes sessions. Cheap to clone; clones share state.
///
/// `St` is the [`SessionStore`]; `S` is your subject type (default [`Uuid`]), stored opaquely.
pub struct Guard<St, S = Uuid> {
    inner: Arc<Inner<St>>,
    _subject: PhantomData<fn() -> S>,
}

struct Inner<St> {
    store: St,
    config: GuardConfig,
    intel: Box<dyn IpIntel>,
    clock: Box<dyn Clock>,
    hook: Option<Hook>,
    ua_cache: UaCache,
    xff_warned: AtomicBool,
    shadow_seen: Mutex<ShadowSeen>,
}

/// Last time each unenforced event was recorded, for shadow-mode deduplication.
struct ShadowSeen {
    seen: HashMap<(Uuid, EventKind), DateTime<Utc>>,
    pruned_at: DateTime<Utc>,
}

impl<St, S> Clone for Guard<St, S> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            _subject: PhantomData,
        }
    }
}

impl<St, S> std::fmt::Debug for Guard<St, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Guard")
            .field("config", &self.inner.config)
            .finish_non_exhaustive()
    }
}

/// Builds a [`Guard`]. Start with [`Guard::builder`].
#[must_use]
pub struct GuardBuilder<St, S = Uuid> {
    store: St,
    config: GuardConfig,
    intel: Box<dyn IpIntel>,
    clock: Box<dyn Clock>,
    hook: Option<Hook>,
    _subject: PhantomData<fn() -> S>,
}

impl<St: SessionStore> Guard<St> {
    /// A guard with the default configuration and [`Uuid`] subjects.
    pub fn new(store: St) -> Self {
        Self::builder(store, GuardConfig::default()).build()
    }

    /// Starts building a guard. Subjects are [`Uuid`] unless changed with
    /// [`GuardBuilder::subject`].
    pub fn builder(store: St, config: GuardConfig) -> GuardBuilder<St> {
        GuardBuilder {
            store,
            config,
            intel: Box::new(NoIpIntel),
            clock: Box::new(SystemClock),
            hook: None,
            _subject: PhantomData,
        }
    }
}

impl<St: SessionStore, S: Subject> GuardBuilder<St, S> {
    /// Uses `T` as the subject type.
    pub fn subject<T: Subject>(self) -> GuardBuilder<St, T> {
        GuardBuilder {
            store: self.store,
            config: self.config,
            intel: self.intel,
            clock: self.clock,
            hook: self.hook,
            _subject: PhantomData,
        }
    }

    /// Country / ASN source. Without one, IP changes are judged by network prefix only.
    pub fn ip_intel(mut self, intel: impl IpIntel) -> Self {
        self.intel = Box::new(intel);
        self
    }

    /// Called synchronously for every recorded event, after it is stored. Keep it fast; a panic
    /// in the hook is caught and logged.
    pub fn on_event(mut self, hook: impl Fn(&SessionEvent) + Send + Sync + 'static) -> Self {
        self.hook = Some(Arc::new(hook));
        self
    }

    /// Time source (default [`SystemClock`]).
    pub fn clock(mut self, clock: impl Clock) -> Self {
        self.clock = Box::new(clock);
        self
    }

    /// Builds the guard.
    pub fn build(self) -> Guard<St, S> {
        Guard {
            inner: Arc::new(Inner {
                store: self.store,
                config: self.config,
                intel: self.intel,
                clock: self.clock,
                hook: self.hook,
                ua_cache: UaCache::new(UA_CACHE_CAPACITY),
                xff_warned: AtomicBool::new(false),
                shadow_seen: Mutex::new(ShadowSeen {
                    seen: HashMap::new(),
                    pruned_at: DateTime::<Utc>::MIN_UTC,
                }),
            }),
            _subject: PhantomData,
        }
    }
}

const UA_CACHE_CAPACITY: usize = 1024;

/// Most (session, kind) pairs the local shadow dedup cache holds, about 6 MB at most.
const SHADOW_SEEN_CAPACITY: usize = 100_000;

/// How a presented token relates to its session's current token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TokenState {
    /// The current token.
    Current,
    /// Superseded moments ago; a request that raced the rotation.
    Grace,
    /// Superseded, but its successor was never used: the rotation response was lost.
    Orphaned,
    /// Superseded and its successor is in use: two parties hold the session.
    Reuse,
}

/// A token resolved to a live session with a decodable subject.
struct Resolved<S> {
    lookup: crate::store::TokenLookup,
    hash: TokenHash,
    subject: S,
    state: TokenState,
}

impl<St: SessionStore, S: Subject> Guard<St, S> {
    /// Creates a session for `subject` and returns its first token.
    ///
    /// Pass the token the client presented, if any: that session is revoked first, so a token
    /// planted before login (session fixation) never becomes authenticated. Call this only
    /// after verifying the subject's credentials, and rate-limit that endpoint yourself.
    ///
    /// # Errors
    ///
    /// Store failures, an unavailable RNG, or a subject that does not serialize.
    pub async fn login(
        &self,
        subject: &S,
        ctx: &ClientContext,
        previous_token: Option<&str>,
    ) -> Result<NewSession, GuardError> {
        let inner = &*self.inner;
        if let Some(hash) = previous_token.and_then(|t| self.presented_hash(t))
            && let Some(old) = inner.store.find_by_token(&hash).await?
            && inner.store.delete_session(old.session.id).await?
        {
            self.emit(old.session.id, &old.session.subject, EventKind::Logout, true, ctx, None)
                .await;
        }

        let encoded = crate::subject::encode(subject)?;
        let token = SessionToken::generate()?;
        let now = self.now();
        let fingerprint = self.fingerprint(ctx);
        let record = SessionRecord {
            id: Uuid::new_v4(),
            subject: encoded,
            created_at: now,
            authenticated_at: now,
            last_seen_at: now,
            expires_at: now + inner.config.session_lifetime,
            step_up_required: false,
            baseline: Baseline::new(fingerprint),
        };
        inner.store.insert_session(&record, &token.hash()).await?;
        self.emit(record.id, &record.subject, EventKind::Login, true, ctx, None)
            .await;
        Ok(NewSession {
            session_id: record.id,
            token: self.issue(&token, record.expires_at),
        })
    }

    /// Checks a request's token with the configured checks.
    ///
    /// On success the request may proceed; send [`Authenticated::rotated`] back as
    /// `Set-Cookie` when present. Every [`Rejection`] maps to 401.
    ///
    /// # Errors
    ///
    /// Store failures only. Bad tokens and risky clients are [`Outcome::Rejected`].
    pub async fn authenticate(&self, token: &str, ctx: &ClientContext) -> Result<Outcome<S>, GuardError> {
        self.authenticate_with(token, ctx, &self.inner.config.checks).await
    }

    /// Like [`authenticate`](Self::authenticate) with other checks, for routes that need
    /// stricter (or looser) treatment. The baseline learns only the signals `checks` scored.
    ///
    /// # Errors
    ///
    /// Store failures only.
    pub async fn authenticate_with(
        &self,
        token: &str,
        ctx: &ClientContext,
        checks: &Checks,
    ) -> Result<Outcome<S>, GuardError> {
        self.authenticate_inner(token, ctx, checks).await
    }

    /// The rotation due for a token in `state`, with its replacement.
    fn plan_rotation(
        &self,
        state: TokenState,
        issued_at: DateTime<Utc>,
        hash: TokenHash,
        now: DateTime<Utc>,
    ) -> Result<Option<(Rotation, SessionToken)>, GuardError> {
        let config = &self.inner.config;
        let supersede = match state {
            TokenState::Current if issued_at <= now - config.rotation_interval => Supersede::Exact(hash),
            TokenState::Orphaned => Supersede::CurrentIssuedBefore(now - config.rotation_grace),
            _ => return Ok(None),
        };
        let token = SessionToken::generate()?;
        let rotation = Rotation {
            new_token: token.hash(),
            supersede,
            prune_superseded_before: now - config.reuse_detection,
        };
        Ok(Some((rotation, token)))
    }

    async fn authenticate_inner(
        &self,
        token: &str,
        ctx: &ClientContext,
        checks: &Checks,
    ) -> Result<Outcome<S>, GuardError> {
        let inner = &*self.inner;
        let config = &inner.config;
        let now = self.now();
        let resolved = match self.resolve(token, now).await? {
            Ok(resolved) => resolved,
            Err(rejection) => return Ok(Outcome::Rejected(rejection)),
        };
        let Resolved {
            lookup,
            hash,
            subject,
            state,
        } = resolved;
        let session = &lookup.session;

        if state == TokenState::Reuse {
            self.revoke_for_reuse(session, ctx).await?;
            return Ok(Outcome::Rejected(Rejection::Revoked));
        }

        let fingerprint = self.fingerprint(ctx);
        let assessment = crate::risk::assess(&session.baseline, &fingerprint, now, config.ping_pong_window, checks);
        let decision = config.thresholds.decide(assessment.score);
        crate::telemetry::assessed(decision, &assessment.signals);
        let shadow = config.mode == Mode::Shadow;
        let step_up = decision == Decision::StepUp;

        if decision == Decision::Revoke || (step_up && config.step_up_policy == StepUpPolicy::Revoke) {
            self.emit(
                session.id,
                &session.subject,
                EventKind::RiskRevoked,
                !shadow,
                ctx,
                Some(&assessment),
            )
            .await;
            if !shadow {
                inner.store.delete_session(session.id).await?;
                return Ok(Outcome::Rejected(Rejection::Revoked));
            }
        } else if session.step_up_required && !shadow {
            return Ok(Outcome::Rejected(Rejection::StepUpRequired));
        } else if step_up {
            let enforced = config.step_up_policy == StepUpPolicy::Require && !shadow;
            self.emit(
                session.id,
                &session.subject,
                EventKind::StepUpRequired,
                enforced,
                ctx,
                Some(&assessment),
            )
            .await;
            if enforced {
                let mut update = SessionUpdate::touch(session.id, now);
                update.step_up_required = Some(true);
                update.mark_used =
                    (state == TokenState::Current && lookup.token.first_used_at.is_none()).then_some(hash);
                inner.store.apply(&update).await?;
                return Ok(Outcome::Rejected(Rejection::StepUpRequired));
            }
        }

        let mut update = SessionUpdate::touch(session.id, now);
        if decision == Decision::Allow {
            let mut baseline = session.baseline.clone();
            if baseline.absorb(&fingerprint, now, checks) {
                update.baseline = Some(baseline);
            }
        }

        let new_token = match self.plan_rotation(state, lookup.token.issued_at, hash, now)? {
            Some((rotation, token)) => {
                update.rotation = Some(rotation);
                Some(token)
            }
            None => None,
        };
        if state == TokenState::Current && lookup.token.first_used_at.is_none() {
            update.mark_used = Some(hash);
        }

        let stale = now - session.last_seen_at >= config.last_seen_write_interval;
        let mut rotated = None;
        if update.rotation.is_some() || update.mark_used.is_some() || update.baseline.is_some() || stale {
            let did_rotate = inner.store.apply(&update).await?;
            if did_rotate && let Some(token) = &new_token {
                rotated = Some(self.issue(token, session.expires_at));
                if state == TokenState::Orphaned {
                    self.emit(session.id, &session.subject, EventKind::TokenReissued, true, ctx, None)
                        .await;
                }
            }
        }

        Ok(Outcome::Authenticated(Authenticated {
            session: AuthSession::new(session, subject),
            rotated,
            assessment,
        }))
    }

    /// Looks a token up without changing anything: no rotation, no `last_seen` write, no
    /// checks. `None` unless the token is current (or within its grace period) and the session
    /// is live.
    ///
    /// # Errors
    ///
    /// Store failures only.
    pub async fn peek(&self, token: &str) -> Result<Option<SessionInfo<S>>, GuardError> {
        Ok(match self.resolve(token, self.now()).await? {
            Ok(resolved) if matches!(resolved.state, TokenState::Current | TokenState::Grace) => {
                SessionInfo::from_record(&resolved.lookup.session)
            }
            _ => None,
        })
    }

    /// Clears a pending step-up after the app has re-verified the subject (password, passkey,
    /// OTP…). The current client becomes the new baseline, `authenticated_at` resets and a new
    /// token is issued.
    ///
    /// `verified_subject` must be the subject the app just verified; a mismatch changes
    /// nothing. Rate-limit the verification yourself.
    ///
    /// # Errors
    ///
    /// Store failures or an unavailable RNG.
    pub async fn complete_step_up(
        &self,
        token: &str,
        ctx: &ClientContext,
        verified_subject: &S,
    ) -> Result<StepUpOutcome, GuardError> {
        let inner = &*self.inner;
        let now = self.now();
        let resolved = match self.resolve(token, now).await? {
            Ok(resolved) => resolved,
            Err(rejection) => return Ok(StepUpOutcome::Rejected(rejection)),
        };
        let session = &resolved.lookup.session;
        if resolved.state == TokenState::Reuse {
            self.revoke_for_reuse(session, ctx).await?;
            return Ok(StepUpOutcome::Rejected(Rejection::Revoked));
        }
        if resolved.subject != *verified_subject {
            return Ok(StepUpOutcome::SubjectMismatch);
        }

        let token = SessionToken::generate()?;
        let mut update = SessionUpdate::touch(session.id, now);
        update.baseline = Some(Baseline::new(self.fingerprint(ctx)));
        update.step_up_required = Some(false);
        update.authenticated_at = Some(now);
        update.rotation = Some(Rotation {
            new_token: token.hash(),
            supersede: Supersede::Current,
            prune_superseded_before: now - inner.config.reuse_detection,
        });
        if !inner.store.apply(&update).await? {
            // The session vanished between lookup and update.
            return Ok(StepUpOutcome::Rejected(Rejection::Revoked));
        }
        self.emit(
            session.id,
            &session.subject,
            EventKind::StepUpCompleted,
            true,
            ctx,
            None,
        )
        .await;
        Ok(StepUpOutcome::Completed(self.issue(&token, session.expires_at)))
    }

    /// Ends the session the token belongs to. Returns whether there was one.
    ///
    /// # Errors
    ///
    /// Store failures only.
    pub async fn logout(&self, token: &str, ctx: &ClientContext) -> Result<bool, GuardError> {
        let inner = &*self.inner;
        let Some(hash) = self.presented_hash(token) else {
            return Ok(false);
        };
        let Some(lookup) = inner.store.find_by_token(&hash).await? else {
            return Ok(false);
        };
        let deleted = inner.store.delete_session(lookup.session.id).await?;
        if deleted {
            self.emit(
                lookup.session.id,
                &lookup.session.subject,
                EventKind::Logout,
                true,
                ctx,
                None,
            )
            .await;
        }
        Ok(deleted)
    }

    /// Deletes one session by id, e.g. from a "your devices" page. Returns whether it existed.
    ///
    /// # Errors
    ///
    /// Store failures only.
    pub async fn revoke_session(&self, session_id: Uuid) -> Result<bool, GuardError> {
        Ok(self.inner.store.delete_session(session_id).await?)
    }

    /// Deletes every session of `subject`, e.g. after a password change. Returns how many.
    ///
    /// # Errors
    ///
    /// Store failures or a subject that does not serialize.
    pub async fn revoke_all_for_subject(&self, subject: &S) -> Result<u64, GuardError> {
        let encoded = crate::subject::encode(subject)?;
        Ok(self.inner.store.delete_subject_sessions(&encoded).await?)
    }

    /// The live sessions of `subject`.
    ///
    /// # Errors
    ///
    /// Store failures or a subject that does not serialize.
    pub async fn list_sessions(&self, subject: &S) -> Result<Vec<SessionInfo<S>>, GuardError> {
        let encoded = crate::subject::encode(subject)?;
        let now = self.now();
        let records = self.inner.store.list_subject_sessions(&encoded).await?;
        Ok(records
            .iter()
            .filter(|r| self.is_live(r, now))
            .filter_map(SessionInfo::from_record)
            .collect())
    }

    /// Deletes expired sessions and events older than the retention period. Run it
    /// periodically (hourly is plenty).
    ///
    /// # Errors
    ///
    /// Store failures only.
    pub async fn purge_expired(&self) -> Result<PurgeReport, GuardError> {
        let config = &self.inner.config;
        let now = self.now();
        let sessions = self.inner.store.delete_expired(now, now - config.idle_timeout).await?;
        let events = self
            .inner
            .store
            .delete_events_before(now - config.event_retention)
            .await?;
        Ok(PurgeReport { sessions, events })
    }

    /// Builds the [`ClientContext`] for a request from the TCP peer address and the request
    /// headers.
    ///
    /// `X-Forwarded-For` is honoured only when `peer` is a configured trusted proxy, walking
    /// right to left past trusted hops. Header values are capped at the configured length.
    pub fn client_context<H: HeaderSource + ?Sized>(&self, peer: IpAddr, headers: &H) -> ClientContext {
        let config = &self.inner.config;
        let forwarded: Vec<&str> = headers
            .header_values("x-forwarded-for")
            .filter_map(|v| std::str::from_utf8(v).ok())
            .collect();
        if config.trusted_proxies.is_empty()
            && !forwarded.is_empty()
            && !self.inner.xff_warned.swap(true, Ordering::Relaxed)
        {
            tracing::warn!(
                "X-Forwarded-For received but no trusted proxies are configured; using the peer address. \
                 Configure trusted_proxies if the app runs behind a reverse proxy."
            );
        }
        let ip = resolve_client_ip(peer, forwarded, &config.trusted_proxies);
        ClientContext::from_headers(
            ip,
            headers,
            config.tls_fingerprint_header.as_deref(),
            config.max_header_len,
        )
    }

    /// The session cookie's value from the request's `Cookie` headers, if present.
    pub fn cookie_token<'a, H: HeaderSource + ?Sized>(&self, headers: &'a H) -> Option<&'a str> {
        headers
            .header_values("cookie")
            .filter_map(|v| std::str::from_utf8(v).ok())
            .find_map(|v| self.inner.config.cookie.find_in(v))
    }

    /// A `Set-Cookie` value that deletes the session cookie.
    pub fn clear_cookie(&self) -> String {
        self.inner.config.cookie.clear_cookie()
    }

    /// Whether the subject last proved who they are more than `max_age` ago. Use it to demand
    /// a fresh login before sensitive actions.
    pub fn requires_reauth(&self, session: &AuthSession<S>, max_age: Duration) -> bool {
        self.now() - session.authenticated_at > td(max_age)
    }

    /// Whether `value` has the shape of this guard's tokens (configured prefix, then 43
    /// base64url characters). Does not touch the store.
    pub fn is_session_token(&self, value: &str) -> bool {
        self.presented_hash(value).is_some()
    }

    fn now(&self) -> DateTime<Utc> {
        self.inner.clock.now()
    }

    fn fingerprint(&self, ctx: &ClientContext) -> Fingerprint {
        Fingerprint::capture_cached(ctx, self.inner.intel.lookup(ctx.ip), &self.inner.ua_cache)
    }

    fn presented_hash(&self, presented: &str) -> Option<TokenHash> {
        let bare = match &self.inner.config.token_prefix {
            Some(prefix) => presented.strip_prefix(prefix.as_str())?,
            None => presented,
        };
        TokenHash::from_presented(bare)
    }

    fn issue(&self, token: &SessionToken, expires_at: DateTime<Utc>) -> IssuedToken {
        let value = match &self.inner.config.token_prefix {
            Some(prefix) => format!("{prefix}{}", token.expose()),
            None => token.expose().to_owned(),
        };
        let max_age = (expires_at - self.now()).num_seconds();
        let set_cookie = self.inner.config.cookie.set_cookie(&value, max_age);
        IssuedToken {
            value: SecretString::from(value),
            expires_at,
            set_cookie,
        }
    }

    fn is_live(&self, record: &SessionRecord, now: DateTime<Utc>) -> bool {
        now < record.expires_at && now - record.last_seen_at < self.inner.config.idle_timeout
    }

    fn classify(&self, lookup: &crate::store::TokenLookup, now: DateTime<Utc>) -> TokenState {
        match lookup.token.superseded_at {
            None => TokenState::Current,
            Some(at) if now - at <= self.inner.config.rotation_grace => TokenState::Grace,
            Some(_) if !lookup.newer_token_used => TokenState::Orphaned,
            Some(_) => TokenState::Reuse,
        }
    }

    /// Finds a token's live session. Expired sessions are deleted on sight.
    async fn resolve(&self, token: &str, now: DateTime<Utc>) -> Result<Result<Resolved<S>, Rejection>, GuardError> {
        let store = &self.inner.store;
        let Some(hash) = self.presented_hash(token) else {
            return Ok(Err(Rejection::NotAuthenticated));
        };
        let Some(lookup) = store.find_by_token(&hash).await? else {
            return Ok(Err(Rejection::NotAuthenticated));
        };
        if !self.is_live(&lookup.session, now) {
            store.delete_session(lookup.session.id).await?;
            return Ok(Err(Rejection::Expired));
        }
        let Some(subject) = crate::subject::decode::<S>(&lookup.session.subject) else {
            tracing::warn!(session_id = %lookup.session.id, "stored subject does not decode as the guard's subject type");
            return Ok(Err(Rejection::NotAuthenticated));
        };
        let state = self.classify(&lookup, now);
        Ok(Ok(Resolved {
            lookup,
            hash,
            subject,
            state,
        }))
    }

    async fn revoke_for_reuse(&self, session: &SessionRecord, ctx: &ClientContext) -> Result<(), GuardError> {
        self.inner.store.delete_session(session.id).await?;
        self.emit(session.id, &session.subject, EventKind::TokenReuse, true, ctx, None)
            .await;
        Ok(())
    }

    /// Records an event, calls the hook and updates metrics. Never fails: a store error is
    /// logged, a hook panic is caught. Unenforced events are recorded at most once per session
    /// and kind per dedup window.
    async fn emit(
        &self,
        session_id: Uuid,
        subject: &str,
        kind: EventKind,
        enforced: bool,
        ctx: &ClientContext,
        assessment: Option<&crate::risk::Assessment>,
    ) {
        let inner = &*self.inner;
        let config = &inner.config;
        let now = self.now();
        if !enforced {
            if self.seen_recently(session_id, kind, now) {
                return;
            }
            match inner
                .store
                .claim_event(session_id, kind, now, config.shadow_dedup_window)
                .await
            {
                Ok(true) => {}
                Ok(false) => return,
                // Better a duplicate than a lost event.
                Err(error) => {
                    tracing::error!(%session_id, kind = kind.as_str(), %error, "failed to claim session event");
                }
            }
        }

        let ip = if config.minimize_event_ip {
            mask_ip(ctx.ip)
        } else {
            ctx.ip
        };
        let event = SessionEvent {
            session_id,
            subject: subject.to_owned(),
            kind,
            enforced,
            score: assessment.map(|a| a.score),
            signals: assessment.map(|a| a.signals.clone()).unwrap_or_default(),
            ip,
            user_agent: ctx
                .user_agent
                .as_deref()
                .map(|ua| crate::client::truncate(ua, config.max_header_len).to_owned()),
            at: now,
        };
        if kind.is_security_relevant() {
            tracing::warn!(%session_id, kind = kind.as_str(), enforced, score = ?event.score, "session event");
        } else {
            tracing::debug!(%session_id, kind = kind.as_str(), "session event");
        }
        if let Err(error) = inner.store.record_event(&event).await {
            tracing::error!(%session_id, kind = kind.as_str(), %error, "failed to record session event");
        }
        if let Some(hook) = &inner.hook
            && catch_unwind(AssertUnwindSafe(|| hook(&event))).is_err()
        {
            tracing::error!(%session_id, kind = kind.as_str(), "on_event hook panicked");
        }
        crate::telemetry::event(kind, enforced);
    }

    /// Whether this process already handled an unenforced `kind` event for the session within
    /// the dedup window; notes this one if not. A cheap first filter in front of the store's
    /// cross-process [`SessionStore::claim_event`].
    fn seen_recently(&self, session_id: Uuid, kind: EventKind, now: DateTime<Utc>) -> bool {
        let window = self.inner.config.shadow_dedup_window;
        let mut state = self.inner.shadow_seen.lock().unwrap_or_else(PoisonError::into_inner);
        if now - state.pruned_at >= window || state.seen.len() >= SHADOW_SEEN_CAPACITY {
            state.seen.retain(|_, at| now - *at < window);
            state.pruned_at = now;
            if state.seen.len() >= SHADOW_SEEN_CAPACITY {
                // A flood of distinct sessions: forget everything and let the store dedupe.
                state.seen.clear();
            }
        }
        match state.seen.get(&(session_id, kind)) {
            Some(at) if now - *at < window => true,
            _ => {
                state.seen.insert((session_id, kind), now);
                false
            }
        }
    }
}

/// Reduces an address to its network prefix (/24 or /48) for event storage.
fn mask_ip(ip: IpAddr) -> IpAddr {
    let len = if ip.is_ipv4() { 24 } else { 48 };
    ipnet::IpNet::new(ip, len).map_or(ip, |net| net.trunc().addr())
}

fn td(duration: Duration) -> TimeDelta {
    TimeDelta::from_std(duration).unwrap_or(TimeDelta::MAX)
}
