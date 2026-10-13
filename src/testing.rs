//! Conformance suite for [`SessionStore`] implementations.
//!
//! Every built-in store runs this suite. Run it against your own store with
//! [`store_conformance!`](crate::store_conformance), which needs `tokio` (with the `macros` and
//! `rt-multi-thread` features) as a dev-dependency:
//!
//! ```no_run
//! # #[cfg(feature = "valkey")]
//! # mod suite {
//! use session_guard::ValkeyStore;
//!
//! session_guard::store_conformance!(|| async {
//!     ValkeyStore::connect("redis://localhost:6379").await.unwrap()
//! });
//! # }
//! ```
//!
//! The tests use random ids and subjects and whole-second timestamps, so they can share one
//! database with each other and with other data.
//!
//! Every check panics when the store breaks the contract.
#![allow(
    clippy::missing_panics_doc,
    reason = "each check panics on a contract violation, documented above"
)]

use std::net::{IpAddr, Ipv4Addr};

use chrono::{DateTime, TimeDelta, Utc};
use uuid::Uuid;

use crate::{
    checks::Check,
    event::{ClientSummary, EventKind, SessionEvent},
    fingerprint::{Baseline, Fingerprint},
    intel::Anonymity,
    store::{Rotation, SessionRecord, SessionStore, SessionUpdate, Supersede},
    token::{SessionToken, TokenHash},
};

/// Generates one `#[tokio::test]` per conformance check. `$make` is a closure returning a
/// future that resolves to a fresh store handle.
#[macro_export]
macro_rules! store_conformance {
    ($make:expr) => {
        $crate::store_conformance!(@tests $make;
            insert_and_find,
            unknown_token_is_none,
            records_round_trip,
            exact_rotation_happens_once,
            concurrent_rotation_has_one_winner,
            rotation_if_issued_before,
            current_rotation,
            newer_token_used_is_tracked,
            mark_used_sets_once,
            mark_used_reaches_the_rotated_token,
            none_fields_are_preserved,
            prune_superseded_tokens,
            delete_session_removes_tokens,
            delete_subject_sessions,
            list_subject_sessions,
            delete_expired_absolute_and_idle,
            events_record_and_purge,
            event_claims_dedupe_within_window,
            apply_to_missing_session,
        );
    };
    (@tests $make:expr; $($name:ident),* $(,)?) => {
        $(
            #[::tokio::test(flavor = "multi_thread")]
            async fn $name() {
                $crate::testing::$name(($make)().await).await;
            }
        )*
    };
}

/// The current time truncated to whole seconds.
pub fn now_secs() -> DateTime<Utc> {
    let now = Utc::now();
    DateTime::from_timestamp(now.timestamp(), 0).unwrap_or(now)
}

/// A fresh random token hash.
///
/// # Panics
///
/// If the OS random number generator is unavailable.
pub fn random_hash() -> TokenHash {
    SessionToken::generate().expect("OS RNG").hash()
}

/// A session for a random subject, created at `now`, expiring in a day.
pub fn sample_session(now: DateTime<Utc>) -> SessionRecord {
    sample_session_for(&format!("\"conformance-{}\"", Uuid::new_v4()), now)
}

/// A session for `subject` (canonical JSON), created at `now`, expiring in a day.
pub fn sample_session_for(subject: &str, now: DateTime<Utc>) -> SessionRecord {
    SessionRecord {
        id: Uuid::new_v4(),
        subject: subject.to_owned(),
        created_at: now,
        authenticated_at: now,
        last_seen_at: now,
        expires_at: now + TimeDelta::days(1),
        step_up_required: false,
        baseline: Baseline::new(Fingerprint {
            ip_prefix: "203.0.113.0/24".into(),
            ..Fingerprint::default()
        }),
    }
}

fn secs(n: i64) -> TimeDelta {
    TimeDelta::seconds(n)
}

fn rotation(new_token: TokenHash, supersede: Supersede, prune_before: DateTime<Utc>) -> Rotation {
    Rotation {
        new_token,
        supersede,
        prune_superseded_before: prune_before,
    }
}

fn rotate(id: Uuid, now: DateTime<Utc>, rotation: Rotation) -> SessionUpdate {
    SessionUpdate {
        rotation: Some(rotation),
        ..SessionUpdate::touch(id, now)
    }
}

/// An inserted session is found by its token, which starts current and unused.
pub async fn insert_and_find<St: SessionStore>(store: St) {
    let now = now_secs();
    let session = sample_session(now);
    let token = random_hash();
    store.insert_session(&session, &token).await.unwrap();

    let found = store
        .find_by_token(&token)
        .await
        .unwrap()
        .expect("inserted token is found");
    assert_eq!(found.session, session);
    assert_eq!(found.token.hash, token);
    assert_eq!(found.token.issued_at, now);
    assert_eq!(found.token.first_used_at, None);
    assert_eq!(found.token.superseded_at, None);
    assert!(!found.newer_token_used);
}

/// An unknown token finds nothing.
pub async fn unknown_token_is_none<St: SessionStore>(store: St) {
    assert!(store.find_by_token(&random_hash()).await.unwrap().is_none());
}

/// Unicode subjects and a fully populated baseline survive storage unchanged.
pub async fn records_round_trip<St: SessionStore>(store: St) {
    let now = now_secs();
    let mut session = sample_session_for(
        &format!("{{\"tenant\":\"zürich-🦀\",\"user\":\"{}\"}}", Uuid::new_v4()),
        now,
    );
    session.step_up_required = true;
    session.authenticated_at = now - secs(30);
    session.last_seen_at = now - secs(5);
    session.baseline = Baseline {
        fingerprint: Fingerprint {
            ip_prefix: "2001:db8:1::/48".into(),
            country: Some("BE".into()),
            asn: Some(64_496),
            browser: Some("Firefox".into()),
            browser_major: Some(131),
            os: Some("Linux".into()),
            ch_platform: Some("Linux".into()),
            ch_mobile: Some(false),
            accept_language: Some("nl-be,nl,en".into()),
            tls: Some("t13d1516h2_8daaf6152771_02713d6af862".into()),
            anonymity: Some(Anonymity::Vpn),
        },
        previous_ip_prefix: Some("198.51.100.0/24".into()),
        ip_changed_at: Some(now - secs(60)),
    };
    let token = random_hash();
    store.insert_session(&session, &token).await.unwrap();
    let found = store.find_by_token(&token).await.unwrap().unwrap();
    assert_eq!(found.session, session);
}

/// `Supersede::Exact` rotates only while that token is current.
pub async fn exact_rotation_happens_once<St: SessionStore>(store: St) {
    let now = now_secs();
    let session = sample_session(now);
    let first = random_hash();
    store.insert_session(&session, &first).await.unwrap();

    let later = now + secs(60);
    let second = random_hash();
    let rotated = store
        .apply(&rotate(
            session.id,
            later,
            rotation(second, Supersede::Exact(first), now),
        ))
        .await
        .unwrap();
    assert!(rotated);

    let third = random_hash();
    let again = store
        .apply(&rotate(
            session.id,
            later,
            rotation(third, Supersede::Exact(first), now),
        ))
        .await
        .unwrap();
    assert!(!again, "a superseded token must not rotate again");
    assert!(store.find_by_token(&third).await.unwrap().is_none());

    let old = store.find_by_token(&first).await.unwrap().unwrap();
    assert_eq!(old.token.superseded_at, Some(later));
    let new = store.find_by_token(&second).await.unwrap().unwrap();
    assert_eq!(new.token.issued_at, later);
    assert_eq!(new.token.superseded_at, None);
    assert_eq!(new.session.last_seen_at, later);
}

/// Of many concurrent `Exact` rotations of one token, exactly one wins and the losers' tokens
/// are never stored.
pub async fn concurrent_rotation_has_one_winner<St: SessionStore>(store: St) {
    let now = now_secs();
    let session = sample_session(now);
    let first = random_hash();
    store.insert_session(&session, &first).await.unwrap();

    let candidates: Vec<TokenHash> = (0..16).map(|_| random_hash()).collect();
    let attempts = candidates.iter().map(|&candidate| {
        let update = rotate(
            session.id,
            now + secs(1),
            rotation(candidate, Supersede::Exact(first), now),
        );
        let store = &store;
        async move { store.apply(&update).await.unwrap() }
    });
    let results = join_all(attempts).await;
    assert_eq!(results.iter().filter(|r| **r).count(), 1, "exactly one rotation wins");

    let mut current = 0;
    for (candidate, won) in candidates.iter().zip(&results) {
        let found = store.find_by_token(candidate).await.unwrap();
        assert_eq!(found.is_some(), *won);
        if found.is_some_and(|f| f.token.superseded_at.is_none()) {
            current += 1;
        }
    }
    assert_eq!(current, 1, "exactly one current token");
}

/// `Supersede::CurrentIssuedBefore` only rotates a current token older than the instant.
pub async fn rotation_if_issued_before<St: SessionStore>(store: St) {
    let now = now_secs();
    let session = sample_session(now);
    let first = random_hash();
    store.insert_session(&session, &first).await.unwrap();

    let too_new = random_hash();
    let rotated = store
        .apply(&rotate(
            session.id,
            now + secs(5),
            rotation(too_new, Supersede::CurrentIssuedBefore(now), now),
        ))
        .await
        .unwrap();
    assert!(!rotated, "issued_at == cutoff is not strictly before");
    assert!(store.find_by_token(&too_new).await.unwrap().is_none());

    let second = random_hash();
    let rotated = store
        .apply(&rotate(
            session.id,
            now + secs(5),
            rotation(second, Supersede::CurrentIssuedBefore(now + secs(1)), now),
        ))
        .await
        .unwrap();
    assert!(rotated);
    let old = store.find_by_token(&first).await.unwrap().unwrap();
    assert_eq!(old.token.superseded_at, Some(now + secs(5)));
}

/// `Supersede::Current` rotates whatever token is current.
pub async fn current_rotation<St: SessionStore>(store: St) {
    let now = now_secs();
    let session = sample_session(now);
    let first = random_hash();
    store.insert_session(&session, &first).await.unwrap();
    let second = random_hash();
    store
        .apply(&rotate(
            session.id,
            now + secs(1),
            rotation(second, Supersede::Exact(first), now),
        ))
        .await
        .unwrap();

    let third = random_hash();
    let rotated = store
        .apply(&rotate(
            session.id,
            now + secs(2),
            rotation(third, Supersede::Current, now),
        ))
        .await
        .unwrap();
    assert!(rotated);
    let second_found = store.find_by_token(&second).await.unwrap().unwrap();
    assert_eq!(second_found.token.superseded_at, Some(now + secs(2)));
    let third_found = store.find_by_token(&third).await.unwrap().unwrap();
    assert_eq!(third_found.token.superseded_at, None);
}

/// `newer_token_used` reports whether a later token of the session has been presented.
pub async fn newer_token_used_is_tracked<St: SessionStore>(store: St) {
    let now = now_secs();
    let session = sample_session(now);
    let first = random_hash();
    store.insert_session(&session, &first).await.unwrap();
    let second = random_hash();
    store
        .apply(&rotate(
            session.id,
            now + secs(1),
            rotation(second, Supersede::Exact(first), now),
        ))
        .await
        .unwrap();
    assert!(!store.find_by_token(&first).await.unwrap().unwrap().newer_token_used);

    store
        .apply(&SessionUpdate {
            mark_used: Some(second),
            ..SessionUpdate::touch(session.id, now + secs(2))
        })
        .await
        .unwrap();
    assert!(store.find_by_token(&first).await.unwrap().unwrap().newer_token_used);
    assert!(!store.find_by_token(&second).await.unwrap().unwrap().newer_token_used);
}

/// `mark_used` sets `first_used_at` once and never moves it.
pub async fn mark_used_sets_once<St: SessionStore>(store: St) {
    let now = now_secs();
    let session = sample_session(now);
    let token = random_hash();
    store.insert_session(&session, &token).await.unwrap();

    for offset in [3, 9] {
        store
            .apply(&SessionUpdate {
                mark_used: Some(token),
                ..SessionUpdate::touch(session.id, now + secs(offset))
            })
            .await
            .unwrap();
    }
    let found = store.find_by_token(&token).await.unwrap().unwrap();
    assert_eq!(found.token.first_used_at, Some(now + secs(3)));
    assert_eq!(found.session.last_seen_at, now + secs(9));
}

/// `mark_used` may name the token the same update's rotation inserts.
pub async fn mark_used_reaches_the_rotated_token<St: SessionStore>(store: St) {
    let now = now_secs();
    let session = sample_session(now);
    let first = random_hash();
    store.insert_session(&session, &first).await.unwrap();
    let second = random_hash();
    let rotated = store
        .apply(&SessionUpdate {
            mark_used: Some(second),
            ..rotate(
                session.id,
                now + secs(1),
                rotation(second, Supersede::Exact(first), now),
            )
        })
        .await
        .unwrap();
    assert!(rotated);
    let found = store.find_by_token(&second).await.unwrap().unwrap();
    assert_eq!(found.token.first_used_at, Some(now + secs(1)));
    assert!(store.find_by_token(&first).await.unwrap().unwrap().newer_token_used);
}

/// `None` fields leave stored values alone; `Some` fields replace them.
pub async fn none_fields_are_preserved<St: SessionStore>(store: St) {
    let now = now_secs();
    let session = sample_session(now);
    let token = random_hash();
    store.insert_session(&session, &token).await.unwrap();

    let mut baseline = session.baseline.clone();
    baseline.fingerprint.country = Some("NL".into());
    store
        .apply(&SessionUpdate {
            baseline: Some(baseline.clone()),
            step_up_required: Some(true),
            authenticated_at: Some(now + secs(4)),
            ..SessionUpdate::touch(session.id, now + secs(4))
        })
        .await
        .unwrap();
    store
        .apply(&SessionUpdate::touch(session.id, now + secs(8)))
        .await
        .unwrap();

    let found = store.find_by_token(&token).await.unwrap().unwrap().session;
    assert_eq!(found.baseline, baseline);
    assert!(found.step_up_required);
    assert_eq!(found.authenticated_at, now + secs(4));
    assert_eq!(found.last_seen_at, now + secs(8));
    assert_eq!(found.created_at, session.created_at);
    assert_eq!(found.expires_at, session.expires_at);
    assert_eq!(found.subject, session.subject);

    store
        .apply(&SessionUpdate {
            step_up_required: Some(false),
            ..SessionUpdate::touch(session.id, now + secs(9))
        })
        .await
        .unwrap();
    assert!(
        !store
            .find_by_token(&token)
            .await
            .unwrap()
            .unwrap()
            .session
            .step_up_required
    );
}

/// A rotation prunes the session's tokens superseded before its cutoff, and only those.
pub async fn prune_superseded_tokens<St: SessionStore>(store: St) {
    let now = now_secs();
    let session = sample_session(now);
    let t1 = random_hash();
    store.insert_session(&session, &t1).await.unwrap();
    let t2 = random_hash();
    store
        .apply(&rotate(
            session.id,
            now + secs(10),
            rotation(t2, Supersede::Exact(t1), now),
        ))
        .await
        .unwrap();
    let t3 = random_hash();
    store
        .apply(&rotate(
            session.id,
            now + secs(20),
            rotation(t3, Supersede::Exact(t2), now),
        ))
        .await
        .unwrap();

    // t1 was superseded at +10, t2 at +20 (the new rotation supersedes t3 at +30).
    let t4 = random_hash();
    store
        .apply(&rotate(
            session.id,
            now + secs(30),
            rotation(t4, Supersede::Exact(t3), now + secs(15)),
        ))
        .await
        .unwrap();
    assert!(
        store.find_by_token(&t1).await.unwrap().is_none(),
        "superseded before cutoff is pruned"
    );
    assert!(store.find_by_token(&t2).await.unwrap().is_some());
    assert!(store.find_by_token(&t3).await.unwrap().is_some());
    assert!(store.find_by_token(&t4).await.unwrap().is_some());
}

/// Deleting a session removes its tokens and reports whether it existed.
pub async fn delete_session_removes_tokens<St: SessionStore>(store: St) {
    let now = now_secs();
    let session = sample_session(now);
    let t1 = random_hash();
    store.insert_session(&session, &t1).await.unwrap();
    let t2 = random_hash();
    store
        .apply(&rotate(
            session.id,
            now + secs(1),
            rotation(t2, Supersede::Exact(t1), now),
        ))
        .await
        .unwrap();

    assert!(store.delete_session(session.id).await.unwrap());
    assert!(!store.delete_session(session.id).await.unwrap());
    assert!(store.find_by_token(&t1).await.unwrap().is_none());
    assert!(store.find_by_token(&t2).await.unwrap().is_none());
}

/// Deleting a subject's sessions leaves other subjects alone.
pub async fn delete_subject_sessions<St: SessionStore>(store: St) {
    let now = now_secs();
    let subject = format!("\"conformance-{}\"", Uuid::new_v4());
    let mut tokens = Vec::new();
    for _ in 0..3 {
        let token = random_hash();
        store
            .insert_session(&sample_session_for(&subject, now), &token)
            .await
            .unwrap();
        tokens.push(token);
    }
    let other = random_hash();
    store.insert_session(&sample_session(now), &other).await.unwrap();

    assert_eq!(store.delete_subject_sessions(&subject).await.unwrap(), 3);
    assert_eq!(store.delete_subject_sessions(&subject).await.unwrap(), 0);
    for token in &tokens {
        assert!(store.find_by_token(token).await.unwrap().is_none());
    }
    assert!(store.find_by_token(&other).await.unwrap().is_some());
}

/// Listing returns exactly the subject's sessions.
pub async fn list_subject_sessions<St: SessionStore>(store: St) {
    let now = now_secs();
    let subject = format!("\"conformance-{}\"", Uuid::new_v4());
    let a = sample_session_for(&subject, now);
    let b = sample_session_for(&subject, now - secs(60));
    store.insert_session(&a, &random_hash()).await.unwrap();
    store.insert_session(&b, &random_hash()).await.unwrap();
    store
        .insert_session(&sample_session(now), &random_hash())
        .await
        .unwrap();

    let mut listed = store.list_subject_sessions(&subject).await.unwrap();
    listed.sort_by_key(|s| s.created_at);
    assert_eq!(listed, vec![b, a]);
    assert_eq!(store.list_subject_sessions("\"nobody\"").await.unwrap(), vec![]);
}

/// Expired (absolute) and idle sessions are purged; live ones stay.
pub async fn delete_expired_absolute_and_idle<St: SessionStore>(store: St) {
    // Far in the past, so these purges only reach rows at least that old: never the live rows
    // of other tests or apps sharing the database. Stores whose keys expire on the wall clock
    // drop `expired` on their own, so only the idle session is sure to be counted; the others
    // expire in real time.
    let base = far_past();
    let later = Utc::now() + TimeDelta::days(1);
    let mut expired = sample_session(base);
    expired.expires_at = base;
    let mut idle = sample_session(base);
    idle.last_seen_at = base - secs(100);
    idle.expires_at = later;
    let mut live = sample_session(base);
    live.expires_at = later;
    live.last_seen_at = base - secs(99);

    let (te, ti, tl) = (random_hash(), random_hash(), random_hash());
    store.insert_session(&expired, &te).await.unwrap();
    store.insert_session(&idle, &ti).await.unwrap();
    store.insert_session(&live, &tl).await.unwrap();

    let deleted = store.delete_expired(base, base - secs(100)).await.unwrap();
    assert!(deleted >= 1);
    assert!(store.find_by_token(&te).await.unwrap().is_none());
    assert!(store.find_by_token(&ti).await.unwrap().is_none());
    assert!(store.find_by_token(&tl).await.unwrap().is_some());
    store.delete_session(live.id).await.unwrap();
}

/// Events are recorded and purged strictly before the cutoff.
pub async fn events_record_and_purge<St: SessionStore>(store: St) {
    let at = far_past();
    let event = SessionEvent {
        session_id: Uuid::new_v4(),
        subject: "\"conformance\"".into(),
        kind: EventKind::RiskRevoked,
        enforced: false,
        score: Some(95),
        signals: vec![Check::OsChanged, Check::CountryChanged],
        ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 0)),
        user_agent: Some("Mozilla/5.0 🦀".into()),
        client: ClientSummary {
            country: Some("BE".into()),
            asn: Some(64500),
            browser: Some("Firefox".into()),
            ..ClientSummary::default()
        },
        at,
    };
    store.record_event(&event).await.unwrap();
    store
        .record_event(&SessionEvent {
            user_agent: None,
            score: None,
            signals: vec![],
            client: ClientSummary::default(),
            ..event.clone()
        })
        .await
        .unwrap();
    store.delete_events_before(at).await.unwrap();
    assert!(store.delete_events_before(at + secs(1)).await.unwrap() >= 2);
}

/// A claim succeeds once per session and kind per window, across store handles.
pub async fn event_claims_dedupe_within_window<St: SessionStore>(store: St) {
    let now = now_secs();
    let window = secs(600);
    let session = Uuid::new_v4();
    let claim = |kind, at| store.claim_event(session, kind, at, window);
    assert!(claim(EventKind::RiskRevoked, now).await.unwrap());
    assert!(!claim(EventKind::RiskRevoked, now + secs(1)).await.unwrap());
    assert!(!claim(EventKind::RiskRevoked, now + secs(599)).await.unwrap());
    assert!(
        claim(EventKind::StepUpRequired, now).await.unwrap(),
        "kinds are independent"
    );
    assert!(
        store
            .claim_event(Uuid::new_v4(), EventKind::RiskRevoked, now, window)
            .await
            .unwrap(),
        "sessions are independent"
    );
    assert!(
        claim(EventKind::RiskRevoked, now + secs(600)).await.unwrap(),
        "the window elapsed"
    );
    assert!(
        !claim(EventKind::RiskRevoked, now + secs(601)).await.unwrap(),
        "the new claim holds"
    );
}

/// Updating a session that does not exist is not an error.
pub async fn apply_to_missing_session<St: SessionStore>(store: St) {
    let now = now_secs();
    let update = rotate(Uuid::new_v4(), now, rotation(random_hash(), Supersede::Current, now));
    assert!(!store.apply(&update).await.unwrap());
}

/// A random whole-minute instant between 1900 and 1931.
fn far_past() -> DateTime<Utc> {
    let bytes = Uuid::new_v4().into_bytes();
    let minutes = i64::from(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], 0]));
    DateTime::from_timestamp(-2_208_988_800 + minutes * 60, 0).unwrap_or_default()
}

/// Polls every future to completion concurrently, without a runtime dependency.
async fn join_all<F: std::future::Future>(futures: impl IntoIterator<Item = F>) -> Vec<F::Output> {
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };

    struct JoinAll<F: std::future::Future> {
        futures: Vec<Option<Pin<Box<F>>>>,
        outputs: Vec<Option<F::Output>>,
    }

    // Every future is boxed and outputs are never pinned.
    impl<F: std::future::Future> Unpin for JoinAll<F> {}

    impl<F: std::future::Future> std::future::Future for JoinAll<F> {
        type Output = Vec<F::Output>;

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            let this = self.get_mut();
            let mut pending = false;
            for (slot, out) in this.futures.iter_mut().zip(this.outputs.iter_mut()) {
                if let Some(fut) = slot {
                    match fut.as_mut().poll(cx) {
                        Poll::Ready(v) => {
                            *out = Some(v);
                            *slot = None;
                        }
                        Poll::Pending => pending = true,
                    }
                }
            }
            if pending {
                Poll::Pending
            } else {
                Poll::Ready(this.outputs.iter_mut().filter_map(Option::take).collect())
            }
        }
    }

    let futures: Vec<_> = futures.into_iter().map(|f| Some(Box::pin(f))).collect();
    let outputs = futures.iter().map(|_| None).collect();
    JoinAll { futures, outputs }.await
}
