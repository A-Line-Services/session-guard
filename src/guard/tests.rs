use std::{
    net::IpAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use chrono::{DateTime, TimeZone, Utc};
use uuid::Uuid;

use super::*;
use crate::{
    checks::Check,
    clock::ManualClock,
    config::{Mode, StepUpPolicy},
    intel::IpInfo,
    store::MemoryStore,
};

const CHROME_WIN: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";
const FIREFOX_LINUX: &str = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0";

fn start() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 3, 1, 12, 0, 0).unwrap()
}

fn mins(n: u64) -> Duration {
    Duration::from_secs(n * 60)
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

/// The victim's usual client: Chrome on Windows in the US.
fn home() -> ClientContext {
    ClientContext::new(ip("203.0.113.7"))
        .with_user_agent(CHROME_WIN)
        .with_ch_platform("\"Windows\"")
        .with_ch_mobile(false)
        .with_accept_language("en-US,en;q=0.9")
}

/// Same browser, other country and network: country (40) + prefix (10) = step-up.
fn abroad() -> ClientContext {
    ClientContext::new(ip("198.51.100.20"))
        .with_user_agent(CHROME_WIN)
        .with_ch_platform("\"Windows\"")
        .with_ch_mobile(false)
        .with_accept_language("en-US,en;q=0.9")
}

/// Another OS and browser: revoke.
fn attacker() -> ClientContext {
    ClientContext::new(ip("192.0.2.66"))
        .with_user_agent(FIREFOX_LINUX)
        .with_accept_language("en-US,en;q=0.5")
}

/// Same browser, other provider in the same country: ASN (20) alone is allowed.
fn mobile() -> ClientContext {
    ClientContext::new(ip("100.64.0.10"))
        .with_user_agent(CHROME_WIN)
        .with_ch_platform("\"Windows\"")
        .with_ch_mobile(false)
        .with_accept_language("en-US,en;q=0.9")
}

fn intel(ip: IpAddr) -> IpInfo {
    let (country, asn) = match ip {
        IpAddr::V4(v4) if v4.octets()[..3] == [198, 51, 100] => ("DE", 64500),
        IpAddr::V4(v4) if v4.octets()[..3] == [100, 64, 0] => ("US", 64501),
        _ => ("US", 64500),
    };
    IpInfo::new(Some(country.into()), Some(asn))
}

struct Harness<S = Uuid> {
    guard: Guard<Arc<MemoryStore>, S>,
    store: Arc<MemoryStore>,
    clock: ManualClock,
    events: Arc<Mutex<Vec<SessionEvent>>>,
}

impl<S> Harness<S> {
    fn kinds(&self) -> Vec<(EventKind, bool)> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .map(|e| (e.kind, e.enforced))
            .collect()
    }

    fn count(&self, kind: EventKind) -> usize {
        self.events.lock().unwrap().iter().filter(|e| e.kind == kind).count()
    }

    fn advance(&self, by: Duration) {
        self.clock.advance(by);
    }
}

fn harness_with(config: GuardConfig) -> Harness {
    harness_typed::<Uuid>(config)
}

fn harness_typed<S: crate::subject::Subject>(config: GuardConfig) -> Harness<S> {
    let store = Arc::new(MemoryStore::new());
    let clock = ManualClock::new(start());
    let events = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&events);
    let guard = Guard::builder(Arc::clone(&store), config)
        .ip_intel(intel)
        .clock(clock.clone())
        .on_event(move |e| sink.lock().unwrap().push(e.clone()))
        .subject::<S>()
        .build();
    Harness {
        guard,
        store,
        clock,
        events,
    }
}

fn harness() -> Harness {
    harness_with(GuardConfig::default())
}

fn authenticated<S: std::fmt::Debug>(outcome: Outcome<S>) -> Authenticated<S> {
    match outcome {
        Outcome::Authenticated(a) => a,
        Outcome::Rejected(r) => panic!("expected authenticated, got {r:?}"),
    }
}

fn rejected<S: std::fmt::Debug>(outcome: Outcome<S>) -> Rejection {
    match outcome {
        Outcome::Authenticated(a) => panic!("expected rejection, got {a:?}"),
        Outcome::Rejected(r) => r,
    }
}

fn max_age(set_cookie: &str) -> i64 {
    set_cookie
        .split("; ")
        .find_map(|p| p.strip_prefix("Max-Age="))
        .unwrap()
        .parse()
        .unwrap()
}

async fn login(h: &Harness, user: Uuid) -> String {
    let new = h.guard.login(&user, &home(), None).await.unwrap();
    new.token.expose().to_owned()
}

// --- login and the normal flow ---

#[tokio::test]
async fn login_then_authenticate() {
    let h = harness();
    let user = Uuid::new_v4();
    let new = h.guard.login(&user, &home(), None).await.unwrap();
    assert_eq!(new.token.expose().len(), 43);
    assert!(
        new.token
            .set_cookie()
            .starts_with(&format!("__Host-sid={}", new.token.expose()))
    );
    assert_eq!(max_age(new.token.set_cookie()), 30 * 24 * 3600);
    assert_eq!(new.token.expires_at(), start() + chrono::TimeDelta::days(30));
    assert!(!format!("{:?}", new.token).contains(new.token.expose()));

    let a = authenticated(h.guard.authenticate(new.token.expose(), &home()).await.unwrap());
    assert_eq!(a.session.subject, user);
    assert_eq!(a.session.session_id, new.session_id);
    assert_eq!(a.session.created_at, start());
    assert!(a.rotated.is_none());
    assert_eq!(a.assessment.signals, vec![]);
    assert_eq!(h.kinds(), vec![(EventKind::Login, true)]);
}

#[tokio::test]
async fn unknown_and_malformed_tokens_are_not_authenticated() {
    let h = harness();
    for token in [
        "",
        "short",
        "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!",
        &"A".repeat(43),
        &"A".repeat(5000),
    ] {
        assert_eq!(
            rejected(h.guard.authenticate(token, &home()).await.unwrap()),
            Rejection::NotAuthenticated,
            "{token:.20}"
        );
    }
}

#[tokio::test]
async fn rotates_after_the_interval_with_clock_based_max_age() {
    let h = harness();
    let t0 = login(&h, Uuid::new_v4()).await;
    h.advance(mins(9));
    assert!(
        authenticated(h.guard.authenticate(&t0, &home()).await.unwrap())
            .rotated
            .is_none()
    );

    h.advance(mins(11));
    let a = authenticated(h.guard.authenticate(&t0, &home()).await.unwrap());
    let t1 = a.rotated.expect("rotated after 20 minutes");
    assert_ne!(t1.expose(), t0);
    assert_eq!(max_age(t1.set_cookie()), 30 * 24 * 3600 - 20 * 60);

    // The new token works and does not rotate again right away.
    assert!(
        authenticated(h.guard.authenticate(t1.expose(), &home()).await.unwrap())
            .rotated
            .is_none()
    );
}

#[tokio::test]
async fn superseded_token_works_within_grace_without_rotating() {
    let h = harness();
    let t0 = login(&h, Uuid::new_v4()).await;
    h.advance(mins(11));
    let t1 = authenticated(h.guard.authenticate(&t0, &home()).await.unwrap())
        .rotated
        .unwrap();
    authenticated(h.guard.authenticate(t1.expose(), &home()).await.unwrap());

    h.advance(Duration::from_secs(10));
    let a = authenticated(h.guard.authenticate(&t0, &home()).await.unwrap());
    assert!(a.rotated.is_none());
    assert_eq!(h.count(EventKind::TokenReuse), 0);
}

#[tokio::test]
async fn lost_rotation_response_is_reissued() {
    let h = harness();
    let t0 = login(&h, Uuid::new_v4()).await;
    h.advance(mins(11));
    // The client never receives t1.
    let _lost = authenticated(h.guard.authenticate(&t0, &home()).await.unwrap())
        .rotated
        .unwrap();

    h.advance(mins(1));
    let a = authenticated(h.guard.authenticate(&t0, &home()).await.unwrap());
    let t2 = a.rotated.expect("orphaned token gets a fresh one");
    assert_eq!(a.assessment.signals, vec![Check::OrphanedToken]);
    assert_eq!(a.assessment.score, 25);
    assert_eq!(h.count(EventKind::TokenReissued), 1);
    let a = authenticated(h.guard.authenticate(t2.expose(), &home()).await.unwrap());
    assert_eq!(a.assessment.signals, vec![]);
}

/// Logs in and rotates once, dropping the successor: the returned token is orphaned once
/// the grace period has passed.
async fn orphan(h: &Harness, user: Uuid) -> String {
    let t0 = login(h, user).await;
    h.advance(mins(11));
    let _lost = authenticated(h.guard.authenticate(&t0, &home()).await.unwrap())
        .rotated
        .unwrap();
    h.advance(mins(1));
    t0
}

#[tokio::test]
async fn orphan_on_another_network_needs_step_up() {
    let h = harness();
    let user = Uuid::new_v4();
    // A network change alone is fine.
    let fresh = login(&h, user).await;
    let a = authenticated(h.guard.authenticate(&fresh, &mobile()).await.unwrap());
    assert_eq!(a.assessment.signals, vec![Check::AsnChanged]);

    let t0 = orphan(&h, user).await;
    assert_eq!(
        rejected(h.guard.authenticate(&t0, &mobile()).await.unwrap()),
        Rejection::StepUpRequired
    );
    let event = h.events.lock().unwrap().last().cloned().unwrap();
    assert_eq!(event.kind, EventKind::StepUpRequired);
    assert_eq!(event.signals, vec![Check::OrphanedToken, Check::AsnChanged]);
    assert_eq!(event.score, Some(45));
    assert_eq!(h.count(EventKind::TokenReissued), 0);

    let StepUpOutcome::Completed(t1) = h.guard.complete_step_up(&t0, &mobile(), &user).await.unwrap() else {
        panic!("step-up with the orphaned token should complete");
    };
    let a = authenticated(h.guard.authenticate(t1.expose(), &mobile()).await.unwrap());
    assert_eq!(a.assessment.signals, vec![]);
}

#[tokio::test]
async fn orphan_without_checks_is_reissued_unscored() {
    let h = harness();
    let t0 = orphan(&h, Uuid::new_v4()).await;
    let a = authenticated(
        h.guard
            .authenticate_with(&t0, &mobile(), &Checks::none())
            .await
            .unwrap(),
    );
    assert!(a.rotated.is_some());
    assert_eq!(a.assessment.signals, vec![]);
    assert_eq!(a.assessment.score, 0);
    assert_eq!(h.count(EventKind::TokenReissued), 1);
}

#[tokio::test]
async fn orphan_signal_can_be_disabled() {
    let h = harness_with(
        GuardConfig::builder()
            .checks(Checks::default().disable(Check::OrphanedToken))
            .build()
            .unwrap(),
    );
    let t0 = orphan(&h, Uuid::new_v4()).await;
    let a = authenticated(h.guard.authenticate(&t0, &mobile()).await.unwrap());
    assert!(a.rotated.is_some());
    assert_eq!(a.assessment.signals, vec![Check::AsnChanged]);
}

#[tokio::test]
async fn orphan_in_shadow_mode_is_reissued() {
    let h = harness_with(GuardConfig::builder().mode(Mode::Shadow).build().unwrap());
    let t0 = orphan(&h, Uuid::new_v4()).await;
    let a = authenticated(h.guard.authenticate(&t0, &mobile()).await.unwrap());
    assert!(a.rotated.is_some());
    assert_eq!(a.assessment.score, 45);
    assert!(h.kinds().contains(&(EventKind::StepUpRequired, false)));
    assert_eq!(h.count(EventKind::TokenReissued), 1);
}

fn reissue_window(window: Duration) -> Harness {
    harness_with(GuardConfig::builder().orphan_reissue_window(window).build().unwrap())
}

#[tokio::test]
async fn orphan_within_the_reissue_window_is_reissued() {
    let h = reissue_window(mins(5));
    let t0 = orphan(&h, Uuid::new_v4()).await;
    h.advance(mins(3));
    let a = authenticated(h.guard.authenticate(&t0, &home()).await.unwrap());
    assert!(a.rotated.is_some());
    assert_eq!(h.count(EventKind::TokenReissued), 1);
}

#[tokio::test]
async fn orphan_beyond_the_reissue_window_is_not_authenticated() {
    let h = reissue_window(mins(5));
    let user = Uuid::new_v4();
    let t0 = login(&h, user).await;
    h.advance(mins(11));
    // Whoever receives t1 keeps the session; t0 goes stale.
    let t1 = authenticated(h.guard.authenticate(&t0, &home()).await.unwrap())
        .rotated
        .unwrap();
    h.advance(mins(6));

    assert_eq!(
        rejected(h.guard.authenticate(&t0, &home()).await.unwrap()),
        Rejection::NotAuthenticated
    );
    assert!(matches!(
        h.guard.complete_step_up(&t0, &home(), &user).await.unwrap(),
        StepUpOutcome::Rejected(Rejection::NotAuthenticated)
    ));
    assert!(h.guard.peek(&t0).await.unwrap().is_none());
    assert_eq!(h.kinds(), vec![(EventKind::Login, true)]);
    assert_eq!(h.store.session_count(), 1);

    let a = authenticated(h.guard.authenticate(t1.expose(), &home()).await.unwrap());
    assert_eq!(a.session.subject, user);
    assert_eq!(a.assessment.signals, vec![]);
}

#[tokio::test]
async fn zero_reissue_window_never_reissues() {
    let h = reissue_window(Duration::ZERO);
    let t0 = orphan(&h, Uuid::new_v4()).await;
    assert_eq!(
        rejected(h.guard.authenticate(&t0, &home()).await.unwrap()),
        Rejection::NotAuthenticated
    );
    assert_eq!(h.store.session_count(), 1);
}

#[tokio::test]
async fn orphans_are_reissued_late_by_default() {
    let h = harness();
    let t0 = orphan(&h, Uuid::new_v4()).await;
    h.advance(Duration::from_hours(6 * 24));
    let a = authenticated(h.guard.authenticate(&t0, &home()).await.unwrap());
    assert!(a.rotated.is_some());
    assert_eq!(h.count(EventKind::TokenReissued), 1);
}

#[tokio::test]
async fn orphaned_token_is_reissued_only_once() {
    let h = harness();
    let t0 = login(&h, Uuid::new_v4()).await;
    h.advance(mins(11));
    // An attacker holding t0 drops every successor to keep t0 alive.
    let _t1 = authenticated(h.guard.authenticate(&t0, &home()).await.unwrap())
        .rotated
        .unwrap();
    h.advance(mins(1));
    let _t2 = authenticated(h.guard.authenticate(&t0, &home()).await.unwrap())
        .rotated
        .unwrap();

    h.advance(mins(1));
    assert_eq!(
        rejected(h.guard.authenticate(&t0, &home()).await.unwrap()),
        Rejection::Revoked
    );
    assert_eq!(h.store.session_count(), 0);
    assert_eq!(h.count(EventKind::TokenReissued), 1);
    assert_eq!(h.count(EventKind::TokenReuse), 1);
}

#[tokio::test]
async fn reissued_token_works_without_an_extra_write() {
    let h = harness();
    let t0 = login(&h, Uuid::new_v4()).await;
    h.advance(mins(11));
    let _lost = authenticated(h.guard.authenticate(&t0, &home()).await.unwrap())
        .rotated
        .unwrap();
    h.advance(mins(1));
    let t2 = authenticated(h.guard.authenticate(&t0, &home()).await.unwrap())
        .rotated
        .unwrap();
    let lookup = h
        .store
        .find_by_token(&TokenHash::of(t2.expose()))
        .await
        .unwrap()
        .unwrap();
    assert!(lookup.token.first_used_at.is_some(), "a reissued token counts as used");
    authenticated(h.guard.authenticate(t2.expose(), &home()).await.unwrap());
}

#[tokio::test]
async fn reuse_after_successor_was_used_revokes_the_session() {
    let h = harness();
    let t0 = login(&h, Uuid::new_v4()).await;
    h.advance(mins(11));
    let t1 = authenticated(h.guard.authenticate(&t0, &home()).await.unwrap())
        .rotated
        .unwrap();
    authenticated(h.guard.authenticate(t1.expose(), &home()).await.unwrap());

    h.advance(mins(1));
    assert_eq!(
        rejected(h.guard.authenticate(&t0, &home()).await.unwrap()),
        Rejection::Revoked
    );
    assert_eq!(h.store.session_count(), 0);
    assert_eq!(
        rejected(h.guard.authenticate(t1.expose(), &home()).await.unwrap()),
        Rejection::NotAuthenticated
    );
    assert_eq!(h.count(EventKind::TokenReuse), 1);
}

// --- theft ---

#[tokio::test]
async fn stolen_cookie_on_another_device_is_revoked() {
    let h = harness();
    let t0 = login(&h, Uuid::new_v4()).await;
    h.advance(mins(1));
    assert_eq!(
        rejected(h.guard.authenticate(&t0, &attacker()).await.unwrap()),
        Rejection::Revoked
    );
    assert_eq!(h.store.session_count(), 0);
    let revoked = h
        .events
        .lock()
        .unwrap()
        .iter()
        .find(|e| e.kind == EventKind::RiskRevoked)
        .cloned()
        .unwrap();
    assert!(revoked.enforced);
    assert!(revoked.score.unwrap() >= 80);
    assert!(revoked.signals.contains(&Check::OsChanged));
    assert_eq!(revoked.ip, ip("192.0.2.66"));
    // The victim is logged out too.
    assert_eq!(
        rejected(h.guard.authenticate(&t0, &home()).await.unwrap()),
        Rejection::NotAuthenticated
    );
}

#[tokio::test]
async fn stolen_cookie_with_cloned_fingerprint_is_caught_by_rotation() {
    let h = harness();
    let t0 = login(&h, Uuid::new_v4()).await;
    // The thief copies t0 and spoofs every header; the victim keeps browsing.
    h.advance(mins(11));
    let t1 = authenticated(h.guard.authenticate(&t0, &home()).await.unwrap())
        .rotated
        .unwrap();
    h.advance(mins(2));
    authenticated(h.guard.authenticate(t1.expose(), &home()).await.unwrap());

    assert_eq!(
        rejected(h.guard.authenticate(&t0, &home()).await.unwrap()),
        Rejection::Revoked
    );
    assert_eq!(h.count(EventKind::TokenReuse), 1);
}

#[tokio::test]
async fn thief_rotating_first_locks_out_victim_and_revokes_on_their_return() {
    let h = harness();
    let t0 = login(&h, Uuid::new_v4()).await;
    h.advance(mins(11));
    // Thief (same fingerprint) wins the rotation and uses the new token.
    let stolen = authenticated(h.guard.authenticate(&t0, &home()).await.unwrap())
        .rotated
        .unwrap();
    authenticated(h.guard.authenticate(stolen.expose(), &home()).await.unwrap());
    h.advance(mins(1));
    // Victim comes back with t0: reuse, both lose the session.
    assert_eq!(
        rejected(h.guard.authenticate(&t0, &home()).await.unwrap()),
        Rejection::Revoked
    );
    assert_eq!(
        rejected(h.guard.authenticate(stolen.expose(), &home()).await.unwrap()),
        Rejection::NotAuthenticated
    );
}

// --- step-up ---

#[tokio::test]
async fn step_up_flow() {
    let h = harness();
    let user = Uuid::new_v4();
    let t0 = login(&h, user).await;
    h.advance(mins(1));

    assert_eq!(
        rejected(h.guard.authenticate(&t0, &abroad()).await.unwrap()),
        Rejection::StepUpRequired
    );
    // The flag sticks, even back home.
    assert_eq!(
        rejected(h.guard.authenticate(&t0, &home()).await.unwrap()),
        Rejection::StepUpRequired
    );
    assert_eq!(h.count(EventKind::StepUpRequired), 1);
    assert!(h.guard.peek(&t0).await.unwrap().unwrap().step_up_required);

    assert!(matches!(
        h.guard.complete_step_up(&t0, &abroad(), &Uuid::new_v4()).await.unwrap(),
        StepUpOutcome::SubjectMismatch
    ));
    assert_eq!(
        rejected(h.guard.authenticate(&t0, &abroad()).await.unwrap()),
        Rejection::StepUpRequired
    );

    h.advance(mins(1));
    let StepUpOutcome::Completed(t1) = h.guard.complete_step_up(&t0, &abroad(), &user).await.unwrap() else {
        panic!("step-up should complete");
    };
    assert_ne!(t1.expose(), t0);
    let a = authenticated(h.guard.authenticate(t1.expose(), &abroad()).await.unwrap());
    assert_eq!(a.session.authenticated_at, start() + chrono::TimeDelta::minutes(2));
    assert!(a.assessment.signals.is_empty(), "baseline was reset to the new client");
    assert!(!h.guard.requires_reauth(&a.session, mins(5)));
    assert_eq!(h.count(EventKind::StepUpCompleted), 1);
    // Step-up does not extend the absolute lifetime.
    let lifetime = chrono::TimeDelta::days(30);
    assert_eq!(a.session.expires_at, start() + lifetime);
    assert_eq!(t1.expires_at(), start() + lifetime);
}

#[tokio::test]
async fn step_up_policy_revoke() {
    let h = harness_with(
        GuardConfig::builder()
            .step_up_policy(StepUpPolicy::Revoke)
            .build()
            .unwrap(),
    );
    let t0 = login(&h, Uuid::new_v4()).await;
    assert_eq!(
        rejected(h.guard.authenticate(&t0, &abroad()).await.unwrap()),
        Rejection::Revoked
    );
    assert_eq!(h.count(EventKind::RiskRevoked), 1);
    assert_eq!(h.store.session_count(), 0);
}

#[tokio::test]
async fn step_up_policy_allow_records_unenforced_event() {
    let h = harness_with(
        GuardConfig::builder()
            .step_up_policy(StepUpPolicy::Allow)
            .build()
            .unwrap(),
    );
    let t0 = login(&h, Uuid::new_v4()).await;
    let a = authenticated(h.guard.authenticate(&t0, &abroad()).await.unwrap());
    assert!(a.assessment.signals.contains(&Check::CountryChanged));
    assert!(h.kinds().contains(&(EventKind::StepUpRequired, false)));
    // Still revokes at the revoke threshold.
    assert_eq!(
        rejected(h.guard.authenticate(&t0, &attacker()).await.unwrap()),
        Rejection::Revoked
    );
}

#[tokio::test]
async fn flagged_session_hit_by_revoke_level_signals_is_revoked() {
    let h = harness();
    let t0 = login(&h, Uuid::new_v4()).await;
    assert_eq!(
        rejected(h.guard.authenticate(&t0, &abroad()).await.unwrap()),
        Rejection::StepUpRequired
    );
    assert_eq!(
        rejected(h.guard.authenticate(&t0, &attacker()).await.unwrap()),
        Rejection::Revoked
    );
    assert_eq!(h.store.session_count(), 0);
}

#[tokio::test]
async fn complete_step_up_with_dead_token_is_rejected() {
    let h = harness();
    let user = Uuid::new_v4();
    assert!(matches!(
        h.guard.complete_step_up(&"A".repeat(43), &home(), &user).await.unwrap(),
        StepUpOutcome::Rejected(Rejection::NotAuthenticated)
    ));
}

// --- shadow mode ---

#[tokio::test]
async fn shadow_mode_records_once_per_window_and_lets_requests_through() {
    let h = harness_with(GuardConfig::builder().mode(Mode::Shadow).build().unwrap());
    let t0 = login(&h, Uuid::new_v4()).await;
    for _ in 0..3 {
        let a = authenticated(h.guard.authenticate(&t0, &attacker()).await.unwrap());
        assert!(a.assessment.score >= 80);
    }
    assert_eq!(h.count(EventKind::RiskRevoked), 1);
    assert!(h.kinds().contains(&(EventKind::RiskRevoked, false)));
    assert_eq!(h.store.session_count(), 1);

    h.advance(mins(11));
    authenticated(h.guard.authenticate(&t0, &attacker()).await.unwrap());
    assert_eq!(h.count(EventKind::RiskRevoked), 2);
}

#[tokio::test]
async fn shadow_dedup_spans_guards_sharing_a_store() {
    // Two pods behind a round-robin load balancer, one store.
    let config = || GuardConfig::builder().mode(Mode::Shadow).build().unwrap();
    let store = Arc::new(MemoryStore::new());
    let clock = ManualClock::new(start());
    let pod = || {
        Guard::builder(Arc::clone(&store), config())
            .ip_intel(intel)
            .clock(clock.clone())
            .build()
    };
    let (a, b) = (pod(), pod());
    let token = a.login(&Uuid::new_v4(), &home(), None).await.unwrap().token;
    for guard in [&a, &b, &a, &b] {
        authenticated(guard.authenticate(token.expose(), &attacker()).await.unwrap());
    }
    let risk = store
        .events()
        .iter()
        .filter(|e| e.kind == EventKind::RiskRevoked)
        .count();
    assert_eq!(risk, 1);
}

#[tokio::test]
async fn shadow_mode_still_enforces_reuse() {
    let h = harness_with(GuardConfig::builder().mode(Mode::Shadow).build().unwrap());
    let t0 = login(&h, Uuid::new_v4()).await;
    h.advance(mins(11));
    let t1 = authenticated(h.guard.authenticate(&t0, &home()).await.unwrap())
        .rotated
        .unwrap();
    authenticated(h.guard.authenticate(t1.expose(), &home()).await.unwrap());
    h.advance(mins(1));
    assert_eq!(
        rejected(h.guard.authenticate(&t0, &home()).await.unwrap()),
        Rejection::Revoked
    );
    assert!(h.kinds().contains(&(EventKind::TokenReuse, true)));
}

// --- lifecycle ---

#[tokio::test]
async fn login_replaces_a_presented_session() {
    let h = harness();
    let user = Uuid::new_v4();
    let old = login(&h, user).await;
    let new = h.guard.login(&user, &home(), Some(&old)).await.unwrap();
    assert_eq!(h.store.session_count(), 1);
    assert_eq!(
        rejected(h.guard.authenticate(&old, &home()).await.unwrap()),
        Rejection::NotAuthenticated
    );
    authenticated(h.guard.authenticate(new.token.expose(), &home()).await.unwrap());
    assert_eq!(h.count(EventKind::Logout), 1);
    // A garbage previous token is ignored.
    h.guard.login(&user, &home(), Some("garbage")).await.unwrap();
}

#[tokio::test]
async fn absolute_expiry() {
    let h = harness_with(
        GuardConfig::builder()
            .session_lifetime(Duration::from_secs(3600))
            .idle_timeout(Duration::from_secs(3600))
            .build()
            .unwrap(),
    );
    let t0 = login(&h, Uuid::new_v4()).await;
    let mut token = t0;
    for _ in 0..5 {
        h.advance(mins(11));
        if let Some(t) = authenticated(h.guard.authenticate(&token, &home()).await.unwrap()).rotated {
            token = t.expose().to_owned();
        }
    }
    h.advance(mins(6));
    assert_eq!(
        rejected(h.guard.authenticate(&token, &home()).await.unwrap()),
        Rejection::Expired
    );
    assert_eq!(h.store.session_count(), 0);
}

#[tokio::test]
async fn idle_expiry() {
    let h = harness_with(
        GuardConfig::builder()
            .idle_timeout(Duration::from_secs(3600))
            .build()
            .unwrap(),
    );
    let t0 = login(&h, Uuid::new_v4()).await;
    h.advance(mins(59));
    let t1 = authenticated(h.guard.authenticate(&t0, &home()).await.unwrap())
        .rotated
        .unwrap();
    h.advance(mins(60));
    assert_eq!(
        rejected(h.guard.authenticate(t1.expose(), &home()).await.unwrap()),
        Rejection::Expired
    );
}

#[tokio::test]
async fn logout_and_bulk_revocation() {
    let h = harness();
    let user = Uuid::new_v4();
    let a = login(&h, user).await;
    assert!(h.guard.logout(&a, &home()).await.unwrap());
    assert!(!h.guard.logout(&a, &home()).await.unwrap());
    assert_eq!(h.count(EventKind::Logout), 1);

    let b = login(&h, user).await;
    let _c = login(&h, user).await;
    let other = login(&h, Uuid::new_v4()).await;
    assert_eq!(h.guard.list_sessions(&user).await.unwrap().len(), 2);
    assert_eq!(h.guard.revoke_all_for_subject(&user).await.unwrap(), 2);
    assert_eq!(
        rejected(h.guard.authenticate(&b, &home()).await.unwrap()),
        Rejection::NotAuthenticated
    );
    authenticated(h.guard.authenticate(&other, &home()).await.unwrap());

    let id = h.guard.peek(&other).await.unwrap().unwrap().session_id;
    assert!(h.guard.revoke_session(id).await.unwrap());
    assert!(h.guard.peek(&other).await.unwrap().is_none());
}

#[tokio::test]
async fn list_sessions_describes_devices_and_skips_expired() {
    let h = harness_with(
        GuardConfig::builder()
            .idle_timeout(Duration::from_secs(3600))
            .build()
            .unwrap(),
    );
    let user = Uuid::new_v4();
    login(&h, user).await;
    h.advance(mins(61));
    login(&h, user).await;
    let list = h.guard.list_sessions(&user).await.unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].browser.as_deref(), Some("Chrome"));
    assert_eq!(list[0].os.as_deref(), Some("Windows"));
    assert_eq!(list[0].country.as_deref(), Some("US"));
}

#[tokio::test]
async fn purge_removes_expired_sessions_and_old_events() {
    let h = harness_with(
        GuardConfig::builder()
            .idle_timeout(Duration::from_secs(3600))
            .build()
            .unwrap(),
    );
    login(&h, Uuid::new_v4()).await;
    h.advance(Duration::from_hours(91 * 24));
    login(&h, Uuid::new_v4()).await;
    let report = h.guard.purge_expired().await.unwrap();
    assert_eq!(report, PurgeReport { sessions: 1, events: 1 });
    assert_eq!(h.store.session_count(), 1);
    assert_eq!(h.store.events().len(), 1);
}

/// Lets spawned tasks run until `done` holds (paused time never advances on its own).
#[cfg(feature = "tokio")]
async fn settle(done: impl Fn() -> bool) {
    for _ in 0..100 {
        if done() {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("condition never held");
}

#[cfg(feature = "tokio")]
#[tokio::test(start_paused = true)]
async fn spawn_purge_purges_now_and_on_every_tick() {
    let h = harness_with(GuardConfig::builder().idle_timeout(mins(60)).build().unwrap());
    login(&h, Uuid::new_v4()).await;
    h.advance(mins(61));
    let task = h.guard.spawn_purge(mins(30));
    settle(|| h.store.session_count() == 0).await;

    login(&h, Uuid::new_v4()).await;
    h.advance(mins(61));
    tokio::time::advance(mins(29)).await;
    tokio::task::yield_now().await;
    assert_eq!(h.store.session_count(), 1, "purged before the tick");
    tokio::time::advance(mins(1)).await;
    settle(|| h.store.session_count() == 0).await;

    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
}

// --- robustness and write behaviour ---

#[tokio::test]
async fn panicking_hook_is_contained() {
    let store = Arc::new(MemoryStore::new());
    let guard = Guard::builder(Arc::clone(&store), GuardConfig::default())
        .on_event(|_| panic!("hook bug"))
        .build();
    let new = guard.login(&Uuid::new_v4(), &home(), None).await.unwrap();
    authenticated(guard.authenticate(new.token.expose(), &home()).await.unwrap());
    assert_eq!(store.events().len(), 1);
}

#[tokio::test]
async fn unchanged_requests_do_not_write() {
    let h = harness();
    let t0 = login(&h, Uuid::new_v4()).await;
    h.advance(Duration::from_secs(5));
    authenticated(h.guard.authenticate(&t0, &home()).await.unwrap()); // marks the token used
    let seen = h.guard.peek(&t0).await.unwrap().unwrap().last_seen_at;
    h.advance(Duration::from_secs(30));
    authenticated(h.guard.authenticate(&t0, &home()).await.unwrap());
    assert_eq!(h.guard.peek(&t0).await.unwrap().unwrap().last_seen_at, seen);
    h.advance(Duration::from_secs(31));
    authenticated(h.guard.authenticate(&t0, &home()).await.unwrap());
    assert_eq!(h.guard.peek(&t0).await.unwrap().unwrap().last_seen_at, h.clock.now());
}

#[tokio::test]
async fn peek_is_read_only() {
    let h = harness();
    let t0 = login(&h, Uuid::new_v4()).await;
    h.advance(mins(30));
    let info = h.guard.peek(&t0).await.unwrap().unwrap();
    assert_eq!(info.last_seen_at, start());
    assert_eq!(h.kinds().len(), 1);
    // Still the current token: authenticate rotates it now.
    assert!(
        authenticated(h.guard.authenticate(&t0, &home()).await.unwrap())
            .rotated
            .is_some()
    );
    assert!(h.guard.peek("garbage").await.unwrap().is_none());
}

#[tokio::test]
async fn minimised_event_ip() {
    let h = harness_with(GuardConfig::builder().minimize_event_ip(true).build().unwrap());
    login(&h, Uuid::new_v4()).await;
    assert_eq!(h.events.lock().unwrap()[0].ip, ip("203.0.113.0"));
}

#[tokio::test]
async fn event_user_agent_is_recorded() {
    let h = harness();
    login(&h, Uuid::new_v4()).await;
    assert_eq!(h.events.lock().unwrap()[0].user_agent.as_deref(), Some(CHROME_WIN));
}

#[test]
fn client_context_honours_only_trusted_proxies() {
    let config = GuardConfig::builder()
        .trusted_proxies(["10.0.0.0/8"])
        .unwrap()
        .build()
        .unwrap();
    let guard = Guard::builder(MemoryStore::new(), config).build();
    let headers = [
        ("X-Forwarded-For", "198.51.100.9, 10.0.0.2"),
        ("User-Agent", CHROME_WIN),
    ];
    let ctx = guard.client_context(ip("10.0.0.1"), &headers);
    assert_eq!(ctx.ip, ip("198.51.100.9"));
    assert_eq!(ctx.user_agent.as_deref(), Some(CHROME_WIN));
    assert_eq!(guard.client_context(ip("203.0.113.1"), &headers).ip, ip("203.0.113.1"));

    let plain = Guard::new(MemoryStore::new());
    assert_eq!(plain.client_context(ip("203.0.113.1"), &headers).ip, ip("203.0.113.1"));
}

/// Headers with raw byte values, which `&str` pairs cannot express.
struct RawHeaders(Vec<(&'static str, &'static [u8])>);

impl crate::HeaderSource for RawHeaders {
    fn header_values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a [u8]> + 'a {
        self.0
            .iter()
            .filter(move |(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| *v)
    }
}

#[test]
fn non_utf8_forwarded_for_falls_back_to_the_peer() {
    let config = GuardConfig::builder()
        .trusted_proxies(["10.0.0.0/8"])
        .unwrap()
        .build()
        .unwrap();
    let guard = Guard::builder(MemoryStore::new(), config).build();
    let headers = RawHeaders(vec![
        ("X-Forwarded-For", b"198.51.100.9"),
        ("X-Forwarded-For", b"203.0.113.\xff"),
    ]);
    assert_eq!(guard.client_context(ip("10.0.0.1"), &headers).ip, ip("10.0.0.1"));
}

#[test]
fn cookie_token_reads_the_configured_cookie() {
    let guard = Guard::new(MemoryStore::new());
    let headers = [("Cookie", "a=1; __Host-sid=abc"), ("Cookie", "b=2")];
    assert_eq!(guard.cookie_token(&headers), Some("abc"));
    assert_eq!(guard.cookie_token(&[("Cookie", "a=1")]), None);
    assert!(guard.clear_cookie().contains("Max-Age=0"));
}

#[tokio::test]
async fn requires_reauth_measures_from_last_verification() {
    let h = harness();
    let t0 = login(&h, Uuid::new_v4()).await;
    h.advance(mins(10));
    let a = authenticated(h.guard.authenticate(&t0, &home()).await.unwrap());
    assert!(h.guard.requires_reauth(&a.session, mins(5)));
    assert!(!h.guard.requires_reauth(&a.session, mins(15)));
}

#[tokio::test]
async fn authenticate_with_no_checks_ignores_fingerprint() {
    let h = harness();
    let t0 = login(&h, Uuid::new_v4()).await;
    let a = authenticated(
        h.guard
            .authenticate_with(&t0, &attacker(), &Checks::none())
            .await
            .unwrap(),
    );
    assert_eq!(a.assessment.signals, vec![]);
    // Not absorbed: the default checks still catch the other device.
    assert_eq!(
        rejected(h.guard.authenticate(&t0, &attacker()).await.unwrap()),
        Rejection::Revoked
    );
}

#[tokio::test]
async fn authenticate_with_learns_the_signals_it_scored() {
    let h = harness();
    let t0 = login(&h, Uuid::new_v4()).await;
    let german = || home().with_accept_language("de-DE");
    let a = authenticated(
        h.guard
            .authenticate_with(&t0, &german(), &Checks::default())
            .await
            .unwrap(),
    );
    assert_eq!(a.assessment.signals, vec![Check::AcceptLanguageChanged]);
    let a = authenticated(h.guard.authenticate(&t0, &german()).await.unwrap());
    assert_eq!(a.assessment.signals, vec![]);
}

#[tokio::test]
async fn authenticate_with_does_not_learn_unscored_signals() {
    let h = harness();
    let t0 = login(&h, Uuid::new_v4()).await;
    let german = || home().with_accept_language("de-DE");
    let lax = Checks::default().disable(Check::AcceptLanguageChanged);
    authenticated(h.guard.authenticate_with(&t0, &german(), &lax).await.unwrap());
    let a = authenticated(h.guard.authenticate(&t0, &german()).await.unwrap());
    assert_eq!(a.assessment.signals, vec![Check::AcceptLanguageChanged]);
}

#[tokio::test]
async fn custom_subject_type() {
    let h = harness_typed::<String>(GuardConfig::default());
    let new = h.guard.login(&"tenant-1/ann".to_owned(), &home(), None).await.unwrap();
    let a = authenticated(h.guard.authenticate(new.token.expose(), &home()).await.unwrap());
    assert_eq!(a.session.subject, "tenant-1/ann");
    assert_eq!(
        h.guard.list_sessions(&"tenant-1/ann".to_owned()).await.unwrap().len(),
        1
    );
}

#[tokio::test]
async fn undecodable_subject_is_not_authenticated() {
    let store = Arc::new(MemoryStore::new());
    let writer = Guard::builder(Arc::clone(&store), GuardConfig::default())
        .subject::<String>()
        .build();
    let reader = Guard::new(Arc::clone(&store));
    let new = writer.login(&"not-a-uuid".to_owned(), &home(), None).await.unwrap();
    assert_eq!(
        rejected(reader.authenticate(new.token.expose(), &home()).await.unwrap()),
        Rejection::NotAuthenticated
    );
}

#[tokio::test]
async fn concurrent_requests_with_one_token_rotate_once() {
    let h = harness();
    let t0 = login(&h, Uuid::new_v4()).await;
    h.advance(mins(11));
    let ctx = home();
    let (a, b) = tokio::join!(h.guard.authenticate(&t0, &ctx), h.guard.authenticate(&t0, &ctx));
    let rotated = [authenticated(a.unwrap()), authenticated(b.unwrap())]
        .into_iter()
        .filter(|a| a.rotated.is_some())
        .count();
    assert_eq!(rotated, 1);
}

// --- token prefix ---

fn prefixed() -> Harness {
    harness_with(GuardConfig::builder().token_prefix("sess_").build().unwrap())
}

#[tokio::test]
async fn prefixed_tokens_round_trip() {
    let h = prefixed();
    let user = Uuid::new_v4();
    let new = h.guard.login(&user, &home(), None).await.unwrap();
    let token = new.token.expose().to_owned();
    assert_eq!(token.len(), "sess_".len() + 43);
    assert!(token.starts_with("sess_"));
    assert!(new.token.set_cookie().starts_with(&format!("__Host-sid={token};")));
    assert!(h.guard.is_session_token(&token));
    assert_eq!(
        authenticated(h.guard.authenticate(&token, &home()).await.unwrap())
            .session
            .subject,
        user
    );
    assert!(h.guard.peek(&token).await.unwrap().is_some());

    // Rotation and step-up keep the prefix.
    h.advance(mins(11));
    let t1 = authenticated(h.guard.authenticate(&token, &home()).await.unwrap())
        .rotated
        .unwrap();
    assert!(t1.expose().starts_with("sess_"));
    h.advance(mins(1));
    assert_eq!(
        rejected(h.guard.authenticate(t1.expose(), &abroad()).await.unwrap()),
        Rejection::StepUpRequired
    );
    let StepUpOutcome::Completed(t2) = h.guard.complete_step_up(t1.expose(), &abroad(), &user).await.unwrap() else {
        panic!("step-up should complete");
    };
    assert!(t2.expose().starts_with("sess_"));
}

#[tokio::test]
async fn tokens_without_the_prefix_are_rejected() {
    let h = prefixed();
    let token = login(&h, Uuid::new_v4()).await;
    let bare = token.strip_prefix("sess_").unwrap();
    for other in [bare.to_owned(), format!("pat_{bare}"), format!("sess_sess_{bare}")] {
        assert!(!h.guard.is_session_token(&other));
        assert_eq!(
            rejected(h.guard.authenticate(&other, &home()).await.unwrap()),
            Rejection::NotAuthenticated
        );
        assert!(h.guard.peek(&other).await.unwrap().is_none());
        assert!(matches!(
            h.guard
                .complete_step_up(&other, &home(), &Uuid::new_v4())
                .await
                .unwrap(),
            StepUpOutcome::Rejected(Rejection::NotAuthenticated)
        ));
    }
    // Without a configured prefix, a prefixed value is not a token.
    let plain = harness();
    assert!(!plain.guard.is_session_token(&token));
    assert!(plain.guard.is_session_token(bare));
}
