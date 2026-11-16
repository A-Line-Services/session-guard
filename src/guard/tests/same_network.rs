//! Requests from the sign-in's own network prefix and browser family: header gaps that some
//! request types have (no client hints on fetch, WebSocket or `EventSource`, no Accept-Language)
//! must not step up on their own.

use super::*;

const SIGN_IN_V6: &str = "2001:db8:1:2::7";

/// Chrome on Windows, signed in over IPv6 with every header.
fn v6_home() -> ClientContext {
    ClientContext::new(ip(SIGN_IN_V6))
        .with_user_agent(CHROME_WIN)
        .with_ch_platform("\"Windows\"")
        .with_ch_mobile(false)
        .with_accept_language("en-US,en;q=0.9")
}

/// The same browser on another /64 inside the sign-in's /48.
fn v6_other_subnet() -> ClientContext {
    ClientContext::new(ip("2001:db8:1:3::9"))
        .with_user_agent(CHROME_WIN)
        .with_ch_platform("\"Windows\"")
        .with_ch_mobile(false)
        .with_accept_language("en-US,en;q=0.9")
}

/// Same browser and network, no client hints.
fn v6_without_hints() -> ClientContext {
    ClientContext::new(ip(SIGN_IN_V6))
        .with_user_agent(CHROME_WIN)
        .with_accept_language("en-US,en;q=0.9")
}

/// Same browser and network, no client hints and no Accept-Language.
fn v6_bare() -> ClientContext {
    ClientContext::new(ip(SIGN_IN_V6)).with_user_agent(CHROME_WIN)
}

/// Same browser, another /48 (and so another network) without hints or language.
fn v6_elsewhere_bare() -> ClientContext {
    ClientContext::new(ip("2001:db8:2::7")).with_user_agent(CHROME_WIN)
}

async fn v6_login(h: &Harness, user: Uuid) -> String {
    h.guard
        .login(&user, &v6_home(), None)
        .await
        .unwrap()
        .token
        .expose()
        .to_owned()
}

/// Logs in over IPv6 and loses the first rotation reply: the token is orphaned.
async fn v6_orphan(h: &Harness, user: Uuid) -> String {
    let t0 = v6_login(h, user).await;
    h.advance(mins(11));
    let _lost = authenticated(h.guard.authenticate(&t0, &v6_home()).await.unwrap())
        .rotated
        .unwrap();
    h.advance(mins(1));
    t0
}

#[tokio::test]
async fn another_subnet_inside_the_sign_in_prefix_scores_nothing() {
    let h = harness();
    let t0 = v6_login(&h, Uuid::new_v4()).await;
    let a = authenticated(h.guard.authenticate(&t0, &v6_other_subnet()).await.unwrap());
    assert_eq!((a.assessment.score, a.assessment.signals), (0, vec![]));
}

#[tokio::test]
async fn missing_client_hints_on_the_same_network_do_not_step_up() {
    let h = harness();
    let t0 = v6_login(&h, Uuid::new_v4()).await;
    let a = authenticated(h.guard.authenticate(&t0, &v6_without_hints()).await.unwrap());
    assert_eq!((a.assessment.score, a.assessment.signals), (0, vec![]));
}

#[tokio::test]
async fn missing_hints_and_language_on_the_same_network_do_not_step_up() {
    let h = harness();
    let t0 = v6_login(&h, Uuid::new_v4()).await;
    let a = authenticated(h.guard.authenticate(&t0, &v6_bare()).await.unwrap());
    assert_eq!((a.assessment.score, a.assessment.signals), (0, vec![]));
    assert_eq!(h.count(EventKind::StepUpRequired), 0);
}

#[tokio::test]
async fn missing_headers_still_count_on_another_network() {
    let h = harness();
    let t0 = v6_login(&h, Uuid::new_v4()).await;
    assert_eq!(
        rejected(h.guard.authenticate(&t0, &v6_elsewhere_bare()).await.unwrap()),
        Rejection::StepUpRequired
    );
    let event = h.events.lock().unwrap().last().cloned().unwrap();
    assert_eq!(
        event.signals,
        vec![
            Check::ClientHintsMissing,
            Check::AcceptLanguageChanged,
            Check::IpPrefixChanged
        ]
    );
}

#[tokio::test]
async fn an_orphan_presented_without_hints_is_reissued_without_step_up() {
    let h = harness();
    let t0 = v6_orphan(&h, Uuid::new_v4()).await;
    let a = authenticated(h.guard.authenticate(&t0, &v6_without_hints()).await.unwrap());
    assert!(a.rotated.is_some());
    assert_eq!(
        (a.assessment.score, a.assessment.signals),
        (25, vec![Check::OrphanedToken])
    );
    assert_eq!(h.count(EventKind::StepUpRequired), 0);
}

#[tokio::test]
async fn bare_requests_after_an_orphan_reissue_do_not_step_up() {
    let h = harness();
    let t0 = v6_orphan(&h, Uuid::new_v4()).await;
    let reissued = authenticated(h.guard.authenticate(&t0, &v6_bare()).await.unwrap())
        .rotated
        .unwrap();
    h.advance(Duration::from_secs(1));
    authenticated(h.guard.authenticate(&t0, &v6_bare()).await.unwrap());
    authenticated(h.guard.authenticate(reissued.expose(), &v6_bare()).await.unwrap());
    assert_eq!(h.count(EventKind::StepUpRequired), 0);
}

#[tokio::test]
async fn a_passed_step_up_is_remembered_for_the_same_signals() {
    let h = harness();
    let user = Uuid::new_v4();
    let t0 = login(&h, user).await;
    assert_eq!(
        rejected(h.guard.authenticate(&t0, &abroad()).await.unwrap()),
        Rejection::StepUpRequired
    );
    let StepUpOutcome::Completed(t1) = h.guard.complete_step_up(&t0, &abroad(), &user).await.unwrap() else {
        panic!("step-up completes");
    };
    let mut token = t1.expose().to_owned();
    // Later requests with the same signals, across rotations: never another prompt.
    for _ in 0..3 {
        h.advance(mins(11));
        let a = authenticated(h.guard.authenticate(&token, &abroad()).await.unwrap());
        assert_eq!(a.assessment.score, 0);
        token = a.rotated.expect("rotated").expose().to_owned();
    }
    // A hint-less request from the confirmed network neither.
    let bare = ClientContext::new(ip("198.51.100.20")).with_user_agent(CHROME_WIN);
    let a = authenticated(h.guard.authenticate(&token, &bare).await.unwrap());
    assert_eq!(a.assessment.score, 0);
    assert_eq!(h.count(EventKind::StepUpRequired), 1);
}
