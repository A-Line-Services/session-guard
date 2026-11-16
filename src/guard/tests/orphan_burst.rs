//! A lost rotation reply followed by a burst of parallel requests that all carry the orphan.

use super::*;

/// Same browser and network as [`home`], but without client hints (some handshakes, such as
/// WebSocket upgrades, may not send them).
fn home_without_hints() -> ClientContext {
    ClientContext::new(ip("203.0.113.9"))
        .with_user_agent(CHROME_WIN)
        .with_accept_language("en-US,en;q=0.9")
}

/// Home's network, another browser family.
fn home_network_other_browser() -> ClientContext {
    ClientContext::new(ip("203.0.113.7"))
        .with_user_agent(FIREFOX_LINUX)
        .with_accept_language("en-US,en;q=0.9")
}

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

#[tokio::test]
async fn second_presentation_of_an_orphan_within_the_grace_is_accepted() {
    let h = harness();
    let t0 = orphan(&h, Uuid::new_v4()).await;
    let reissued = authenticated(h.guard.authenticate(&t0, &home()).await.unwrap())
        .rotated
        .expect("first orphan presentation is reissued");

    // A parallel request with the same orphan, after the reissue.
    h.advance(secs(2));
    let a = authenticated(h.guard.authenticate(&t0, &home()).await.unwrap());
    assert!(a.rotated.is_none(), "at most one reissue per orphan");

    assert_eq!(h.count(EventKind::TokenReissued), 1);
    assert_eq!(h.count(EventKind::TokenReuse), 0);
    assert_eq!(h.store.session_count(), 1);
    authenticated(h.guard.authenticate(reissued.expose(), &home()).await.unwrap());
}

#[tokio::test]
async fn three_presentations_of_an_orphan_within_the_grace_are_all_accepted() {
    let h = harness();
    let t0 = orphan(&h, Uuid::new_v4()).await;
    let reissued = authenticated(h.guard.authenticate(&t0, &home()).await.unwrap())
        .rotated
        .unwrap();
    for _ in 0..2 {
        h.advance(secs(10));
        let a = authenticated(h.guard.authenticate(&t0, &home()).await.unwrap());
        assert!(a.rotated.is_none());
    }
    assert_eq!(h.count(EventKind::TokenReissued), 1);
    assert_eq!(h.count(EventKind::TokenReuse), 0);
    authenticated(h.guard.authenticate(reissued.expose(), &home()).await.unwrap());
}

#[tokio::test]
async fn concurrent_presentations_of_an_orphan_share_one_reissue() {
    let h = harness();
    let t0 = orphan(&h, Uuid::new_v4()).await;
    let ctx = home();
    let (a, b, c) = tokio::join!(
        h.guard.authenticate(&t0, &ctx),
        h.guard.authenticate(&t0, &ctx),
        h.guard.authenticate(&t0, &ctx),
    );
    let rotated = [a, b, c]
        .into_iter()
        .map(|outcome| authenticated(outcome.unwrap()).rotated)
        .filter(Option::is_some)
        .count();
    assert_eq!(rotated, 1);
    assert_eq!(h.count(EventKind::TokenReissued), 1);
    assert_eq!(h.count(EventKind::TokenReuse), 0);
    assert_eq!(h.store.session_count(), 1);
}

#[tokio::test]
async fn orphan_presented_after_the_reissue_grace_is_reuse() {
    let h = harness();
    let t0 = orphan(&h, Uuid::new_v4()).await;
    authenticated(h.guard.authenticate(&t0, &home()).await.unwrap());
    h.advance(secs(31));
    assert_eq!(
        rejected(h.guard.authenticate(&t0, &home()).await.unwrap()),
        Rejection::Revoked
    );
    assert_eq!(h.count(EventKind::TokenReuse), 1);
    assert_eq!(h.store.session_count(), 0);
}

#[tokio::test]
async fn orphan_replayed_from_another_network_within_the_grace_is_reuse() {
    let h = harness();
    let t0 = orphan(&h, Uuid::new_v4()).await;
    authenticated(h.guard.authenticate(&t0, &home()).await.unwrap());
    h.advance(secs(2));
    assert_eq!(
        rejected(h.guard.authenticate(&t0, &mobile()).await.unwrap()),
        Rejection::Revoked
    );
    assert_eq!(h.count(EventKind::TokenReuse), 1);
}

#[tokio::test]
async fn orphan_replayed_by_another_browser_within_the_grace_is_reuse() {
    let h = harness();
    let t0 = orphan(&h, Uuid::new_v4()).await;
    authenticated(h.guard.authenticate(&t0, &home()).await.unwrap());
    h.advance(secs(2));
    assert_eq!(
        rejected(h.guard.authenticate(&t0, &home_network_other_browser()).await.unwrap()),
        Rejection::Revoked
    );
    assert_eq!(h.count(EventKind::TokenReuse), 1);
}

#[tokio::test]
async fn older_token_replayed_within_a_reissue_grace_is_reuse() {
    let h = harness();
    let older = login(&h, Uuid::new_v4()).await;
    h.advance(mins(11));
    // `older` rotates normally and its successor is used, then that successor's reply is lost.
    let used = authenticated(h.guard.authenticate(&older, &home()).await.unwrap())
        .rotated
        .unwrap();
    authenticated(h.guard.authenticate(used.expose(), &home()).await.unwrap());
    h.advance(mins(11));
    let _lost = authenticated(h.guard.authenticate(used.expose(), &home()).await.unwrap())
        .rotated
        .unwrap();
    h.advance(mins(1));
    authenticated(h.guard.authenticate(used.expose(), &home()).await.unwrap())
        .rotated
        .expect("orphan reissued");

    h.advance(secs(2));
    assert_eq!(
        rejected(h.guard.authenticate(&older, &home()).await.unwrap()),
        Rejection::Revoked
    );
}

#[tokio::test]
async fn orphan_burst_without_client_hints_does_not_step_up() {
    let h = harness();
    let t0 = orphan(&h, Uuid::new_v4()).await;
    let reissued = authenticated(h.guard.authenticate(&t0, &home()).await.unwrap())
        .rotated
        .unwrap();
    h.advance(secs(1));
    authenticated(h.guard.authenticate(&t0, &home_without_hints()).await.unwrap());
    authenticated(h.guard.authenticate(reissued.expose(), &home_without_hints()).await.unwrap());
    assert_eq!(h.count(EventKind::StepUpRequired), 0);
}
