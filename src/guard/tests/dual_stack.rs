//! A dual-stack browser: happy eyeballs lands page loads, fetches and WebSocket connections on IPv4 or
//! IPv6 at random, so one session alternates between a v4 /24 and a v6 /48 within seconds.
//! Each family's network must be remembered on its own, and ping-pong only counts within a
//! family.

use super::*;

const V6: &str = "2001:db8:1:2::7";
const V4: &str = "192.0.2.10";
const OTHER_V4: &str = "203.0.113.10";

fn full(addr: &str) -> ClientContext {
    ClientContext::new(ip(addr))
        .with_user_agent(CHROME_WIN)
        .with_ch_platform("\"Windows\"")
        .with_ch_mobile(false)
        .with_accept_language("en-US,en;q=0.9")
}

/// No client hints and no Accept-Language, as on a WebSocket upgrade.
fn bare(addr: &str) -> ClientContext {
    ClientContext::new(ip(addr)).with_user_agent(CHROME_WIN)
}

async fn v6_login(h: &Harness, user: Uuid) -> String {
    h.guard.login(&user, &full(V6), None).await.unwrap().token.expose().to_owned()
}

/// Authenticates, follows a rotation and returns the score and signals.
async fn request(h: &Harness, token: &mut String, ctx: &ClientContext) -> (u32, Vec<Check>) {
    let a = authenticated(h.guard.authenticate(token, ctx).await.unwrap());
    if let Some(next) = a.rotated {
        *token = next.expose().to_owned();
    }
    (a.assessment.score, a.assessment.signals)
}

#[tokio::test]
async fn the_first_request_from_the_other_family_scores_a_prefix_change() {
    let h = harness();
    let mut token = v6_login(&h, Uuid::new_v4()).await;
    h.advance(Duration::from_secs(5));
    assert_eq!(request(&h, &mut token, &full(V4)).await, (10, vec![Check::IpPrefixChanged]));
}

#[tokio::test]
async fn alternating_families_never_ping_pong_or_step_up() {
    let h = harness();
    let mut token = v6_login(&h, Uuid::new_v4()).await;
    h.advance(Duration::from_secs(5));
    request(&h, &mut token, &full(V4)).await;
    for round in 0..10 {
        for addr in [V6, V4] {
            h.advance(Duration::from_secs(30));
            let ctx = if round % 2 == 0 { full(addr) } else { bare(addr) };
            assert_eq!(request(&h, &mut token, &ctx).await, (0, vec![]), "round {round} from {addr}");
        }
    }
    assert_eq!(h.count(EventKind::StepUpRequired), 0);
}

#[tokio::test]
async fn a_new_network_within_a_family_still_scores_and_ping_pongs() {
    let h = harness();
    let mut token = v6_login(&h, Uuid::new_v4()).await;
    h.advance(Duration::from_secs(5));
    request(&h, &mut token, &full(V4)).await;
    h.advance(Duration::from_secs(30));
    assert_eq!(request(&h, &mut token, &full(OTHER_V4)).await, (10, vec![Check::IpPrefixChanged]));
    h.advance(Duration::from_secs(30));
    assert_eq!(request(&h, &mut token, &full(V6)).await, (0, vec![]));
    h.advance(Duration::from_secs(30));
    let (_, signals) = request(&h, &mut token, &full(V4)).await;
    assert_eq!(signals, vec![Check::IpPingPong, Check::IpPrefixChanged]);
}

#[tokio::test]
async fn a_completed_step_up_keeps_the_other_family_known() {
    let h = harness();
    let user = Uuid::new_v4();
    let mut token = v6_login(&h, user).await;
    h.advance(Duration::from_secs(5));
    request(&h, &mut token, &full(V4)).await;
    h.advance(Duration::from_secs(30));
    let StepUpOutcome::Completed(next) = h.guard.complete_step_up(&token, &full(V6), &user).await.unwrap() else {
        panic!("step-up completes");
    };
    let mut token = next.expose().to_owned();
    h.advance(Duration::from_secs(30));
    assert_eq!(request(&h, &mut token, &bare(V4)).await, (0, vec![]));
}
