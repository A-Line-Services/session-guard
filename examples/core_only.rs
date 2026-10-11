//! session-guard without any web framework.
//!
//! The core crate only needs a [`ClientContext`] (who is calling) and a token (the cookie
//! value). This example plays a browser and an attacker against an in-memory store with a manual
//! clock, so ten minutes pass instantly, and prints what the guard decides at each step.
//!
//! ```text
//! cargo run --example core_only
//! ```

use std::{net::IpAddr, time::Duration};

use chrono::{TimeZone, Utc};
use session_guard::{
    ClientContext, Guard, GuardConfig, IpInfo, ManualClock, MemoryStore, Outcome, Rejection, SessionEvent,
    StepUpOutcome,
};
use uuid::Uuid;

const CHROME_WINDOWS: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";

/// Prints what an `Outcome` means for the app's response.
fn describe(outcome: &Outcome<Uuid>) -> String {
    match outcome {
        Outcome::Authenticated(auth) if auth.rotated.is_some() => {
            "authenticated, send the rotated token as a new cookie".to_owned()
        }
        Outcome::Authenticated(_) => "authenticated".to_owned(),
        Outcome::Rejected(rejection) => format!("rejected: 401 {}", rejection.as_str()),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // A manual clock lets the example skip time. Production code uses the default system clock.
    let clock = ManualClock::new(Utc.with_ymd_and_hms(2026, 3, 1, 12, 0, 0).unwrap());

    let guard = Guard::builder(MemoryStore::new(), GuardConfig::builder().build()?)
        // Country lookup, so that changing country is a risk signal. Use `MaxMindIntel` in
        // production (feature `maxmind`).
        .ip_intel(|ip: IpAddr| {
            let country = if ip.to_string().starts_with("198.51.100.") {
                "DE"
            } else {
                "US"
            };
            IpInfo::new(Some(country.into()), None)
        })
        // Every security decision arrives here: log it, count it, or ship it to a SIEM.
        .on_event(|event: &SessionEvent| {
            println!("    event: {} (enforced: {})", event.kind.as_str(), event.enforced);
        })
        .clock(clock.clone())
        .build();

    // What your web framework would build from each request.
    let home = ClientContext::new("203.0.113.7".parse()?).with_user_agent(CHROME_WINDOWS);
    let abroad = ClientContext::new("198.51.100.20".parse()?).with_user_agent(CHROME_WINDOWS);

    // The app verified the password (the crate does not), so the user is known.
    let user = Uuid::new_v4();

    println!("1. Login");
    let session = guard.login(&user, &home, None).await?;
    let first = session.token.expose().to_owned();
    println!(
        "   session {} created, cookie header: {}",
        session.session_id,
        session.token.set_cookie()
    );

    println!("2. Request right after login");
    let outcome = guard.authenticate(&first, &home).await?;
    println!("   {}", describe(&outcome));
    assert!(matches!(&outcome, Outcome::Authenticated(a) if a.rotated.is_none()));

    println!("3. Request 11 minutes later (tokens rotate every 10)");
    clock.advance(Duration::from_mins(11));
    let Outcome::Authenticated(auth) = guard.authenticate(&first, &home).await? else {
        return Err("expected the session to survive".into());
    };
    let second = auth.rotated.ok_or("expected a rotated token")?.expose().to_owned();
    println!("   authenticated, rotated to a new token; the old one is superseded");

    println!("4. The browser uses the new token, then an attacker replays the copied old one");
    let outcome = guard.authenticate(&second, &home).await?;
    println!("   browser: {}", describe(&outcome));
    assert!(matches!(outcome, Outcome::Authenticated(_)));
    clock.advance(Duration::from_mins(1)); // past the 30 second grace window
    let outcome = guard.authenticate(&first, &abroad).await?;
    println!("   attacker: {}", describe(&outcome));
    assert!(matches!(outcome, Outcome::Rejected(Rejection::Revoked)));
    let outcome = guard.authenticate(&second, &home).await?;
    println!("   browser again: {} (the whole session is gone)", describe(&outcome));
    assert!(matches!(
        outcome,
        Outcome::Rejected(Rejection::NotAuthenticated | Rejection::Revoked)
    ));

    println!("5. Log in again, then the same cookie shows up from another country");
    let session = guard.login(&user, &home, None).await?;
    let token = session.token.expose().to_owned();
    let outcome = guard.authenticate(&token, &abroad).await?;
    println!("   {}", describe(&outcome));
    assert!(matches!(outcome, Outcome::Rejected(Rejection::StepUpRequired)));

    println!("6. The app re-verifies the user (password, passkey, MFA), then completes the step-up");
    // `user` is whoever the app just re-verified. A different subject is refused.
    let StepUpOutcome::Completed(fresh) = guard.complete_step_up(&token, &abroad, &user).await? else {
        return Err("expected the step-up to complete".into());
    };
    println!("   completed, new cookie header: {}", fresh.set_cookie());
    let outcome = guard.authenticate(fresh.expose(), &abroad).await?;
    println!("   {}", describe(&outcome));
    assert!(matches!(outcome, Outcome::Authenticated(_)));

    println!("7. Logout");
    guard.logout(fresh.expose(), &abroad).await?;
    let outcome = guard.authenticate(fresh.expose(), &abroad).await?;
    println!("   {}", describe(&outcome));
    assert!(matches!(
        outcome,
        Outcome::Rejected(Rejection::NotAuthenticated | Rejection::Revoked)
    ));

    Ok(())
}
