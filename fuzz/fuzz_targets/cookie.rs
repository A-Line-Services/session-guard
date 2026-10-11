//! `Cookie` header parsing and token shape checks on arbitrary input.
#![no_main]

use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use session_guard::{CookieConfig, Guard, GuardConfig, MemoryStore, TOKEN_LEN, TokenHash, find_cookie, is_well_formed};

const PREFIX: &str = "sg_";

static GUARD: LazyLock<Guard<MemoryStore>> = LazyLock::new(|| {
    let config = GuardConfig::builder()
        .token_prefix(PREFIX)
        .build()
        .expect("valid config");
    Guard::builder(MemoryStore::new(), config).build()
});

/// Asserts `part` borrows from `whole`.
fn assert_slice_of(whole: &str, part: &str) {
    let start = (part.as_ptr() as usize).wrapping_sub(whole.as_ptr() as usize);
    assert!(
        start <= whole.len() && part.len() <= whole.len() - start,
        "{part:?} is not a slice of {whole:?}"
    );
}

fn check_token_shape(candidate: &str) {
    let well_formed = is_well_formed(candidate);
    let hash = TokenHash::from_presented(candidate);
    assert_eq!(hash.is_some(), well_formed);
    if well_formed {
        assert_eq!(candidate.len(), TOKEN_LEN);
        assert_eq!(hash, Some(TokenHash::of(candidate)));
        // A token we would issue survives a Set-Cookie / Cookie round trip.
        let cookie = CookieConfig::default();
        let set_cookie = cookie.set_cookie(candidate, 60);
        let pair = set_cookie.split(';').next().unwrap_or_default();
        assert_eq!(cookie.find_in(pair), Some(candidate));
    }
    let prefixed = candidate.strip_prefix(PREFIX).is_some_and(is_well_formed);
    assert_eq!(GUARD.is_session_token(candidate), prefixed);
}

fuzz_target!(|input: (&str, &str)| {
    let (header, name) = input;

    let found = find_cookie(header, name);
    if let Some(value) = found {
        assert_slice_of(header, value);
        assert!(!value.contains(';'));
    }
    assert_eq!(CookieConfig::named(name).find_in(header), found);

    let headers = [("cookie", header)];
    let from_guard = GUARD.cookie_token(&headers);
    assert_eq!(from_guard, CookieConfig::default().find_in(header));
    if let Some(value) = from_guard {
        assert_slice_of(header, value);
    }

    for candidate in [Some(header), Some(name), found, from_guard].into_iter().flatten() {
        check_token_shape(candidate);
    }
});
