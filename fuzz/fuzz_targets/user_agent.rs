//! Header extraction, User-Agent parsing and fingerprint capture on arbitrary headers.
#![no_main]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::LazyLock;

use chrono::{DateTime, TimeDelta};
use libfuzzer_sys::fuzz_target;
use session_guard::{
    __bench::CachedCapture, Baseline, Check, Checks, ClientContext, Fingerprint, Guard, GuardConfig, IpInfo,
    MemoryStore, assess,
};

static GUARD: LazyLock<Guard<MemoryStore>> = LazyLock::new(|| {
    let config = GuardConfig::builder()
        .trusted_proxies(["10.0.0.0/8"])
        .expect("valid proxies")
        .build()
        .expect("valid config");
    Guard::builder(MemoryStore::new(), config).build()
});

static CACHE: LazyLock<CachedCapture> = LazyLock::new(|| CachedCapture::new(64));

type Input<'a> = (
    &'a str,
    Option<&'a str>,
    Option<&'a str>,
    Option<&'a str>,
    Option<&'a str>,
    [u8; 4],
);

fn check_fingerprint(ctx: &ClientContext) {
    let info = IpInfo::default();
    let fingerprint = Fingerprint::capture(ctx, info.clone());
    assert_eq!(CACHE.capture(ctx, info.clone()), fingerprint, "cache miss differs");
    assert_eq!(CACHE.capture(ctx, info), fingerprint, "cache hit differs");

    let now = DateTime::UNIX_EPOCH;
    let assessment = assess(
        &Baseline::new(fingerprint.clone()),
        &fingerprint,
        now,
        TimeDelta::minutes(10),
        &Checks::strict(),
    );
    // Only the point-in-time hint check may fire when nothing changed.
    assert!(
        assessment.signals.iter().all(|c| *c == Check::InconsistentHints),
        "identical request fired {:?}",
        assessment.signals
    );
    assert!(!Baseline::new(fingerprint.clone()).absorb(&fingerprint, now));

    let json = serde_json::to_string(&fingerprint).expect("serializes");
    assert_eq!(
        serde_json::from_str::<Fingerprint>(&json).expect("deserializes"),
        fingerprint
    );
}

fuzz_target!(|input: Input<'_>| {
    let (ua, platform, mobile, language, xff, peer) = input;
    let max_len = GuardConfig::default().max_header_len();

    let mut headers = vec![("user-agent", ua)];
    let optional = [
        ("sec-ch-ua-platform", platform),
        ("sec-ch-ua-mobile", mobile),
        ("accept-language", language),
        ("x-forwarded-for", xff),
    ];
    headers.extend(optional.into_iter().filter_map(|(name, value)| Some((name, value?))));
    let ctx = GUARD.client_context(IpAddr::V4(Ipv4Addr::from(peer)), &headers);
    for value in [&ctx.user_agent, &ctx.ch_platform, &ctx.accept_language]
        .into_iter()
        .flatten()
    {
        assert!(!value.is_empty() && value.len() <= max_len, "{value:?}");
    }
    check_fingerprint(&ctx);

    let mut direct = ClientContext::new(IpAddr::V4(Ipv4Addr::from(peer))).with_user_agent(ua);
    if let Some(platform) = platform {
        direct = direct.with_ch_platform(platform);
    }
    if let Some(language) = language {
        direct = direct.with_accept_language(language);
    }
    direct = direct.with_ch_mobile(mobile.is_some());
    check_fingerprint(&direct);
});
