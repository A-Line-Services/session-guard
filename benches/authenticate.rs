//! Request-path benchmarks on the in-memory store. Run with `just bench`
//! (`cargo bench --features testing`).

use std::hint::black_box;
use std::time::{Duration, Instant};

use chrono::{DateTime, TimeDelta, Utc};
use criterion::{Criterion, criterion_group, criterion_main};
use session_guard::{
    __bench::CachedCapture, Baseline, Checks, ClientContext, Fingerprint, Guard, GuardConfig, IpInfo, ManualClock,
    MemoryStore, Outcome, TokenHash, assess,
};
use tokio::runtime::Runtime;
use uuid::Uuid;

const CHROME: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) \
                      Chrome/124.0.0.0 Safari/537.36";
const FIREFOX: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:125.0) Gecko/20100101 Firefox/125.0";

fn start() -> DateTime<Utc> {
    "2026-01-01T00:00:00Z".parse().unwrap()
}

fn ctx() -> ClientContext {
    ClientContext::new("203.0.113.7".parse().unwrap())
        .with_user_agent(CHROME)
        .with_ch_platform("\"Windows\"")
        .with_ch_mobile(false)
        .with_accept_language("en-GB,en;q=0.9,nl;q=0.8")
}

fn runtime() -> Runtime {
    tokio::runtime::Builder::new_current_thread().build().unwrap()
}

fn guard(clock: &ManualClock) -> Guard<MemoryStore> {
    Guard::builder(MemoryStore::new(), GuardConfig::default())
        .clock(clock.clone())
        .build()
}

fn authenticate(c: &mut Criterion) {
    let rt = runtime();
    let ctx = ctx();

    // Same client, same instant: no rotation and no `last_seen` write.
    let clock = ManualClock::new(start());
    let hot = guard(&clock);
    let token = rt
        .block_on(hot.login(&Uuid::new_v4(), &ctx, None))
        .unwrap()
        .token
        .expose()
        .to_owned();
    c.bench_function("authenticate/hot_path", |b| {
        b.to_async(&rt).iter(|| async {
            let outcome = hot.authenticate(black_box(&token), &ctx).await.unwrap();
            assert!(matches!(&outcome, Outcome::Authenticated(a) if a.rotated.is_none()));
            outcome
        });
    });

    // Each measured call finds a token past the rotation interval and rotates it.
    let clock = ManualClock::new(start());
    let rotating = guard(&clock);
    let interval = GuardConfig::default().rotation().interval + Duration::from_secs(1);
    c.bench_function("authenticate/rotation", |b| {
        b.to_async(&rt).iter_custom(|iters| {
            let (guard, clock, ctx) = (&rotating, &clock, &ctx);
            async move {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    clock.set(start());
                    let session = guard.login(&Uuid::new_v4(), ctx, None).await.unwrap();
                    clock.advance(interval);
                    let started = Instant::now();
                    let outcome = guard
                        .authenticate(black_box(session.token.expose()), ctx)
                        .await
                        .unwrap();
                    total += started.elapsed();
                    assert!(matches!(&outcome, Outcome::Authenticated(a) if a.rotated.is_some()));
                }
                total
            }
        });
    });

    let clock = ManualClock::new(start());
    let logins = guard(&clock);
    c.bench_function("login", |b| {
        b.to_async(&rt)
            .iter(|| async { logins.login(&Uuid::new_v4(), black_box(&ctx), None).await.unwrap() });
    });
}

fn risk(c: &mut Criterion) {
    let known = Fingerprint::capture(&ctx(), &IpInfo::new(Some("BE".into()), Some(5432)));
    let baseline = Baseline::new(known);
    let moved = ClientContext::new("198.51.100.20".parse().unwrap()).with_user_agent(FIREFOX);
    let current = Fingerprint::capture(&moved, &IpInfo::new(Some("NL".into()), Some(1136)));
    let checks = Checks::default();
    let window = TimeDelta::minutes(10);
    c.bench_function("risk/assess_changed", |b| {
        b.iter(|| assess(black_box(&baseline), black_box(&current), start(), window, &checks));
    });
}

fn user_agent(c: &mut Criterion) {
    let ctx = ctx();
    c.bench_function("user_agent/uncached", |b| {
        b.iter(|| Fingerprint::capture(black_box(&ctx), &IpInfo::default()));
    });
    let cache = CachedCapture::new(1024);
    c.bench_function("user_agent/cached", |b| {
        b.iter(|| cache.capture(black_box(&ctx), &IpInfo::default()));
    });
}

fn token_hash(c: &mut Criterion) {
    let token = "a".repeat(session_guard::TOKEN_LEN);
    c.bench_function("token_hash/of", |b| b.iter(|| TokenHash::of(black_box(&token))));
    c.bench_function("token_hash/from_presented", |b| {
        b.iter(|| TokenHash::from_presented(black_box(&token)));
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().measurement_time(Duration::from_secs(3)).warm_up_time(Duration::from_secs(1));
    targets = authenticate, risk, user_agent, token_hash
}
criterion_main!(benches);
