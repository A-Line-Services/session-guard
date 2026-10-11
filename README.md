# session-guard

[![crates.io](https://img.shields.io/crates/v/session-guard.svg)](https://crates.io/crates/session-guard)
[![docs.rs](https://docs.rs/session-guard/badge.svg)](https://docs.rs/session-guard)
[![CI](https://github.com/A-Line-Services/session-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/A-Line-Services/session-guard/actions/workflows/ci.yml)
[![License](https://img.shields.io/crates/l/session-guard.svg)](#license)
[![MSRV](https://img.shields.io/badge/MSRV-1.94-blue.svg)](#msrv)

Stolen session cookies become useless: rotating tokens with reuse detection and risk-based step-up for Rust web apps.

session-guard issues opaque session tokens, stores only their SHA-256 hashes and rotates them every few minutes.
A superseded token that comes back after its successor was used is the signature of a copied cookie, and revokes the session.
Every request is also scored against the session's client fingerprint; a moderate change asks the app to re-verify the user, a drastic one revokes.

## How it works

**Tokens.** A token is 32 random bytes from the OS RNG, encoded as unpadded base64url: 43 characters, plus the optional configured prefix.
Only the SHA-256 hash is stored and compared (in constant time). Malformed tokens are rejected before the store is touched.

**Rotation.** A request whose current token is older than 10 minutes gets a new token in a `Set-Cookie`.
The old token stays valid for a 30 second grace period, so parallel requests do not fail.
Rotation is race-safe: the store applies it atomically, and when two requests present the same token only the winner receives the new one.

**Superseded tokens.** A token that was already replaced is classified as follows.

| Outcome | When | Result |
| --- | --- | --- |
| Grace | Superseded less than the grace period ago | Accepted |
| Orphaned | Superseded, and its successor was never presented (the reply was probably lost) | A fresh token is issued once, a `token_reissued` event is recorded; presenting it again counts as reuse |
| Reuse | Superseded, and its successor was presented | Session revoked, a `token_reuse` event is recorded, `Rejection::Revoked` |

Reuse is always enforced, even in shadow mode.

**Risk scoring.** Each request is compared to the session's baseline. Every check that fires adds its weight to the score.

| Check | Weight | Fires when |
| --- | --- | --- |
| `os_changed` | 80 | OS family changed |
| `browser_changed` | 80 | Browser family changed |
| `platform_hint_changed` | 80 | `Sec-CH-UA-Platform` changed to an incompatible platform |
| `inconsistent_hints` | 60 | Platform hint contradicts the User-Agent's OS |
| `browser_downgraded` | 50 | Same browser, lower major version |
| `user_agent_missing` | 50 | User-Agent disappeared or lost its known browser or OS |
| `mobile_hint_changed` | 50 | `Sec-CH-UA-Mobile` flipped |
| `country_changed` | 40 | IP moved to another country (needs an `IpIntel` source) |
| `client_hints_missing` | 30 | Hints the session used to send disappeared |
| `tls_changed` | 30 | TLS fingerprint changed while the browser major version stayed the same |
| `ip_ping_pong` | 25 | Returned to the previous network within 5 minutes of leaving it |
| `asn_changed` | 20 | IP moved to another autonomous system (needs an `IpIntel` source) |
| `accept_language_changed` | 15 | Preferred languages changed |
| `ip_prefix_changed` | 10 | IP left its /24 (IPv4) or /48 (IPv6) |

On an IP change exactly one of country, ASN or prefix fires (in that order); ping-pong can fire in addition.
Android and Linux, and iOS and macOS, count as compatible operating systems.
Missing data never bypasses a check: a value the baseline knows but the request lacks counts as a change.

Thresholds: a score below 40 is allowed, 40 to 79 requires step-up, 80 or more revokes the session.

**Baseline.** The browser, OS and client hints are fixed at login or step-up. The baseline only learns soft signals (network, country, ASN, languages, TLS, browser version), only those scored by the checks in use for that request (weight above zero), and only when the request was allowed.
Completing a step-up resets the baseline to the current client.

**Step-up policy.** `StepUpPolicy` decides what a step-up score does.

| Policy | Effect |
| --- | --- |
| `Require` (default) | Requests are rejected with `step_up_required` until the app calls `complete_step_up` |
| `Revoke` | A step-up score is treated as a revoke |
| `Allow` | The request passes and an unenforced `step_up_required` event is recorded |

**Shadow mode.** `Mode::Shadow` records every decision as an event with `enforced = false` and lets the request pass, so you can measure before enforcing. Reuse detection stays enforced.
With several instances, unenforced events are deduplicated per session and kind, in process and through `SessionStore::claim_event` (window `shadow_dedup_window`, 10 minutes by default).

## Quick start (axum and Postgres)

```toml
[dependencies]
session-guard = { version = "0.1", features = ["axum", "postgres"] }
```

```rust,no_run
use std::net::SocketAddr;

use axum::{
    Router,
    extract::{Request, State},
    http::{StatusCode, header},
    response::IntoResponse,
    routing::{get, post},
};
use session_guard::{AuthSession, Guard, PgStore};

type AppGuard = Guard<PgStore>;

async fn me(session: AuthSession<uuid::Uuid>) -> String {
    format!("session {} for {}", session.session_id, session.subject)
}

// Your own handler: verify the password and rate limit first, then ask the guard for a session.
async fn login(State(guard): State<AppGuard>, request: Request) -> Result<impl IntoResponse, StatusCode> {
    let (parts, _body) = request.into_parts();
    let ctx = session_guard::axum::client_context(&guard, &parts).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let user = uuid::Uuid::new_v4(); // the verified user id
    let previous = guard.cookie_token(&parts.headers); // revokes the old session (fixation defence)
    let session = guard
        .login(&user, &ctx, previous.as_deref())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(([(header::SET_COOKIE, session.token.set_cookie().to_owned())], "welcome"))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pool = sqlx::PgPool::connect("postgres://localhost/app").await?;
    let guard = Guard::new(PgStore::migrated(pool).await?);

    let app = Router::new()
        .route("/me", get(me))
        .layer(guard.layer())
        .route("/login", post(login))
        .with_state(guard);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    // The layer needs the peer address.
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
    Ok(())
}
```

`Guard::new` uses `GuardConfig::default()`. Use `Guard::builder(store, config)` to change the config, set a custom subject type (`.subject::<T>()`), an `IpIntel` source, an event hook (`.on_event`) or a clock.
`PgStore::migrated` runs the embedded migrations and is safe to call from many processes. To run them in your own pipeline, use `PgStore::migrator()` and `PgStore::new(pool)` instead.
Without `ConnectInfo<SocketAddr>` the layer fails closed with a 500.

Without a framework, call the guard directly:

```rust
# async fn demo() -> Result<(), session_guard::GuardError> {
use session_guard::{ClientContext, Guard, MemoryStore, Outcome};

let guard = Guard::new(MemoryStore::new());
let ctx = ClientContext::new("203.0.113.7".parse().unwrap()).with_user_agent("Mozilla/5.0");
let user = uuid::Uuid::new_v4();

let session = guard.login(&user, &ctx, None).await?;
match guard.authenticate(session.token.expose(), &ctx).await? {
    Outcome::Authenticated(auth) => {
        assert_eq!(auth.session.subject, user);
        // send `auth.rotated` as Set-Cookie when present
    }
    Outcome::Rejected(rejection) => {
        // answer 401 with {"error": rejection.as_str()}
        # let _ = rejection;
    }
}
# Ok(())
# }
```

Complete examples: [`examples/axum_postgres.rs`](examples/axum_postgres.rs), [`examples/axum_valkey.rs`](examples/axum_valkey.rs), [`examples/core_only.rs`](examples/core_only.rs).

## Feature flags

| Feature | Enables |
| --- | --- |
| `axum` | Tower layer (`Guard::layer`) and the `AuthSession` extractor for axum 0.8 |
| `postgres` | `PgStore` on sqlx, with embedded migrations |
| `valkey` | `ValkeyStore` for Valkey or Redis, with atomic Lua rotation (a single primary; Cluster mode is not supported) |
| `maxmind` | `MaxMindIntel`: country and ASN from GeoLite2 / GeoIP2 databases |
| `metrics` | Counters through the `metrics` facade |
| `testing` | The `store_conformance!` suite and helpers for custom stores |

No feature is enabled by default. `MemoryStore` is always available and meant for tests.

## Scope

session-guard manages sessions only. Your app owns login, password verification, rate limiting, session caps and any per-session payload.
The subject is a generic opaque type `S: Subject` (anything serializable, comparable and cloneable; `Uuid` by default). It is stored as JSON, so use a deterministic serialization (no `HashMap`).
There are no auth routes. A tower-sessions adapter and Valkey Cluster support are future work.

**Your app MUST rate-limit its login and step-up endpoints.** The guard does not.

## The 401 contract

When a request is rejected the layer answers `401` with `Content-Type: application/json`, `Cache-Control: no-store` and one of these bodies.

| `Rejection` | Body | Cookie | Meaning |
| --- | --- | --- | --- |
| `NotAuthenticated` | `{"error":"not_authenticated"}` | Cleared | No cookie, unknown token or token not accepted |
| `Expired` | `{"error":"session_expired"}` | Cleared | Absolute or idle lifetime exceeded |
| `Revoked` | `{"error":"session_revoked"}` | Cleared, plus `Clear-Site-Data: "cookies"` | Token reuse or risk revocation |
| `StepUpRequired` | `{"error":"step_up_required"}` | Kept | The user must re-verify, then the app calls `complete_step_up` |

Store failures answer `500` with `{"error":"internal"}`.
Successful responses carry `Cache-Control: no-store` too, and a `Set-Cookie` when the token rotated.

A frontend should treat `step_up_required` as "show the re-verification prompt, then retry" and every other code as "signed out: go to login".

After the user re-verified, complete the step-up with the verified subject. A subject mismatch changes nothing.

```rust,no_run
# use session_guard::{ClientContext, Guard, MemoryStore, StepUpOutcome};
# async fn demo(guard: Guard<MemoryStore>, token: &str, ctx: ClientContext, user: uuid::Uuid) -> Result<(), session_guard::GuardError> {
match guard.complete_step_up(token, &ctx, &user).await? {
    StepUpOutcome::Completed(new_token) => { /* send new_token.set_cookie() */ let _ = new_token; }
    StepUpOutcome::SubjectMismatch | StepUpOutcome::Rejected(_) => { /* 401 */ }
}
# Ok(())
# }
```

`complete_step_up` trusts the subject you pass, so call it only after your own verification succeeded. A session waiting for step-up keeps aging: if the idle timeout passes first, it expires and the user logs in again.

To demand a recent proof of identity on sensitive routes, use `guard.layer().require_recent_auth(Duration::from_secs(300))`; older sessions get `step_up_required` with the cookie kept.

## Cookie format

The default cookie is `__Host-sid`: `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/`, no `Domain`, and `Max-Age` taken from the session's remaining lifetime on the guard's clock.

```rust
use session_guard::CookieConfig;

let line = CookieConfig::default().set_cookie("TOKEN", 2_592_000);
assert_eq!(line, "__Host-sid=TOKEN; Path=/; Max-Age=2592000; HttpOnly; Secure; SameSite=Lax");
```

Customise with `CookieConfig`:

```rust
use session_guard::{CookieConfig, GuardConfig, SameSite};

let config = GuardConfig::builder()
    .cookie(CookieConfig::named("__Secure-app").same_site(SameSite::Strict).path("/app"))
    .build()
    .unwrap();
# let _ = config;
```

`build()` validates the cookie: the name must be a valid HTTP token, the path must start with `/` and contain no `;`, the domain must not be empty or contain `;`, `__Host-` requires `Secure`, no `Domain` and `Path=/`, `__Secure-` requires `Secure`, and `SameSite=None` requires `Secure`.
`persistent(false)` omits `Max-Age` (a session cookie).

## Token prefixes and API keys

A prefix makes tokens recognisable in logs and secret scanners. Tokens without it are rejected before the store is hit.

```rust
use session_guard::GuardConfig;

let config = GuardConfig::builder().token_prefix("sess_").build().unwrap();
assert_eq!(config.token_prefix(), Some("sess_"));
```

If the same endpoints also accept API keys, tell the layer which requests to leave alone. Bypassed requests reach the inner service untouched (no `AuthSession`, no headers added) and your app authenticates them.

```rust,no_run
# use session_guard::{Guard, MemoryStore};
# let guard = Guard::new(MemoryStore::new());
let layer = guard
    .layer()
    .bypass_bearer_prefixes(["pat_", "svc_"])
    .bypass_when(|headers| headers.contains_key("x-api-key"));
# let _ = layer;
```

## Reverse proxies

Behind a proxy the peer address is the proxy. List your proxies so the guard can read the client address from `X-Forwarded-For`.

```rust
use session_guard::GuardConfig;

let config = GuardConfig::builder()
    .trusted_proxies(["10.0.0.0/8", "192.168.1.5"])
    .unwrap()
    .tls_fingerprint_header("X-TLS-Fingerprint")
    .max_header_len(512)
    .build()
    .unwrap();
# let _ = config;
```

`X-Forwarded-For` is honoured only when the direct peer is a trusted proxy. The chain is walked right to left, skipping trusted hops; the first untrusted address is the client. A malformed hop stops the walk and falls back to the peer.
If `X-Forwarded-For` arrives while no trusted proxies are configured, a warning is logged once.
Header values are read from the first occurrence, trimmed and truncated to `max_header_len` (default 512).

Make the edge proxy overwrite the header rather than trust the client's.

```nginx
# nginx, directly facing clients
proxy_set_header X-Forwarded-For $remote_addr;
# the TLS fingerprint comes from your fingerprinting module; this overwrites any client value
proxy_set_header X-TLS-Fingerprint $your_tls_fingerprint_variable;
```

```caddyfile
# Caddy: reverse_proxy replaces X-Forwarded-For from untrusted clients by default
example.com {
    reverse_proxy 127.0.0.1:3000
}
```

```yaml
# Traefik static configuration: only trust forwarded headers from your own load balancer
entryPoints:
  websecure:
    address: ":443"
    forwardedHeaders:
      trustedIPs: ["10.0.0.0/8"]
```

`tls_fingerprint_header` names a header set by your TLS terminator. The value is opaque; a change while the browser version is the same fires `tls_changed`.

## Threat model

Defended:

- Cookie theft (an infostealer, or XSS exfiltration) with the cookie replayed from another machine: rotation, reuse detection and client fingerprint checks.
- Session fixation: `login` revokes the session presented with the request.

Not defended:

- An attacker on the same device or browser.
- Real-time proxying through the victim's browser.
- XSS acting inside the victim's page.

**Orphan reissue.** If a superseded token's successor was never presented, the guard assumes the response was lost and rotates again instead of revoking. This gives the presenter a fresh token without proof that it is the legitimate client, so a thief who replays an orphaned token first gets a working session. The fingerprint checks still apply to that request. Each orphan is reissued only once: the fresh token counts as used from the start, so presenting the orphan again is reuse and revokes the session. A client that loses two rotation responses in a row is logged out.

### CSRF

`SameSite=Lax` is not full CSRF protection. Use CSRF tokens or `Origin` checks on state-changing requests.

## Tuning

```rust
use std::time::Duration;

use session_guard::{Check, Checks, GuardConfig, Mode, RotationConfig, Thresholds};

let config = GuardConfig::builder()
    .mode(Mode::Shadow)
    .checks(Checks::default().weight(Check::AsnChanged, 40).disable(Check::AcceptLanguageChanged))
    .thresholds(Thresholds { step_up: 40, revoke: 80 })
    .rotation(RotationConfig {
        interval: Duration::from_secs(300),
        grace: Duration::from_secs(20),
        reuse_detection: Duration::from_secs(7 * 24 * 3600),
    })
    .session_lifetime(Duration::from_secs(14 * 24 * 3600))
    .idle_timeout(Duration::from_secs(3 * 24 * 3600))
    .last_seen_write_interval(Duration::from_secs(60))
    .build()
    .unwrap();
# let _ = config;
```

Presets: `Checks::default()`, `Checks::none()` (only rotation and reuse detection) and `Checks::strict()` (IP prefix, ASN, language, TLS and ping-pong at 40, country change at 80).
Apply a different set per route with `guard.layer().with(Checks::strict())`.

| Setting | Default |
| --- | --- |
| `session_lifetime` | 30 days |
| `idle_timeout` | 7 days |
| `rotation.interval` / `grace` / `reuse_detection` | 10 minutes / 30 seconds / 7 days |
| `ping_pong_window` | 5 minutes (zero disables) |
| `last_seen_write_interval` | 60 seconds (zero writes on every request) |
| `thresholds` | step-up 40, revoke 80 |

`grace` must be shorter than `interval`. `last_seen_write_interval` limits store writes on the hot path.
Roll out in shadow mode first: watch the events, tune weights, then switch to `Mode::Enforce`.

## Privacy and GDPR

Stored per session: the subject, timestamps, the token hashes and a fingerprint baseline (IP prefix, country, ASN, browser, OS, client hints, languages, TLS fingerprint).
Events additionally store the client IP and a truncated User-Agent.
Events are kept for 90 days (`event_retention`); `guard.purge_expired()` deletes expired sessions and old events and returns a `PurgeReport`. Call it periodically.
`minimize_event_ip(true)` masks event IPs to /24 (IPv4) or /48 (IPv6).
You, as the controller, decide the legal basis, the retention you configure, and how data subjects' requests are handled (`list_sessions`, `revoke_all_for_subject`).

## MaxMind

Enable `maxmind` and give the guard an `IpIntel` source. Without one, IP changes are judged by network prefix only.

```rust,no_run
use std::sync::Arc;

use session_guard::{Guard, GuardConfig, MaxMindIntel, MemoryStore};

let country = "/var/lib/GeoIP/GeoLite2-Country.mmdb";
let asn = "/var/lib/GeoIP/GeoLite2-ASN.mmdb";
let intel = Arc::new(MaxMindIntel::open(country, Some(asn)).unwrap());

// The guard shares the source; keep the handle to reload it.
let guard = Guard::builder(MemoryStore::new(), GuardConfig::default())
    .ip_intel(Arc::clone(&intel))
    .build();

// After geoipupdate, swap the databases without a restart; lookups stay lock-free.
intel.reload(country, Some(asn)).unwrap();
# let _ = guard;
```

If you never reload, pass the `MaxMindIntel` itself to `ip_intel`. Any closure `Fn(IpAddr) -> IpInfo`, and any `Arc` of an `IpIntel`, is an `IpIntel`.

## Performance

Criterion medians with the in-memory store (`just bench` reproduces them):

| Operation | Median |
| --- | --- |
| `authenticate`, hot path | 3.17 µs |
| `authenticate` with rotation | 5.68 µs |
| `login` | 7.38 µs |
| Risk assessment | 557 ns |
| User-Agent parse, uncached / cached | 4.65 µs / 1.14 µs |
| `TokenHash::of` | 228 ns |
| `TokenHash::from_presented` | 418 ns |

A real store adds its own round trip.

## Custom stores

Implement `SessionStore` (the guard holds all security logic; a store persists records and applies updates atomically), then run the conformance suite with the `testing` feature and `tokio` as a dev-dependency.

```rust,ignore
session_guard::store_conformance!(|| async { MyStore::connect("...").await.unwrap() });
```

## MSRV

Rust 1.94 (edition 2024).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Report vulnerabilities privately, see [SECURITY.md](SECURITY.md).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this crate by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
