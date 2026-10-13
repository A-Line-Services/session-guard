# session-guard

[![crates.io](https://img.shields.io/crates/v/session-guard.svg)](https://crates.io/crates/session-guard)
[![docs.rs](https://docs.rs/session-guard/badge.svg)](https://docs.rs/session-guard)
[![CI](https://github.com/A-Line-Services/session-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/A-Line-Services/session-guard/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/A-Line-Services/session-guard/graph/badge.svg)](https://codecov.io/gh/A-Line-Services/session-guard)
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
| Orphaned | Superseded, and its successor was never presented (the reply was probably lost) | The request is scored with `orphaned_token`; if allowed, a fresh token is issued once and a `token_reissued` event is recorded; presenting it again counts as reuse. With `orphan_reissue_window` set, older orphans get `not_authenticated` |
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
| `tor_or_proxy_entered` | 50 | IP moved onto a Tor exit node or open proxy (needs an `IpIntel` source that reports `Anonymity`) |
| `country_changed` | 40 | IP moved to another country (needs an `IpIntel` source) |
| `client_hints_missing` | 30 | Hints the session used to send disappeared |
| `tls_changed` | 30 | TLS fingerprint changed while the browser major version stayed the same |
| `anonymizer_entered` | 30 | IP moved from a direct connection onto a VPN, hosting provider or residential proxy (needs an `IpIntel` source that reports `Anonymity`) |
| `ip_ping_pong` | 25 | Returned to the previous network within 5 minutes of leaving it |
| `orphaned_token` | 25 | The token is orphaned: superseded, past the grace period, and its successor was never presented |
| `asn_changed` | 20 | IP moved to another autonomous system (needs an `IpIntel` source) |
| `accept_language_changed` | 15 | Preferred languages changed |
| `ip_prefix_changed` | 10 | IP left its /24 (IPv4) or /48 (IPv6) |

On an IP change exactly one of country, ASN or prefix fires (in that order); ping-pong can fire in addition.
The two anonymizer checks can also fire on an IP change, unless the client returned to its previous prefix; moving to a less anonymous network never fires.
Android and Linux, and iOS and macOS, count as compatible operating systems.
Missing data never bypasses a check: a value the baseline knows but the request lacks counts as a change.

Thresholds: a score below 40 is allowed, 40 to 79 requires step-up, 80 or more revokes the session.

`orphaned_token` adds to the fingerprint score.
An orphan from an unchanged client (25) or with only an IP prefix change (35) is reissued.
An orphan with an ASN change (45), ping-pong (50) or a country change (65) requires step-up, and with an OS or browser change it revokes.
It is not learned into the baseline.

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
session-guard = { version = "0.2", features = ["axum", "postgres"] }
```

```rust,no_run
use std::{net::SocketAddr, time::Duration};

use axum::{Router, routing::{get, post}};
use session_guard::{AuthSession, Guard, GuardError, NewSession, PgStore, Sessions};

async fn me(session: AuthSession<uuid::Uuid>) -> String {
    format!("session {} for {}", session.session_id, session.subject)
}

// Your own handler: verify the password and rate limit first, then ask the guard for a session.
// `login` also revokes the session the request presented (fixation defence).
async fn login(sessions: Sessions<PgStore>) -> Result<(NewSession, &'static str), GuardError> {
    let user = uuid::Uuid::new_v4(); // the verified user id
    Ok((sessions.login(&user).await?, "welcome"))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pool = sqlx::PgPool::connect("postgres://localhost/app").await?;
    let guard = Guard::new(PgStore::migrated(pool).await?);
    let _purge = guard.spawn_purge(Duration::from_secs(600)); // deletes expired sessions and old events

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
The event hook is called once per state change, in the process that made the change, after the event is stored. Of several racing requests only the one whose change took effect reports it, except `step_up_required`, which each racing request may report. Delivery is at most once: there is no outbox, so a crash between the change and the hook loses the event.
To page a subject's owner once rather than once per session, set `alert_dedup_window`: enforced security events (`step_up_required`, `risk_revoked`, `token_reuse`, `token_reissued`) then reach the hook at most once per subject and kind per window, across instances through `SessionStore::claim_event`. Suppressed duplicates are still logged and stored; if the claim fails, the hook is called anyway.
`revoke_session(subject, id, ctx)` (scoped to `subject`, so another subject's session id is a no-op) and `revoke_all_for_subject(subject, ctx)` record a `revoked` event per session they delete, carrying the client that asked.

The hook runs inside the request and is synchronous. For slow work (email, webhooks), hand the event to a task and never wait on it:

```rust
use session_guard::{Guard, GuardConfig, MemoryStore, SessionEvent};
use tokio::sync::mpsc;

#[tokio::main]
async fn main() {
    let (tx, mut rx) = mpsc::channel::<SessionEvent>(1024);
    tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            // Send the email, call the webhook...
            println!("{} on session {}", event.kind, event.session_id);
        }
    });
    let _guard = Guard::builder(MemoryStore::new(), GuardConfig::default())
        .on_event(move |event| {
            // A full queue drops the event rather than slowing the request.
            if tx.try_send(event.clone()).is_err() {
                eprintln!("event queue full, dropped {}", event.kind);
            }
        })
        .build();
}
```

`PgStore::migrated` runs the embedded migrations and is safe to call from many processes. To run them in your own pipeline, use `PgStore::migrator()` and `PgStore::new(pool)` instead.
Without `ConnectInfo<SocketAddr>` the layer fails closed with a 500.

`Sessions` is the extractor for routes outside the layer: `login`, `logout` and `complete_step_up` for the session the request presented.
`NewSession`, `IssuedToken` and `LoggedOut` are response parts that set or delete the cookie, and `GuardError` and `StepUpError` turn into the JSON error responses described in [the 401 contract](#the-401-contract).

Without a framework, call the guard directly:

```rust
use session_guard::{ClientContext, Guard, MemoryStore, Outcome};

async fn demo() -> Result<(), session_guard::GuardError> {
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
        }
    }
    Ok(())
}
```

### Examples

The examples are a separate crate in the workspace, `examples`.
[`examples/axum_simple.rs`](examples/axum_simple.rs) is the shortest start: login, a protected route and logout in one file (`cargo run -p examples --bin axum_simple`).

[`examples/app/`](examples/app) is a complete app on axum and rovo: login, logout, step-up, session listing and revocation, a strict layer for a sensitive route, an API key route, and Swagger UI.
Three binaries run it on different stores:

```sh
cargo run -p examples --bin axum_memory    # nothing to install
cargo run -p examples --bin axum_postgres  # DATABASE_URL
cargo run -p examples --bin axum_valkey    # VALKEY_URL
```

Then open <http://127.0.0.1:3000/swagger> and log in with `demo` / `demo-password`.
[`examples/core_only.rs`](examples/core_only.rs) uses the guard without a framework (`cargo run -p examples --bin core_only`).

## Feature flags

| Feature | Enables |
| --- | --- |
| `axum` | Tower layer (`Guard::layer`), the `AuthSession` and `Sessions` extractors and response impls for axum 0.8; enables `tokio` |
| `aide` | OpenAPI docs through aide and rovo: the `session_cookie` security scheme; enables `axum` |
| `tokio` | `Guard::spawn_purge`, a background task that purges expired sessions |
| `postgres` | `PgStore` on sqlx, with embedded migrations |
| `valkey` | `ValkeyStore` for Valkey or Redis, with atomic Lua rotation (a single primary; Cluster mode is not supported) |
| `maxmind` | `MaxMindIntel`: country, city, ASN, network name and anonymizers from GeoLite2 / GeoIP2 databases |
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
use session_guard::{ClientContext, Guard, MemoryStore, StepUpOutcome};

async fn demo(guard: Guard<MemoryStore>, token: &str, ctx: ClientContext, user: uuid::Uuid) -> Result<(), session_guard::GuardError> {
    match guard.complete_step_up(token, &ctx, &user).await? {
        StepUpOutcome::Completed(new_token) => { /* send new_token.set_cookie() */ }
        StepUpOutcome::SubjectMismatch | StepUpOutcome::Rejected(_) => { /* 401 */ }
    }
    Ok(())
}
```

`complete_step_up` trusts the subject you pass, so call it only after your own verification succeeded. A session waiting for step-up keeps aging: if the idle timeout passes first, it expires and the user logs in again.

To demand a recent proof of identity on sensitive routes, use `guard.layer().require_recent_auth(Duration::from_secs(300))`; older sessions get `step_up_required` with the cookie kept.
A zero window can never be met, since the retry after a step-up is already later; to confirm each action (such as a delete), verify the credential in that handler instead.

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
use session_guard::{Guard, MemoryStore};

let guard = Guard::new(MemoryStore::new());
let layer = guard
    .layer()
    .bypass_bearer_prefixes(["pat_", "svc_"])
    .bypass_when(|headers| headers.contains_key("x-api-key"));
```

## OpenAPI (aide and rovo)

With the `aide` feature the extractors and errors document themselves:

- `AuthSession` marks its route as requiring the `session_cookie` scheme and documents the layer's 401 rejections.
- `Sessions` leaves the route public.
- `GuardError` documents its 500, and `StepUpError` its 401, 403 and 500.

Add the scheme itself in `finish_api_with`: `session_guard::aide::security_scheme(&guard)` is an `apiKey` in the cookie, named after the guard's cookie, registered under `SECURITY_SCHEME`.
With rovo, name other schemes with `@security` in the handler's metadata, and register them the same way.

```rust
use rovo::{Router, aide::openapi::OpenApi, routing::get, rovo};
use session_guard::{
    AuthSession, Guard, MemoryStore,
    aide::{SECURITY_SCHEME, security_scheme},
};
use uuid::Uuid;

/// The signed-in user.
///
/// # Responses
///
/// 200: String - The subject
#[rovo]
async fn me(session: AuthSession<Uuid>) -> String {
    session.subject.to_string()
}

/// Ping with an API key; the layer bypasses it (see `bypass_bearer_prefixes`).
///
/// # Responses
///
/// 200: String - Pong
///
/// # Metadata
///
/// @security bearer
#[rovo]
async fn ping() -> String {
    "pong".to_owned()
}

let guard = Guard::new(MemoryStore::new());
let mut api = OpenApi::default();
let app: axum::Router = Router::new()
    .route("/me", get(me))
    .route("/api/ping", get(ping))
    .into_inner()
    .layer(guard.layer().bypass_bearer_prefixes(["pat_"]))
    .finish_api_with(&mut api, |api| {
        api.title("My API")
            .security_scheme(SECURITY_SCHEME, security_scheme(&guard))
        // .security_scheme("bearer", ..) for `@security bearer`
    });
// Serve `api` with rovo's Swagger UI.
```

`examples/app/` shows the whole setup, including Swagger UI and a separate strict layer for sensitive routes.

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

**Orphan reissue.** If a superseded token's successor was never presented, the guard assumes the response was lost and rotates again instead of revoking.
This gives the presenter a fresh token without proof that it is the legitimate client.
The request is scored with `orphaned_token` (25) on top of the fingerprint checks, so a thief who replays an orphan first only gets a session if its fingerprint matches closely enough to stay below 40.
Each orphan is reissued only once: the fresh token counts as used from the start, so presenting the orphan again is reuse and revokes the session.
The victim's next request presents a superseded token whose successor was used, which also revokes the session, so the thief's access lasts until the victim returns.
`orphan_reissue_window` bounds how old a reissued orphan can be. Older orphans are rejected as `not_authenticated` and the session is left untouched, so whoever holds the successor keeps it.
A zero window never reissues, so a client that loses a single rotation response is signed out.
The cost of a window: a phone that lost a response while backgrounded and returns hours later is logged out.
Without a window, a client that loses two rotation responses in a row is logged out.

### CSRF

session-guard does not protect against CSRF. That is the app's job, as with any cookie authentication.

`SameSite=Lax` covers part of it: browsers do not send the cookie on cross-site `POST`, `PUT`, `PATCH` or `DELETE` requests.
It leaves these gaps:

- Same-site but cross-origin attackers: a sibling subdomain such as `evil.example.com` can still forge requests to `app.example.com`.
- State-changing `GET` requests, which `Lax` sends cross-site on top-level navigation.
- Login CSRF: the login route sits outside the layer.

On every state-changing route, including login and step-up, reject unsafe-method requests whose `Sec-Fetch-Site` is not `same-origin` (or `none`).
When the header is missing, compare `Origin` with your expected origin instead.
CSRF tokens work as well.
Requests the layer bypasses (API keys) carry no ambient credentials, so they do not need the check.

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
```

Presets: `Checks::default()`, `Checks::none()` (only rotation and reuse detection; no `orphaned_token`) and `Checks::strict()` (IP prefix, ASN, language, TLS, ping-pong, orphaned token and `anonymizer_entered` at 40, country change and `tor_or_proxy_entered` at 80).
Apply a different set per route with `guard.layer().with(Checks::strict())`.

| Setting | Default |
| --- | --- |
| `session_lifetime` | 30 days |
| `idle_timeout` | 7 days |
| `rotation.interval` / `grace` / `reuse_detection` | 10 minutes / 30 seconds / 7 days |
| `ping_pong_window` | 5 minutes (zero disables) |
| `last_seen_write_interval` | 60 seconds (zero writes on every request) |
| `thresholds` | step-up 40, revoke 80 |
| `alert_dedup_window` | off (hook alerts are not deduplicated per subject) |
| `orphan_reissue_window` | off (orphans are reissued until `rotation.reuse_detection` prunes them; zero never reissues) |
| `minimize_stored_events` | on (stored events keep the IP's /24 or /48, no raw User-Agent, no city) |
| `keep_origin_client` | off (a session's origin keeps the IP's /24 or /48, no raw User-Agent, no city) |

`grace` must be shorter than `interval`. `last_seen_write_interval` limits store writes on the hot path.
Roll out in shadow mode first: watch the events, tune weights, then switch to `Mode::Enforce`.

## Privacy and GDPR

Stored per session: the subject, timestamps, the token hashes, a fingerprint baseline (IP prefix, country, ASN, browser, OS, client hints, languages, TLS fingerprint) and a `SessionOrigin` recorded at login (time, IP /24 or /48 network, `ClientSummary` without city).
`keep_origin_client(true)` also keeps the origin's full IP, truncated User-Agent and city; leave it off unless you need them.
Events carry the client IP, a truncated User-Agent and a `ClientSummary` (country, city, ASN, network name, anonymizer, browser, OS).
The `on_event` hook always gets all of it, e.g. to email the subject where a sign-in came from.
The stored copy is minimized by default: the IP is masked to /24 (IPv4) or /48 (IPv6), and the raw User-Agent and the city are left out. `minimize_stored_events(false)` stores the full event.
Events are kept for 90 days (`event_retention`); `guard.purge_expired()` deletes expired sessions and old events and returns a `PurgeReport`. Call it periodically, or let `guard.spawn_purge(every)` (`tokio` feature) do it.
You, as the controller, decide the legal basis, the retention you configure, and how data subjects' requests are handled (`list_sessions`, `revoke_all_for_subject`).

`guard.list_sessions(&subject)` returns a `SessionInfo` per live session for a "your devices" page: timestamps, the current browser, OS and country, and `origin` (where the session started; `None` for sessions created before 0.2).

## MaxMind

Enable `maxmind` and give the guard an `IpIntel` source. Without one, IP changes are judged by network prefix only.

A lookup returns an `IpInfo` with the ISO country code (City or Country edition), the English city name (City edition only), the autonomous system number and its organization name, e.g. `"Example Telecom"` (ASN database), and the anonymity (see [Anonymizers](#anonymizers)). The guard does not score the city or the network name. Both reach the `on_event` hook in `SessionEvent::client`, e.g. to describe where a sign-in came from; the stored copy leaves out the city by default (see [Privacy and GDPR](#privacy-and-gdpr)).

`MaxMindIntel` reads the databases into memory, so lookups never touch the disk. `geoipupdate` (a cron job, a sidecar or an auto-updated volume) replaces the files when MaxMind publishes new ones, and the guard only sees them after a reload. With the `tokio` feature, `spawn_reload` checks the files on an interval and reloads them when they change:

```rust,no_run
use std::sync::Arc;
use std::time::Duration;

use session_guard::{Guard, GuardConfig, MaxMindIntel, MemoryStore};

let country = "/var/lib/GeoIP/GeoLite2-Country.mmdb";
let asn = "/var/lib/GeoIP/GeoLite2-ASN.mmdb";
let intel = Arc::new(MaxMindIntel::open(country, Some(asn)).unwrap());

// Check the files hourly; lookups stay lock-free while a reload swaps the databases.
intel.spawn_reload(Duration::from_secs(60 * 60));

// The guard shares the source with the reload task.
let guard = Guard::builder(MemoryStore::new(), GuardConfig::default())
    .ip_intel(Arc::clone(&intel))
    .build();
```

- A change is detected from each file's modification time and size, not from file system events, so it also works on network file systems and Kubernetes volumes. A check of unchanged files costs one `stat` per file.
- A file that fails to load (missing, or only partly written) leaves the current databases in place and is retried on the next tick. Reloads are logged at `info` and failures at `warn` through `tracing`.
- Without tokio, call `intel.reload_if_changed()` from your own scheduler, off the async runtime since it reads the files when they changed. `reload(paths)` and `reload_from_bytes` swap the databases unconditionally.

If you never reload, pass the `MaxMindIntel` itself to `ip_intel`. Any closure `Fn(IpAddr) -> IpInfo`, and any `Arc` of an `IpIntel`, is an `IpIntel`.

### Anonymizers

The `tor_or_proxy_entered` and `anonymizer_entered` checks need to know whether an address is a VPN, proxy or Tor exit node. Add one of MaxMind's paid anonymizer databases (GeoIP2 Anonymous IP, GeoIP Anonymous Plus or GeoIP2 IP Risk) with `with_anonymizer`:

```rust,no_run
use session_guard::MaxMindIntel;

let intel = MaxMindIntel::open("/var/lib/GeoIP/GeoLite2-Country.mmdb", None::<&str>)
    .unwrap()
    .with_anonymizer("/var/lib/GeoIP/GeoIP2-Anonymous-IP.mmdb")
    .unwrap();
```

| Database flag | `Anonymity` |
|---|---|
| `is_tor_exit_node` | `TorExitNode` |
| `is_public_proxy` | `PublicProxy` |
| `is_residential_proxy` | `ResidentialProxy` |
| `is_anonymous_vpn`, unless `anonymizer_confidence` is below 50 | `Vpn` |
| `is_hosting_provider` | `HostingProvider` |
| none, or an address the database does not list | `Direct` |

The most severe flag wins. A failed lookup, such as an IPv6 address in an IPv4-only database, leaves the anonymity unknown, so neither check fires. IP Risk's `ip_risk` score is not used: the guard scores what changes during a session, not how risky an address is on its own.

`reload_if_changed` and `spawn_reload` follow the anonymizer file too, independently of the others, so a failed update of one never holds back the rest. `reload` and `reload_from_bytes` leave the anonymizer in place; `reload_anonymizer` and `reload_anonymizer_from_bytes` swap it.

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
