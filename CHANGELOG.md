# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - Unreleased

Initial release.

### Added

- Rotating session tokens with reuse detection: replaying a rotated token
  revokes the session family. Tokens are 32 random bytes; only their SHA-256
  hash is stored, and comparisons are constant time.
- Token prefixes: `GuardConfig::token_prefix` (for example `als_`) marks
  session tokens so they are distinguishable from other credentials and
  recognisable by secret scanners. `Guard::is_session_token` checks the shape
  without touching the store.
- Risk scoring with step-up, configured through `StepUpPolicy`
  (`Require`, `Revoke`, `Allow`), over IP prefix (/24, /48), country, ASN,
  User-Agent and Accept-Language changes.
- Shadow mode to log and measure decisions without enforcing them. Shadow
  events are deduplicated per session and kind within a window (default 10
  minutes), and across instances through the new `SessionStore::claim_event`
  (atomic in the Postgres, Valkey and in-memory stores; the default always
  succeeds, leaving deduplication to each process).
- Login revokes the session behind the token the client presented
  (`Guard::login(.., previous_token)`), so a token planted before login
  (session fixation) never becomes authenticated.
- Generic, opaque subject type; no user payload stored.
- Configurable cookie (`CookieConfig`: name, path, domain, `Secure`,
  `HttpOnly`, `SameSite`, persistent or session). The default is a
  `__Host-sid` cookie.
- Client context extraction with trusted-proxy aware `X-Forwarded-For`
  parsing and bounded header lengths.
- Step-up completion, logout, single-session and per-subject revocation,
  session listing, `peek`, `requires_reauth` and `purge_expired`.
- GDPR controls: event retention (default 90 days, enforced by
  `purge_expired`) and `minimize_event_ip`, which stores only the IP prefix
  in events instead of the full address.
- Parsed User-Agents are cached in a bounded cache, so repeated strings are
  parsed once.
- Convenience constructors: `Guard::new(store)` for default configuration and
  `PgStore::migrated(pool)`, which runs the embedded migrations and returns the
  store.
- axum integration (`axum` feature): tower layer and `AuthSession` extractor.
  Rejections are 401 JSON responses that clear the cookie, and revocation also
  sends `Clear-Site-Data: "cookies"`.
- axum bypass: `bypass_bearer_prefixes` skips requests whose
  `Authorization: Bearer` token starts with a configured prefix (such as API
  keys handled by other middleware), and `bypass_when` takes any predicate over
  the headers. Bypassed requests get no authentication and no `AuthSession`.
- PostgreSQL store with embedded migrations (`postgres` feature).
- Valkey / Redis store with atomic Lua rotation (`valkey` feature).
- In-memory store for tests and single-process use.
- MaxMind GeoLite2 / GeoIP2 country and ASN IP intelligence with hot reload
  (`maxmind` feature).
- Metrics via the `metrics` facade (`metrics` feature).
- `store_conformance!` test suite and helpers for custom stores (`testing`
  feature).
- cargo-fuzz targets for cookie parsing, `X-Forwarded-For` resolution and
  User-Agent parsing (`fuzz/`, with seed inputs), and criterion benchmarks for
  authentication, risk scoring, User-Agent parsing and token hashing
  (`benches/`).

[0.1.0]: https://github.com/A-Line-Services/session-guard/releases/tag/v0.1.0
