# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - Unreleased

Initial release.

### Added

- Rotating session tokens with reuse detection: replaying a rotated token
  revokes the session family.
- Risk scoring with step-up, configured through `StepUpPolicy`
  (`Require`, `Revoke`, `Allow`).
- Shadow mode to log and measure decisions without enforcing them.
- Generic, opaque subject type; no user payload stored.
- axum integration: tower layer and `AuthSession` extractor (`axum` feature).
- PostgreSQL store with embedded migrations (`postgres` feature).
- Valkey / Redis store with atomic Lua rotation (`valkey` feature).
- MaxMind GeoLite2 / GeoIP2 country and ASN IP intelligence (`maxmind` feature).
- Metrics via the `metrics` facade (`metrics` feature).
- `store_conformance!` test suite for custom stores (`testing` feature).

[0.1.0]: https://github.com/A-Line-Services/session-guard/releases/tag/v0.1.0
