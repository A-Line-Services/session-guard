//! Stolen session cookies become useless: rotating tokens with reuse detection and risk-based
//! step-up for Rust web apps.
//!
//! A [`Guard`] issues opaque session tokens, stores only their SHA-256 hashes, rotates them
//! every few minutes and revokes the session when a superseded token comes back after its
//! successor was used: the signature of a copied cookie. Every request is also scored against
//! the session's client fingerprint (OS, browser, client hints, country, network); a moderate
//! change asks the app to re-verify the subject, a drastic one revokes the session.
//!
//! The crate handles sessions only. Logging in, verifying passwords and rate limiting stay in
//! the app.
//!
//! ```
//! # async fn demo() -> Result<(), session_guard::GuardError> {
//! use session_guard::{ClientContext, Guard, MemoryStore, Outcome};
//!
//! let guard = Guard::new(MemoryStore::new());
//! let ctx = ClientContext::new("203.0.113.7".parse().unwrap()).with_user_agent("Mozilla/5.0 …");
//!
//! // After the app has verified the user's credentials:
//! let user = uuid::Uuid::new_v4();
//! let session = guard.login(&user, &ctx, None).await?;
//! let set_cookie = session.token.set_cookie(); // send as `Set-Cookie`
//! # let _ = set_cookie;
//!
//! // On every later request:
//! match guard.authenticate(session.token.expose(), &ctx).await? {
//!     Outcome::Authenticated(auth) => {
//!         assert_eq!(auth.session.subject, user);
//!         // send `auth.rotated` as `Set-Cookie` when present
//!     }
//!     Outcome::Rejected(rejection) => {
//!         // answer 401 with `{"error": rejection.as_str()}`
//!         # let _ = rejection;
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Features
//!
//! - `axum`: a tower layer that authenticates requests, the `AuthSession` and `Sessions`
//!   extractors and response impls (see the `axum` module). Enables `tokio`.
//! - `aide`: OpenAPI docs through `aide` and `rovo`: the `session_cookie` security scheme
//!   (see the `aide` module).
//! - `tokio`: `Guard::spawn_purge`, a background task that purges expired sessions.
//! - `postgres`: a [`SessionStore`] on sqlx with embedded migrations.
//! - `valkey`: a [`SessionStore`] on Valkey or Redis.
//! - `maxmind`: [`IpIntel`] backed by `MaxMind` `GeoLite2`/`GeoIP2` databases, reloaded when
//!   `geoipupdate` replaces the files.
//! - `metrics`: counters through the `metrics` facade.
//! - `testing`: the `store_conformance!` suite for custom stores.
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(feature = "aide")]
#[cfg_attr(docsrs, doc(cfg(feature = "aide")))]
pub mod aide;
#[cfg(feature = "axum")]
#[cfg_attr(docsrs, doc(cfg(feature = "axum")))]
pub mod axum;
pub mod checks;
pub mod client;
pub mod clock;
pub mod config;
pub mod cookie;
pub mod error;
pub mod event;
pub mod fingerprint;
mod guard;
pub mod intel;
pub mod risk;
pub mod store;
pub mod subject;
mod telemetry;
#[cfg(any(test, feature = "testing"))]
#[cfg_attr(docsrs, doc(cfg(feature = "testing")))]
pub mod testing;
pub mod token;

/// Internals the crate's own benchmarks measure. Not part of the public API; may change in any
/// release.
#[cfg(feature = "testing")]
#[doc(hidden)]
pub mod __bench {
    use crate::{ClientContext, Fingerprint, IpInfo, fingerprint::UaCache};

    /// Fingerprint capture through the guard's User-Agent cache.
    #[derive(Debug)]
    pub struct CachedCapture(UaCache);

    impl CachedCapture {
        /// A cache holding up to `capacity` parsed User-Agents.
        pub fn new(capacity: usize) -> Self {
            Self(UaCache::new(capacity))
        }

        /// [`Fingerprint::capture`], parsing the User-Agent through the cache.
        pub fn capture(&self, ctx: &ClientContext, info: IpInfo) -> Fingerprint {
            Fingerprint::capture_cached(ctx, info, &self.0)
        }
    }
}

#[cfg(feature = "axum")]
#[cfg_attr(docsrs, doc(cfg(feature = "axum")))]
pub use crate::axum::{GuardLayer, GuardService, Sessions};
pub use checks::{Check, Checks, Decision, Thresholds, UnknownCheck};
pub use client::{ClientContext, HeaderSource, canonical_ip, resolve_client_ip};
pub use clock::{Clock, ManualClock, SystemClock};
pub use config::{GuardConfig, GuardConfigBuilder, Mode, RotationConfig, StepUpPolicy};
pub use cookie::{CookieConfig, SameSite, find_cookie};
pub use error::{ConfigError, GuardError, StoreError};
pub use event::{EventKind, SessionEvent};
pub use fingerprint::{Baseline, Fingerprint, ip_prefix};
pub use guard::{
    AuthSession, Authenticated, Guard, GuardBuilder, IssuedToken, NewSession, Outcome, PurgeReport, Rejection,
    SessionInfo, StepUpOutcome,
};
pub use intel::{IpInfo, IpIntel, NoIpIntel};
#[cfg(feature = "maxmind")]
#[cfg_attr(docsrs, doc(cfg(feature = "maxmind")))]
pub use intel::{MaxMindDatabase, MaxMindError, MaxMindIntel};
pub use risk::{Assessment, assess};
#[cfg(feature = "postgres")]
#[cfg_attr(docsrs, doc(cfg(feature = "postgres")))]
pub use store::PgStore;
#[cfg(feature = "valkey")]
#[cfg_attr(docsrs, doc(cfg(feature = "valkey")))]
pub use store::ValkeyStore;
pub use store::{
    MemoryStore, Rotation, SessionRecord, SessionStore, SessionUpdate, Supersede, TokenLookup, TokenRecord,
};
pub use subject::Subject;
pub use token::{SessionToken, TOKEN_LEN, TokenHash, is_well_formed};

// The README examples use these features, so other feature sets skip them.
#[cfg(all(
    doctest,
    feature = "aide",
    feature = "axum",
    feature = "maxmind",
    feature = "postgres",
    feature = "testing"
))]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
