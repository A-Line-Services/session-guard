//! The session-guard wiring: configuration, the guard and its layers.

use std::time::Duration;

use session_guard::{Checks, ConfigError, CookieConfig, Guard, GuardBuilder, GuardConfig, GuardLayer};
use uuid::Uuid;

use crate::Store;

/// How recent a login must be for the sensitive routes.
pub const RECENT_AUTH: Duration = Duration::from_mins(15);

/// How often expired sessions and old events are deleted.
pub const PURGE_EVERY: Duration = Duration::from_mins(10);

/// The guard configuration.
///
/// # Errors
///
/// [`ConfigError`] for an invalid proxy range or cookie.
pub fn config() -> Result<GuardConfig, ConfigError> {
    GuardConfig::builder()
        // Plain-HTTP localhost needs a non-`Secure`, non-`__Host-` cookie. In production keep
        // the default (`__Host-sid`, `Secure`) and serve over HTTPS.
        .cookie(CookieConfig::named("sid").secure(false))
        // Only these proxies may set `X-Forwarded-For`. Without any, the TCP peer is the
        // client, which is right when nothing sits in front of the app.
        .trusted_proxies(["10.0.0.0/8", "172.16.0.0/12"])?
        // A recognizable prefix lets secret scanners find leaked session tokens.
        .token_prefix("sess_")
        .build()
}

/// The guard builder, before the clock and IP intelligence (tests set those).
///
/// # Errors
///
/// [`ConfigError`] from [`config`].
pub fn builder(store: Store) -> Result<GuardBuilder<Store>, ConfigError> {
    Ok(Guard::builder(store, config()?))
}

/// The finished guard.
///
/// Add `.ip_intel(MaxMindIntel::open(..))` (feature `maxmind`) for country and ASN signals,
/// and `.on_event(..)` to ship security events to your logs or SIEM.
///
/// # Errors
///
/// [`ConfigError`] from [`config`].
pub fn guard(store: Store) -> Result<Guard<Store>, ConfigError> {
    Ok(builder(store)?.build())
}

/// The layer for ordinary signed-in routes.
///
/// API keys with these prefixes belong to an app-side handler, so the guard lets them
/// through untouched (they get no `AuthSession`).
pub fn layer(guard: &Guard<Store>) -> GuardLayer<Store, Uuid> {
    guard.layer().bypass_bearer_prefixes(["pat_", "svc_"])
}

/// The layer for sensitive routes: strict risk checks, and a login no older than
/// [`RECENT_AUTH`]. Failing either gives 401 `step_up_required`, with the cookie kept.
pub fn sensitive_layer(guard: &Guard<Store>) -> GuardLayer<Store, Uuid> {
    guard.layer().with(Checks::strict()).require_recent_auth(RECENT_AUTH)
}
