//! Guard configuration.

use std::{net::IpAddr, time::Duration};

use chrono::TimeDelta;
use ipnet::IpNet;

use crate::{
    checks::{Checks, Thresholds},
    cookie::CookieConfig,
    error::ConfigError,
};

/// Longest accepted duration (100 years), so timestamp arithmetic cannot overflow.
const MAX_DURATION: Duration = Duration::from_hours(100 * 365 * 24);

/// Whether risk decisions are enforced.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Mode {
    /// Step-up and revoke decisions take effect.
    #[default]
    Enforce,
    /// Decisions are only recorded as events with `enforced = false`; requests pass. Use this to
    /// tune weights on real traffic before enforcing. Token reuse is always enforced.
    Shadow,
}

/// What a step-up decision (score between the step-up and revoke thresholds) does.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StepUpPolicy {
    /// Reject with `step_up_required` until the app re-verifies the subject and calls
    /// [`Guard::complete_step_up`](crate::Guard::complete_step_up).
    #[default]
    Require,
    /// Revoke the session, as if the revoke threshold had been reached. For apps without a
    /// re-authentication flow that prefer a fresh login.
    Revoke,
    /// Let the request through and record a `step_up_required` event with `enforced = false`.
    /// For apps without a re-authentication flow that only want revoke-level protection.
    Allow,
}

/// Token rotation settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RotationConfig {
    /// How old the current token may get before a request rotates it. Default 10 minutes.
    pub interval: Duration,
    /// How long a superseded token stays valid, for parallel requests and lost responses.
    /// Default 30 seconds. Must be shorter than `interval`.
    pub grace: Duration,
    /// How long superseded tokens are kept to detect reuse. A stolen token replayed after this
    /// is simply unknown. Default 7 days.
    pub reuse_detection: Duration,
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_mins(10),
            grace: Duration::from_secs(30),
            reuse_detection: Duration::from_hours(7 * 24),
        }
    }
}

/// Validated guard configuration. Build with [`GuardConfig::builder`] or take the
/// [`Default`].
#[derive(Clone, Debug)]
pub struct GuardConfig {
    pub(crate) cookie: CookieConfig,
    pub(crate) session_lifetime: TimeDelta,
    pub(crate) idle_timeout: TimeDelta,
    pub(crate) trusted_proxies: Vec<IpNet>,
    pub(crate) tls_fingerprint_header: Option<String>,
    pub(crate) rotation_interval: TimeDelta,
    pub(crate) rotation_grace: TimeDelta,
    pub(crate) reuse_detection: TimeDelta,
    pub(crate) checks: Checks,
    pub(crate) thresholds: Thresholds,
    pub(crate) mode: Mode,
    pub(crate) step_up_policy: StepUpPolicy,
    pub(crate) ping_pong_window: TimeDelta,
    pub(crate) last_seen_write_interval: TimeDelta,
    pub(crate) event_retention: TimeDelta,
    pub(crate) minimize_stored_events: bool,
    pub(crate) shadow_dedup_window: TimeDelta,
    pub(crate) max_header_len: usize,
    pub(crate) token_prefix: Option<String>,
    pub(crate) orphan_reissue_window: Option<TimeDelta>,
}

impl Default for GuardConfig {
    fn default() -> Self {
        GuardConfigBuilder::default()
            .build()
            .unwrap_or_else(|_| unreachable!("default configuration is valid"))
    }
}

impl GuardConfig {
    /// Starts from the defaults.
    pub fn builder() -> GuardConfigBuilder {
        GuardConfigBuilder::default()
    }

    /// Cookie attributes.
    pub fn cookie(&self) -> &CookieConfig {
        &self.cookie
    }

    /// Absolute session lifetime.
    pub fn session_lifetime(&self) -> Duration {
        to_std(self.session_lifetime)
    }

    /// Inactivity after which a session expires.
    pub fn idle_timeout(&self) -> Duration {
        to_std(self.idle_timeout)
    }

    /// Proxies whose `X-Forwarded-For` is honoured.
    pub fn trusted_proxies(&self) -> &[IpNet] {
        &self.trusted_proxies
    }

    /// Request header carrying a TLS fingerprint (e.g. JA4) set by the proxy, lowercase.
    pub fn tls_fingerprint_header(&self) -> Option<&str> {
        self.tls_fingerprint_header.as_deref()
    }

    /// Rotation settings.
    pub fn rotation(&self) -> RotationConfig {
        RotationConfig {
            interval: to_std(self.rotation_interval),
            grace: to_std(self.rotation_grace),
            reuse_detection: to_std(self.reuse_detection),
        }
    }

    /// Default checks (routes can override).
    pub fn checks(&self) -> &Checks {
        &self.checks
    }

    /// Score thresholds.
    pub fn thresholds(&self) -> Thresholds {
        self.thresholds
    }

    /// Enforcement mode.
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// What a step-up decision does.
    pub fn step_up_policy(&self) -> StepUpPolicy {
        self.step_up_policy
    }

    /// Window in which returning to the previous network counts as ping-pong.
    pub fn ping_pong_window(&self) -> Duration {
        to_std(self.ping_pong_window)
    }

    /// How stale `last_seen` may get before an otherwise unchanged request writes it.
    pub fn last_seen_write_interval(&self) -> Duration {
        to_std(self.last_seen_write_interval)
    }

    /// How long events are kept before [`Guard::purge_expired`](crate::Guard::purge_expired)
    /// deletes them.
    pub fn event_retention(&self) -> Duration {
        to_std(self.event_retention)
    }

    /// Whether the store gets a reduced copy of each event; see
    /// [`GuardConfigBuilder::minimize_stored_events`].
    pub fn minimize_stored_events(&self) -> bool {
        self.minimize_stored_events
    }

    /// Window in which repeated shadow events for the same session and kind are dropped.
    pub fn shadow_dedup_window(&self) -> Duration {
        to_std(self.shadow_dedup_window)
    }

    /// Maximum length of a header value considered for fingerprinting.
    pub fn max_header_len(&self) -> usize {
        self.max_header_len
    }

    /// Prefix of issued tokens, if any.
    pub fn token_prefix(&self) -> Option<&str> {
        self.token_prefix.as_deref()
    }

    /// How long after being superseded an orphaned token is still reissued, if limited.
    pub fn orphan_reissue_window(&self) -> Option<Duration> {
        self.orphan_reissue_window.map(to_std)
    }
}

fn to_std(delta: TimeDelta) -> Duration {
    delta.to_std().unwrap_or_default()
}

/// Builder for [`GuardConfig`].
#[derive(Clone, Debug)]
#[must_use]
pub struct GuardConfigBuilder {
    cookie: CookieConfig,
    session_lifetime: Duration,
    idle_timeout: Duration,
    trusted_proxies: Vec<IpNet>,
    tls_fingerprint_header: Option<String>,
    rotation: RotationConfig,
    checks: Checks,
    thresholds: Thresholds,
    mode: Mode,
    step_up_policy: StepUpPolicy,
    ping_pong_window: Duration,
    last_seen_write_interval: Duration,
    event_retention: Duration,
    minimize_stored_events: bool,
    shadow_dedup_window: Duration,
    max_header_len: usize,
    token_prefix: Option<String>,
    orphan_reissue_window: Option<Duration>,
}

impl Default for GuardConfigBuilder {
    fn default() -> Self {
        const MINUTE: u64 = 60;
        const DAY: u64 = 24 * 60 * MINUTE;
        Self {
            cookie: CookieConfig::default(),
            session_lifetime: Duration::from_secs(30 * DAY),
            idle_timeout: Duration::from_secs(7 * DAY),
            trusted_proxies: Vec::new(),
            tls_fingerprint_header: None,
            rotation: RotationConfig::default(),
            checks: Checks::default(),
            thresholds: Thresholds::default(),
            mode: Mode::Enforce,
            step_up_policy: StepUpPolicy::Require,
            ping_pong_window: Duration::from_secs(5 * MINUTE),
            last_seen_write_interval: Duration::from_secs(MINUTE),
            event_retention: Duration::from_secs(90 * DAY),
            minimize_stored_events: true,
            shadow_dedup_window: Duration::from_secs(10 * MINUTE),
            max_header_len: 512,
            token_prefix: None,
            orphan_reissue_window: None,
        }
    }
}

impl GuardConfigBuilder {
    /// Cookie attributes. See [`CookieConfig`].
    pub fn cookie(mut self, cookie: CookieConfig) -> Self {
        self.cookie = cookie;
        self
    }

    /// Shorthand for changing only the cookie name.
    pub fn cookie_name(mut self, name: impl Into<String>) -> Self {
        self.cookie = self.cookie.name(name);
        self
    }

    /// Absolute session lifetime, counted from login. Activity, rotation and step-up never extend
    /// it; the subject must log in again. Default 30 days.
    pub fn session_lifetime(mut self, lifetime: Duration) -> Self {
        self.session_lifetime = lifetime;
        self
    }

    /// Inactivity timeout. Default 7 days.
    pub fn idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = timeout;
        self
    }

    /// Reverse proxies (IP addresses or CIDR ranges) whose `X-Forwarded-For` is honoured.
    /// Without any, the TCP peer address is the client address.
    ///
    /// # Errors
    ///
    /// [`ConfigError::InvalidProxy`] for an entry that is not an IP or CIDR range.
    pub fn trusted_proxies<I, T>(mut self, proxies: I) -> Result<Self, ConfigError>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
    {
        self.trusted_proxies = proxies
            .into_iter()
            .map(|p| {
                let p = p.as_ref().trim();
                p.parse::<IpNet>()
                    .or_else(|_| p.parse::<IpAddr>().map(IpNet::from))
                    .map(|net| net.trunc())
                    .map_err(|_| ConfigError::InvalidProxy(p.to_owned()))
            })
            .collect::<Result<_, _>>()?;
        Ok(self)
    }

    /// Header with a TLS fingerprint (e.g. JA4) set by your proxy. Enables
    /// [`Check::TlsChanged`](crate::Check::TlsChanged). Only use a header your proxy
    /// overwrites on every request.
    pub fn tls_fingerprint_header(mut self, header: impl Into<String>) -> Self {
        self.tls_fingerprint_header = Some(header.into().to_ascii_lowercase());
        self
    }

    /// Token rotation settings.
    pub fn rotation(mut self, rotation: RotationConfig) -> Self {
        self.rotation = rotation;
        self
    }

    /// Checks and weights. Default: all checks at default weights.
    pub fn checks(mut self, checks: Checks) -> Self {
        self.checks = checks;
        self
    }

    /// Score thresholds. Default: step-up at 40, revoke at 80.
    pub fn thresholds(mut self, thresholds: Thresholds) -> Self {
        self.thresholds = thresholds;
        self
    }

    /// Enforce or shadow mode. Default enforce.
    pub fn mode(mut self, mode: Mode) -> Self {
        self.mode = mode;
        self
    }

    /// What a step-up decision does. Default [`StepUpPolicy::Require`].
    pub fn step_up_policy(mut self, policy: StepUpPolicy) -> Self {
        self.step_up_policy = policy;
        self
    }

    /// How long after being superseded an orphaned token (its successor never presented) is
    /// still reissued. Past it the token is rejected as unknown and the session is left to
    /// whoever holds the successor. Default off: orphans are reissued until
    /// `rotation.reuse_detection` prunes them.
    ///
    /// Zero never reissues: a client that loses a single rotation response is signed out.
    pub fn orphan_reissue_window(mut self, window: Duration) -> Self {
        self.orphan_reissue_window = Some(window);
        self
    }

    /// Ping-pong window. Default 5 minutes. Zero disables ping-pong detection.
    pub fn ping_pong_window(mut self, window: Duration) -> Self {
        self.ping_pong_window = window;
        self
    }

    /// How stale `last_seen` may get before an unchanged request writes it. Default 60 seconds.
    /// Zero writes on every request.
    pub fn last_seen_write_interval(mut self, interval: Duration) -> Self {
        self.last_seen_write_interval = interval;
        self
    }

    /// Event retention. Default 90 days.
    pub fn event_retention(mut self, retention: Duration) -> Self {
        self.event_retention = retention;
        self
    }

    /// Write a reduced copy of each event to the store: the IP's /24 (IPv4) or /48 (IPv6)
    /// network instead of the address, no raw User-Agent (the browser and OS families stay in
    /// [`ClientSummary`](crate::ClientSummary)) and no city. Default on. The
    /// [`on_event`](crate::GuardBuilder::on_event) hook always gets the full event.
    pub fn minimize_stored_events(mut self, minimize: bool) -> Self {
        self.minimize_stored_events = minimize;
        self
    }

    /// Shadow event dedup window. Default 10 minutes. Zero records every shadow event.
    pub fn shadow_dedup_window(mut self, window: Duration) -> Self {
        self.shadow_dedup_window = window;
        self
    }

    /// Maximum header value length considered. Longer values are truncated. Default 512.
    pub fn max_header_len(mut self, len: usize) -> Self {
        self.max_header_len = len;
        self
    }

    /// Prefix for issued tokens, such as `"sess_"`. Default none.
    ///
    /// The cookie value becomes the prefix followed by the usual 43 characters, and any presented
    /// token without the prefix is rejected before the store is consulted. Use it to tell browser
    /// sessions apart from other credentials at a glance (for example `pat_` and `svc_` API keys
    /// handled elsewhere), and to let secret scanners recognise leaked tokens. The prefix is not
    /// secret and is not part of the stored hash.
    pub fn token_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.token_prefix = Some(prefix.into());
        self
    }

    /// Validates and builds.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] for invalid cookie attributes, zero or oversized durations, a grace not
    /// shorter than the rotation interval, invalid thresholds, header names or token prefix.
    pub fn build(self) -> Result<GuardConfig, ConfigError> {
        self.cookie.validate()?;
        if !self.thresholds.is_valid() {
            return Err(ConfigError::InvalidThresholds);
        }
        if self.rotation.grace >= self.rotation.interval {
            return Err(ConfigError::GraceTooLong);
        }
        if self.max_header_len == 0 {
            return Err(ConfigError::InvalidDuration("max_header_len"));
        }
        if let Some(h) = &self.tls_fingerprint_header
            && (h.is_empty() || !h.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
        {
            return Err(ConfigError::InvalidHeaderName(h.clone()));
        }
        if let Some(p) = &self.token_prefix
            && (p.is_empty() || p.len() > 32 || !p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
        {
            return Err(ConfigError::InvalidTokenPrefix(p.clone()));
        }
        Ok(GuardConfig {
            cookie: self.cookie,
            session_lifetime: positive(self.session_lifetime, "session_lifetime")?,
            idle_timeout: positive(self.idle_timeout, "idle_timeout")?,
            trusted_proxies: self.trusted_proxies,
            tls_fingerprint_header: self.tls_fingerprint_header,
            rotation_interval: positive(self.rotation.interval, "rotation.interval")?,
            rotation_grace: bounded(self.rotation.grace, "rotation.grace")?,
            reuse_detection: positive(self.rotation.reuse_detection, "rotation.reuse_detection")?,
            checks: self.checks,
            thresholds: self.thresholds,
            mode: self.mode,
            step_up_policy: self.step_up_policy,
            ping_pong_window: bounded(self.ping_pong_window, "ping_pong_window")?,
            last_seen_write_interval: bounded(self.last_seen_write_interval, "last_seen_write_interval")?,
            event_retention: positive(self.event_retention, "event_retention")?,
            minimize_stored_events: self.minimize_stored_events,
            shadow_dedup_window: bounded(self.shadow_dedup_window, "shadow_dedup_window")?,
            max_header_len: self.max_header_len,
            token_prefix: self.token_prefix,
            orphan_reissue_window: self
                .orphan_reissue_window
                .map(|w| bounded(w, "orphan_reissue_window"))
                .transpose()?,
        })
    }
}

fn positive(d: Duration, name: &'static str) -> Result<TimeDelta, ConfigError> {
    if d.is_zero() {
        return Err(ConfigError::InvalidDuration(name));
    }
    bounded(d, name)
}

fn bounded(d: Duration, name: &'static str) -> Result<TimeDelta, ConfigError> {
    if d > MAX_DURATION {
        return Err(ConfigError::InvalidDuration(name));
    }
    TimeDelta::from_std(d).map_err(|_| ConfigError::InvalidDuration(name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::Check;

    #[test]
    fn defaults_match_the_spec() {
        let c = GuardConfig::default();
        assert_eq!(c.cookie().cookie_name(), "__Host-sid");
        assert_eq!(c.session_lifetime(), Duration::from_hours(30 * 24));
        assert_eq!(c.idle_timeout(), Duration::from_hours(7 * 24));
        assert_eq!(c.rotation(), RotationConfig::default());
        assert_eq!(c.rotation().interval, Duration::from_secs(600));
        assert_eq!(c.rotation().grace, Duration::from_secs(30));
        assert_eq!(c.mode(), Mode::Enforce);
        assert_eq!(c.step_up_policy(), StepUpPolicy::Require);
        assert_eq!(c.checks(), &Checks::default());
        assert_eq!(c.thresholds(), Thresholds::default());
        assert_eq!(c.event_retention(), Duration::from_hours(90 * 24));
        assert!(c.minimize_stored_events());
        assert_eq!(c.trusted_proxies(), &[]);
        assert_eq!(c.orphan_reissue_window(), None);
    }

    #[test]
    fn builder_sets_everything() {
        let c = GuardConfig::builder()
            .cookie_name("__Host-app")
            .session_lifetime(Duration::from_secs(3600))
            .idle_timeout(Duration::from_secs(600))
            .trusted_proxies(["10.0.0.0/8", "::1", " 192.168.1.7 "])
            .unwrap()
            .tls_fingerprint_header("X-JA4")
            .checks(Checks::default().disable(Check::AsnChanged))
            .thresholds(Thresholds {
                step_up: 30,
                revoke: 90,
            })
            .mode(Mode::Shadow)
            .step_up_policy(StepUpPolicy::Allow)
            .minimize_stored_events(false)
            .orphan_reissue_window(Duration::from_secs(3600))
            .build()
            .unwrap();
        assert_eq!(c.cookie().cookie_name(), "__Host-app");
        assert_eq!(c.orphan_reissue_window(), Some(Duration::from_secs(3600)));
        assert_eq!(c.trusted_proxies().len(), 3);
        assert!(
            c.trusted_proxies()
                .iter()
                .any(|n| n.contains(&"10.1.2.3".parse::<IpAddr>().unwrap()))
        );
        assert!(
            c.trusted_proxies()
                .iter()
                .any(|n| n.contains(&"192.168.1.7".parse::<IpAddr>().unwrap()))
        );
        assert!(
            !c.trusted_proxies()
                .iter()
                .any(|n| n.contains(&"192.168.1.8".parse::<IpAddr>().unwrap()))
        );
        assert_eq!(c.tls_fingerprint_header(), Some("x-ja4"));
        assert_eq!(c.mode(), Mode::Shadow);
        assert_eq!(c.step_up_policy(), StepUpPolicy::Allow);
        assert!(!c.minimize_stored_events());
    }

    #[test]
    fn invalid_configs_are_rejected() {
        let b = GuardConfig::builder;
        assert_eq!(
            b().trusted_proxies(["nope"]).unwrap_err(),
            ConfigError::InvalidProxy("nope".into())
        );
        assert!(matches!(
            b().cookie(CookieConfig::default().secure(false)).build(),
            Err(ConfigError::InvalidCookie(_))
        ));
        assert_eq!(
            b().thresholds(Thresholds {
                step_up: 90,
                revoke: 80
            })
            .build()
            .unwrap_err(),
            ConfigError::InvalidThresholds
        );
        assert_eq!(
            b().rotation(RotationConfig {
                grace: Duration::from_secs(600),
                ..RotationConfig::default()
            })
            .build()
            .unwrap_err(),
            ConfigError::GraceTooLong
        );
        assert_eq!(
            b().session_lifetime(Duration::ZERO).build().unwrap_err(),
            ConfigError::InvalidDuration("session_lifetime")
        );
        assert_eq!(
            b().idle_timeout(Duration::MAX).build().unwrap_err(),
            ConfigError::InvalidDuration("idle_timeout")
        );
        assert_eq!(
            b().orphan_reissue_window(Duration::MAX).build().unwrap_err(),
            ConfigError::InvalidDuration("orphan_reissue_window")
        );
        assert!(matches!(
            b().tls_fingerprint_header("x ja4").build(),
            Err(ConfigError::InvalidHeaderName(_))
        ));
    }

    #[test]
    fn token_prefix_is_optional_and_validated() {
        assert_eq!(GuardConfig::default().token_prefix(), None);
        let c = GuardConfig::builder().token_prefix("sess_").build().unwrap();
        assert_eq!(c.token_prefix(), Some("sess_"));
        for bad in ["", "se ss_", "sess;", "sess=", "é_", &"a".repeat(33)] {
            assert_eq!(
                GuardConfig::builder().token_prefix(bad).build().unwrap_err(),
                ConfigError::InvalidTokenPrefix(bad.to_owned()),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn zero_is_allowed_where_it_means_off() {
        let c = GuardConfig::builder()
            .ping_pong_window(Duration::ZERO)
            .last_seen_write_interval(Duration::ZERO)
            .shadow_dedup_window(Duration::ZERO)
            .orphan_reissue_window(Duration::ZERO)
            .rotation(RotationConfig {
                grace: Duration::ZERO,
                ..RotationConfig::default()
            })
            .build()
            .unwrap();
        assert_eq!(c.rotation().grace, Duration::ZERO);
        assert_eq!(c.orphan_reissue_window(), Some(Duration::ZERO));
    }
}
