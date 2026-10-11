//! Normalised client signals and the per-session baseline they are compared against.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use ipnet::IpNet;
use quick_cache::sync::Cache;
use serde::{Deserialize, Serialize};

use crate::{
    checks::{Check, Checks},
    client::ClientContext,
    intel::IpInfo,
};

/// Normalised client signals. Stored server-side only, never sent to the client.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[non_exhaustive]
pub struct Fingerprint {
    /// The client's /24 (IPv4) or /48 (IPv6) network, e.g. `203.0.113.0/24`.
    pub ip_prefix: String,
    /// Country code from the [`IpIntel`](crate::IpIntel) source.
    pub country: Option<String>,
    /// Autonomous system number from the [`IpIntel`](crate::IpIntel) source.
    pub asn: Option<u32>,
    /// Browser family parsed from the User-Agent.
    pub browser: Option<String>,
    /// Browser major version.
    pub browser_major: Option<u32>,
    /// Operating system family parsed from the User-Agent.
    pub os: Option<String>,
    /// Platform family from `Sec-CH-UA-Platform`.
    pub ch_platform: Option<String>,
    /// `Sec-CH-UA-Mobile`.
    pub ch_mobile: Option<bool>,
    /// Up to three lowercase language tags, comma separated.
    pub accept_language: Option<String>,
    /// TLS fingerprint (for example JA4) passed by the proxy.
    pub tls: Option<String>,
}

impl Fingerprint {
    /// Normalises a request context. `info` comes from the [`IpIntel`](crate::IpIntel) source.
    pub fn capture(ctx: &ClientContext, info: IpInfo) -> Self {
        Self::build(
            ctx,
            info,
            ctx.user_agent.as_deref().map(parse_user_agent).unwrap_or_default(),
        )
    }

    pub(crate) fn capture_cached(ctx: &ClientContext, info: IpInfo, cache: &UaCache) -> Self {
        Self::build(
            ctx,
            info,
            ctx.user_agent.as_deref().map(|ua| cache.parse(ua)).unwrap_or_default(),
        )
    }

    fn build(ctx: &ClientContext, info: IpInfo, ua: ParsedUa) -> Self {
        Self {
            ip_prefix: ip_prefix(ctx.ip),
            country: info.country.filter(|c| !c.is_empty()),
            asn: info.asn,
            browser: ua.browser,
            browser_major: ua.major,
            os: ua.os,
            ch_platform: ctx.ch_platform.as_deref().and_then(platform_family),
            ch_mobile: ctx.ch_mobile,
            accept_language: ctx.accept_language.as_deref().and_then(normalise_languages),
            tls: ctx.tls_fingerprint.clone().filter(|t| !t.is_empty()),
        }
    }
}

/// What a session is compared against.
///
/// Hard identity (browser family, OS, client hints) is fixed at login or step-up. Soft signals
/// (network, country, ASN, languages, TLS fingerprint, browser version) follow the client as
/// trusted requests come in.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[non_exhaustive]
pub struct Baseline {
    /// The reference fingerprint.
    pub fingerprint: Fingerprint,
    /// The network the client was on before the last move.
    pub previous_ip_prefix: Option<String>,
    /// When the client last moved network.
    pub ip_changed_at: Option<DateTime<Utc>>,
}

impl Baseline {
    /// A fresh baseline, as set at login and after a completed step-up.
    pub fn new(fingerprint: Fingerprint) -> Self {
        Self {
            fingerprint,
            previous_ip_prefix: None,
            ip_changed_at: None,
        }
    }

    /// Learns soft signals from a request that was let through. Only signals that `checks`
    /// scored are learned, so a route with looser checks cannot slip a change past stricter
    /// ones. Hard identity is never learned and missing values never erase known ones. Returns
    /// whether anything changed.
    pub fn absorb(&mut self, current: &Fingerprint, now: DateTime<Utc>, checks: &Checks) -> bool {
        let before = self.clone();
        let fp = &mut self.fingerprint;
        let ip_scored = checks.scores(Check::IpPrefixChanged) || checks.scores(Check::IpPingPong);
        if ip_scored && fp.ip_prefix != current.ip_prefix && !current.ip_prefix.is_empty() {
            self.previous_ip_prefix = Some(std::mem::replace(&mut fp.ip_prefix, current.ip_prefix.clone()));
            self.ip_changed_at = Some(now);
        }
        if checks.scores(Check::CountryChanged) {
            keep_known(&mut fp.country, current.country.as_ref());
        }
        if checks.scores(Check::AsnChanged) {
            keep_known(&mut fp.asn, current.asn.as_ref());
        }
        if checks.scores(Check::AcceptLanguageChanged) {
            keep_known(&mut fp.accept_language, current.accept_language.as_ref());
        }
        if checks.scores(Check::TlsChanged) {
            keep_known(&mut fp.tls, current.tls.as_ref());
        }
        if checks.scores(Check::BrowserDowngraded) {
            fp.browser_major = fp.browser_major.max(current.browser_major);
        }
        *self != before
    }
}

fn keep_known<T: Clone>(slot: &mut Option<T>, value: Option<&T>) {
    if let Some(v) = value {
        *slot = Some(v.clone());
    }
}

/// The client's /24 (IPv4) or /48 (IPv6) network.
pub fn ip_prefix(ip: IpAddr) -> String {
    let len = if ip.is_ipv4() { 24 } else { 48 };
    IpNet::new(ip, len).map_or_else(|_| ip.to_string(), |net| net.trunc().to_string())
}

/// Android↔Linux and iOS↔macOS flip with desktop-mode toggles, so they are compatible.
pub(crate) fn os_compatible(a: &str, b: &str) -> bool {
    a == b
        || matches!(
            (a, b),
            ("Android", "Linux") | ("Linux", "Android") | ("iOS", "macOS") | ("macOS", "iOS")
        )
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ParsedUa {
    browser: Option<String>,
    major: Option<u32>,
    os: Option<String>,
}

fn parse_user_agent(ua: &str) -> ParsedUa {
    let Some(parsed) = woothee::parser::Parser::new().parse(ua) else {
        return ParsedUa::default();
    };
    let known = |v: &str| (!v.is_empty() && v != woothee::woothee::VALUE_UNKNOWN).then(|| v.to_owned());
    let browser = known(parsed.name);
    ParsedUa {
        major: browser
            .as_ref()
            .and(parsed.version.split('.').next())
            .and_then(|m| m.parse().ok()),
        os: known(parsed.os).map(|os| os_family(&os)),
        browser,
    }
}

/// Bounded LRU-ish cache of parsed User-Agents; most traffic repeats a handful of strings.
pub(crate) struct UaCache(Cache<String, ParsedUa>);

impl UaCache {
    pub(crate) fn new(capacity: usize) -> Self {
        Self(Cache::new(capacity.max(1)))
    }

    fn parse(&self, ua: &str) -> ParsedUa {
        if let Some(hit) = self.0.get(ua) {
            return hit;
        }
        let parsed = parse_user_agent(ua);
        self.0.insert(ua.to_owned(), parsed.clone());
        parsed
    }
}

impl std::fmt::Debug for UaCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UaCache").field("len", &self.0.len()).finish()
    }
}

fn os_family(os: &str) -> String {
    match os {
        os if os.starts_with("Windows") => "Windows",
        "Mac OSX" | "Mac OS Classic" => "macOS",
        "iPhone" | "iPad" | "iPod" | "iOS" => "iOS",
        "ChromeOS" => "ChromeOS",
        other => other,
    }
    .to_owned()
}

fn platform_family(platform: &str) -> Option<String> {
    match platform.trim() {
        "Unknown" | "" => None,
        "Chrome OS" | "Chromium OS" => Some("ChromeOS".to_owned()),
        other => Some(other.to_owned()),
    }
}

fn normalise_languages(header: &str) -> Option<String> {
    let tags: Vec<String> = header
        .split(',')
        .filter_map(|part| part.split(';').next())
        .map(|tag| tag.trim().to_ascii_lowercase())
        .filter(|tag| !tag.is_empty() && tag != "*")
        .take(3)
        .collect();
    (!tags.is_empty()).then(|| tags.join(","))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const CHROME_WIN: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36";

    fn ctx(ua: Option<&str>) -> ClientContext {
        let mut ctx = ClientContext::new("203.0.113.77".parse().unwrap())
            .with_ch_platform("\"Windows\"")
            .with_ch_mobile(false)
            .with_accept_language("nl-BE,nl;q=0.9,en-US;q=0.8,en;q=0.7");
        ctx.user_agent = ua.map(str::to_owned);
        ctx
    }

    #[test]
    fn captures_normalised_signals() {
        let fp = Fingerprint::capture(&ctx(Some(CHROME_WIN)), IpInfo::new(Some("BE".into()), Some(5432)));
        assert_eq!(fp.ip_prefix, "203.0.113.0/24");
        assert_eq!(fp.country.as_deref(), Some("BE"));
        assert_eq!(fp.asn, Some(5432));
        assert_eq!(fp.browser.as_deref(), Some("Chrome"));
        assert_eq!(fp.browser_major, Some(141));
        assert_eq!(fp.os.as_deref(), Some("Windows"));
        assert_eq!(fp.ch_platform.as_deref(), Some("Windows"));
        assert_eq!(fp.accept_language.as_deref(), Some("nl-be,nl,en-us"));
    }

    #[test]
    fn cached_capture_matches_uncached() {
        let cache = UaCache::new(8);
        let a = Fingerprint::capture(&ctx(Some(CHROME_WIN)), IpInfo::default());
        let b = Fingerprint::capture_cached(&ctx(Some(CHROME_WIN)), IpInfo::default(), &cache);
        let c = Fingerprint::capture_cached(&ctx(Some(CHROME_WIN)), IpInfo::default(), &cache);
        assert_eq!(a, b);
        assert_eq!(b, c);
    }

    #[test]
    fn garbage_user_agent_yields_unknowns() {
        let fp = Fingerprint::capture(&ctx(Some("definitely not a browser")), IpInfo::default());
        assert_eq!((fp.browser, fp.browser_major, fp.os), (None, None, None));
        let fp = Fingerprint::capture(&ctx(None), IpInfo::default());
        assert_eq!(fp.browser, None);
    }

    #[test]
    fn os_families_and_platforms() {
        let mac = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15";
        let iphone = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1";
        assert_eq!(
            Fingerprint::capture(&ctx(Some(mac)), IpInfo::default()).os.as_deref(),
            Some("macOS")
        );
        assert_eq!(
            Fingerprint::capture(&ctx(Some(iphone)), IpInfo::default())
                .os
                .as_deref(),
            Some("iOS")
        );
        assert_eq!(platform_family("Chrome OS").as_deref(), Some("ChromeOS"));
        assert_eq!(platform_family("Unknown"), None);
        assert!(os_compatible("Android", "Linux") && os_compatible("macOS", "iOS"));
        assert!(!os_compatible("Windows", "macOS"));
    }

    #[test]
    fn ip_prefixes() {
        assert_eq!(ip_prefix("2001:db8:abcd:12::1".parse().unwrap()), "2001:db8:abcd::/48");
        assert_eq!(ip_prefix("10.1.2.3".parse().unwrap()), "10.1.2.0/24");
    }

    #[test]
    fn languages_are_normalised() {
        assert_eq!(normalise_languages("*"), None);
        assert_eq!(normalise_languages(" EN ; q=1, fr").as_deref(), Some("en,fr"));
    }

    fn base() -> Fingerprint {
        Fingerprint::capture(&ctx(Some(CHROME_WIN)), IpInfo::new(Some("BE".into()), Some(5432)))
    }

    #[test]
    fn absorb_tracks_moves_and_never_downgrades_version() {
        let now = Utc::now();
        let original = base();
        let mut baseline = Baseline::new(original.clone());

        let mut moved = original.clone();
        moved.ip_prefix = "198.51.100.0/24".to_owned();
        moved.asn = Some(6848);
        moved.country = None;
        moved.browser_major = Some(140);
        moved.accept_language = None;
        assert!(baseline.absorb(&moved, now, &Checks::default()));

        let fp = &baseline.fingerprint;
        assert_eq!(fp.ip_prefix, "198.51.100.0/24");
        assert_eq!(baseline.previous_ip_prefix.as_deref(), Some("203.0.113.0/24"));
        assert_eq!(baseline.ip_changed_at, Some(now));
        assert_eq!(fp.asn, Some(6848));
        assert_eq!(fp.country.as_deref(), Some("BE"), "missing country never erases");
        assert_eq!(fp.browser_major, Some(141));
        assert_eq!(fp.accept_language, original.accept_language);
    }

    #[test]
    fn absorb_never_learns_hard_identity() {
        let mut baseline = Baseline::new(base());
        let mut other = base();
        other.browser = Some("Firefox".into());
        other.os = Some("Linux".into());
        other.ch_platform = Some("Linux".into());
        other.ch_mobile = Some(true);
        assert!(!baseline.absorb(&other, Utc::now(), &Checks::default()));
        assert_eq!(baseline.fingerprint, base());
    }

    #[test]
    fn absorb_learns_only_scored_signals() {
        let original = base();
        let mut baseline = Baseline::new(original.clone());
        let mut moved = original.clone();
        moved.ip_prefix = "198.51.100.0/24".to_owned();
        moved.asn = Some(6848);
        moved.accept_language = Some("de-DE".into());
        let checks = Checks::default()
            .disable(Check::AsnChanged)
            .disable(Check::IpPrefixChanged)
            .disable(Check::IpPingPong)
            .weight(Check::AcceptLanguageChanged, 0);
        assert!(!baseline.absorb(&moved, Utc::now(), &checks));
        assert_eq!(baseline.fingerprint, original);

        let ping_pong_only = Checks::none().enable(Check::IpPingPong);
        assert!(baseline.absorb(&moved, Utc::now(), &ping_pong_only));
        assert_eq!(baseline.fingerprint.ip_prefix, "198.51.100.0/24");
        assert_eq!(baseline.fingerprint.asn, original.asn);
    }

    #[test]
    fn absorb_reports_no_change_for_identical_request() {
        let mut baseline = Baseline::new(base());
        assert!(!baseline.absorb(&base(), Utc::now(), &Checks::default()));
    }

    #[test]
    fn baseline_round_trips_json_and_tolerates_missing_fields() {
        let b = Baseline::new(base());
        let json = serde_json::to_string(&b).unwrap();
        assert_eq!(serde_json::from_str::<Baseline>(&json).unwrap(), b);
        assert_eq!(serde_json::from_str::<Baseline>("{}").unwrap(), Baseline::default());
    }
}
