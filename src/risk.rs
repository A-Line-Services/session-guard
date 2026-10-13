//! Scores the current request against a session's baseline.

use chrono::{DateTime, TimeDelta, Utc};

use crate::{
    checks::{Check, Checks, Decision, Thresholds},
    fingerprint::{Baseline, Fingerprint, anonymity_change, os_compatible},
};

/// The checks that fired for a request and their summed weight.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Assessment {
    /// Sum of the weights of `signals`.
    pub score: u32,
    /// Enabled checks that fired, in [`Check::ALL`] order.
    pub signals: Vec<Check>,
}

impl Assessment {
    /// Maps the score onto a decision.
    pub fn decision(&self, thresholds: &Thresholds) -> Decision {
        thresholds.decide(self.score)
    }

    /// Adds a signal the fingerprint comparison cannot see, if `checks` enables it, keeping
    /// [`Check::ALL`] order.
    pub(crate) fn add(&mut self, check: Check, checks: &Checks) {
        if let Some(weight) = checks.weight_of(check)
            && !self.signals.contains(&check)
        {
            let at = self.signals.partition_point(|c| *c < check);
            self.signals.insert(at, check);
            self.score = self.score.saturating_add(weight);
        }
    }
}

/// Compares `current` against `baseline`.
///
/// A value the baseline knows but the request lacks counts as a change: stripping headers
/// never lowers the score. Values the baseline never had are not compared.
pub fn assess(
    baseline: &Baseline,
    current: &Fingerprint,
    now: DateTime<Utc>,
    ping_pong_window: TimeDelta,
    checks: &Checks,
) -> Assessment {
    let known = &baseline.fingerprint;
    let mut fired = Vec::with_capacity(4);

    if let (Some(a), Some(b)) = (&known.os, &current.os)
        && !os_compatible(a, b)
    {
        fired.push(Check::OsChanged);
    }

    if let (Some(a), Some(b)) = (&known.browser, &current.browser) {
        if a != b {
            fired.push(Check::BrowserChanged);
        } else if let (Some(a), Some(b)) = (known.browser_major, current.browser_major)
            && b < a
        {
            fired.push(Check::BrowserDowngraded);
        }
    }

    if lost(known.browser.as_ref(), current.browser.as_ref()) || lost(known.os.as_ref(), current.os.as_ref()) {
        fired.push(Check::UserAgentMissing);
    }

    if let (Some(a), Some(b)) = (&known.ch_platform, &current.ch_platform)
        && !os_compatible(a, b)
    {
        fired.push(Check::PlatformHintChanged);
    }

    if lost(known.ch_platform.as_ref(), current.ch_platform.as_ref())
        || lost(known.ch_mobile.as_ref(), current.ch_mobile.as_ref())
    {
        fired.push(Check::ClientHintsMissing);
    }

    if matches!((known.ch_mobile, current.ch_mobile), (Some(a), Some(b)) if a != b) {
        fired.push(Check::MobileHintChanged);
    }

    if let (Some(platform), Some(os)) = (&current.ch_platform, &current.os)
        && !os_compatible(platform, os)
    {
        fired.push(Check::InconsistentHints);
    }

    if known.ip_prefix != current.ip_prefix {
        if differs(known.country.as_ref(), current.country.as_ref()) {
            fired.push(Check::CountryChanged);
        } else if differs(known.asn.as_ref(), current.asn.as_ref()) {
            fired.push(Check::AsnChanged);
        } else {
            fired.push(Check::IpPrefixChanged);
        }

        let returned = baseline.previous_ip_prefix.as_deref() == Some(current.ip_prefix.as_str());
        let recent = baseline
            .ip_changed_at
            .is_some_and(|at| now.signed_duration_since(at) <= ping_pong_window);
        if returned && recent {
            fired.push(Check::IpPingPong);
        }

        // Returning to the previous network is no news: the client was trusted there.
        if !returned
            && let (Some(was), Some(now)) = (known.anonymity, current.anonymity)
            && let Some(check) = anonymity_change(was, now)
        {
            fired.push(check);
        }
    }

    let version_changed = matches!((known.browser_major, current.browser_major), (Some(a), Some(b)) if a != b);
    if !version_changed && differs(known.tls.as_ref(), current.tls.as_ref()) {
        fired.push(Check::TlsChanged);
    }

    if differs(known.accept_language.as_ref(), current.accept_language.as_ref()) {
        fired.push(Check::AcceptLanguageChanged);
    }

    let mut signals = Vec::with_capacity(fired.len());
    let mut score = 0u32;
    for check in Check::ALL {
        if fired.contains(&check)
            && let Some(weight) = checks.weight_of(check)
        {
            signals.push(check);
            score = score.saturating_add(weight);
        }
    }
    Assessment { score, signals }
}

/// Known and now different, or known and now missing.
fn differs<T: PartialEq>(known: Option<&T>, current: Option<&T>) -> bool {
    match (known, current) {
        (Some(a), Some(b)) => a != b,
        (Some(_), None) => true,
        (None, _) => false,
    }
}

fn lost<T>(known: Option<&T>, current: Option<&T>) -> bool {
    known.is_some() && current.is_none()
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::intel::Anonymity;

    fn chrome_on_windows() -> Fingerprint {
        Fingerprint {
            ip_prefix: "203.0.113.0/24".to_owned(),
            country: Some("BE".to_owned()),
            asn: Some(5432),
            browser: Some("Chrome".to_owned()),
            browser_major: Some(141),
            os: Some("Windows".to_owned()),
            ch_platform: Some("Windows".to_owned()),
            ch_mobile: Some(false),
            accept_language: Some("nl-be,nl,en".to_owned()),
            tls: Some("t13d1516h2_8daaf6152771_02713d6af862".to_owned()),
            anonymity: Some(Anonymity::Direct),
        }
    }

    fn via(anonymity: Anonymity) -> Fingerprint {
        let mut fp = chrome_on_windows();
        fp.ip_prefix = "198.51.100.0/24".to_owned();
        fp.asn = Some(9009);
        fp.anonymity = Some(anonymity);
        fp
    }

    fn assess_now(baseline: &Baseline, current: &Fingerprint) -> Assessment {
        assess(baseline, current, Utc::now(), TimeDelta::minutes(5), &Checks::default())
    }

    fn decide(current: &Fingerprint) -> (Decision, Vec<Check>) {
        let a = assess_now(&Baseline::new(chrome_on_windows()), current);
        (a.decision(&Thresholds::default()), a.signals)
    }

    #[test]
    fn added_signals_keep_check_order_and_respect_weights() {
        let mut current = chrome_on_windows();
        current.ip_prefix = "198.51.100.0/24".to_owned();
        current.asn = Some(6848);
        current.accept_language = Some("en".to_owned());
        let mut a = assess_now(&Baseline::new(chrome_on_windows()), &current);
        a.add(Check::OrphanedToken, &Checks::default());
        assert_eq!(
            a.signals,
            vec![Check::OrphanedToken, Check::AsnChanged, Check::AcceptLanguageChanged]
        );
        assert_eq!(a.score, 25 + 20 + 15);

        let mut a = Assessment::default();
        a.add(Check::OrphanedToken, &Checks::none());
        assert_eq!(a, Assessment::default());
    }

    #[test]
    fn identical_request_is_allowed() {
        assert_eq!(decide(&chrome_on_windows()), (Decision::Allow, vec![]));
    }

    // Legitimate users: none of these may step up or revoke.

    #[test]
    fn network_switch_within_same_provider_is_allowed() {
        let mut current = chrome_on_windows();
        current.ip_prefix = "203.0.200.0/24".to_owned();
        assert_eq!(decide(&current), (Decision::Allow, vec![Check::IpPrefixChanged]));
    }

    #[test]
    fn wifi_to_mobile_data_is_allowed() {
        let mut current = chrome_on_windows();
        current.ip_prefix = "198.51.100.0/24".to_owned();
        current.asn = Some(6848);
        assert_eq!(decide(&current), (Decision::Allow, vec![Check::AsnChanged]));
    }

    #[test]
    fn browser_update_is_allowed_even_though_tls_changes() {
        let mut current = chrome_on_windows();
        current.browser_major = Some(142);
        current.tls = Some("t13d1517h2_8daaf6152771_b0da82dd1658".to_owned());
        assert_eq!(decide(&current), (Decision::Allow, vec![]));
    }

    #[test]
    fn language_tweak_is_allowed() {
        let mut current = chrome_on_windows();
        current.accept_language = Some("en".to_owned());
        assert_eq!(decide(&current).0, Decision::Allow);
    }

    #[test]
    fn android_desktop_mode_toggle_steps_up_not_revokes() {
        let mut fp = chrome_on_windows();
        fp.os = Some("Android".to_owned());
        fp.ch_platform = Some("Android".to_owned());
        fp.ch_mobile = Some(true);
        let mut current = fp.clone();
        current.os = Some("Linux".to_owned());
        current.ch_mobile = Some(false);
        let a = assess_now(&Baseline::new(fp), &current);
        assert_eq!(a.signals, vec![Check::MobileHintChanged]);
        assert_eq!(a.decision(&Thresholds::default()), Decision::StepUp);
    }

    #[test]
    fn travel_abroad_steps_up_not_revokes() {
        let mut current = chrome_on_windows();
        current.ip_prefix = "192.0.2.0/24".to_owned();
        current.country = Some("FR".to_owned());
        current.asn = Some(3215);
        assert_eq!(decide(&current), (Decision::StepUp, vec![Check::CountryChanged]));
    }

    #[test]
    fn baseline_without_hints_ignores_hints() {
        let mut firefox = chrome_on_windows();
        firefox.browser = Some("Firefox".to_owned());
        firefox.ch_platform = None;
        firefox.ch_mobile = None;
        let a = assess_now(&Baseline::new(firefox.clone()), &firefox);
        assert_eq!(a.score, 0);
    }

    // Theft.

    #[test]
    fn different_operating_system_is_revoked() {
        let mut current = chrome_on_windows();
        current.os = Some("macOS".to_owned());
        current.ch_platform = Some("macOS".to_owned());
        assert_eq!(decide(&current).0, Decision::Revoke);
    }

    #[test]
    fn different_browser_is_revoked() {
        let mut current = chrome_on_windows();
        current.browser = Some("Firefox".to_owned());
        current.ch_platform = None;
        current.ch_mobile = None;
        assert_eq!(decide(&current).0, Decision::Revoke);
    }

    #[test]
    fn empty_user_agent_cannot_bypass_checks() {
        let mut current = chrome_on_windows();
        current.browser = None;
        current.browser_major = None;
        current.os = None;
        current.ch_platform = None;
        current.ch_mobile = None;
        let (decision, signals) = decide(&current);
        assert!(signals.contains(&Check::UserAgentMissing));
        assert!(signals.contains(&Check::ClientHintsMissing));
        assert_eq!(decision, Decision::Revoke);
    }

    #[test]
    fn dropping_only_the_mobile_hint_is_noticed() {
        let mut current = chrome_on_windows();
        current.ch_mobile = None;
        assert_eq!(decide(&current).1, vec![Check::ClientHintsMissing]);
    }

    #[test]
    fn stripping_soft_headers_never_lowers_the_score() {
        let mut current = chrome_on_windows();
        current.accept_language = None;
        current.tls = None;
        assert_eq!(
            decide(&current).1,
            vec![Check::TlsChanged, Check::AcceptLanguageChanged]
        );

        let mut current = chrome_on_windows();
        current.ip_prefix = "198.51.100.0/24".to_owned();
        current.country = None;
        assert_eq!(decide(&current).1, vec![Check::CountryChanged]);
    }

    #[test]
    fn copied_user_agent_from_script_in_same_country_is_revoked() {
        let mut current = chrome_on_windows();
        current.ip_prefix = "198.51.100.0/24".to_owned();
        current.asn = Some(9999);
        current.ch_platform = None;
        current.ch_mobile = None;
        current.tls = Some("t13d311200_e8f1e7e78f70_d41ae481755e".to_owned());
        current.accept_language = None;
        assert_eq!(decide(&current).0, Decision::Revoke);
    }

    #[test]
    fn spoofed_ua_contradicting_client_hints_is_flagged() {
        let mut current = chrome_on_windows();
        current.ch_platform = Some("Linux".to_owned());
        let (decision, signals) = decide(&current);
        assert_eq!(signals, vec![Check::PlatformHintChanged, Check::InconsistentHints]);
        assert_eq!(decision, Decision::Revoke);
    }

    #[test]
    fn alternating_between_two_networks_adds_ping_pong() {
        let now = Utc::now();
        let mut baseline = Baseline::new(chrome_on_windows());
        let mut elsewhere = chrome_on_windows();
        elsewhere.ip_prefix = "198.51.100.0/24".to_owned();
        elsewhere.asn = Some(9999);
        baseline.absorb(&elsewhere, now, &Checks::default());

        let back = chrome_on_windows();
        let soon = assess(
            &baseline,
            &back,
            now + TimeDelta::seconds(20),
            TimeDelta::minutes(5),
            &Checks::default(),
        );
        assert_eq!(soon.signals, vec![Check::IpPingPong, Check::AsnChanged]);
        // Bouncing between two ASNs within minutes looks like two parties sharing one cookie.
        assert_eq!(soon.decision(&Thresholds::default()), Decision::StepUp);

        let later = assess(
            &baseline,
            &back,
            now + TimeDelta::minutes(10),
            TimeDelta::minutes(5),
            &Checks::default(),
        );
        assert_eq!(later.signals, vec![Check::AsnChanged]);
    }

    #[test]
    fn switching_on_a_vpn_steps_up() {
        for anonymizer in [Anonymity::Vpn, Anonymity::HostingProvider, Anonymity::ResidentialProxy] {
            assert_eq!(
                decide(&via(anonymizer)),
                (Decision::StepUp, vec![Check::AnonymizerEntered, Check::AsnChanged]),
                "{anonymizer:?}"
            );
        }
        let mut abroad = via(Anonymity::Vpn);
        abroad.country = Some("NL".to_owned());
        assert_eq!(
            decide(&abroad),
            (Decision::StepUp, vec![Check::CountryChanged, Check::AnonymizerEntered])
        );
    }

    #[test]
    fn tor_steps_up_and_tor_abroad_revokes() {
        for anonymizer in [Anonymity::TorExitNode, Anonymity::PublicProxy] {
            assert_eq!(
                decide(&via(anonymizer)),
                (Decision::StepUp, vec![Check::TorOrProxyEntered, Check::AsnChanged]),
                "{anonymizer:?}"
            );
        }
        let mut abroad = via(Anonymity::TorExitNode);
        abroad.country = Some("DE".to_owned());
        assert_eq!(
            decide(&abroad),
            (Decision::Revoke, vec![Check::TorOrProxyEntered, Check::CountryChanged])
        );
    }

    #[test]
    fn anonymity_only_scores_moves_onto_a_worse_network() {
        let assess_from = |was: Option<Anonymity>, now: Option<Anonymity>| {
            let mut known = via(Anonymity::Direct);
            known.anonymity = was;
            let mut current = chrome_on_windows();
            current.anonymity = now;
            assess_now(&Baseline::new(known), &current).signals
        };
        let vpn = Some(Anonymity::Vpn);
        let tor = Some(Anonymity::TorExitNode);
        let direct = Some(Anonymity::Direct);
        assert_eq!(assess_from(vpn, direct), vec![Check::AsnChanged], "leaving a VPN");
        assert_eq!(
            assess_from(vpn, Some(Anonymity::HostingProvider)),
            vec![Check::AsnChanged]
        );
        assert_eq!(assess_from(tor, vpn), vec![Check::AsnChanged], "Tor to VPN");
        assert_eq!(assess_from(tor, Some(Anonymity::PublicProxy)), vec![Check::AsnChanged]);
        assert_eq!(assess_from(vpn, tor), vec![Check::TorOrProxyEntered, Check::AsnChanged]);
        assert_eq!(assess_from(None, tor), vec![Check::AsnChanged], "unknown baseline");
        assert_eq!(assess_from(direct, None), vec![Check::AsnChanged], "lookup failed");
    }

    #[test]
    fn anonymity_needs_a_network_move() {
        let mut current = chrome_on_windows();
        current.anonymity = Some(Anonymity::Vpn);
        assert_eq!(decide(&current), (Decision::Allow, vec![]));
    }

    #[test]
    fn toggling_a_vpn_back_on_does_not_revoke() {
        let now = Utc::now();
        let mut baseline = Baseline::new(chrome_on_windows());
        baseline.absorb(&via(Anonymity::Vpn), now, &Checks::default());
        baseline.absorb(&chrome_on_windows(), now + TimeDelta::seconds(10), &Checks::default());

        let a = assess(
            &baseline,
            &via(Anonymity::Vpn),
            now + TimeDelta::seconds(20),
            TimeDelta::minutes(5),
            &Checks::default(),
        );
        // The client was already trusted on this VPN: only the bounce counts.
        assert_eq!(a.signals, vec![Check::IpPingPong, Check::AsnChanged]);
        assert_eq!(a.decision(&Thresholds::default()), Decision::StepUp);
    }

    #[test]
    fn downgrade_is_flagged() {
        let mut current = chrome_on_windows();
        current.browser_major = Some(120);
        assert_eq!(decide(&current), (Decision::StepUp, vec![Check::BrowserDowngraded]));
    }

    #[test]
    fn disabled_checks_and_custom_weights() {
        let mut current = chrome_on_windows();
        current.os = Some("macOS".to_owned());
        let checks = Checks::default()
            .disable(Check::OsChanged)
            .weight(Check::InconsistentHints, 5);
        let a = assess(
            &Baseline::new(chrome_on_windows()),
            &current,
            Utc::now(),
            TimeDelta::minutes(5),
            &checks,
        );
        assert_eq!(a.signals, vec![Check::InconsistentHints]);
        assert_eq!(a.score, 5);
        let none = assess(
            &Baseline::new(chrome_on_windows()),
            &current,
            Utc::now(),
            TimeDelta::minutes(5),
            &Checks::none(),
        );
        assert_eq!(none, Assessment::default());
    }

    /// Changes legitimate users make routinely, one at a time.
    fn routine_change() -> impl Strategy<Value = (u8, u32)> {
        (0u8..9, any::<u32>())
    }

    fn apply_routine(fp: &mut Fingerprint, kind: u8, n: u32) {
        match kind {
            0 => fp.ip_prefix = format!("198.51.{}.0/24", n % 256),
            1 => {
                fp.ip_prefix = format!("100.64.{}.0/24", n % 256);
                fp.asn = Some(n);
            }
            2 => {
                fp.ip_prefix = format!("192.0.{}.0/24", n % 256);
                fp.country = Some(["FR", "DE", "US", "JP"][(n % 4) as usize].to_owned());
                fp.asn = Some(n);
            }
            3 => {
                fp.browser_major = fp.browser_major.map(|m| m + 1 + n % 5);
                fp.tls = Some(format!("tls-{n}"));
            }
            4 => fp.accept_language = Some(["en", "fr,en", "de-de,de"][(n % 3) as usize].to_owned()),
            5 => fp.tls = Some(format!("tls-{n}")),
            6 => fp.ch_mobile = fp.ch_mobile.map(|m| !m),
            7 => {
                fp.ip_prefix = format!("185.{}.0.0/24", n % 256);
                fp.country = Some(["BE", "NL", "CH", "US"][(n % 4) as usize].to_owned());
                fp.asn = Some(n);
                fp.anonymity = Some(Anonymity::Vpn);
            }
            _ => fp.os = Some("Linux".to_owned()),
        }
    }

    proptest! {
        #[test]
        fn no_single_routine_change_revokes(
            (kind, n) in routine_change(),
            android in any::<bool>(),
            previous in any::<bool>(),
            secs in 0i64..600,
        ) {
            let mut fp = chrome_on_windows();
            if android {
                fp.os = Some("Android".into());
                fp.ch_platform = Some("Android".into());
                fp.ch_mobile = Some(true);
            }
            if !android && kind == 8 {
                // Linux is only a routine change for Android devices.
                return Ok(());
            }
            let now = Utc::now();
            let mut baseline = Baseline::new(fp.clone());
            let mut current = fp.clone();
            apply_routine(&mut current, kind, n);
            if previous {
                baseline.previous_ip_prefix = Some(current.ip_prefix.clone());
                baseline.ip_changed_at = Some(now - TimeDelta::seconds(secs));
            }
            let a = assess(&baseline, &current, now, TimeDelta::minutes(5), &Checks::default());
            prop_assert_ne!(a.decision(&Thresholds::default()), Decision::Revoke, "{:?}", a);
        }

        #[test]
        fn score_is_sum_of_signal_weights(
            os in proptest::option::of("[A-Za-z]{1,8}"),
            browser in proptest::option::of("[A-Za-z]{1,8}"),
            major in proptest::option::of(0u32..300),
            platform in proptest::option::of("[A-Za-z]{1,8}"),
            mobile in proptest::option::of(any::<bool>()),
            lang in proptest::option::of("[a-z]{2}"),
        ) {
            let current = Fingerprint {
                os, browser, browser_major: major, ch_platform: platform, ch_mobile: mobile,
                accept_language: lang, ..chrome_on_windows()
            };
            let a = assess(&Baseline::new(chrome_on_windows()), &current, Utc::now(), TimeDelta::minutes(5), &Checks::default());
            let sum: u32 = a.signals.iter().map(|c| c.default_weight()).sum();
            prop_assert_eq!(a.score, sum);
        }
    }
}
