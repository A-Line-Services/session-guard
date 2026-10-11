//! Risk checks, their weights and the score thresholds.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};

/// A risk signal compared between a session's baseline and the current request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Check {
    /// The operating system family changed (Android↔Linux and iOS↔macOS are compatible).
    OsChanged,
    /// The browser family changed.
    BrowserChanged,
    /// The `Sec-CH-UA-Platform` client hint changed to an incompatible platform.
    PlatformHintChanged,
    /// The platform hint contradicts the operating system in the User-Agent.
    InconsistentHints,
    /// Same browser, lower major version.
    BrowserDowngraded,
    /// The User-Agent disappeared or became unparseable.
    UserAgentMissing,
    /// `Sec-CH-UA-Mobile` flipped.
    MobileHintChanged,
    /// The IP moved to another country (needs an [`IpIntel`](crate::IpIntel) source).
    CountryChanged,
    /// Client hints the session used to send disappeared.
    ClientHintsMissing,
    /// The TLS fingerprint changed while the browser version stayed the same.
    TlsChanged,
    /// The IP returned to the previous network shortly after leaving it.
    IpPingPong,
    /// The IP moved to another autonomous system (needs an [`IpIntel`](crate::IpIntel) source).
    AsnChanged,
    /// The preferred languages changed.
    AcceptLanguageChanged,
    /// The IP left its /24 (IPv4) or /48 (IPv6) network.
    IpPrefixChanged,
}

impl Check {
    /// Every check, in declaration order.
    pub const ALL: [Check; 14] = [
        Check::OsChanged,
        Check::BrowserChanged,
        Check::PlatformHintChanged,
        Check::InconsistentHints,
        Check::BrowserDowngraded,
        Check::UserAgentMissing,
        Check::MobileHintChanged,
        Check::CountryChanged,
        Check::ClientHintsMissing,
        Check::TlsChanged,
        Check::IpPingPong,
        Check::AsnChanged,
        Check::AcceptLanguageChanged,
        Check::IpPrefixChanged,
    ];

    /// The weight used by [`Checks::default`].
    pub const fn default_weight(self) -> u32 {
        match self {
            Check::OsChanged | Check::BrowserChanged | Check::PlatformHintChanged => 80,
            Check::InconsistentHints => 60,
            Check::BrowserDowngraded | Check::UserAgentMissing | Check::MobileHintChanged => 50,
            Check::CountryChanged => 40,
            Check::ClientHintsMissing | Check::TlsChanged => 30,
            Check::IpPingPong => 25,
            Check::AsnChanged => 20,
            Check::AcceptLanguageChanged => 15,
            Check::IpPrefixChanged => 10,
        }
    }

    /// Stable `snake_case` name, used in events, metrics and logs.
    pub const fn as_str(self) -> &'static str {
        match self {
            Check::OsChanged => "os_changed",
            Check::BrowserChanged => "browser_changed",
            Check::PlatformHintChanged => "platform_hint_changed",
            Check::InconsistentHints => "inconsistent_hints",
            Check::BrowserDowngraded => "browser_downgraded",
            Check::UserAgentMissing => "user_agent_missing",
            Check::MobileHintChanged => "mobile_hint_changed",
            Check::CountryChanged => "country_changed",
            Check::ClientHintsMissing => "client_hints_missing",
            Check::TlsChanged => "tls_changed",
            Check::IpPingPong => "ip_ping_pong",
            Check::AsnChanged => "asn_changed",
            Check::AcceptLanguageChanged => "accept_language_changed",
            Check::IpPrefixChanged => "ip_prefix_changed",
        }
    }

    const fn index(self) -> usize {
        self as usize
    }
}

impl fmt::Display for Check {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Returned when parsing an unknown check name.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown check {0:?}")]
pub struct UnknownCheck(pub String);

impl FromStr for Check {
    type Err = UnknownCheck;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Check::ALL
            .into_iter()
            .find(|c| c.as_str() == s)
            .ok_or_else(|| UnknownCheck(s.to_owned()))
    }
}

/// Which checks run and how much each contributes to the score.
///
/// A disabled check is not computed at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checks {
    weights: [Option<u32>; 14],
}

impl Default for Checks {
    /// Every check enabled at its [default weight](Check::default_weight).
    fn default() -> Self {
        Self {
            weights: Check::ALL.map(|c| Some(c.default_weight())),
        }
    }
}

impl Checks {
    /// No checks: only token rotation and reuse detection protect the session.
    pub const fn none() -> Self {
        Self { weights: [None; 14] }
    }

    /// Default weights with network and environment signals raised, for sensitive routes:
    /// IP prefix, ASN, language, TLS and ping-pong weigh 40 (step-up on their own) and a country
    /// change weighs 80 (revoke).
    pub fn strict() -> Self {
        Self::default()
            .weight(Check::IpPrefixChanged, 40)
            .weight(Check::AsnChanged, 40)
            .weight(Check::AcceptLanguageChanged, 40)
            .weight(Check::TlsChanged, 40)
            .weight(Check::IpPingPong, 40)
            .weight(Check::CountryChanged, 80)
    }

    /// Turns `check` off.
    #[must_use]
    pub const fn disable(mut self, check: Check) -> Self {
        self.weights[check.index()] = None;
        self
    }

    /// Turns `check` on at its default weight (keeps a custom weight if already enabled).
    #[must_use]
    pub const fn enable(mut self, check: Check) -> Self {
        if self.weights[check.index()].is_none() {
            self.weights[check.index()] = Some(check.default_weight());
        }
        self
    }

    /// Enables `check` with a custom weight.
    #[must_use]
    pub const fn weight(mut self, check: Check, weight: u32) -> Self {
        self.weights[check.index()] = Some(weight);
        self
    }

    /// Whether `check` runs.
    pub const fn is_enabled(&self, check: Check) -> bool {
        self.weights[check.index()].is_some()
    }

    /// The weight of `check`, or `None` if disabled.
    pub const fn weight_of(&self, check: Check) -> Option<u32> {
        self.weights[check.index()]
    }
}

/// What the score means.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Decision {
    /// Below the step-up threshold.
    Allow,
    /// At or above step-up, below revoke.
    StepUp,
    /// At or above revoke.
    Revoke,
}

impl Decision {
    /// Stable `snake_case` name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Decision::Allow => "allow",
            Decision::StepUp => "step_up",
            Decision::Revoke => "revoke",
        }
    }
}

/// Score thresholds. Defaults: step-up at 40, revoke at 80.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Thresholds {
    /// Scores at or above this need step-up.
    pub step_up: u32,
    /// Scores at or above this revoke the session.
    pub revoke: u32,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            step_up: 40,
            revoke: 80,
        }
    }
}

impl Thresholds {
    /// Maps a score to a decision.
    pub const fn decide(&self, score: u32) -> Decision {
        if score >= self.revoke {
            Decision::Revoke
        } else if score >= self.step_up {
            Decision::StepUp
        } else {
            Decision::Allow
        }
    }

    pub(crate) const fn is_valid(self) -> bool {
        self.step_up > 0 && self.step_up <= self.revoke
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_weights_match_the_spec() {
        let c = Checks::default();
        let expected = [80, 80, 80, 60, 50, 50, 50, 40, 30, 30, 25, 20, 15, 10];
        for (check, w) in Check::ALL.into_iter().zip(expected) {
            assert_eq!(c.weight_of(check), Some(w), "{check}");
        }
    }

    #[test]
    fn names_round_trip_and_match_serde() {
        for check in Check::ALL {
            assert_eq!(check.as_str().parse::<Check>(), Ok(check));
            assert_eq!(
                serde_json::to_string(&check).unwrap(),
                format!("\"{}\"", check.as_str())
            );
        }
        assert!("nope".parse::<Check>().is_err());
    }

    #[test]
    fn enable_disable_and_weight() {
        let c = Checks::default().disable(Check::AsnChanged);
        assert!(!c.is_enabled(Check::AsnChanged));
        assert_eq!(c.enable(Check::AsnChanged).weight_of(Check::AsnChanged), Some(20));
        let c = Checks::none().weight(Check::OsChanged, 5).enable(Check::OsChanged);
        assert_eq!(c.weight_of(Check::OsChanged), Some(5));
        assert!(Check::ALL.into_iter().skip(1).all(|ch| !c.is_enabled(ch)));
    }

    #[test]
    fn strict_raises_soft_signals() {
        let s = Checks::strict();
        assert_eq!(s.weight_of(Check::IpPrefixChanged), Some(40));
        assert_eq!(s.weight_of(Check::CountryChanged), Some(80));
        assert_eq!(s.weight_of(Check::OsChanged), Some(80));
    }

    #[test]
    fn thresholds_decide() {
        let t = Thresholds::default();
        assert_eq!(t.decide(0), Decision::Allow);
        assert_eq!(t.decide(39), Decision::Allow);
        assert_eq!(t.decide(40), Decision::StepUp);
        assert_eq!(t.decide(79), Decision::StepUp);
        assert_eq!(t.decide(80), Decision::Revoke);
        assert!(t.is_valid());
        assert!(!Thresholds { step_up: 0, revoke: 10 }.is_valid());
        assert!(
            !Thresholds {
                step_up: 50,
                revoke: 10
            }
            .is_valid()
        );
    }
}
