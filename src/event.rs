//! Security events: what happened to a session, recorded in the store and passed to the hook.

use std::{fmt, net::IpAddr};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    checks::Check,
    fingerprint::Fingerprint,
    intel::{Anonymity, IpInfo},
    subject::Subject,
};

/// What happened.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EventKind {
    /// A session was created.
    Login,
    /// The client ended its session.
    Logout,
    /// The risk score reached the step-up threshold.
    StepUpRequired,
    /// The subject re-verified and the session was trusted again.
    StepUpCompleted,
    /// The risk score reached the revoke threshold (or step-up under
    /// [`StepUpPolicy::Revoke`](crate::StepUpPolicy::Revoke)).
    RiskRevoked,
    /// A superseded token was presented after its successor was used: two parties hold the
    /// session, so it was revoked. Always enforced, also in shadow mode.
    TokenReuse,
    /// A token whose successor never reached the client was replaced (lost response).
    TokenReissued,
    /// The app ended the session ([`Guard::revoke_session`](crate::Guard::revoke_session) or
    /// [`Guard::revoke_all_for_subject`](crate::Guard::revoke_all_for_subject)). The event's
    /// client is whoever asked, not the session's.
    Revoked,
}

impl EventKind {
    /// Every kind, in declaration order.
    pub const ALL: [EventKind; 8] = [
        EventKind::Login,
        EventKind::Logout,
        EventKind::StepUpRequired,
        EventKind::StepUpCompleted,
        EventKind::RiskRevoked,
        EventKind::TokenReuse,
        EventKind::TokenReissued,
        EventKind::Revoked,
    ];

    /// Stable `snake_case` name, as stored.
    pub const fn as_str(self) -> &'static str {
        match self {
            EventKind::Login => "login",
            EventKind::Logout => "logout",
            EventKind::StepUpRequired => "step_up_required",
            EventKind::StepUpCompleted => "step_up_completed",
            EventKind::RiskRevoked => "risk_revoked",
            EventKind::TokenReuse => "token_reuse",
            EventKind::TokenReissued => "token_reissued",
            EventKind::Revoked => "revoked",
        }
    }

    /// Parses [`as_str`](Self::as_str) output.
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == name)
    }

    /// Whether this kind points at a possible attack (logged as a warning).
    ///
    /// [`TokenReissued`](Self::TokenReissued) is not one: a lost response is routine, and the
    /// attack signal is [`TokenReuse`](Self::TokenReuse).
    pub const fn is_security_relevant(self) -> bool {
        matches!(
            self,
            EventKind::StepUpRequired | EventKind::RiskRevoked | EventKind::TokenReuse
        )
    }
}

impl fmt::Display for EventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One security event.
///
/// The subject is kept in its stored form (canonical JSON, see [`Subject`]); use
/// [`subject`](Self::subject) to get it back as your type.
///
/// The [`on_event`](crate::GuardBuilder::on_event) hook gets every client detail, for alerts.
/// The copy written to the store leaves out the precise ones unless
/// [`minimize_stored_events`](crate::GuardConfigBuilder::minimize_stored_events) is turned off.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct SessionEvent {
    /// The session concerned.
    pub session_id: Uuid,
    /// The session's subject, as stored.
    pub subject: String,
    /// What happened.
    pub kind: EventKind,
    /// `false` when the decision was only recorded (shadow mode, or
    /// [`StepUpPolicy::Allow`](crate::StepUpPolicy::Allow)).
    pub enforced: bool,
    /// Risk score, for risk decisions.
    pub score: Option<u32>,
    /// Signals that fired, for risk decisions.
    pub signals: Vec<Check>,
    /// Client IP. The stored copy keeps only its /24 or /48 network address by default.
    pub ip: IpAddr,
    /// Client User-Agent, truncated to the header cap. Not stored by default.
    pub user_agent: Option<String>,
    /// Where the request came from and what sent it. The stored copy leaves out the city by
    /// default.
    pub client: ClientSummary,
    /// When it happened.
    pub at: DateTime<Utc>,
}

impl SessionEvent {
    /// The subject as `S`, or `None` if the stored value does not parse as `S`.
    pub fn subject<S: Subject>(&self) -> Option<S> {
        crate::subject::decode(&self.subject)
    }
}

/// What the guard knew about the client of an event: [`IpIntel`](crate::IpIntel) data and the
/// parsed User-Agent. Each field is `None` when its source has no answer.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[non_exhaustive]
pub struct ClientSummary {
    /// ISO 3166-1 alpha-2 country code.
    pub country: Option<String>,
    /// City name.
    pub city: Option<String>,
    /// Autonomous system number.
    pub asn: Option<u32>,
    /// Name of the organization behind the autonomous system.
    pub network: Option<String>,
    /// Anonymizer the network belongs to.
    pub anonymity: Option<Anonymity>,
    /// Browser family.
    pub browser: Option<String>,
    /// Operating system family.
    pub os: Option<String>,
}

impl ClientSummary {
    pub(crate) fn observed(info: IpInfo, fingerprint: Fingerprint) -> Self {
        Self {
            country: fingerprint.country,
            city: info.city.filter(|c| !c.is_empty()),
            asn: fingerprint.asn,
            network: info.network.filter(|n| !n.is_empty()),
            anonymity: fingerprint.anonymity,
            browser: fingerprint.browser,
            os: fingerprint.os,
        }
    }

    /// The summary as kept in the store under `minimize_stored_events`: the city could undo
    /// the IP masking.
    pub(crate) fn minimized(mut self) -> Self {
        self.city = None;
        self
    }
}

/// Where a session started, recorded at login. The precise parts (`ip`, `user_agent`, the
/// city) are kept only with
/// [`keep_origin_client`](crate::GuardConfigBuilder::keep_origin_client).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SessionOrigin {
    /// Login time.
    pub at: DateTime<Utc>,
    /// The client IP's /24 (IPv4) or /48 (IPv6) network address.
    pub ip_prefix: IpAddr,
    /// Client IP. Only with `keep_origin_client`.
    #[serde(default)]
    pub ip: Option<IpAddr>,
    /// Client User-Agent, truncated to the header cap. Only with `keep_origin_client`.
    #[serde(default)]
    pub user_agent: Option<String>,
    /// Where the login came from and what sent it. No city unless `keep_origin_client`.
    #[serde(default)]
    pub client: ClientSummary,
}

/// Reduces an address to its /24 (IPv4) or /48 (IPv6) network address.
pub(crate) fn mask_ip(ip: IpAddr) -> IpAddr {
    let len = if ip.is_ipv4() { 24 } else { 48 };
    ipnet::IpNet::new(ip, len).map_or(ip, |net| net.trunc().addr())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip_and_match_serde() {
        for kind in EventKind::ALL {
            assert_eq!(EventKind::parse(kind.as_str()), Some(kind));
            assert_eq!(serde_json::to_string(&kind).unwrap(), format!("\"{kind}\""));
        }
        assert_eq!(EventKind::parse("nope"), None);
    }

    #[test]
    fn client_summary_reads_missing_fields_as_none() {
        let client: ClientSummary = serde_json::from_str(r#"{"country":"BE","later":1}"#).unwrap();
        assert_eq!(client.country.as_deref(), Some("BE"));
        assert_eq!(client.city, None);
        let all = ClientSummary {
            country: Some("BE".into()),
            city: Some("Ghent".into()),
            asn: Some(64500),
            network: Some("Example Net".into()),
            anonymity: Some(Anonymity::Vpn),
            browser: Some("Firefox".into()),
            os: Some("Linux".into()),
        };
        let json = serde_json::to_string(&all).unwrap();
        assert_eq!(serde_json::from_str::<ClientSummary>(&json).unwrap(), all);
    }

    #[test]
    fn session_origin_reads_missing_fields_as_none() {
        let origin: SessionOrigin =
            serde_json::from_str(r#"{"at":"2026-03-01T12:00:00Z","ip_prefix":"203.0.113.0"}"#).unwrap();
        assert_eq!(origin.ip_prefix, "203.0.113.0".parse::<IpAddr>().unwrap());
        assert_eq!(origin.ip, None);
        assert_eq!(origin.user_agent, None);
        assert_eq!(origin.client, ClientSummary::default());
        let full = SessionOrigin {
            ip: Some("203.0.113.7".parse().unwrap()),
            user_agent: Some("Firefox".into()),
            client: ClientSummary {
                city: Some("Ghent".into()),
                ..ClientSummary::default()
            },
            ..origin
        };
        let json = serde_json::to_string(&full).unwrap();
        assert_eq!(serde_json::from_str::<SessionOrigin>(&json).unwrap(), full);
    }

    #[test]
    fn mask_ip_keeps_the_network() {
        assert_eq!(
            mask_ip("203.0.113.7".parse().unwrap()),
            "203.0.113.0".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            mask_ip("2001:db8:1:2::7".parse().unwrap()),
            "2001:db8:1::".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn subject_decodes() {
        let id = Uuid::new_v4();
        let event = SessionEvent {
            session_id: Uuid::new_v4(),
            subject: crate::subject::encode(&id).unwrap(),
            kind: EventKind::Login,
            enforced: true,
            score: None,
            signals: vec![],
            ip: "203.0.113.7".parse().unwrap(),
            user_agent: None,
            client: ClientSummary::default(),
            at: Utc::now(),
        };
        assert_eq!(event.subject::<Uuid>(), Some(id));
        assert_eq!(event.subject::<i64>(), None);
    }
}
