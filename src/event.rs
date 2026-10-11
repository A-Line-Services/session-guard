//! Security events: what happened to a session, recorded in the store and passed to the hook.

use std::{fmt, net::IpAddr};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{checks::Check, subject::Subject};

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
}

impl EventKind {
    /// Every kind, in declaration order.
    pub const ALL: [EventKind; 7] = [
        EventKind::Login,
        EventKind::Logout,
        EventKind::StepUpRequired,
        EventKind::StepUpCompleted,
        EventKind::RiskRevoked,
        EventKind::TokenReuse,
        EventKind::TokenReissued,
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
        }
    }

    /// Parses [`as_str`](Self::as_str) output.
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == name)
    }

    /// Whether this kind points at a possible attack (logged as a warning).
    pub const fn is_security_relevant(self) -> bool {
        matches!(
            self,
            EventKind::StepUpRequired | EventKind::RiskRevoked | EventKind::TokenReuse | EventKind::TokenReissued
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
#[derive(Clone, Debug, PartialEq, Eq)]
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
    /// Client IP, or only its /24 or /48 network address with
    /// [`minimize_event_ip`](crate::GuardConfigBuilder::minimize_event_ip).
    pub ip: IpAddr,
    /// Client User-Agent, truncated to the header cap.
    pub user_agent: Option<String>,
    /// When it happened.
    pub at: DateTime<Utc>,
}

impl SessionEvent {
    /// The subject as `S`, or `None` if the stored value does not parse as `S`.
    pub fn subject<S: Subject>(&self) -> Option<S> {
        crate::subject::decode(&self.subject)
    }
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
            at: Utc::now(),
        };
        assert_eq!(event.subject::<Uuid>(), Some(id));
        assert_eq!(event.subject::<i64>(), None);
    }
}
