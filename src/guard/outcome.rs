//! What guard operations return.

use std::fmt;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use crate::{event::SessionOrigin, risk::Assessment, store::SessionRecord, subject::Subject};

/// An authenticated session, as handed to the app.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct AuthSession<S> {
    /// Session id. Safe to log; key per-session app data by it.
    pub session_id: Uuid,
    /// Who the session belongs to.
    pub subject: S,
    /// When the session was created.
    pub created_at: DateTime<Utc>,
    /// When the subject last proved who they are (login or completed step-up).
    pub authenticated_at: DateTime<Utc>,
    /// Absolute expiry.
    pub expires_at: DateTime<Utc>,
}

impl<S> AuthSession<S> {
    pub(crate) fn new(session: &SessionRecord, subject: S) -> Self {
        Self {
            session_id: session.id,
            subject,
            created_at: session.created_at,
            authenticated_at: session.authenticated_at,
            expires_at: session.expires_at,
        }
    }
}

/// A freshly issued token and the `Set-Cookie` value that delivers it.
///
/// `Debug` hides the token.
#[derive(Clone)]
pub struct IssuedToken {
    /// The cookie value: the configured prefix, if any, then the token.
    pub(crate) value: SecretString,
    pub(crate) expires_at: DateTime<Utc>,
    /// Holds the token too, so it is wiped on drop like `value`.
    pub(crate) set_cookie: Zeroizing<String>,
}

impl IssuedToken {
    /// The cookie value: the configured token prefix, if any, followed by 43 base64url
    /// characters. Send it only in the cookie.
    pub fn expose(&self) -> &str {
        self.value.expose_secret()
    }

    /// When the session, and so the cookie, expires.
    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    /// The `Set-Cookie` header value. `Max-Age` counts from the guard's clock at issue time.
    pub fn set_cookie(&self) -> &str {
        &self.set_cookie
    }
}

impl fmt::Debug for IssuedToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssuedToken")
            .field("token", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// Result of [`Guard::login`](crate::Guard::login).
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct NewSession {
    /// The new session's id.
    pub session_id: Uuid,
    /// Its first token. Send [`IssuedToken::set_cookie`] with the response.
    pub token: IssuedToken,
}

/// Result of [`Guard::authenticate`](crate::Guard::authenticate).
#[derive(Clone, Debug)]
pub enum Outcome<S> {
    /// The request may proceed.
    Authenticated(Authenticated<S>),
    /// The request must be answered with 401.
    Rejected(Rejection),
}

impl<S> Outcome<S> {
    /// The session, if authenticated.
    pub fn session(&self) -> Option<&AuthSession<S>> {
        match self {
            Outcome::Authenticated(a) => Some(&a.session),
            Outcome::Rejected(_) => None,
        }
    }

    /// The rejection, if rejected.
    pub fn rejection(&self) -> Option<Rejection> {
        match self {
            Outcome::Authenticated(_) => None,
            Outcome::Rejected(r) => Some(*r),
        }
    }
}

/// An authenticated request.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Authenticated<S> {
    /// The session.
    pub session: AuthSession<S>,
    /// A replacement token to send with the response, when the token was rotated.
    pub rotated: Option<IssuedToken>,
    /// The risk assessment. Non-empty signals on an authenticated request mean the decision was
    /// recorded but not enforced (shadow mode or [`StepUpPolicy::Allow`](crate::StepUpPolicy)).
    pub assessment: Assessment,
}

/// Why a request was rejected. Every variant maps to 401.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Rejection {
    /// No token, a malformed one, or one the store does not know.
    NotAuthenticated,
    /// The session passed its absolute or idle expiry and was deleted.
    Expired,
    /// The session was revoked for token reuse or risk, and deleted.
    Revoked,
    /// The session is waiting for step-up. Keep the cookie and call
    /// [`Guard::complete_step_up`](crate::Guard::complete_step_up) after re-verifying the
    /// subject.
    StepUpRequired,
}

impl Rejection {
    /// The `error` value of the 401 JSON body.
    pub const fn as_str(self) -> &'static str {
        match self {
            Rejection::NotAuthenticated => "not_authenticated",
            Rejection::Expired => "session_expired",
            Rejection::Revoked => "session_revoked",
            Rejection::StepUpRequired => "step_up_required",
        }
    }

    /// Whether the response should delete the cookie. Everything but step-up does.
    pub const fn clears_cookie(self) -> bool {
        !matches!(self, Rejection::StepUpRequired)
    }

    /// Whether the response should also send `Clear-Site-Data: "cookies"`.
    pub const fn clears_site_data(self) -> bool {
        matches!(self, Rejection::Revoked)
    }
}

impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Result of [`Guard::complete_step_up`](crate::Guard::complete_step_up).
#[derive(Clone, Debug)]
pub enum StepUpOutcome {
    /// The session is trusted again from the current client. Send the new token.
    Completed(IssuedToken),
    /// The verified subject is not the session's subject. Nothing changed.
    SubjectMismatch,
    /// The token does not lead to a live session.
    Rejected(Rejection),
}

/// A session as listed by [`Guard::list_sessions`](crate::Guard::list_sessions) or returned by
/// [`Guard::peek`](crate::Guard::peek), for "your devices" pages.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct SessionInfo<S> {
    /// Session id.
    pub session_id: Uuid,
    /// Who the session belongs to.
    pub subject: S,
    /// When it was created.
    pub created_at: DateTime<Utc>,
    /// When the subject last proved who they are.
    pub authenticated_at: DateTime<Utc>,
    /// Last request (written at most once per write interval).
    pub last_seen_at: DateTime<Utc>,
    /// Absolute expiry.
    pub expires_at: DateTime<Utc>,
    /// Whether the session is waiting for step-up.
    pub step_up_required: bool,
    /// Browser family of the session's client.
    pub browser: Option<String>,
    /// Operating system family of the session's client.
    pub os: Option<String>,
    /// Country of the session's client, if an IP intelligence source is configured.
    pub country: Option<String>,
    /// Where the session started. `None` for sessions created before 0.2.
    pub origin: Option<SessionOrigin>,
}

impl<S: Subject> SessionInfo<S> {
    pub(crate) fn from_record(record: &SessionRecord) -> Option<Self> {
        let fp = &record.baseline.fingerprint;
        Some(Self {
            session_id: record.id,
            subject: crate::subject::decode(&record.subject)?,
            created_at: record.created_at,
            authenticated_at: record.authenticated_at,
            last_seen_at: record.last_seen_at,
            expires_at: record.expires_at,
            step_up_required: record.step_up_required,
            browser: fp.browser.clone(),
            os: fp.os.clone(),
            country: fp.country.clone(),
            origin: record.origin.clone(),
        })
    }
}

/// Result of [`Guard::purge_expired`](crate::Guard::purge_expired).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct PurgeReport {
    /// Expired sessions deleted.
    pub sessions: u64,
    /// Events older than the retention period deleted.
    pub events: u64,
}
