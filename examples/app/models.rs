//! Request and response bodies.

use rovo::schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use session_guard::SessionInfo;
use uuid::Uuid;

/// What the client sends to log in, and again to step up.
#[derive(Deserialize, JsonSchema)]
pub struct Credentials {
    /// Account name.
    pub username: String,
    /// Account password.
    pub password: String,
}

/// An error response body.
#[derive(Serialize, JsonSchema)]
pub struct ErrorBody {
    /// Machine-readable error code.
    pub error: String,
}

/// The session that was just created.
#[derive(Serialize, JsonSchema)]
pub struct LoggedIn {
    /// The new session's id.
    pub session_id: Uuid,
}

/// Acknowledgement of an action.
#[derive(Serialize, JsonSchema)]
pub struct Done {
    /// Always `true`.
    pub ok: bool,
}

/// Who is signed in.
#[derive(Serialize, JsonSchema)]
pub struct Me {
    /// The session's subject, the id passed to `login`.
    pub subject: Uuid,
    /// This session's id.
    pub session_id: Uuid,
    /// When the user last proved who they are (login or step-up), RFC 3339.
    pub authenticated_at: String,
    /// When the session expires, RFC 3339.
    pub expires_at: String,
}

/// One of the user's sessions ("your devices").
#[derive(Serialize, JsonSchema)]
pub struct SessionView {
    /// Session id, what `DELETE /sessions/{id}` takes.
    pub session_id: Uuid,
    /// Whether this is the session making the request.
    pub current: bool,
    /// When it was created, RFC 3339.
    pub created_at: String,
    /// When it was last seen, RFC 3339.
    pub last_seen_at: String,
    /// Browser family, if known.
    pub browser: Option<String>,
    /// Operating system family, if known.
    pub os: Option<String>,
    /// Country, if an IP intelligence source is configured.
    pub country: Option<String>,
}

impl SessionView {
    /// The view of `info`, as seen from the session `current`.
    pub fn new(info: SessionInfo<Uuid>, current: Uuid) -> Self {
        Self {
            session_id: info.session_id,
            current: info.session_id == current,
            created_at: info.created_at.to_rfc3339(),
            last_seen_at: info.last_seen_at.to_rfc3339(),
            browser: info.browser,
            os: info.os,
            country: info.country,
        }
    }
}

/// The outcome of the sensitive action.
#[derive(Serialize, JsonSchema)]
pub struct Transferred {
    /// Always `transferred`.
    pub status: String,
}

/// Which credential an API request used.
#[derive(Serialize, JsonSchema)]
pub struct Pong {
    /// Always `api_key`.
    pub auth: String,
}
