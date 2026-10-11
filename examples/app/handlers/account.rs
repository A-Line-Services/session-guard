//! The signed-in user and their sessions.

use rovo::{
    extract::{Path, State},
    response::Json,
    rovo,
};
use session_guard::AuthSession;
use uuid::Uuid;

use crate::app::{
    errors::AppError,
    models::{Done, ErrorBody, Me, SessionView},
    state::AppState,
};

/// The signed-in user.
///
/// `AuthSession` is the session the layer authenticated. Without a valid session this handler
/// is never reached: the extractor answers 401 `not_authenticated`.
///
/// # Responses
///
/// 200: Json<Me> - The current session
///
/// # Metadata
///
/// @tag account
#[rovo(state = AppState)]
pub async fn me(session: AuthSession<Uuid>) -> Json<Me> {
    Json(Me {
        subject: session.subject,
        session_id: session.session_id,
        authenticated_at: session.authenticated_at.to_rfc3339(),
        expires_at: session.expires_at.to_rfc3339(),
    })
}

/// List the user's sessions.
///
/// # Responses
///
/// 200: Json<Vec<SessionView>> - Every live session of the signed-in user
/// 500: Json<ErrorBody> - Internal error
///
/// # Metadata
///
/// @tag account
#[rovo]
pub async fn list_sessions(
    State(state): State<AppState>,
    session: AuthSession<Uuid>,
) -> Result<Json<Vec<SessionView>>, AppError> {
    let sessions = state.guard.list_sessions(&session.subject).await?;
    Ok(Json(
        sessions
            .into_iter()
            .map(|info| SessionView::new(info, session.session_id))
            .collect(),
    ))
}

/// Revoke one of the user's sessions.
///
/// # Path Parameters
///
/// id: The session to revoke
///
/// # Responses
///
/// 200: Json<Done> - The session is gone
/// 404: Json<ErrorBody> - The user has no such session
/// 500: Json<ErrorBody> - Internal error
///
/// # Metadata
///
/// @tag account
#[rovo]
pub async fn revoke_session(
    State(state): State<AppState>,
    session: AuthSession<Uuid>,
    Path(id): Path<Uuid>,
) -> Result<Json<Done>, AppError> {
    // `revoke_session` takes any id, so check ownership first: otherwise a user could revoke
    // someone else's session.
    let sessions = state.guard.list_sessions(&session.subject).await?;
    if !sessions.iter().any(|s| s.session_id == id) {
        return Err(AppError::NotFound);
    }
    state.guard.revoke_session(id).await?;
    Ok(Json(Done { ok: true }))
}
