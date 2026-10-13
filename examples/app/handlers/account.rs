//! The signed-in user and their sessions.

use rovo::{
    extract::{Path, State},
    response::Json,
    rovo,
};
use session_guard::{AuthSession, Sessions};
use uuid::Uuid;

use crate::{
    Store,
    app::{
        errors::AppError,
        models::{Done, ErrorBody, Me, SessionView},
        state::AppState,
    },
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
#[rovo(state = AppState)]
pub async fn revoke_session(
    session: AuthSession<Uuid>,
    sessions: Sessions<Store>,
    Path(id): Path<Uuid>,
) -> Result<Json<Done>, AppError> {
    // Scoped to the signed-in user: someone else's session id is a 404.
    if !sessions
        .guard()
        .revoke_session(&session.subject, id, sessions.client())
        .await?
    {
        return Err(AppError::NotFound);
    }
    Ok(Json(Done { ok: true }))
}
