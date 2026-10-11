//! Logging in and out, and stepping up.

use rovo::{response::Json, rovo};
use session_guard::{GuardError, IssuedToken, NewSession, Sessions, axum::LoggedOut};

use crate::{
    Store,
    app::{
        errors::AppError,
        models::{Credentials, Done, ErrorBody, LoggedIn},
        state::AppState,
        users::verify,
    },
};

/// Log in.
///
/// Checks the credentials, then asks session-guard for a session and sets its cookie. A
/// session the client already holds is revoked first, which defeats session fixation.
///
/// # Responses
///
/// 200: Json<LoggedIn> - Logged in; the session cookie is set
/// 401: Json<ErrorBody> - Wrong username or password
/// 500: Json<ErrorBody> - Internal error
///
/// # Metadata
///
/// @tag auth
#[rovo(state = AppState)]
pub async fn login(
    sessions: Sessions<Store>,
    Json(credentials): Json<Credentials>,
) -> Result<(NewSession, Json<LoggedIn>), AppError> {
    // Your job: check who this is (and rate-limit this route).
    let user = verify(&credentials).ok_or(AppError::InvalidCredentials)?;
    // The guard's job: create the session.
    let session = sessions.login(&user).await?;
    let session_id = session.session_id;
    Ok((session, Json(LoggedIn { session_id })))
}

/// Log out.
///
/// Deletes the session behind the cookie and clears the cookie. It sits outside the layers,
/// so it also works for a session that is waiting for step-up.
///
/// # Responses
///
/// 200: Json<Done> - Logged out; the cookie is cleared
/// 500: Json<ErrorBody> - Internal error
///
/// # Metadata
///
/// @tag auth
#[rovo(state = AppState)]
pub async fn logout(sessions: Sessions<Store>) -> Result<(LoggedOut, Json<Done>), GuardError> {
    Ok((sessions.logout().await?, Json(Done { ok: true })))
}

/// Step up.
///
/// The answer to a 401 `step_up_required`. The user proves who they are again (here with the
/// password, in your app a passkey or MFA), then session-guard marks the session trusted from
/// the current client and issues a fresh token.
///
/// # Responses
///
/// 200: Json<Done> - Trusted again; the new cookie is set
/// 401: Json<ErrorBody> - Wrong credentials, or no valid session
/// 403: Json<ErrorBody> - The credentials belong to a different user
/// 500: Json<ErrorBody> - Internal error
///
/// # Metadata
///
/// @tag auth
#[rovo(state = AppState)]
pub async fn step_up(
    sessions: Sessions<Store>,
    Json(credentials): Json<Credentials>,
) -> Result<(IssuedToken, Json<Done>), AppError> {
    // Your job: re-verify the user (and rate-limit this route).
    let user = verify(&credentials).ok_or(AppError::InvalidCredentials)?;
    // The guard's job: refuse unless the verified user owns this session.
    let token = sessions.complete_step_up(&user).await?;
    Ok((token, Json(Done { ok: true })))
}
