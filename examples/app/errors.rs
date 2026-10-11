//! The app's error type.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use rovo::response::Json;
use session_guard::{GuardError, axum::StepUpError};

use super::models::ErrorBody;

/// Everything a handler can fail with.
///
/// The guard's errors already know their responses (500, or the step-up's 401 and 403), so
/// `?` on a guard call is all a handler needs.
#[derive(Debug)]
pub enum AppError {
    /// Wrong username or password.
    InvalidCredentials,
    /// Unknown API key.
    InvalidApiKey,
    /// No such resource for this user.
    NotFound,
    /// The guard or its store failed.
    Guard(GuardError),
    /// Step-up was refused.
    StepUp(StepUpError),
}

impl From<GuardError> for AppError {
    fn from(error: GuardError) -> Self {
        Self::Guard(error)
    }
}

impl From<StepUpError> for AppError {
    fn from(error: StepUpError) -> Self {
        Self::StepUp(error)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::InvalidCredentials => (StatusCode::UNAUTHORIZED, "invalid_credentials"),
            Self::InvalidApiKey => (StatusCode::UNAUTHORIZED, "invalid_api_key"),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Self::Guard(error) => return error.into_response(),
            Self::StepUp(error) => return error.into_response(),
        };
        (status, Json(ErrorBody { error: code.to_owned() })).into_response()
    }
}

/// The handlers list their error responses under `# Responses`.
impl rovo::aide::OperationOutput for AppError {
    type Inner = Self;
}
