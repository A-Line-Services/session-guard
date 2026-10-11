//! A route for API keys instead of sessions.

use axum::http::HeaderMap;
use rovo::{extract::State, response::Json, rovo};

use crate::app::{
    errors::AppError,
    models::{ErrorBody, Pong},
    state::AppState,
    users::has_api_key,
};

/// Ping with an API key.
///
/// Keys starting with `pat_` or `svc_` skip session-guard entirely (see the layer's
/// `bypass_bearer_prefixes`), so this handler is the only thing judging them.
///
/// # Responses
///
/// 200: Json<Pong> - The key is valid
/// 401: Json<ErrorBody> - Unknown key
///
/// # Metadata
///
/// @tag api
/// @security bearer
#[rovo]
pub async fn ping(State(_): State<AppState>, headers: HeaderMap) -> Result<Json<Pong>, AppError> {
    if !has_api_key(&headers) {
        return Err(AppError::InvalidApiKey);
    }
    Ok(Json(Pong {
        auth: "api_key".to_owned(),
    }))
}
