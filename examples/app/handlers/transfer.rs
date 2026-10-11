//! A sensitive action.

use rovo::{extract::State, response::Json, rovo};
use session_guard::AuthSession;
use uuid::Uuid;

use crate::app::{models::Transferred, state::AppState};

/// A sensitive action.
///
/// This route sits behind the strict layer: a risky client or a login older than 15 minutes
/// gets 401 `step_up_required` and must `POST /step-up` first.
///
/// # Responses
///
/// 200: Json<Transferred> - Done
///
/// # Metadata
///
/// @tag account
#[rovo]
pub async fn transfer(State(_): State<AppState>, _session: AuthSession<Uuid>) -> Json<Transferred> {
    Json(Transferred {
        status: "transferred".to_owned(),
    })
}
