//! Which handler sits behind which layer. `mod.rs` applies the layers per group.

use rovo::routing::{delete, get, post};

use super::{
    handlers::{account, api, auth, transfer},
    state::AppState,
};

/// Routes that need no session: log in, log out and step up.
///
/// Step-up must stay outside the layer that answers `step_up_required`, or it could never be
/// reached.
pub fn public() -> rovo::Router<AppState> {
    rovo::Router::<AppState>::new()
        .route("/login", post(auth::login))
        .route("/logout", post(auth::logout))
        .route("/step-up", post(auth::step_up))
}

/// Routes for signed-in users (or API keys), behind the standard layer.
pub fn account() -> rovo::Router<AppState> {
    rovo::Router::<AppState>::new()
        .route("/me", get(account::me))
        .route("/sessions", get(account::list_sessions))
        .route("/sessions/{id}", delete(account::revoke_session))
        .route("/api/ping", get(api::ping))
}

/// Routes that need a recent, low-risk login, behind the strict layer.
pub fn sensitive() -> rovo::Router<AppState> {
    rovo::Router::<AppState>::new().route("/transfer", post(transfer::transfer))
}
