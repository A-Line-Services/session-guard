//! What every handler can reach.

use axum::extract::FromRef;
use session_guard::Guard;

use crate::Store;

/// The app state: the guard, and in a real app your database pool and so on.
///
/// `FromRef` lets the `Sessions` extractor take the guard out of it.
#[derive(Clone, FromRef)]
pub struct AppState {
    /// The session guard.
    pub guard: Guard<Store>,
}
