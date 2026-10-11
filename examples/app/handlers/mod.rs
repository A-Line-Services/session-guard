//! The endpoints. rovo turns each doc comment into the route's OpenAPI operation.
//!
//! rovo reads the router's state type from the handler's `State` parameter. A handler that does
//! not use the state names it with `#[rovo(state = AppState)]` instead.
//!
//! A handler that takes `AuthSession` is documented as requiring the `session_cookie` scheme
//! (and as answering 401) without any annotation; `@security session_cookie` would say the same
//! explicitly. Other schemes are named with `@security`, as on [`api::ping`].

pub mod account;
pub mod api;
pub mod auth;
pub mod transfer;
