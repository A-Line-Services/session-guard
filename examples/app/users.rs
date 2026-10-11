//! The credential and API key checks: your app's job, not session-guard's.

use axum::http::{HeaderMap, header};
use uuid::Uuid;

use super::models::Credentials;

/// The one demo user. Replace this with your user table.
pub const DEMO_USER: Uuid = Uuid::from_u128(1);
const DEMO_USERNAME: &str = "demo";
const DEMO_PASSWORD: &str = "demo-password";

/// An API key the app accepts, standing in for your key lookup.
const DEMO_API_KEY: &str = "pat_demo-key";

/// Toy credential check against a hardcoded user.
///
/// Replace with your real authentication (password hash, SSO, passkey, ...), and
/// rate-limit every route that calls it. session-guard does neither.
pub fn verify(credentials: &Credentials) -> Option<Uuid> {
    (credentials.username == DEMO_USERNAME && credentials.password == DEMO_PASSWORD).then_some(DEMO_USER)
}

/// Whether the request carries a valid API key as its bearer token. Look keys up in your own
/// table instead.
pub fn has_api_key(headers: &HeaderMap) -> bool {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        == Some(DEMO_API_KEY)
}
