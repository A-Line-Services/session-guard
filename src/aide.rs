//! OpenAPI support through [`aide`], and so through `rovo`.
//!
//! With the `aide` feature the extractors and error types document themselves:
//!
//! - [`AuthSession`] marks its route as requiring the [`SECURITY_SCHEME`] cookie and documents
//!   the layer's 401 rejections. `Option<AuthSession>` adds the requirement as well, so a bypass
//!   route that also takes an API key lists both as alternatives.
//! - [`Sessions`] leaves the route public: it is what login and step-up handlers take.
//! - [`GuardError`] and [`StepUpError`] document the responses they convert into.
//!
//! [`register`] adds the scheme itself to the spec; call it once, after `finish_api`. With rovo,
//! `@security session_cookie` on a handler adds the same requirement explicitly.
//!
//! ```
//! use aide::{axum::{ApiRouter, routing::get}, openapi::OpenApi};
//! use session_guard::{AuthSession, Guard, MemoryStore};
//! use uuid::Uuid;
//!
//! async fn me(session: AuthSession<Uuid>) -> String {
//!     session.subject.to_string()
//! }
//!
//! let guard = Guard::new(MemoryStore::new());
//! let mut api = OpenApi::default();
//! let app: axum::Router = ApiRouter::new()
//!     .api_route("/me", get(me))
//!     .with_state(guard.clone())
//!     .finish_api(&mut api);
//! session_guard::aide::register(&mut api, &guard);
//! ```

use ::aide::{
    OperationInput, OperationOutput,
    generate::GenContext,
    openapi::{ApiKeyLocation, MediaType, OpenApi, Operation, ReferenceOr, Response, SchemaObject, SecurityScheme},
    transform::TransformOperation,
};
use serde_json::json;

use crate::{
    AuthSession, Guard, GuardError, Rejection, SessionStore, Subject,
    axum::{Sessions, StepUpError},
};

/// The name of the session cookie's security scheme: `session_cookie`.
pub const SECURITY_SCHEME: &str = "session_cookie";

/// The session cookie as an OpenAPI `apiKey` scheme, named after the guard's cookie.
#[expect(clippy::default_trait_access, reason = "aide does not re-export IndexMap")]
pub fn security_scheme<St: SessionStore, S: Subject>(guard: &Guard<St, S>) -> SecurityScheme {
    SecurityScheme::ApiKey {
        location: ApiKeyLocation::Cookie,
        name: guard.cookie_name().to_owned(),
        description: Some("Session cookie, rotated by the server.".to_owned()),
        extensions: Default::default(),
    }
}

/// Adds [`security_scheme`] to `api` as [`SECURITY_SCHEME`].
pub fn register<St: SessionStore, S: Subject>(api: &mut OpenApi, guard: &Guard<St, S>) {
    api.components
        .get_or_insert_default()
        .security_schemes
        .insert(SECURITY_SCHEME.to_owned(), ReferenceOr::Item(security_scheme(guard)));
}

impl<S> OperationInput for AuthSession<S> {
    fn operation_input(_: &mut GenContext, operation: &mut Operation) {
        let _ = TransformOperation::new(operation).security_requirement(SECURITY_SCHEME);
    }

    fn inferred_early_responses(_: &mut GenContext, _: &mut Operation) -> Vec<(Option<u16>, Response)> {
        let codes = [
            Rejection::NotAuthenticated,
            Rejection::Expired,
            Rejection::Revoked,
            Rejection::StepUpRequired,
        ]
        .map(Rejection::as_str);
        vec![(Some(401), error_response("No valid session.", &codes))]
    }
}

impl<St, S> OperationInput for Sessions<St, S> {}

impl OperationOutput for GuardError {
    type Inner = Self;

    fn operation_response(_: &mut GenContext, _: &mut Operation) -> Option<Response> {
        Some(internal())
    }

    fn inferred_responses(_: &mut GenContext, _: &mut Operation) -> Vec<(Option<u16>, Response)> {
        vec![(Some(500), internal())]
    }
}

impl OperationOutput for StepUpError {
    type Inner = Self;

    fn inferred_responses(_: &mut GenContext, _: &mut Operation) -> Vec<(Option<u16>, Response)> {
        let rejected = [Rejection::NotAuthenticated, Rejection::Expired, Rejection::Revoked].map(Rejection::as_str);
        vec![
            (Some(401), error_response("No valid session.", &rejected)),
            (
                Some(403),
                error_response("The verified subject does not own the session.", &["subject_mismatch"]),
            ),
            (Some(500), internal()),
        ]
    }
}

fn internal() -> Response {
    error_response("Internal error.", &["internal"])
}

/// A JSON `{"error": <code>}` response.
fn error_response(description: &str, codes: &[&str]) -> Response {
    let schema = json!({
        "type": "object",
        "required": ["error"],
        "properties": { "error": { "type": "string", "enum": codes } },
    });
    Response {
        description: description.to_owned(),
        content: [(
            "application/json".to_owned(),
            MediaType {
                schema: Some(SchemaObject {
                    json_schema: serde_json::from_value(schema).unwrap_or_default(),
                    external_docs: None,
                    example: None,
                }),
                ..MediaType::default()
            },
        )]
        .into(),
        ..Response::default()
    }
}
