//! OpenAPI output of the `aide` integration.

use aide::{
    axum::{
        ApiRouter,
        routing::{get, get_with, post},
    },
    openapi::OpenApi,
};
use axum::http::StatusCode;
use serde_json::{Value, json};
use session_guard::{
    AuthSession, Guard, GuardConfig, GuardError, IssuedToken, MemoryStore, NewSession,
    axum::{Sessions, StepUpError},
};
use uuid::Uuid;

type Store = MemoryStore;

async fn me(_: AuthSession<Uuid>) -> &'static str {
    "me"
}

async fn maybe(_: Option<AuthSession<Uuid>>) -> &'static str {
    "maybe"
}

async fn login(_: Sessions<Store>) -> Result<(NewSession, StatusCode), GuardError> {
    Err(GuardError::Subject("unused".into()))
}

async fn step_up(_: Sessions<Store>) -> Result<(IssuedToken, StatusCode), StepUpError> {
    unreachable!()
}

fn spec(guard: &Guard<Store>) -> Value {
    let mut api = OpenApi::default();
    let _router: axum::Router = ApiRouter::new()
        .api_route("/me", get(me))
        .api_route("/maybe", get_with(maybe, |op| op.security_requirement("api_key")))
        .api_route("/login", post(login))
        .api_route("/step-up", post(step_up))
        .with_state(guard.clone())
        .finish_api(&mut api);
    session_guard::aide::register(&mut api, guard);
    serde_json::to_value(&api).unwrap()
}

fn default_spec() -> Value {
    spec(&Guard::new(MemoryStore::new()))
}

#[test]
fn register_adds_the_cookie_scheme() {
    let spec = default_spec();
    assert_eq!(
        spec["components"]["securitySchemes"][session_guard::aide::SECURITY_SCHEME],
        json!({
            "type": "apiKey",
            "in": "cookie",
            "name": "__Host-sid",
            "description": "Session cookie, rotated by the server.",
        })
    );
}

#[test]
fn scheme_uses_the_configured_cookie_name() {
    let config = GuardConfig::builder().cookie_name("__Host-app").build().unwrap();
    let spec = spec(&Guard::builder(MemoryStore::new(), config).build());
    assert_eq!(
        spec["components"]["securitySchemes"]["session_cookie"]["name"],
        "__Host-app"
    );
}

#[test]
fn auth_session_requires_the_cookie() {
    let spec = default_spec();
    assert_eq!(
        spec["paths"]["/me"]["get"]["security"],
        json!([{ "session_cookie": [] }])
    );
}

#[test]
fn optional_auth_session_combines_with_other_schemes() {
    let spec = default_spec();
    assert_eq!(
        spec["paths"]["/maybe"]["get"]["security"],
        json!([{ "session_cookie": [] }, { "api_key": [] }])
    );
}

#[test]
fn sessions_routes_are_public() {
    let spec = default_spec();
    assert!(spec["paths"]["/login"]["post"].get("security").is_none());
    assert!(spec["paths"]["/step-up"]["post"].get("security").is_none());
}

fn error_codes(spec: &Value, path: &str, method: &str) -> Vec<(String, Value)> {
    let responses = spec["paths"][path][method]["responses"].as_object().unwrap();
    responses
        .iter()
        .filter(|(code, _)| code.starts_with(['4', '5']))
        .map(|(code, response)| {
            let schema = &response["content"]["application/json"]["schema"];
            (code.clone(), schema["properties"]["error"]["enum"].clone())
        })
        .collect()
}

#[test]
fn auth_session_documents_the_layer_rejections() {
    let spec = default_spec();
    assert_eq!(
        error_codes(&spec, "/me", "get"),
        [(
            "401".to_owned(),
            json!([
                "not_authenticated",
                "session_expired",
                "session_revoked",
                "step_up_required"
            ])
        )]
    );
    assert!(
        error_codes(&spec, "/maybe", "get").is_empty(),
        "optional extraction never rejects"
    );
}

#[test]
fn guard_error_documents_a_500() {
    let spec = default_spec();
    assert_eq!(
        error_codes(&spec, "/login", "post"),
        [("500".to_owned(), json!(["internal"]))]
    );
}

#[test]
fn step_up_error_documents_its_failures() {
    let spec = default_spec();
    assert_eq!(
        error_codes(&spec, "/step-up", "post"),
        [
            (
                "401".to_owned(),
                json!(["not_authenticated", "session_expired", "session_revoked"])
            ),
            ("403".to_owned(), json!(["subject_mismatch"])),
            ("500".to_owned(), json!(["internal"])),
        ]
    );
}
