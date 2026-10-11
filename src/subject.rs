//! The opaque subject a session belongs to.

use serde::{Serialize, de::DeserializeOwned};

use crate::error::GuardError;

/// Who a session belongs to: a user id, an account/tenant pair, an API client, anything.
///
/// The guard never interprets the subject. It serializes it to JSON for the store and
/// deserializes it back when a session is authenticated. Blanket-implemented for every type
/// with the right bounds, e.g. [`uuid::Uuid`], [`i64`], [`String`] or your own
/// `#[derive(Serialize, Deserialize, PartialEq, Eq, Clone)]` struct.
///
/// The serialized form must be deterministic, because stores find a subject's sessions by
/// comparing it: equal values must produce equal JSON. Avoid `HashMap` fields inside subjects
/// (use `BTreeMap`), and keep the representation stable across releases of your app.
pub trait Subject: Serialize + DeserializeOwned + Eq + Clone + Send + Sync + 'static {}

impl<T> Subject for T where T: Serialize + DeserializeOwned + Eq + Clone + Send + Sync + 'static {}

/// Canonical text form written to the store.
pub(crate) fn encode<S: Subject>(subject: &S) -> Result<String, GuardError> {
    serde_json::to_string(subject).map_err(|e| GuardError::Subject(e.to_string()))
}

/// Parses a stored subject. `None` means the stored value no longer matches `S`.
pub(crate) fn decode<S: Subject>(stored: &str) -> Option<S> {
    serde_json::from_str(stored).ok()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde::Deserialize;
    use uuid::Uuid;

    use super::*;

    fn round_trip<S: Subject + std::fmt::Debug>(subject: S) {
        let stored = encode(&subject).unwrap();
        assert_eq!(decode::<S>(&stored), Some(subject));
    }

    #[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Debug)]
    struct TenantUser {
        tenant: u32,
        user: String,
        tags: BTreeMap<String, String>,
    }

    #[test]
    fn common_subjects_round_trip() {
        round_trip(Uuid::new_v4());
        round_trip(-42_i64);
        round_trip(u64::MAX);
        round_trip("user:ü@example.com\"';--".to_owned());
        round_trip(TenantUser {
            tenant: 7,
            user: "ann".into(),
            tags: BTreeMap::from([("b".into(), "2".into()), ("a".into(), "1".into())]),
        });
    }

    #[test]
    fn encoding_is_deterministic() {
        let id = Uuid::new_v4();
        assert_eq!(encode(&id).unwrap(), encode(&id).unwrap());
    }

    #[test]
    fn mismatched_stored_values_are_rejected() {
        assert_eq!(decode::<Uuid>("\"nope\""), None);
        assert_eq!(decode::<i64>("\"12\""), None);
    }
}
