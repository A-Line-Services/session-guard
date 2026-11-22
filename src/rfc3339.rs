//! Serde for timestamps as RFC 3339 strings in UTC, the format stored by 0.3 and earlier.

use serde::{Deserialize, Deserializer, Serializer, de::Error as _, ser::Error as _};
use time::{OffsetDateTime, UtcOffset, format_description::well_known::Rfc3339};

pub(crate) fn serialize<S: Serializer>(at: &OffsetDateTime, serializer: S) -> Result<S::Ok, S::Error> {
    let text = at
        .to_offset(UtcOffset::UTC)
        .format(&Rfc3339)
        .map_err(S::Error::custom)?;
    serializer.serialize_str(&text)
}

pub(crate) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<OffsetDateTime, D::Error> {
    let text = String::deserialize(deserializer)?;
    OffsetDateTime::parse(&text, &Rfc3339)
        .map(|at| at.to_offset(UtcOffset::UTC))
        .map_err(D::Error::custom)
}

pub(crate) mod option {
    use serde::{Deserialize, Deserializer, Serializer};
    use time::OffsetDateTime;

    #[derive(Deserialize)]
    struct Wrapped(#[serde(with = "super")] OffsetDateTime);

    #[expect(clippy::ref_option, reason = "serde `with` passes `&Option<T>`")]
    pub(crate) fn serialize<S: Serializer>(at: &Option<OffsetDateTime>, serializer: S) -> Result<S::Ok, S::Error> {
        match at {
            Some(at) => super::serialize(at, serializer),
            None => serializer.serialize_none(),
        }
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<OffsetDateTime>, D::Error> {
        Ok(Option::<Wrapped>::deserialize(deserializer)?.map(|Wrapped(at)| at))
    }
}
