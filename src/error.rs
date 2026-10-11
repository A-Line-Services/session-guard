//! Error types.

/// Error type stores return. Boxed so store implementations can surface their own errors.
pub type StoreError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Errors from guard operations. Request-level outcomes (expired, revoked, step-up) are not
/// errors; see [`Outcome`](crate::Outcome).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum GuardError {
    /// The session store failed.
    #[error("session store error: {0}")]
    Store(#[from] StoreError),
    /// The operating system RNG was unavailable, so no token could be generated.
    #[error("operating system random number generator unavailable")]
    Random,
    /// The subject could not be serialized.
    #[error("subject could not be serialized: {0}")]
    Subject(String),
}

/// Invalid [`GuardConfig`](crate::GuardConfig) or [`CookieConfig`](crate::CookieConfig).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// A trusted proxy entry is neither an IP address nor a CIDR range.
    #[error("invalid trusted proxy {0:?}: expected an IP address or CIDR range")]
    InvalidProxy(String),
    /// The cookie settings are inconsistent or rejected by browsers.
    #[error("invalid cookie configuration: {0}")]
    InvalidCookie(&'static str),
    /// A duration is zero or too large.
    #[error("invalid duration for {0}: must be greater than zero and fit in a timestamp")]
    InvalidDuration(&'static str),
    /// Rotation grace must be shorter than the rotation interval.
    #[error("rotation grace must be shorter than the rotation interval")]
    GraceTooLong,
    /// Thresholds must satisfy `0 < step_up <= revoke`.
    #[error("thresholds must satisfy 0 < step_up <= revoke")]
    InvalidThresholds,
    /// A header name is not a valid lowercase HTTP header name.
    #[error("invalid header name {0:?}")]
    InvalidHeaderName(String),
    /// A token prefix must be 1 to 32 characters of `A-Z a-z 0-9 _ -`.
    #[error("invalid token prefix {0:?}: expected 1 to 32 characters of A-Z a-z 0-9 _ -")]
    InvalidTokenPrefix(String),
}
