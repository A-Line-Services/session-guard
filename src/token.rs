//! Opaque session tokens and their stored hashes.
//!
//! A token is 32 bytes from the OS RNG, encoded as 43 characters of unpadded base64url. Nothing
//! else is encoded in it. Only the SHA-256 of the token is ever stored, so a database leak does
//! not leak usable cookies.

use std::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::error::GuardError;

/// Length of an encoded token in characters.
pub const TOKEN_LEN: usize = 43;

/// A freshly issued session token. The value is wiped from memory on drop and redacted from
/// `Debug` output.
pub struct SessionToken(SecretString);

impl SessionToken {
    /// Generates a new token from 32 bytes of OS randomness.
    ///
    /// # Errors
    ///
    /// [`GuardError::Random`] if the operating system RNG is unavailable.
    pub fn generate() -> Result<Self, GuardError> {
        let mut bytes = [0_u8; 32];
        getrandom::fill(&mut bytes).map_err(|_| GuardError::Random)?;
        let encoded = URL_SAFE_NO_PAD.encode(bytes);
        bytes.zeroize();
        Ok(Self(SecretString::from(encoded)))
    }

    /// The cookie value. Avoid logging it.
    pub fn expose(&self) -> &str {
        self.0.expose_secret()
    }

    /// The hash under which this token is stored.
    pub fn hash(&self) -> TokenHash {
        TokenHash::of(self.expose())
    }
}

impl fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionToken(<redacted>)")
    }
}

/// SHA-256 of a token. Comparison is constant-time.
#[derive(Clone, Copy, Eq, Hash)]
#[allow(
    clippy::derived_hash_with_manual_eq,
    reason = "constant-time eq agrees with byte-wise Hash"
)]
pub struct TokenHash([u8; 32]);

impl TokenHash {
    /// Hashes a token string without validating it.
    pub fn of(token: &str) -> Self {
        Self(Sha256::digest(token.as_bytes()).into())
    }

    /// Hashes a token presented by a client, or `None` if it cannot be a token we issued
    /// (wrong length or alphabet). Avoids a store lookup for garbage cookies.
    pub fn from_presented(presented: &str) -> Option<Self> {
        is_well_formed(presented).then(|| Self::of(presented))
    }

    /// Wraps raw hash bytes read from a store.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Raw hash bytes, for stores.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hex, for stores that key by string.
    pub fn to_hex(&self) -> String {
        use fmt::Write as _;
        self.0.iter().fold(String::with_capacity(64), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
    }

    /// Parses [`TokenHash::to_hex`] output.
    pub fn from_hex(hex: &str) -> Option<Self> {
        if hex.len() != 64 || !hex.is_ascii() {
            return None;
        }
        let mut bytes = [0_u8; 32];
        for (slot, pair) in bytes.iter_mut().zip(hex.as_bytes().as_chunks::<2>().0) {
            let pair = std::str::from_utf8(pair).ok()?;
            *slot = u8::from_str_radix(pair, 16).ok()?;
        }
        Some(Self(bytes))
    }
}

impl PartialEq for TokenHash {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl fmt::Debug for TokenHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TokenHash({}…)", &self.to_hex()[..8])
    }
}

/// Whether `value` has the shape of a token we issue: exactly 43 base64url characters.
pub fn is_well_formed(value: &str) -> bool {
    value.len() == TOKEN_LEN
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn generated_tokens_are_43_base64url_chars_and_unique() {
        let a = SessionToken::generate().unwrap();
        let b = SessionToken::generate().unwrap();
        assert_eq!(a.expose().len(), TOKEN_LEN);
        assert!(is_well_formed(a.expose()));
        assert_ne!(a.expose(), b.expose());
        assert_eq!(URL_SAFE_NO_PAD.decode(a.expose()).unwrap().len(), 32);
    }

    #[test]
    fn debug_output_never_contains_the_token() {
        let token = SessionToken::generate().unwrap();
        assert!(!format!("{token:?}").contains(token.expose()));
        assert!(!format!("{:?}", token.hash()).contains(&token.hash().to_hex()));
    }

    #[test]
    fn presented_tokens_are_validated_before_hashing() {
        let token = SessionToken::generate().unwrap();
        assert_eq!(TokenHash::from_presented(token.expose()), Some(token.hash()));
        assert_eq!(TokenHash::from_presented(""), None);
        assert_eq!(TokenHash::from_presented(&"a".repeat(42)), None);
        assert_eq!(TokenHash::from_presented(&"a".repeat(44)), None);
        assert_eq!(TokenHash::from_presented(&format!("{}=", "a".repeat(42))), None);
        assert_eq!(TokenHash::from_presented(&format!("{}é", "a".repeat(41))), None);
    }

    #[test]
    fn hash_matches_sha256() {
        // echo -n abc | sha256sum
        assert_eq!(
            TokenHash::of("abc").to_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    proptest! {
        #[test]
        fn hex_round_trips(bytes in any::<[u8; 32]>()) {
            let hash = TokenHash::from_bytes(bytes);
            prop_assert_eq!(TokenHash::from_hex(&hash.to_hex()), Some(hash));
        }

        #[test]
        fn from_hex_never_panics(s in ".{0,80}") {
            let _ = TokenHash::from_hex(&s);
        }

        #[test]
        fn from_presented_accepts_only_well_formed(s in "[A-Za-z0-9_=+/ -]{40,46}") {
            prop_assert_eq!(TokenHash::from_presented(&s).is_some(), is_well_formed(&s));
        }
    }
}
