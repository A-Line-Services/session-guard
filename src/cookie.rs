//! The session cookie: configuration, `Set-Cookie` rendering and `Cookie` parsing.
//!
//! The cookie value is the bare token (43 base64url characters); nothing else is encoded in it.

use std::fmt::Write as _;

use crate::error::ConfigError;

/// The cookie `SameSite` attribute.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum SameSite {
    /// Never sent on cross-site requests, including top-level navigations.
    Strict,
    /// Sent on top-level cross-site navigations (GET), not on cross-site subrequests or POSTs.
    #[default]
    Lax,
    /// Always sent. Requires `Secure`, and CSRF protection becomes your job.
    None,
}

impl SameSite {
    const fn as_str(self) -> &'static str {
        match self {
            SameSite::Strict => "Strict",
            SameSite::Lax => "Lax",
            SameSite::None => "None",
        }
    }
}

/// Session cookie attributes.
///
/// The defaults are the safest option for a same-origin app:
///
/// ```text
/// Set-Cookie: __Host-sid=<43 chars>; Path=/; Max-Age=2592000; HttpOnly; Secure; SameSite=Lax
/// ```
///
/// Browsers enforce the `__Host-` prefix: the cookie must be `Secure`, have `Path=/` and no
/// `Domain`, so a sibling subdomain cannot set or overwrite it. [`CookieConfig::validate`] (run by
/// [`GuardConfig`](crate::GuardConfig)'s `build`) rejects combinations browsers would drop.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CookieConfig {
    name: String,
    path: String,
    domain: Option<String>,
    secure: bool,
    http_only: bool,
    same_site: SameSite,
    persistent: bool,
}

impl Default for CookieConfig {
    fn default() -> Self {
        Self {
            name: "__Host-sid".to_owned(),
            path: "/".to_owned(),
            domain: None,
            secure: true,
            http_only: true,
            same_site: SameSite::Lax,
            persistent: true,
        }
    }
}

impl CookieConfig {
    /// Defaults with a different cookie name.
    pub fn named(name: impl Into<String>) -> Self {
        Self::default().name(name)
    }

    /// Cookie name. Keep the `__Host-` prefix unless you need `Domain` or a narrower `Path`.
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// `Path` attribute (default `/`).
    #[must_use]
    pub fn path(mut self, path: impl Into<String>) -> Self {
        self.path = path.into();
        self
    }

    /// `Domain` attribute (default none, i.e. host-only). Not allowed with `__Host-`.
    #[must_use]
    pub fn domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = Some(domain.into());
        self
    }

    /// `Secure` attribute (default on). Only turn this off for plain-HTTP local development, and
    /// then also drop the `__Host-` prefix.
    #[must_use]
    pub const fn secure(mut self, secure: bool) -> Self {
        self.secure = secure;
        self
    }

    /// `HttpOnly` attribute (default on), which hides the token from JavaScript.
    #[must_use]
    pub const fn http_only(mut self, http_only: bool) -> Self {
        self.http_only = http_only;
        self
    }

    /// `SameSite` attribute (default `Lax`).
    #[must_use]
    pub const fn same_site(mut self, same_site: SameSite) -> Self {
        self.same_site = same_site;
        self
    }

    /// Whether the cookie carries `Max-Age` (default on). When off, it is a browser-session
    /// cookie that disappears when the browser closes; server-side expiry still applies.
    #[must_use]
    pub const fn persistent(mut self, persistent: bool) -> Self {
        self.persistent = persistent;
        self
    }

    /// The cookie name.
    pub fn cookie_name(&self) -> &str {
        &self.name
    }

    /// Checks the attributes against what browsers accept.
    ///
    /// # Errors
    ///
    /// [`ConfigError::InvalidCookie`] describing the first problem found.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let invalid = ConfigError::InvalidCookie;
        if self.name.is_empty() || !self.name.bytes().all(is_token_byte) {
            return Err(invalid("name must be a non-empty HTTP token"));
        }
        if !self.path.starts_with('/') || !self.path.bytes().all(is_attr_byte) {
            return Err(invalid(
                "path must start with '/' and contain no ';' or control characters",
            ));
        }
        if let Some(domain) = &self.domain
            && (domain.is_empty() || !domain.bytes().all(is_attr_byte))
        {
            return Err(invalid(
                "domain must be non-empty and contain no ';' or control characters",
            ));
        }
        if self.name.starts_with("__Host-") {
            if !self.secure {
                return Err(invalid("__Host- cookies must be Secure"));
            }
            if self.domain.is_some() {
                return Err(invalid("__Host- cookies must not have a Domain"));
            }
            if self.path != "/" {
                return Err(invalid("__Host- cookies must have Path=/"));
            }
        }
        if self.name.starts_with("__Secure-") && !self.secure {
            return Err(invalid("__Secure- cookies must be Secure"));
        }
        if self.same_site == SameSite::None && !self.secure {
            return Err(invalid("SameSite=None requires Secure"));
        }
        Ok(())
    }

    /// Renders a `Set-Cookie` value carrying `token`. `max_age_secs` is clamped at zero and only
    /// emitted for persistent cookies.
    pub fn set_cookie(&self, token: &str, max_age_secs: i64) -> String {
        let mut out = format!("{}={}", self.name, token);
        self.push_attributes(&mut out, self.persistent.then_some(max_age_secs.max(0)));
        out
    }

    /// Renders a `Set-Cookie` value that deletes the cookie.
    pub fn clear_cookie(&self) -> String {
        let mut out = format!("{}=", self.name);
        self.push_attributes(&mut out, Some(0));
        out
    }

    fn push_attributes(&self, out: &mut String, max_age: Option<i64>) {
        let _ = write!(out, "; Path={}", self.path);
        if let Some(domain) = &self.domain {
            let _ = write!(out, "; Domain={domain}");
        }
        if let Some(max_age) = max_age {
            let _ = write!(out, "; Max-Age={max_age}");
        }
        if self.http_only {
            out.push_str("; HttpOnly");
        }
        if self.secure {
            out.push_str("; Secure");
        }
        let _ = write!(out, "; SameSite={}", self.same_site.as_str());
    }

    /// Finds this cookie's value in one `Cookie` header value. Takes the first occurrence (the
    /// browser sends the most specific path first). Returns the raw value, unvalidated.
    pub fn find_in<'a>(&self, cookie_header: &'a str) -> Option<&'a str> {
        find_cookie(cookie_header, &self.name)
    }
}

/// Finds `name` in a `Cookie` header value. Never panics on arbitrary input.
pub fn find_cookie<'a>(cookie_header: &'a str, name: &str) -> Option<&'a str> {
    cookie_header.split(';').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        if key.trim() != name {
            return None;
        }
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .unwrap_or(value);
        Some(value)
    })
}

const fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
        )
}

const fn is_attr_byte(b: u8) -> bool {
    b.is_ascii_graphic() && b != b';'
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    const TOKEN: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    #[test]
    fn default_set_cookie_is_host_prefixed_and_locked_down() {
        let c = CookieConfig::default();
        assert!(c.validate().is_ok());
        assert_eq!(
            c.set_cookie(TOKEN, 2_592_000),
            format!("__Host-sid={TOKEN}; Path=/; Max-Age=2592000; HttpOnly; Secure; SameSite=Lax")
        );
        assert_eq!(
            c.clear_cookie(),
            "__Host-sid=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax"
        );
    }

    #[test]
    fn custom_attributes_render() {
        let c = CookieConfig::named("sid")
            .domain("example.com")
            .path("/app")
            .same_site(SameSite::Strict)
            .http_only(false)
            .persistent(false);
        assert!(c.validate().is_ok());
        assert_eq!(
            c.set_cookie("v", 10),
            "sid=v; Path=/app; Domain=example.com; Secure; SameSite=Strict"
        );
        assert_eq!(
            c.clear_cookie(),
            "sid=; Path=/app; Domain=example.com; Max-Age=0; Secure; SameSite=Strict"
        );
    }

    #[test]
    fn negative_max_age_is_clamped() {
        assert!(CookieConfig::default().set_cookie("v", -5).contains("Max-Age=0"));
    }

    #[test]
    fn browser_rejected_combinations_fail_validation() {
        let bad = [
            CookieConfig::default().secure(false),
            CookieConfig::default().domain("example.com"),
            CookieConfig::default().path("/app"),
            CookieConfig::named("__Secure-sid").secure(false),
            CookieConfig::named("sid").secure(false).same_site(SameSite::None),
            CookieConfig::named(""),
            CookieConfig::named("s id"),
            CookieConfig::named("s;id"),
            CookieConfig::named("sid").path("app"),
            CookieConfig::named("sid").path("/a;b"),
            CookieConfig::named("sid").domain(""),
            CookieConfig::named("sid").domain("a.com; Secure"),
        ];
        for c in bad {
            assert!(c.validate().is_err(), "{c:?}");
        }
        assert!(CookieConfig::named("sid").secure(false).validate().is_ok());
    }

    #[test]
    fn finds_cookie_values() {
        let c = CookieConfig::default();
        assert_eq!(c.find_in("a=1; __Host-sid=abc; b=2"), Some("abc"));
        assert_eq!(c.find_in("__Host-sid=first;__Host-sid=second"), Some("first"));
        assert_eq!(c.find_in("__Host-sid=\"q\""), Some("q"));
        assert_eq!(c.find_in(" __Host-sid = x "), Some("x"));
        assert_eq!(c.find_in("x__Host-sid=1; __Host-sidx=2"), None);
        assert_eq!(c.find_in(""), None);
        assert_eq!(c.find_in("__Host-sid"), None);
        assert_eq!(c.find_in("__Host-sid="), Some(""));
    }

    proptest! {
        #[test]
        fn find_cookie_never_panics(header in ".{0,200}", name in "[a-z_-]{1,12}") {
            let _ = find_cookie(&header, &name);
        }

        #[test]
        fn rendered_cookie_is_found_again(token in "[A-Za-z0-9_-]{43}") {
            let c = CookieConfig::default();
            let set = c.set_cookie(&token, 60);
            let pair = set.split(';').next().unwrap();
            let header = format!("other=1; {pair}");
            prop_assert_eq!(c.find_in(&header), Some(token.as_str()));
        }
    }
}
