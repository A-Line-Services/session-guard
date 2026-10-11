//! What the guard knows about the client making a request.

use std::net::IpAddr;

use ipnet::IpNet;

/// Request attributes used for fingerprinting. Build it with
/// [`Guard::client_context`](crate::Guard::client_context) from headers, or by hand with
/// [`ClientContext::new`] and the `with_*` methods.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ClientContext {
    /// Client IP after proxy resolution.
    pub ip: IpAddr,
    /// `User-Agent`.
    pub user_agent: Option<String>,
    /// `Sec-CH-UA-Platform`, without quotes.
    pub ch_platform: Option<String>,
    /// `Sec-CH-UA-Mobile`: `?1` is `true`, `?0` is `false`.
    pub ch_mobile: Option<bool>,
    /// `Accept-Language`.
    pub accept_language: Option<String>,
    /// TLS fingerprint from the configured proxy header.
    pub tls_fingerprint: Option<String>,
}

impl ClientContext {
    /// A context with only an IP address.
    pub fn new(ip: IpAddr) -> Self {
        Self {
            ip: canonical_ip(ip),
            user_agent: None,
            ch_platform: None,
            ch_mobile: None,
            accept_language: None,
            tls_fingerprint: None,
        }
    }

    /// Sets the `User-Agent`.
    #[must_use]
    pub fn with_user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = Some(ua.into());
        self
    }

    /// Sets the platform client hint (quotes are trimmed).
    #[must_use]
    pub fn with_ch_platform(mut self, platform: impl AsRef<str>) -> Self {
        self.ch_platform = Some(platform.as_ref().trim().trim_matches('"').to_owned());
        self
    }

    /// Sets the mobile client hint.
    #[must_use]
    pub fn with_ch_mobile(mut self, mobile: bool) -> Self {
        self.ch_mobile = Some(mobile);
        self
    }

    /// Sets `Accept-Language`.
    #[must_use]
    pub fn with_accept_language(mut self, value: impl Into<String>) -> Self {
        self.accept_language = Some(value.into());
        self
    }

    /// Sets the TLS fingerprint.
    #[must_use]
    pub fn with_tls_fingerprint(mut self, value: impl Into<String>) -> Self {
        self.tls_fingerprint = Some(value.into());
        self
    }

    /// Reads fingerprint headers. `ip` must already be resolved (see [`resolve_client_ip`]).
    pub(crate) fn from_headers<H: HeaderSource + ?Sized>(
        ip: IpAddr,
        headers: &H,
        tls_header: Option<&str>,
        max_len: usize,
    ) -> Self {
        let get = |name: &str| first_header(headers, name, max_len);
        Self {
            ip: canonical_ip(ip),
            user_agent: get("user-agent"),
            ch_platform: get("sec-ch-ua-platform")
                .map(|p| p.trim_matches('"').trim().to_owned())
                .filter(|p| !p.is_empty()),
            ch_mobile: get("sec-ch-ua-mobile").and_then(|m| match m.as_str() {
                "?1" => Some(true),
                "?0" => Some(false),
                _ => None,
            }),
            accept_language: get("accept-language"),
            tls_fingerprint: tls_header.and_then(get),
        }
    }
}

/// Read access to request headers, so the core works without any HTTP library.
///
/// Implemented for `[(&str, &str)]` slices (names compared case-insensitively) and, with the
/// `axum` feature, for `http::HeaderMap`.
pub trait HeaderSource {
    /// All values of the header `name` (lowercase), in order.
    fn header_values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a [u8]> + 'a;
}

impl HeaderSource for [(&str, &str)] {
    fn header_values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a [u8]> + 'a {
        self.iter()
            .filter(move |(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_bytes())
    }
}

impl<const N: usize> HeaderSource for [(&str, &str); N] {
    fn header_values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a [u8]> + 'a {
        self.as_slice().header_values(name)
    }
}

impl HeaderSource for Vec<(&str, &str)> {
    fn header_values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a [u8]> + 'a {
        self.as_slice().header_values(name)
    }
}

#[cfg(feature = "axum")]
impl HeaderSource for http::HeaderMap {
    fn header_values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a [u8]> + 'a {
        self.get_all(name).iter().map(http::HeaderValue::as_bytes)
    }
}

/// First value of `name` as trimmed UTF-8, truncated to `max_len` bytes at a char boundary.
/// Non-UTF-8 and empty values are `None`.
pub(crate) fn first_header<H: HeaderSource + ?Sized>(headers: &H, name: &str, max_len: usize) -> Option<String> {
    let raw = headers.header_values(name).next()?;
    let value = std::str::from_utf8(raw).ok()?.trim();
    if value.is_empty() {
        return None;
    }
    Some(truncate(value, max_len).to_owned())
}

pub(crate) fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Maps IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) to IPv4.
pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 @ IpAddr::V4(_) => v4,
    }
}

/// Resolves the client IP from the TCP peer and `X-Forwarded-For` values.
///
/// `X-Forwarded-For` is only honoured when the peer is a trusted proxy. The chain is walked
/// right to left, skipping trusted proxies, and the first untrusted address is the client. A
/// malformed entry stops the walk and the peer address is used, so a client cannot inject an
/// address by sending a garbage header. Never panics on arbitrary input.
pub fn resolve_client_ip<'a>(peer: IpAddr, xff_values: impl IntoIterator<Item = &'a str>, trusted: &[IpNet]) -> IpAddr {
    let peer = canonical_ip(peer);
    let is_trusted = |ip: &IpAddr| trusted.iter().any(|net| net.contains(ip));
    if !is_trusted(&peer) {
        return peer;
    }
    let values: Vec<&str> = xff_values.into_iter().collect();
    let mut client = peer;
    for hop in values.iter().rev().flat_map(|v| v.rsplit(',')) {
        let Some(ip) = parse_hop(hop) else {
            return peer;
        };
        client = ip;
        if !is_trusted(&ip) {
            break;
        }
    }
    client
}

fn parse_hop(hop: &str) -> Option<IpAddr> {
    let hop = hop.trim();
    if let Ok(ip) = hop.parse::<IpAddr>() {
        return Some(canonical_ip(ip));
    }
    // "[2001:db8::1]:443" or "1.2.3.4:80"
    if let Ok(sock) = hop.parse::<std::net::SocketAddr>() {
        return Some(canonical_ip(sock.ip()));
    }
    None
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn nets(s: &[&str]) -> Vec<IpNet> {
        s.iter().map(|n| n.parse().unwrap()).collect()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn untrusted_peer_ignores_xff() {
        assert_eq!(resolve_client_ip(ip("1.2.3.4"), ["9.9.9.9"], &[]), ip("1.2.3.4"));
        assert_eq!(
            resolve_client_ip(ip("1.2.3.4"), ["9.9.9.9"], &nets(&["10.0.0.0/8"])),
            ip("1.2.3.4")
        );
    }

    #[test]
    fn walks_right_to_left_past_trusted_hops() {
        let trusted = nets(&["10.0.0.0/8"]);
        assert_eq!(
            resolve_client_ip(ip("10.0.0.1"), ["6.6.6.6, 5.5.5.5, 10.0.0.2"], &trusted),
            ip("5.5.5.5")
        );
        assert_eq!(
            resolve_client_ip(ip("10.0.0.1"), ["6.6.6.6", "5.5.5.5, 10.0.0.2"], &trusted),
            ip("5.5.5.5")
        );
    }

    #[test]
    fn spoofed_leftmost_entry_is_ignored() {
        let trusted = nets(&["10.0.0.0/8"]);
        // The attacker sends "X-Forwarded-For: 1.1.1.1"; the proxy appends the real address.
        assert_eq!(
            resolve_client_ip(ip("10.0.0.1"), ["1.1.1.1, 7.7.7.7"], &trusted),
            ip("7.7.7.7")
        );
    }

    #[test]
    fn garbage_falls_back_to_peer() {
        let trusted = nets(&["10.0.0.0/8"]);
        assert_eq!(
            resolve_client_ip(ip("10.0.0.1"), ["7.7.7.7, nope"], &trusted),
            ip("10.0.0.1")
        );
        assert_eq!(resolve_client_ip(ip("10.0.0.1"), [""], &trusted), ip("10.0.0.1"));
        assert_eq!(
            resolve_client_ip(ip("10.0.0.1"), ["7.7.7.7,"], &trusted),
            ip("10.0.0.1")
        );
    }

    #[test]
    fn all_trusted_chain_returns_leftmost() {
        let trusted = nets(&["10.0.0.0/8"]);
        assert_eq!(
            resolve_client_ip(ip("10.0.0.1"), ["10.0.0.3, 10.0.0.2"], &trusted),
            ip("10.0.0.3")
        );
        assert_eq!(
            resolve_client_ip(ip("10.0.0.1"), Vec::<&str>::new(), &trusted),
            ip("10.0.0.1")
        );
    }

    #[test]
    fn ports_brackets_and_mapped_addresses() {
        let trusted = nets(&["10.0.0.0/8", "::1/128"]);
        assert_eq!(
            resolve_client_ip(ip("::1"), ["[2001:db8::1]:443"], &trusted),
            ip("2001:db8::1")
        );
        assert_eq!(
            resolve_client_ip(ip("::ffff:10.0.0.1"), ["8.8.8.8:80"], &trusted),
            ip("8.8.8.8")
        );
        assert_eq!(
            resolve_client_ip(ip("::ffff:1.2.3.4"), ["8.8.8.8"], &trusted),
            ip("1.2.3.4")
        );
    }

    #[test]
    fn reads_and_normalises_headers() {
        let headers = [
            ("User-Agent", "  Mozilla/5.0  "),
            ("sec-ch-ua-platform", "\"macOS\""),
            ("Sec-CH-UA-Mobile", "?0"),
            ("accept-language", "en-US,en;q=0.9"),
            ("x-ja4", "t13d1516h2_8daaf6152771_02713d6af862"),
        ];
        let ctx = ClientContext::from_headers(ip("1.2.3.4"), &headers, Some("x-ja4"), 512);
        assert_eq!(ctx.user_agent.as_deref(), Some("Mozilla/5.0"));
        assert_eq!(ctx.ch_platform.as_deref(), Some("macOS"));
        assert_eq!(ctx.ch_mobile, Some(false));
        assert_eq!(ctx.accept_language.as_deref(), Some("en-US,en;q=0.9"));
        assert!(ctx.tls_fingerprint.is_some());

        let ctx = ClientContext::from_headers(
            ip("1.2.3.4"),
            &[("sec-ch-ua-mobile", "maybe"), ("user-agent", "")],
            None,
            512,
        );
        assert_eq!(ctx.ch_mobile, None);
        assert_eq!(ctx.user_agent, None);
        assert_eq!(ctx.tls_fingerprint, None);
    }

    #[test]
    fn truncates_at_char_boundary() {
        let long = "é".repeat(400);
        let headers = [("user-agent", long.as_str())];
        let ctx = ClientContext::from_headers(ip("1.2.3.4"), &headers, None, 513);
        assert_eq!(ctx.user_agent.unwrap().len(), 512);
    }

    proptest! {
        #[test]
        fn resolve_never_panics(xff in proptest::collection::vec(".{0,60}", 0..4), v6 in any::<bool>()) {
            let trusted = nets(&["0.0.0.0/0", "::/0"]);
            let peer = if v6 { ip("::1") } else { ip("127.0.0.1") };
            let _ = resolve_client_ip(peer, xff.iter().map(String::as_str), &trusted);
        }

        #[test]
        fn untrusted_peer_always_wins(xff in ".{0,60}", a in any::<u32>()) {
            let peer = IpAddr::V4(a.into());
            prop_assert_eq!(resolve_client_ip(peer, [xff.as_str()], &[]), peer);
        }
    }
}
