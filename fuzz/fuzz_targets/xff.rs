//! Client IP resolution from arbitrary `X-Forwarded-For` values and trusted proxy lists.
#![no_main]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use ipnet::IpNet;
use libfuzzer_sys::fuzz_target;
use session_guard::{canonical_ip, resolve_client_ip};

fn ip(v6: bool, bytes: [u8; 16]) -> IpAddr {
    if v6 {
        IpAddr::V6(Ipv6Addr::from(bytes))
    } else {
        IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
    }
}

/// An independent reading of one hop: an IP, or a socket address.
fn hop(s: &str) -> Option<IpAddr> {
    let s = s.trim();
    s.parse::<IpAddr>()
        .ok()
        .or_else(|| s.parse::<SocketAddr>().ok().map(|sock| sock.ip()))
        .map(canonical_ip)
}

/// `(is_v6, address bytes, prefix length)`, reduced into range.
type Net = (bool, [u8; 16], u8);

fuzz_target!(|input: (bool, [u8; 16], Vec<&str>, Vec<Net>)| {
    let (v6, peer, xff, nets) = input;
    let peer = ip(v6, peer);
    let trusted: Vec<IpNet> = nets
        .into_iter()
        .map(|(v6, bytes, prefix)| {
            let max = if v6 { 128 } else { 32 };
            IpNet::new(ip(v6, bytes), prefix % (max + 1)).expect("prefix in range")
        })
        .collect();
    let is_trusted = |ip: &IpAddr| trusted.iter().any(|net| net.contains(ip));

    let resolved = resolve_client_ip(peer, xff.iter().copied(), &trusted);
    let peer = canonical_ip(peer);

    assert_eq!(canonical_ip(resolved), resolved, "result is canonical");
    if !is_trusted(&peer) {
        assert_eq!(resolved, peer, "an untrusted peer's headers are ignored");
    }
    if resolved != peer {
        let hops: Vec<IpAddr> = xff.iter().flat_map(|v| v.split(',')).filter_map(hop).collect();
        assert!(hops.contains(&resolved), "{resolved} was not in {xff:?}");
        let leftmost = xff.first().and_then(|v| v.split(',').next()).and_then(hop);
        assert!(
            !is_trusted(&resolved) || leftmost == Some(resolved),
            "a trusted hop is returned only when the whole chain is trusted"
        );
    }
});
