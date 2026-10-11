//! Country and ASN lookups for client IPs.

use std::net::IpAddr;

/// What an [`IpIntel`] source knows about an address.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct IpInfo {
    /// ISO 3166-1 alpha-2 country code.
    pub country: Option<String>,
    /// Autonomous system number.
    pub asn: Option<u32>,
}

impl IpInfo {
    /// Builds an `IpInfo`.
    pub fn new(country: Option<String>, asn: Option<u32>) -> Self {
        Self { country, asn }
    }
}

/// A geolocation / ASN source. Without one, IP changes are judged by network prefix only.
///
/// Lookups run on the request path and must be fast and non-blocking. With the `maxmind`
/// feature, `MaxMindIntel` reads memory-mapped `GeoLite2` / `GeoIP2` databases.
pub trait IpIntel: Send + Sync + 'static {
    /// Looks up `ip`. Return empty fields for unknown addresses; never panic.
    fn lookup(&self, ip: IpAddr) -> IpInfo;
}

/// The default source: knows nothing.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoIpIntel;

impl IpIntel for NoIpIntel {
    fn lookup(&self, _ip: IpAddr) -> IpInfo {
        IpInfo::default()
    }
}

impl<F> IpIntel for F
where
    F: Fn(IpAddr) -> IpInfo + Send + Sync + 'static,
{
    fn lookup(&self, ip: IpAddr) -> IpInfo {
        self(ip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closures_are_sources() {
        let intel = |_ip: IpAddr| IpInfo::new(Some("BE".into()), Some(5432));
        assert_eq!(intel.lookup("1.2.3.4".parse().unwrap()).asn, Some(5432));
        assert_eq!(NoIpIntel.lookup("1.2.3.4".parse().unwrap()), IpInfo::default());
    }
}
