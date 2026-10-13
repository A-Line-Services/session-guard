//! Country, city, ASN, network name and anonymizer lookups for client IPs.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

#[cfg(feature = "maxmind")]
#[cfg_attr(docsrs, doc(cfg(feature = "maxmind")))]
mod maxmind;
#[cfg(feature = "maxmind")]
#[cfg_attr(docsrs, doc(cfg(feature = "maxmind")))]
pub use maxmind::{MaxMindDatabase, MaxMindError, MaxMindIntel};

/// What an [`IpIntel`] source knows about an address.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct IpInfo {
    /// ISO 3166-1 alpha-2 country code.
    pub country: Option<String>,
    /// Autonomous system number.
    pub asn: Option<u32>,
    /// Whether the address belongs to a VPN, proxy, hosting provider or Tor. `None` when the
    /// source does not know.
    pub anonymity: Option<Anonymity>,
    /// The city's English name, e.g. from a `MaxMind` City database. For display; not scored.
    pub city: Option<String>,
    /// The name of the organization behind the autonomous system, e.g. `"Example Telecom"`.
    /// For display; not scored.
    pub network: Option<String>,
}

impl IpInfo {
    /// Builds an `IpInfo` without anonymity, city or network information.
    pub fn new(country: Option<String>, asn: Option<u32>) -> Self {
        Self {
            country,
            asn,
            ..Self::default()
        }
    }

    /// Sets what the source knows about the network hiding the client.
    #[must_use]
    pub fn with_anonymity(mut self, anonymity: Anonymity) -> Self {
        self.anonymity = Some(anonymity);
        self
    }

    /// Sets the city's English name.
    #[must_use]
    pub fn with_city(mut self, city: impl Into<String>) -> Self {
        self.city = Some(city.into());
        self
    }

    /// Sets the name of the organization behind the autonomous system.
    #[must_use]
    pub fn with_network(mut self, network: impl Into<String>) -> Self {
        self.network = Some(network.into());
        self
    }
}

/// The kind of network an address belongs to, as far as hiding the client goes.
///
/// Moving from [`Direct`](Self::Direct) onto an anonymizer fires
/// [`Check::AnonymizerEntered`](crate::Check::AnonymizerEntered), moving onto Tor or an open
/// proxy fires [`Check::TorOrProxyEntered`](crate::Check::TorOrProxyEntered).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Anonymity {
    /// Looked up and not on a known anonymizer.
    Direct,
    /// A commercial VPN.
    Vpn,
    /// A hosting or cloud provider, where self-hosted VPNs and scripts run.
    HostingProvider,
    /// A residential proxy: traffic relayed through home connections.
    ResidentialProxy,
    /// An open proxy anyone can use.
    PublicProxy,
    /// A Tor exit node.
    TorExitNode,
}

/// A geolocation / ASN source. Without one, IP changes are judged by network prefix only.
///
/// Lookups run on the request path and must be fast and non-blocking. With the `maxmind`
/// feature, `MaxMindIntel` reads `GeoLite2` / `GeoIP2` databases held in memory.
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

/// Lets the guard share a source the app keeps a handle to, for example to reload `MaxMind`
/// databases.
impl<T: IpIntel + ?Sized> IpIntel for std::sync::Arc<T> {
    fn lookup(&self, ip: IpAddr) -> IpInfo {
        (**self).lookup(ip)
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

    #[test]
    fn builders_set_city_and_network() {
        let info = IpInfo::new(Some("BE".into()), Some(5432))
            .with_city("Brussels")
            .with_network(String::from("Example Telecom"));
        assert_eq!(info.city.as_deref(), Some("Brussels"));
        assert_eq!(info.network.as_deref(), Some("Example Telecom"));
        assert_eq!(info.country.as_deref(), Some("BE"));
        assert_eq!(info.asn, Some(5432));
        assert_eq!(IpInfo::new(None, None).city, None);
        assert_eq!(IpInfo::new(None, None).network, None);
    }

    #[test]
    fn shared_sources_are_sources() {
        fn source(intel: impl IpIntel) -> impl IpIntel {
            intel
        }
        #[derive(Debug)]
        struct Fixed;
        impl IpIntel for Fixed {
            fn lookup(&self, _ip: IpAddr) -> IpInfo {
                IpInfo::new(Some("BE".into()), None)
            }
        }
        let shared = std::sync::Arc::new(Fixed);
        let intel = source(std::sync::Arc::clone(&shared));
        assert_eq!(intel.lookup("1.2.3.4".parse().unwrap()).country.as_deref(), Some("BE"));
    }
}
