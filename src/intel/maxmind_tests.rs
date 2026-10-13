//! Tests for [`MaxMindIntel`], using tiny databases built in memory.

use std::net::IpAddr;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use super::*;

/// Minimal MMDB writer: an IPv4 tree with one node splitting the address space in halves.
mod mmdb {
    fn ctrl(kind: u8, size: usize) -> Vec<u8> {
        let (low, extra) = if size < 29 {
            (u8::try_from(size).expect("small"), None)
        } else {
            (29, Some(u8::try_from(size - 29).expect("under 285 bytes")))
        };
        let mut out = if kind <= 7 {
            vec![(kind << 5) | low]
        } else {
            vec![low, kind - 7]
        };
        out.extend(extra);
        out
    }

    pub fn string(s: &str) -> Vec<u8> {
        let mut out = ctrl(2, s.len());
        out.extend_from_slice(s.as_bytes());
        out
    }

    fn uint(kind: u8, value: u64) -> Vec<u8> {
        let bytes: Vec<u8> = value.to_be_bytes().into_iter().skip_while(|b| *b == 0).collect();
        let mut out = ctrl(kind, bytes.len());
        out.extend(bytes);
        out
    }

    pub fn u16(value: u16) -> Vec<u8> {
        uint(5, value.into())
    }

    pub fn u32(value: u32) -> Vec<u8> {
        uint(6, value.into())
    }

    pub fn u64(value: u64) -> Vec<u8> {
        uint(9, value)
    }

    pub fn bool(value: bool) -> Vec<u8> {
        ctrl(14, usize::from(value))
    }

    pub fn map(pairs: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut out = ctrl(7, pairs.len());
        for (key, value) in pairs {
            out.extend(string(key));
            out.extend_from_slice(value);
        }
        out
    }

    fn array(items: &[Vec<u8>]) -> Vec<u8> {
        let mut out = ctrl(11, items.len());
        for item in items {
            out.extend_from_slice(item);
        }
        out
    }

    /// `low` covers 0.0.0.0/1, `high` covers 128.0.0.0/1; `None` means no data.
    pub fn build(database_type: &str, low: Option<Vec<u8>>, high: Option<Vec<u8>>) -> Vec<u8> {
        const NODES: u32 = 1;
        let mut data = Vec::new();
        let mut record = |entry: Option<Vec<u8>>| match entry {
            None => NODES,
            Some(bytes) => {
                let offset = u32::try_from(data.len()).expect("small");
                data.extend(bytes);
                NODES + 16 + offset
            }
        };
        let (low, high) = (record(low), record(high));
        let mut out = Vec::new();
        for value in [low, high] {
            out.extend_from_slice(&value.to_be_bytes()[1..]);
        }
        out.extend([0u8; 16]);
        out.extend(data);
        out.extend_from_slice(b"\xAB\xCD\xEFMaxMind.com");
        out.extend(map(&[
            ("binary_format_major_version", u16(2)),
            ("binary_format_minor_version", u16(0)),
            ("build_epoch", u64(1_700_000_000)),
            ("database_type", string(database_type)),
            ("description", map(&[("en", string("test"))])),
            ("ip_version", u16(4)),
            ("languages", array(&[string("en")])),
            ("node_count", u32(NODES)),
            ("record_size", u16(24)),
        ]));
        out
    }

    pub fn country(database_type: &str, iso: &str) -> Vec<u8> {
        let record = map(&[
            ("city", map(&[("geoname_id", u32(2_800_866))])),
            ("country", map(&[("iso_code", string(iso))])),
        ]);
        build(database_type, Some(record), None)
    }

    pub fn asn(number: u32) -> Vec<u8> {
        let record = map(&[
            ("autonomous_system_number", u32(number)),
            ("autonomous_system_organization", string("Example")),
        ]);
        build("GeoLite2-ASN", Some(record), None)
    }

    /// An Anonymous IP database flagging 0.0.0.0/1 with `flags`, as `MaxMind` does: flags are
    /// only present when true.
    pub fn anonymizer(flags: &[&str], confidence: Option<u16>) -> Vec<u8> {
        let mut pairs: Vec<(&str, Vec<u8>)> = vec![("is_anonymous", bool(true))];
        pairs.extend(flags.iter().map(|flag| (*flag, bool(true))));
        pairs.extend(confidence.map(|value| ("anonymizer_confidence", u16(value))));
        build("GeoIP2-Anonymous-IP", Some(map(&pairs)), None)
    }
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn info(country: Option<&str>, asn: Option<u32>) -> IpInfo {
    IpInfo::new(country.map(str::to_owned), asn)
}

fn temp_file(name: &str, bytes: &[u8]) -> PathBuf {
    let path = std::env::temp_dir().join(format!("session-guard-{}-{name}", uuid::Uuid::new_v4()));
    std::fs::write(&path, bytes).unwrap();
    path
}

#[test]
fn country_database_yields_iso_code() {
    let intel = MaxMindIntel::from_bytes(mmdb::country("GeoLite2-Country", "BE"), None).unwrap();
    assert_eq!(intel.lookup(ip("1.2.3.4")), info(Some("BE"), None));
}

#[test]
fn city_database_is_accepted_for_country() {
    let intel = MaxMindIntel::from_bytes(mmdb::country("GeoLite2-City", "NL"), None).unwrap();
    assert_eq!(intel.lookup(ip("1.2.3.4")), info(Some("NL"), None));
}

#[test]
fn asn_database_yields_number() {
    let intel = MaxMindIntel::from_bytes(mmdb::country("GeoIP2-Country", "BE"), Some(mmdb::asn(5432))).unwrap();
    assert_eq!(intel.lookup(ip("1.2.3.4")), info(Some("BE"), Some(5432)));
}

#[test]
fn unknown_addresses_yield_empty_info() {
    let intel = MaxMindIntel::from_bytes(mmdb::country("GeoLite2-Country", "BE"), Some(mmdb::asn(5432))).unwrap();
    assert_eq!(intel.lookup(ip("200.1.2.3")), IpInfo::default());
}

#[test]
fn ipv6_in_ipv4_database_yields_empty_info_and_mapped_addresses_resolve() {
    let intel = MaxMindIntel::from_bytes(mmdb::country("GeoLite2-Country", "BE"), Some(mmdb::asn(5432))).unwrap();
    assert_eq!(intel.lookup(ip("2001:db8::1")), IpInfo::default());
    assert_eq!(intel.lookup(ip("::ffff:1.2.3.4")), info(Some("BE"), Some(5432)));
}

#[test]
fn records_without_the_field_yield_none() {
    let empty = mmdb::build("GeoLite2-Country", Some(mmdb::map(&[])), None);
    let intel = MaxMindIntel::from_bytes(empty, None).unwrap();
    assert_eq!(intel.lookup(ip("1.2.3.4")), IpInfo::default());
}

#[test]
fn falls_back_to_registered_country() {
    let record = mmdb::map(&[("registered_country", mmdb::map(&[("iso_code", mmdb::string("US"))]))]);
    let intel = MaxMindIntel::from_bytes(mmdb::build("GeoLite2-Country", Some(record), None), None).unwrap();
    assert_eq!(intel.lookup(ip("1.2.3.4")), info(Some("US"), None));
}

#[test]
fn garbage_bytes_are_rejected() {
    let err = MaxMindIntel::from_bytes(b"not a database".to_vec(), None).unwrap_err();
    assert!(
        matches!(
            err,
            MaxMindError::Invalid {
                database: MaxMindDatabase::Country,
                ..
            }
        ),
        "{err:?}"
    );

    let err = MaxMindIntel::from_bytes(mmdb::country("GeoLite2-Country", "BE"), Some(vec![0; 64])).unwrap_err();
    assert!(
        matches!(
            err,
            MaxMindError::Invalid {
                database: MaxMindDatabase::Asn,
                ..
            }
        ),
        "{err:?}"
    );
}

#[test]
fn swapped_databases_are_rejected() {
    let err = MaxMindIntel::from_bytes(mmdb::asn(1), None).unwrap_err();
    assert!(
        matches!(&err, MaxMindError::WrongDatabase { database: MaxMindDatabase::Country, found } if found == "GeoLite2-ASN"),
        "{err:?}"
    );

    let country = mmdb::country("GeoLite2-Country", "BE");
    let err = MaxMindIntel::from_bytes(country.clone(), Some(country)).unwrap_err();
    assert!(
        matches!(
            err,
            MaxMindError::WrongDatabase {
                database: MaxMindDatabase::Asn,
                ..
            }
        ),
        "{err:?}"
    );
}

#[test]
fn missing_file_reports_the_path() {
    let missing = std::env::temp_dir().join("session-guard-definitely-missing.mmdb");
    let err = MaxMindIntel::open(&missing, None::<&str>).unwrap_err();
    match &err {
        MaxMindError::Io { path, .. } => assert_eq!(path, &missing),
        other => panic!("unexpected {other:?}"),
    }
    assert!(err.to_string().contains("session-guard-definitely-missing.mmdb"));
}

#[test]
fn opens_files() {
    let country = temp_file("country.mmdb", &mmdb::country("GeoLite2-City", "BE"));
    let asn = temp_file("asn.mmdb", &mmdb::asn(64_500));
    let intel = MaxMindIntel::open(&country, Some(&asn)).unwrap();
    assert_eq!(intel.lookup(ip("1.2.3.4")), info(Some("BE"), Some(64_500)));
    std::fs::remove_file(country).unwrap();
    std::fs::remove_file(asn).unwrap();
}

#[test]
fn reload_swaps_databases_and_failed_reload_keeps_the_old_ones() {
    let intel = MaxMindIntel::from_bytes(mmdb::country("GeoLite2-Country", "BE"), None).unwrap();

    intel
        .reload_from_bytes(mmdb::country("GeoLite2-Country", "FR"), Some(mmdb::asn(7)))
        .unwrap();
    assert_eq!(intel.lookup(ip("1.2.3.4")), info(Some("FR"), Some(7)));

    assert!(intel.reload_from_bytes(b"garbage".to_vec(), None).is_err());
    let missing = std::env::temp_dir().join("session-guard-missing-reload.mmdb");
    assert!(intel.reload(&missing, None::<&str>).is_err());
    assert_eq!(intel.lookup(ip("1.2.3.4")), info(Some("FR"), Some(7)));

    let country = temp_file("reload.mmdb", &mmdb::country("GeoLite2-Country", "DE"));
    intel.reload(&country, None::<&str>).unwrap();
    assert_eq!(intel.lookup(ip("1.2.3.4")), info(Some("DE"), None));
    std::fs::remove_file(country).unwrap();
}

/// A modification time `secs` after the epoch, so change detection in the tests does not hinge
/// on the file system's timestamp resolution.
fn at(secs: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
}

/// Writes `path` with the given contents and modification time.
fn write_file(path: &Path, bytes: &[u8], modified: SystemTime) {
    std::fs::write(path, bytes).unwrap();
    let file = std::fs::File::options().write(true).open(path).unwrap();
    file.set_modified(modified).unwrap();
}

/// Replaces `path` the way `geoipupdate` does: write a sibling file, then rename it over.
fn replace_file(path: &Path, bytes: &[u8], modified: SystemTime) {
    let staged = path.with_extension("staged");
    write_file(&staged, bytes, modified);
    std::fs::rename(&staged, path).unwrap();
}

#[test]
fn reload_if_changed_leaves_unchanged_files_unread() {
    let country = temp_file("unchanged.mmdb", &[]);
    let bytes = mmdb::country("GeoLite2-Country", "BE");
    write_file(&country, &bytes, at(1));
    let intel = MaxMindIntel::open(&country, None::<&str>).unwrap();
    assert!(!intel.reload_if_changed().unwrap());

    // Same size and modification time: the contents are not even read.
    write_file(&country, &vec![0; bytes.len()], at(1));
    assert!(!intel.reload_if_changed().unwrap());
    assert_eq!(intel.lookup(ip("1.2.3.4")), info(Some("BE"), None));
    std::fs::remove_file(country).unwrap();
}

#[test]
fn reload_if_changed_picks_up_replaced_files() {
    let country = temp_file("replaced-country.mmdb", &mmdb::country("GeoLite2-Country", "BE"));
    let asn = temp_file("replaced-asn.mmdb", &mmdb::asn(1));
    let intel = MaxMindIntel::open(&country, Some(&asn)).unwrap();

    replace_file(&country, &mmdb::country("GeoLite2-Country", "FR"), at(2));
    assert!(intel.reload_if_changed().unwrap());
    assert_eq!(intel.lookup(ip("1.2.3.4")), info(Some("FR"), Some(1)));
    assert!(!intel.reload_if_changed().unwrap());

    // A change to the ASN database alone is enough.
    replace_file(&asn, &mmdb::asn(2), at(3));
    assert!(intel.reload_if_changed().unwrap());
    assert_eq!(intel.lookup(ip("1.2.3.4")), info(Some("FR"), Some(2)));
    assert!(!intel.reload_if_changed().unwrap());

    std::fs::remove_file(country).unwrap();
    std::fs::remove_file(asn).unwrap();
}

#[test]
fn reload_if_changed_keeps_the_old_databases_and_retries_after_a_failure() {
    let country = temp_file("retry.mmdb", &mmdb::country("GeoLite2-Country", "BE"));
    let intel = MaxMindIntel::open(&country, None::<&str>).unwrap();

    // A writer that is still busy with the file, then a file briefly gone during a swap.
    write_file(&country, b"half a database", at(2));
    assert!(intel.reload_if_changed().is_err());
    assert!(intel.reload_if_changed().is_err(), "a failed reload is retried");
    std::fs::remove_file(&country).unwrap();
    assert!(matches!(intel.reload_if_changed(), Err(MaxMindError::Io { .. })));
    assert_eq!(intel.lookup(ip("1.2.3.4")), info(Some("BE"), None));

    write_file(&country, &mmdb::country("GeoLite2-Country", "DE"), at(2));
    assert!(intel.reload_if_changed().unwrap());
    assert_eq!(intel.lookup(ip("1.2.3.4")), info(Some("DE"), None));
    std::fs::remove_file(country).unwrap();
}

#[test]
fn reload_if_changed_follows_the_files_of_the_last_reload() {
    let intel = MaxMindIntel::from_bytes(mmdb::country("GeoLite2-Country", "BE"), None).unwrap();
    assert!(
        !intel.reload_if_changed().unwrap(),
        "databases from bytes have no files"
    );

    let first = temp_file("first.mmdb", &mmdb::country("GeoLite2-Country", "FR"));
    let second = temp_file("second.mmdb", &mmdb::country("GeoLite2-Country", "DE"));
    intel.reload(&first, None::<&str>).unwrap();
    intel.reload(&second, None::<&str>).unwrap();
    replace_file(&first, &mmdb::country("GeoLite2-Country", "NL"), at(2));
    assert!(!intel.reload_if_changed().unwrap());
    replace_file(&second, &mmdb::country("GeoLite2-Country", "LU"), at(2));
    assert!(intel.reload_if_changed().unwrap());
    assert_eq!(intel.lookup(ip("1.2.3.4")), info(Some("LU"), None));

    intel
        .reload_from_bytes(mmdb::country("GeoLite2-Country", "BE"), None)
        .unwrap();
    replace_file(&second, &mmdb::country("GeoLite2-Country", "AT"), at(3));
    assert!(!intel.reload_if_changed().unwrap(), "bytes replace the files");
    assert_eq!(intel.lookup(ip("1.2.3.4")), info(Some("BE"), None));

    std::fs::remove_file(first).unwrap();
    std::fs::remove_file(second).unwrap();
}

/// Waits (in real time) until `ip` resolves to `expected`.
#[cfg(feature = "tokio")]
async fn eventually_resolves(intel: &MaxMindIntel, expected: IpInfo) {
    for _ in 0..500 {
        if intel.lookup(ip("1.2.3.4")) == expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("never resolved to {expected:?}");
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn spawn_reload_picks_up_changes_and_survives_failures() {
    let country = temp_file("spawned.mmdb", &mmdb::country("GeoLite2-Country", "BE"));
    let intel = Arc::new(MaxMindIntel::open(&country, None::<&str>).unwrap());
    let task = intel.spawn_reload(Duration::from_millis(10));

    replace_file(&country, b"garbage", at(2));
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(intel.lookup(ip("1.2.3.4")), info(Some("BE"), None));

    replace_file(&country, &mmdb::country("GeoLite2-Country", "FR"), at(3));
    eventually_resolves(&intel, info(Some("FR"), None)).await;

    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    std::fs::remove_file(country).unwrap();
}

fn country_be() -> Vec<u8> {
    mmdb::country("GeoLite2-Country", "BE")
}

fn anonymity(intel: &MaxMindIntel, address: &str) -> Option<Anonymity> {
    intel.lookup(ip(address)).anonymity
}

fn with_anonymizer(country: Vec<u8>, flags: &[&str]) -> MaxMindIntel {
    MaxMindIntel::from_bytes(country, None)
        .unwrap()
        .with_anonymizer_bytes(mmdb::anonymizer(flags, None))
        .unwrap()
}

#[test]
fn anonymizer_flags_map_to_the_most_severe_anonymity() {
    use Anonymity::{Direct, HostingProvider, PublicProxy, ResidentialProxy, TorExitNode, Vpn};
    let cases: [(&[&str], Option<u16>, Anonymity); 10] = [
        (
            &[
                "is_tor_exit_node",
                "is_public_proxy",
                "is_anonymous_vpn",
                "is_hosting_provider",
            ],
            Some(99),
            TorExitNode,
        ),
        (
            &["is_public_proxy", "is_residential_proxy", "is_anonymous_vpn"],
            Some(99),
            PublicProxy,
        ),
        (
            &["is_residential_proxy", "is_anonymous_vpn", "is_hosting_provider"],
            Some(99),
            ResidentialProxy,
        ),
        (&["is_anonymous_vpn", "is_hosting_provider"], Some(99), Vpn),
        (&["is_anonymous_vpn"], Some(50), Vpn),
        (&["is_anonymous_vpn"], None, Vpn),
        // Low confidence that the network is a VPN: only the other flags count.
        (&["is_anonymous_vpn", "is_hosting_provider"], Some(30), HostingProvider),
        (&["is_anonymous_vpn"], Some(30), Direct),
        (&["is_hosting_provider"], None, HostingProvider),
        (&[], None, Direct),
    ];
    for (flags, confidence, expected) in cases {
        let intel = MaxMindIntel::from_bytes(country_be(), None)
            .unwrap()
            .with_anonymizer_bytes(mmdb::anonymizer(flags, confidence))
            .unwrap();
        assert_eq!(anonymity(&intel, "1.2.3.4"), Some(expected), "{flags:?} {confidence:?}");
    }
}

#[test]
fn unlisted_addresses_are_direct_and_unknown_without_an_anonymizer() {
    let intel = MaxMindIntel::from_bytes(country_be(), Some(mmdb::asn(5432))).unwrap();
    assert_eq!(anonymity(&intel, "1.2.3.4"), None);

    let intel = intel
        .with_anonymizer_bytes(mmdb::anonymizer(&["is_anonymous_vpn"], None))
        .unwrap();
    assert_eq!(
        intel.lookup(ip("1.2.3.4")),
        info(Some("BE"), Some(5432)).with_anonymity(Anonymity::Vpn)
    );
    assert_eq!(anonymity(&intel, "200.1.2.3"), Some(Anonymity::Direct));
    assert_eq!(anonymity(&intel, "2001:db8::1"), None, "a failed lookup is unknown");
}

#[test]
fn anonymizer_opens_from_a_file() {
    let anonymizer = temp_file("anonymizer.mmdb", &mmdb::anonymizer(&["is_tor_exit_node"], None));
    let intel = MaxMindIntel::from_bytes(country_be(), None)
        .unwrap()
        .with_anonymizer(&anonymizer)
        .unwrap();
    assert_eq!(anonymity(&intel, "1.2.3.4"), Some(Anonymity::TorExitNode));
    std::fs::remove_file(anonymizer).unwrap();

    let missing = std::env::temp_dir().join("session-guard-missing-anonymizer.mmdb");
    let err = MaxMindIntel::from_bytes(country_be(), None)
        .unwrap()
        .with_anonymizer(&missing)
        .unwrap_err();
    assert!(
        matches!(
            err,
            MaxMindError::Io {
                database: MaxMindDatabase::Anonymizer,
                ..
            }
        ),
        "{err:?}"
    );
    assert!(err.to_string().contains("MaxMind anonymizer database"), "{err}");
}

#[test]
fn anonymizer_databases_only_fit_the_anonymizer_slot() {
    let wrong = |err: MaxMindError, slot: MaxMindDatabase| {
        assert!(
            matches!(&err, MaxMindError::WrongDatabase { database, .. } if *database == slot),
            "{err:?}"
        );
    };
    for kind in ["GeoIP2-Anonymous-IP", "GeoIP-Anonymous-Plus", "GeoIP2-IP-Risk"] {
        let bytes = mmdb::build(kind, Some(mmdb::map(&[])), None);
        wrong(
            MaxMindIntel::from_bytes(bytes.clone(), None).unwrap_err(),
            MaxMindDatabase::Country,
        );
        wrong(
            MaxMindIntel::from_bytes(country_be(), Some(bytes.clone())).unwrap_err(),
            MaxMindDatabase::Asn,
        );
        let intel = MaxMindIntel::from_bytes(country_be(), None).unwrap();
        assert!(intel.with_anonymizer_bytes(bytes).is_ok(), "{kind}");
    }
    for bytes in [mmdb::country("GeoLite2-City", "BE"), mmdb::asn(1)] {
        let intel = MaxMindIntel::from_bytes(country_be(), None).unwrap();
        wrong(
            intel.with_anonymizer_bytes(bytes).unwrap_err(),
            MaxMindDatabase::Anonymizer,
        );
    }
    let intel = MaxMindIntel::from_bytes(country_be(), None).unwrap();
    let err = intel.with_anonymizer_bytes(b"garbage".to_vec()).unwrap_err();
    assert!(
        matches!(
            err,
            MaxMindError::Invalid {
                database: MaxMindDatabase::Anonymizer,
                ..
            }
        ),
        "{err:?}"
    );
}

#[test]
fn reload_keeps_the_anonymizer_and_reload_anonymizer_swaps_it() {
    let intel = with_anonymizer(country_be(), &["is_anonymous_vpn"]);
    let vpn = |iso| info(Some(iso), None).with_anonymity(Anonymity::Vpn);

    intel
        .reload_from_bytes(mmdb::country("GeoLite2-Country", "FR"), None)
        .unwrap();
    assert_eq!(intel.lookup(ip("1.2.3.4")), vpn("FR"));
    let country = temp_file("keeps-anonymizer.mmdb", &mmdb::country("GeoLite2-Country", "DE"));
    intel.reload(&country, None::<&str>).unwrap();
    assert_eq!(intel.lookup(ip("1.2.3.4")), vpn("DE"));

    intel
        .reload_anonymizer_from_bytes(mmdb::anonymizer(&["is_tor_exit_node"], None))
        .unwrap();
    assert_eq!(anonymity(&intel, "1.2.3.4"), Some(Anonymity::TorExitNode));
    assert!(intel.reload_anonymizer_from_bytes(b"garbage".to_vec()).is_err());
    assert!(intel.reload_anonymizer(&country).is_err());
    assert_eq!(anonymity(&intel, "1.2.3.4"), Some(Anonymity::TorExitNode));

    let anonymizer = temp_file("swapped-anonymizer.mmdb", &mmdb::anonymizer(&["is_public_proxy"], None));
    intel.reload_anonymizer(&anonymizer).unwrap();
    assert_eq!(anonymity(&intel, "1.2.3.4"), Some(Anonymity::PublicProxy));
    assert_eq!(intel.lookup(ip("1.2.3.4")).country.as_deref(), Some("DE"));

    std::fs::remove_file(country).unwrap();
    std::fs::remove_file(anonymizer).unwrap();
}

#[test]
fn reload_if_changed_follows_the_anonymizer_file_on_its_own() {
    let country = temp_file("own-country.mmdb", &country_be());
    let anonymizer = temp_file("own-anonymizer.mmdb", &mmdb::anonymizer(&["is_anonymous_vpn"], None));
    let intel = MaxMindIntel::open(&country, None::<&str>)
        .unwrap()
        .with_anonymizer(&anonymizer)
        .unwrap();
    assert!(!intel.reload_if_changed().unwrap());

    replace_file(&anonymizer, &mmdb::anonymizer(&["is_tor_exit_node"], None), at(2));
    assert!(intel.reload_if_changed().unwrap());
    assert_eq!(
        intel.lookup(ip("1.2.3.4")),
        info(Some("BE"), None).with_anonymity(Anonymity::TorExitNode)
    );
    assert!(!intel.reload_if_changed().unwrap());

    // A broken anonymizer update does not hold back the country database, and is retried.
    replace_file(&anonymizer, b"garbage", at(3));
    replace_file(&country, &mmdb::country("GeoLite2-Country", "FR"), at(3));
    assert!(intel.reload_if_changed().is_err());
    assert_eq!(
        intel.lookup(ip("1.2.3.4")),
        info(Some("FR"), None).with_anonymity(Anonymity::TorExitNode)
    );
    replace_file(&anonymizer, &mmdb::anonymizer(&["is_public_proxy"], None), at(4));
    assert!(intel.reload_if_changed().unwrap());
    assert_eq!(anonymity(&intel, "1.2.3.4"), Some(Anonymity::PublicProxy));

    // Country databases from bytes still leave the anonymizer file followed.
    intel.reload_from_bytes(country_be(), None).unwrap();
    replace_file(&anonymizer, &mmdb::anonymizer(&["is_anonymous_vpn"], None), at(5));
    assert!(intel.reload_if_changed().unwrap());
    assert_eq!(anonymity(&intel, "1.2.3.4"), Some(Anonymity::Vpn));

    // An anonymizer from bytes has no file to follow.
    intel
        .reload_anonymizer_from_bytes(mmdb::anonymizer(&["is_hosting_provider"], None))
        .unwrap();
    replace_file(&anonymizer, &mmdb::anonymizer(&["is_tor_exit_node"], None), at(6));
    assert!(!intel.reload_if_changed().unwrap());
    assert_eq!(anonymity(&intel, "1.2.3.4"), Some(Anonymity::HostingProvider));

    std::fs::remove_file(country).unwrap();
    std::fs::remove_file(anonymizer).unwrap();
}

#[test]
fn debug_names_the_databases_and_files() {
    let anonymizer = temp_file("debug-anonymizer.mmdb", &mmdb::anonymizer(&[], None));
    let intel = MaxMindIntel::from_bytes(country_be(), None)
        .unwrap()
        .with_anonymizer(&anonymizer)
        .unwrap();
    let debug = format!("{intel:?}");
    assert!(debug.contains("GeoIP2-Anonymous-IP"), "{debug}");
    assert!(debug.contains("debug-anonymizer.mmdb"), "{debug}");
    std::fs::remove_file(anonymizer).unwrap();
}

#[test]
fn plugs_into_the_guard() {
    let intel = MaxMindIntel::from_bytes(mmdb::country("GeoLite2-Country", "BE"), None).unwrap();
    let _guard = crate::Guard::builder(crate::MemoryStore::new(), crate::GuardConfig::default())
        .ip_intel(intel)
        .build();
}

/// Real-database smoke test. Set `SESSION_GUARD_MAXMIND_TEST_DB` to a GeoLite2/GeoIP2 City or
/// Country file (and optionally `SESSION_GUARD_MAXMIND_TEST_ASN_DB` to a GeoLite2-ASN file).
#[test]
fn real_database_from_env() {
    let Some(country) = std::env::var_os("SESSION_GUARD_MAXMIND_TEST_DB") else {
        eprintln!("SESSION_GUARD_MAXMIND_TEST_DB unset; skipping");
        return;
    };
    let asn = std::env::var_os("SESSION_GUARD_MAXMIND_TEST_ASN_DB");
    let intel = MaxMindIntel::open(country, asn.as_ref()).unwrap();
    // A well-known, stably geolocated address (Google public DNS).
    let found = intel.lookup(ip("8.8.8.8"));
    assert_eq!(found.country.as_deref(), Some("US"));
    if asn.is_some() {
        assert_eq!(found.asn, Some(15169));
    }
    assert_eq!(intel.lookup(ip("10.0.0.1")), IpInfo::default());
}
