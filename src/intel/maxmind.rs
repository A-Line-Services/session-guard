//! [`IpIntel`] backed by `MaxMind` `GeoLite2` / `GeoIP2` databases.

use std::fmt;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::SystemTime;

use arc_swap::{ArcSwap, ArcSwapOption};
use maxminddb::{PathElement, Reader};
use serde::Deserialize;

use super::{Anonymity, IpInfo, IpIntel};

/// Which database an error is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MaxMindDatabase {
    /// The City or Country database, used for the ISO country code.
    Country,
    /// The ASN database, used for the autonomous system number.
    Asn,
    /// The Anonymous IP, Anonymous Plus or IP Risk database, used for the [`Anonymity`].
    Anonymizer,
}

impl fmt::Display for MaxMindDatabase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Country => "country",
            Self::Asn => "ASN",
            Self::Anonymizer => "anonymizer",
        })
    }
}

/// Errors loading `MaxMind` databases.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MaxMindError {
    /// The database file could not be read.
    #[error("cannot read MaxMind {database} database {}: {source}", path.display())]
    Io {
        /// Which database.
        database: MaxMindDatabase,
        /// The path that failed.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The bytes are not a valid MMDB file.
    #[error("invalid MaxMind {database} database: {source}")]
    Invalid {
        /// Which database.
        database: MaxMindDatabase,
        /// The parser's error.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },
    /// A valid database of the wrong kind, e.g. an ASN database passed as the country database.
    #[error("expected a MaxMind {database} database, found {found:?}")]
    WrongDatabase {
        /// Which slot the database was passed for.
        database: MaxMindDatabase,
        /// The database type from the file's metadata.
        found: String,
    },
}

/// Country, ASN and anonymizer lookups from `MaxMind` databases (`GeoLite2-City` /
/// `GeoLite2-Country` / `GeoIP2-*` for the country, `GeoLite2-ASN` for the network, and
/// optionally `GeoIP2-Anonymous-IP`, `GeoIP-Anonymous-Plus` or `GeoIP2-IP-Risk` for VPNs,
/// proxies and Tor, added with [`with_anonymizer`](Self::with_anonymizer)).
///
/// Databases are read into memory once, so lookups on the request path never touch the disk
/// and are lock-free. Unknown addresses and lookup errors yield empty fields.
///
/// # Anonymizers
///
/// The anonymizer databases are paid `GeoIP2` products; there is no `GeoLite2` edition. With
/// one loaded, every lookup sets [`IpInfo::anonymity`], which feeds the
/// [`TorOrProxyEntered`](crate::Check::TorOrProxyEntered) and
/// [`AnonymizerEntered`](crate::Check::AnonymizerEntered) checks. The database's flags map to
/// the most severe [`Anonymity`] that applies:
///
/// | Flag | Anonymity |
/// |---|---|
/// | `is_tor_exit_node` | [`TorExitNode`](Anonymity::TorExitNode) |
/// | `is_public_proxy` | [`PublicProxy`](Anonymity::PublicProxy) |
/// | `is_residential_proxy` | [`ResidentialProxy`](Anonymity::ResidentialProxy) |
/// | `is_anonymous_vpn`, unless `anonymizer_confidence` is below 50 | [`Vpn`](Anonymity::Vpn) |
/// | `is_hosting_provider` | [`HostingProvider`](Anonymity::HostingProvider) |
/// | none of these, or an address the database does not list | [`Direct`](Anonymity::Direct) |
///
/// A failed lookup (e.g. an IPv6 address in an IPv4-only database) leaves the anonymity
/// unknown, so it never fires a check. The IP Risk database's `ip_risk` score is not used: the
/// guard scores what changed during a session rather than how risky an address is on its own.
///
/// ```no_run
/// use session_guard::MaxMindIntel;
///
/// let intel = MaxMindIntel::open("/var/lib/GeoIP/GeoLite2-Country.mmdb", None::<&str>)?
///     .with_anonymizer("/var/lib/GeoIP/GeoIP2-Anonymous-IP.mmdb")?;
/// # let _ = intel;
/// # Ok::<(), session_guard::MaxMindError>(())
/// ```
///
/// ```no_run
/// use session_guard::{Guard, GuardConfig, MaxMindIntel, MemoryStore};
///
/// let intel = MaxMindIntel::open(
///     "/var/lib/GeoIP/GeoLite2-Country.mmdb",
///     Some("/var/lib/GeoIP/GeoLite2-ASN.mmdb"),
/// )?;
/// let guard = Guard::builder(MemoryStore::new(), GuardConfig::default()).ip_intel(intel).build();
/// # let _ = guard;
/// # Ok::<(), session_guard::MaxMindError>(())
/// ```
///
/// # Keeping the databases up to date
///
/// `MaxMind` publishes new databases weekly or twice a week, and `geoipupdate` (as a cron job,
/// a sidecar or a shared volume) replaces the files on disk. Those new files are only used once
/// they are reloaded:
///
/// - [`spawn_reload`](Self::spawn_reload) (feature `tokio`) checks the files on an interval
///   and reloads them when they change. This is the usual choice.
/// - [`reload_if_changed`](Self::reload_if_changed) does a single check, to drive from your own
///   scheduler or runtime.
/// - [`reload`](Self::reload) and [`reload_from_bytes`](Self::reload_from_bytes) swap the
///   databases unconditionally.
///
/// A change is detected from each file's modification time and size, so it works on every kind
/// of mount, including network file systems and Kubernetes volumes that deliver no file system
/// events. A reload swaps the country and ASN databases at once; in-flight lookups finish on the
/// old ones. The anonymizer database is checked and reloaded on its own, so a failed update of
/// one never holds back the other. [`reload`](Self::reload) and
/// [`reload_from_bytes`](Self::reload_from_bytes) leave the anonymizer in place; swap it with
/// [`reload_anonymizer`](Self::reload_anonymizer) or
/// [`reload_anonymizer_from_bytes`](Self::reload_anonymizer_from_bytes).
///
/// To reload a source the guard uses, wrap it in an `Arc`, pass a clone to
/// [`GuardBuilder::ip_intel`](crate::GuardBuilder::ip_intel) and keep the other:
///
/// ```no_run
/// # #[cfg(feature = "tokio")]
/// # async fn run() -> Result<(), session_guard::MaxMindError> {
/// use std::sync::Arc;
/// use std::time::Duration;
///
/// use session_guard::{Guard, GuardConfig, MaxMindIntel, MemoryStore};
///
/// let intel = Arc::new(MaxMindIntel::open(
///     "/var/lib/GeoIP/GeoLite2-Country.mmdb",
///     Some("/var/lib/GeoIP/GeoLite2-ASN.mmdb"),
/// )?);
/// intel.spawn_reload(Duration::from_secs(60 * 60));
/// let guard = Guard::builder(MemoryStore::new(), GuardConfig::default())
///     .ip_intel(Arc::clone(&intel))
///     .build();
/// # let _ = guard;
/// # Ok(())
/// # }
/// ```
pub struct MaxMindIntel {
    databases: ArcSwap<Databases>,
    anonymizer: ArcSwapOption<Reader<Vec<u8>>>,
    /// The files the current databases were read from. The lock also serializes reloads, so an
    /// older read never replaces a newer one.
    files: Mutex<Watched>,
}

/// The files [`MaxMindIntel::reload_if_changed`] follows; `None` for databases from bytes.
#[derive(Default)]
struct Watched {
    geo: Option<Files>,
    anonymizer: Option<AnonymizerFile>,
}

/// The files behind the databases and their state just before they were read.
struct Files {
    country: PathBuf,
    asn: Option<PathBuf>,
    stamp: Stamp,
}

/// The state of the country and ASN files that [`MaxMindIntel::reload_if_changed`] compares.
type Stamp = (FileStamp, Option<FileStamp>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileStamp {
    modified: Option<SystemTime>,
    len: u64,
}

impl Files {
    /// Reads the databases at `country` and `asn`. The files' state is taken before reading, so
    /// a change during the read is caught by the next check instead of being missed.
    fn read(country: PathBuf, asn: Option<PathBuf>) -> Result<(Databases, Self), MaxMindError> {
        let stamp = stamp(&country, asn.as_deref())?;
        let databases = Databases::read(&country, asn.as_deref())?;
        Ok((databases, Self { country, asn, stamp }))
    }
}

/// The anonymizer database's file and its state just before it was read.
struct AnonymizerFile {
    path: PathBuf,
    stamp: FileStamp,
}

impl AnonymizerFile {
    /// Like [`Files::read`], for the anonymizer database.
    fn read(path: PathBuf) -> Result<(Reader<Vec<u8>>, Self), MaxMindError> {
        let database = MaxMindDatabase::Anonymizer;
        let stamp = file_stamp(database, &path)?;
        let bytes = std::fs::read(&path).map_err(io_error(database, &path))?;
        Ok((reader(database, bytes)?, Self { path, stamp }))
    }
}

fn stamp(country: &Path, asn: Option<&Path>) -> Result<Stamp, MaxMindError> {
    Ok((
        file_stamp(MaxMindDatabase::Country, country)?,
        asn.map(|path| file_stamp(MaxMindDatabase::Asn, path)).transpose()?,
    ))
}

fn file_stamp(database: MaxMindDatabase, path: &Path) -> Result<FileStamp, MaxMindError> {
    let metadata = std::fs::metadata(path).map_err(io_error(database, path))?;
    Ok(FileStamp {
        modified: metadata.modified().ok(),
        len: metadata.len(),
    })
}

fn io_error(database: MaxMindDatabase, path: &Path) -> impl FnOnce(std::io::Error) -> MaxMindError + '_ {
    move |source| MaxMindError::Io {
        database,
        path: path.to_owned(),
        source,
    }
}

struct Databases {
    country: Reader<Vec<u8>>,
    asn: Option<Reader<Vec<u8>>>,
}

impl Databases {
    fn read(country: &Path, asn: Option<impl AsRef<Path>>) -> Result<Self, MaxMindError> {
        let read = |database, path: &Path| std::fs::read(path).map_err(io_error(database, path));
        let country = read(MaxMindDatabase::Country, country)?;
        let asn = asn.map(|path| read(MaxMindDatabase::Asn, path.as_ref())).transpose()?;
        Self::parse(country, asn)
    }

    fn parse(country: Vec<u8>, asn: Option<Vec<u8>>) -> Result<Self, MaxMindError> {
        Ok(Self {
            country: reader(MaxMindDatabase::Country, country)?,
            asn: asn.map(|bytes| reader(MaxMindDatabase::Asn, bytes)).transpose()?,
        })
    }
}

fn reader(database: MaxMindDatabase, bytes: Vec<u8>) -> Result<Reader<Vec<u8>>, MaxMindError> {
    let reader = Reader::from_source(bytes).map_err(|source| MaxMindError::Invalid {
        database,
        source: Box::new(source),
    })?;
    let kind = reader.metadata().database_type.to_ascii_lowercase();
    // A database of a kind we do not recognize gets the benefit of the doubt in every slot.
    let kinds = [
        (
            MaxMindDatabase::Country,
            kind.contains("country") || kind.contains("city"),
        ),
        (MaxMindDatabase::Asn, kind.contains("asn")),
        (
            MaxMindDatabase::Anonymizer,
            kind.contains("anonymous") || kind.contains("ip-risk"),
        ),
    ];
    let fits = kinds.iter().any(|&(slot, is)| is && slot == database) || kinds.iter().all(|&(_, is)| !is);
    if !fits {
        return Err(MaxMindError::WrongDatabase {
            database,
            found: reader.metadata().database_type.clone(),
        });
    }
    Ok(reader)
}

impl MaxMindIntel {
    /// Reads the country database (City or Country edition) and, optionally, the ASN database.
    ///
    /// # Errors
    ///
    /// Fails when a file cannot be read, is not a valid MMDB file, or is the wrong kind of
    /// database.
    pub fn open(country_db: impl AsRef<Path>, asn_db: Option<impl AsRef<Path>>) -> Result<Self, MaxMindError> {
        let (databases, files) = Files::read(
            country_db.as_ref().to_owned(),
            asn_db.map(|path| path.as_ref().to_owned()),
        )?;
        Ok(Self {
            databases: ArcSwap::from_pointee(databases),
            anonymizer: ArcSwapOption::empty(),
            files: Mutex::new(Watched {
                geo: Some(files),
                anonymizer: None,
            }),
        })
    }

    /// Like [`open`](Self::open), from database contents already in memory.
    ///
    /// # Errors
    ///
    /// Fails when the bytes are not a valid MMDB file or the wrong kind of database.
    pub fn from_bytes(country_db: Vec<u8>, asn_db: Option<Vec<u8>>) -> Result<Self, MaxMindError> {
        Ok(Self {
            databases: ArcSwap::from_pointee(Databases::parse(country_db, asn_db)?),
            anonymizer: ArcSwapOption::empty(),
            files: Mutex::new(Watched::default()),
        })
    }

    /// Adds an Anonymous IP, Anonymous Plus or IP Risk database, so lookups also report the
    /// [`Anonymity`] of the network; see [Anonymizers](Self#anonymizers).
    /// [`reload_if_changed`](Self::reload_if_changed) follows its file too.
    ///
    /// # Errors
    ///
    /// Fails when the file cannot be read, is not a valid MMDB file, or is the wrong kind of
    /// database.
    pub fn with_anonymizer(self, anonymizer_db: impl AsRef<Path>) -> Result<Self, MaxMindError> {
        self.reload_anonymizer(anonymizer_db)?;
        Ok(self)
    }

    /// Like [`with_anonymizer`](Self::with_anonymizer), from database contents already in
    /// memory.
    ///
    /// # Errors
    ///
    /// Fails when the bytes are not a valid MMDB file or the wrong kind of database.
    pub fn with_anonymizer_bytes(self, anonymizer_db: Vec<u8>) -> Result<Self, MaxMindError> {
        self.reload_anonymizer_from_bytes(anonymizer_db)?;
        Ok(self)
    }

    /// Replaces the country and ASN databases with freshly read files, which later
    /// [`reload_if_changed`](Self::reload_if_changed) checks follow. In-flight lookups finish on
    /// the old databases. On error the current databases and files stay in place. The
    /// anonymizer database is left as it is.
    ///
    /// # Errors
    ///
    /// As for [`open`](Self::open).
    pub fn reload(&self, country_db: impl AsRef<Path>, asn_db: Option<impl AsRef<Path>>) -> Result<(), MaxMindError> {
        let mut files = self.lock_files();
        let (databases, read) = Files::read(
            country_db.as_ref().to_owned(),
            asn_db.map(|path| path.as_ref().to_owned()),
        )?;
        self.databases.store(Arc::new(databases));
        files.geo = Some(read);
        Ok(())
    }

    /// Like [`reload`](Self::reload), from database contents already in memory. The databases
    /// no longer come from files, so [`reload_if_changed`](Self::reload_if_changed) stops
    /// checking them (but still checks the anonymizer database's file, if it has one).
    ///
    /// # Errors
    ///
    /// As for [`from_bytes`](Self::from_bytes).
    pub fn reload_from_bytes(&self, country_db: Vec<u8>, asn_db: Option<Vec<u8>>) -> Result<(), MaxMindError> {
        let mut files = self.lock_files();
        self.databases.store(Arc::new(Databases::parse(country_db, asn_db)?));
        files.geo = None;
        Ok(())
    }

    /// Replaces (or adds) the anonymizer database with a freshly read file, which later
    /// [`reload_if_changed`](Self::reload_if_changed) checks follow. On error the current
    /// anonymizer database and file stay in place.
    ///
    /// # Errors
    ///
    /// As for [`with_anonymizer`](Self::with_anonymizer).
    pub fn reload_anonymizer(&self, anonymizer_db: impl AsRef<Path>) -> Result<(), MaxMindError> {
        let mut files = self.lock_files();
        let (reader, read) = AnonymizerFile::read(anonymizer_db.as_ref().to_owned())?;
        self.anonymizer.store(Some(Arc::new(reader)));
        files.anonymizer = Some(read);
        Ok(())
    }

    /// Like [`reload_anonymizer`](Self::reload_anonymizer), from database contents already in
    /// memory. [`reload_if_changed`](Self::reload_if_changed) then stops checking the
    /// anonymizer database.
    ///
    /// # Errors
    ///
    /// As for [`with_anonymizer_bytes`](Self::with_anonymizer_bytes).
    pub fn reload_anonymizer_from_bytes(&self, anonymizer_db: Vec<u8>) -> Result<(), MaxMindError> {
        let mut files = self.lock_files();
        let reader = reader(MaxMindDatabase::Anonymizer, anonymizer_db)?;
        self.anonymizer.store(Some(Arc::new(reader)));
        files.anonymizer = None;
        Ok(())
    }

    /// Reloads the databases if their files changed since they were last read, and returns
    /// whether it did.
    ///
    /// The files are those given to [`open`](Self::open) or the latest
    /// [`reload`](Self::reload), and to [`with_anonymizer`](Self::with_anonymizer) or the latest
    /// [`reload_anonymizer`](Self::reload_anonymizer). Each is compared by modification time and
    /// size, which costs a `stat` per file; unchanged files are not read. The country and ASN
    /// databases are reloaded together, the anonymizer database on its own. Databases from
    /// bytes have no files and are never reloaded here.
    ///
    /// This blocks while it reads and parses changed files (tens of megabytes for a City
    /// database), so call it off the async runtime, or use [`spawn_reload`](Self::spawn_reload).
    ///
    /// # Errors
    ///
    /// As for [`open`](Self::open), for example when a file is missing, or only partly written
    /// by a tool that does not replace it atomically. The databases that failed then stay in
    /// place and the next call tries again; the others are still reloaded. With failures on both
    /// sides, the country or ASN error is returned.
    pub fn reload_if_changed(&self) -> Result<bool, MaxMindError> {
        let mut files = self.lock_files();
        let geo = self.reload_geo_if_changed(&mut files.geo);
        let anonymizer = self.reload_anonymizer_if_changed(&mut files.anonymizer);
        Ok(geo? | anonymizer?)
    }

    fn reload_geo_if_changed(&self, files: &mut Option<Files>) -> Result<bool, MaxMindError> {
        let Some(current) = files.as_ref() else {
            return Ok(false);
        };
        if stamp(&current.country, current.asn.as_deref())? == current.stamp {
            return Ok(false);
        }
        let (databases, read) = Files::read(current.country.clone(), current.asn.clone())?;
        self.databases.store(Arc::new(databases));
        *files = Some(read);
        Ok(true)
    }

    fn reload_anonymizer_if_changed(&self, file: &mut Option<AnonymizerFile>) -> Result<bool, MaxMindError> {
        let Some(current) = file.as_ref() else {
            return Ok(false);
        };
        if file_stamp(MaxMindDatabase::Anonymizer, &current.path)? == current.stamp {
            return Ok(false);
        }
        let (reader, read) = AnonymizerFile::read(current.path.clone())?;
        self.anonymizer.store(Some(Arc::new(reader)));
        *file = Some(read);
        Ok(true)
    }

    /// Runs [`reload_if_changed`](Self::reload_if_changed) now and then every `every` on the
    /// tokio runtime, reading files on its blocking pool. Each reload is logged (`info`, with
    /// the databases' build times) and each failure too (`warn`), with `tracing`. A failed check
    /// does not stop the task and is retried on the next tick; abort the handle to stop it.
    ///
    /// `MaxMind` releases new databases at most twice a week, so an interval of minutes to an
    /// hour is plenty, and a check of unchanged files is cheap.
    ///
    /// # Panics
    ///
    /// Outside a tokio runtime, or if `every` is zero.
    #[cfg(feature = "tokio")]
    #[cfg_attr(docsrs, doc(cfg(feature = "tokio")))]
    pub fn spawn_reload(self: &Arc<Self>, every: std::time::Duration) -> tokio::task::JoinHandle<()> {
        let intel = Arc::clone(self);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(every);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                let check = Arc::clone(&intel);
                match tokio::task::spawn_blocking(move || check.reload_if_changed()).await {
                    Ok(Ok(true)) => {
                        let databases = intel.databases.load();
                        tracing::info!(
                            country_built = databases.country.metadata().build_epoch,
                            asn_built = databases.asn.as_ref().map(|reader| reader.metadata().build_epoch),
                            anonymizer_built = intel
                                .anonymizer
                                .load()
                                .as_ref()
                                .map(|reader| reader.metadata().build_epoch),
                            "reloaded MaxMind databases"
                        );
                    }
                    Ok(Ok(false)) => {}
                    Ok(Err(error)) => tracing::warn!(%error, "reloading MaxMind databases failed"),
                    Err(error) => tracing::warn!(%error, "reloading MaxMind databases panicked"),
                }
            }
        })
    }

    /// A reload that panicked left the previous state intact (it is only replaced on success),
    /// so a poisoned lock is safe to reuse.
    fn lock_files(&self) -> MutexGuard<'_, Watched> {
        self.files.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

const COUNTRY: [PathElement<'static>; 2] = [PathElement::Key("country"), PathElement::Key("iso_code")];
const REGISTERED_COUNTRY: [PathElement<'static>; 2] =
    [PathElement::Key("registered_country"), PathElement::Key("iso_code")];
const ASN: [PathElement<'static>; 1] = [PathElement::Key("autonomous_system_number")];

/// Below this `anonymizer_confidence`, `is_anonymous_vpn` is ignored.
const VPN_CONFIDENCE: u16 = 50;

/// The fields shared by the Anonymous IP, Anonymous Plus and IP Risk databases. Flags are only
/// present when true.
#[derive(Default, Deserialize)]
#[serde(default)]
#[allow(clippy::struct_excessive_bools, reason = "mirrors the database's record")]
struct AnonymizerRecord {
    is_anonymous_vpn: bool,
    is_hosting_provider: bool,
    is_public_proxy: bool,
    is_residential_proxy: bool,
    is_tor_exit_node: bool,
    anonymizer_confidence: Option<u16>,
}

impl AnonymizerRecord {
    fn anonymity(&self) -> Anonymity {
        if self.is_tor_exit_node {
            Anonymity::TorExitNode
        } else if self.is_public_proxy {
            Anonymity::PublicProxy
        } else if self.is_residential_proxy {
            Anonymity::ResidentialProxy
        } else if self.is_anonymous_vpn && self.anonymizer_confidence.is_none_or(|c| c >= VPN_CONFIDENCE) {
            Anonymity::Vpn
        } else if self.is_hosting_provider {
            Anonymity::HostingProvider
        } else {
            Anonymity::Direct
        }
    }
}

impl IpIntel for MaxMindIntel {
    fn lookup(&self, ip: IpAddr) -> IpInfo {
        let ip = crate::client::canonical_ip(ip);
        let databases = self.databases.load();
        let country = databases.country.lookup(ip).ok().and_then(|found| {
            [&COUNTRY[..], &REGISTERED_COUNTRY[..]]
                .into_iter()
                .find_map(|path| found.decode_path::<&str>(path).ok().flatten())
                .map(str::to_owned)
        });
        let asn = databases
            .asn
            .as_ref()
            .and_then(|reader| reader.lookup(ip).ok())
            .and_then(|found| found.decode_path::<u32>(&ASN).ok().flatten());
        // An address the database does not list is not known to be an anonymizer.
        let anonymity = self.anonymizer.load().as_ref().and_then(|reader| {
            let found = reader.lookup(ip).ok()?.decode::<AnonymizerRecord>().ok()?;
            Some(found.map_or(Anonymity::Direct, |record| record.anonymity()))
        });
        IpInfo {
            anonymity,
            ..IpInfo::new(country, asn)
        }
    }
}

impl fmt::Debug for MaxMindIntel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let databases = self.databases.load();
        let anonymizer = self.anonymizer.load();
        let files = self.files.lock().unwrap_or_else(PoisonError::into_inner);
        let geo = files.geo.as_ref();
        f.debug_struct("MaxMindIntel")
            .field("country", &databases.country.metadata().database_type)
            .field("asn", &databases.asn.as_ref().map(|r| &r.metadata().database_type))
            .field("anonymizer", &anonymizer.as_ref().map(|r| &r.metadata().database_type))
            .field("country_file", &geo.map(|files| &files.country))
            .field("asn_file", &geo.and_then(|files| files.asn.as_ref()))
            .field("anonymizer_file", &files.anonymizer.as_ref().map(|file| &file.path))
            .finish()
    }
}

#[cfg(test)]
#[path = "maxmind_tests.rs"]
mod tests;
