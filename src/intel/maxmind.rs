//! [`IpIntel`] backed by `MaxMind` `GeoLite2` / `GeoIP2` databases.

use std::fmt;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::SystemTime;

use arc_swap::ArcSwap;
use maxminddb::{PathElement, Reader};

use super::{IpInfo, IpIntel};

/// Which of the two databases an error is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MaxMindDatabase {
    /// The City or Country database, used for the ISO country code.
    Country,
    /// The ASN database, used for the autonomous system number.
    Asn,
}

impl fmt::Display for MaxMindDatabase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Country => "country",
            Self::Asn => "ASN",
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

/// Country and ASN lookups from `MaxMind` databases (`GeoLite2-City` / `GeoLite2-Country` /
/// `GeoIP2-*` for the country, `GeoLite2-ASN` for the network).
///
/// Databases are read into memory once, so lookups on the request path never touch the disk
/// and are lock-free. Unknown addresses and lookup errors yield empty fields.
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
/// events. A reload swaps both databases at once; in-flight lookups finish on the old ones.
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
    /// The files the current databases were read from; `None` when they came from bytes. The
    /// lock also serializes reloads, so an older read never replaces a newer one.
    files: Mutex<Option<Files>>,
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

fn stamp(country: &Path, asn: Option<&Path>) -> Result<Stamp, MaxMindError> {
    let file = |database, path: &Path| {
        let metadata = std::fs::metadata(path).map_err(io_error(database, path))?;
        Ok(FileStamp {
            modified: metadata.modified().ok(),
            len: metadata.len(),
        })
    };
    Ok((
        file(MaxMindDatabase::Country, country)?,
        asn.map(|path| file(MaxMindDatabase::Asn, path)).transpose()?,
    ))
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
    let has_country = kind.contains("country") || kind.contains("city");
    let has_asn = kind.contains("asn");
    let fits = match database {
        MaxMindDatabase::Country => has_country || !has_asn,
        MaxMindDatabase::Asn => has_asn || !has_country,
    };
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
            files: Mutex::new(Some(files)),
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
            files: Mutex::new(None),
        })
    }

    /// Replaces both databases with freshly read files, which later
    /// [`reload_if_changed`](Self::reload_if_changed) checks follow. In-flight lookups finish on
    /// the old databases. On error the current databases and files stay in place.
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
        *files = Some(read);
        Ok(())
    }

    /// Like [`reload`](Self::reload), from database contents already in memory. The databases
    /// no longer come from files, so [`reload_if_changed`](Self::reload_if_changed) stops
    /// checking them.
    ///
    /// # Errors
    ///
    /// As for [`from_bytes`](Self::from_bytes).
    pub fn reload_from_bytes(&self, country_db: Vec<u8>, asn_db: Option<Vec<u8>>) -> Result<(), MaxMindError> {
        let mut files = self.lock_files();
        self.databases.store(Arc::new(Databases::parse(country_db, asn_db)?));
        *files = None;
        Ok(())
    }

    /// Reloads the databases if their files changed since they were last read, and returns
    /// whether it did.
    ///
    /// The files are those given to [`open`](Self::open) or the latest
    /// [`reload`](Self::reload). Each is compared by modification time and size, which costs a
    /// `stat` per file; unchanged files are not read. Databases created with
    /// [`from_bytes`](Self::from_bytes) or [`reload_from_bytes`](Self::reload_from_bytes) have no
    /// files and always return `Ok(false)`.
    ///
    /// This blocks while it reads and parses changed files (tens of megabytes for a City
    /// database), so call it off the async runtime, or use [`spawn_reload`](Self::spawn_reload).
    ///
    /// # Errors
    ///
    /// As for [`open`](Self::open), for example when a file is missing, or only partly written
    /// by a tool that does not replace it atomically. The current databases then stay in place
    /// and the next call tries again.
    pub fn reload_if_changed(&self) -> Result<bool, MaxMindError> {
        let mut files = self.lock_files();
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
    fn lock_files(&self) -> MutexGuard<'_, Option<Files>> {
        self.files.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

const COUNTRY: [PathElement<'static>; 2] = [PathElement::Key("country"), PathElement::Key("iso_code")];
const REGISTERED_COUNTRY: [PathElement<'static>; 2] =
    [PathElement::Key("registered_country"), PathElement::Key("iso_code")];
const ASN: [PathElement<'static>; 1] = [PathElement::Key("autonomous_system_number")];

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
        IpInfo::new(country, asn)
    }
}

impl fmt::Debug for MaxMindIntel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let databases = self.databases.load();
        let files = self.files.lock().unwrap_or_else(PoisonError::into_inner);
        f.debug_struct("MaxMindIntel")
            .field("country", &databases.country.metadata().database_type)
            .field("asn", &databases.asn.as_ref().map(|r| &r.metadata().database_type))
            .field("country_file", &files.as_ref().map(|files| &files.country))
            .field("asn_file", &files.as_ref().and_then(|files| files.asn.as_ref()))
            .finish()
    }
}

#[cfg(test)]
#[path = "maxmind_tests.rs"]
mod tests;
