//! [`IpIntel`] backed by `MaxMind` `GeoLite2` / `GeoIP2` databases.

use std::fmt;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

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
/// Databases are read into memory and can be swapped at runtime with [`reload`](Self::reload)
/// (for example after a `geoipupdate` run); lookups on the request path are lock-free. Unknown
/// addresses and lookup errors yield empty fields.
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
pub struct MaxMindIntel {
    databases: ArcSwap<Databases>,
}

struct Databases {
    country: Reader<Vec<u8>>,
    asn: Option<Reader<Vec<u8>>>,
}

impl Databases {
    fn read(country: &Path, asn: Option<impl AsRef<Path>>) -> Result<Self, MaxMindError> {
        let read = |database, path: &Path| {
            std::fs::read(path).map_err(|source| MaxMindError::Io {
                database,
                path: path.to_owned(),
                source,
            })
        };
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
        let databases = Databases::read(country_db.as_ref(), asn_db)?;
        Ok(Self {
            databases: ArcSwap::from_pointee(databases),
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
        })
    }

    /// Replaces both databases with freshly read files. In-flight lookups finish on the old
    /// databases. On error the current databases stay in place.
    ///
    /// To reload a source the guard uses, wrap it in an `Arc`, pass a clone to
    /// [`GuardBuilder::ip_intel`](crate::GuardBuilder::ip_intel) and keep the other.
    ///
    /// # Errors
    ///
    /// As for [`open`](Self::open).
    pub fn reload(&self, country_db: impl AsRef<Path>, asn_db: Option<impl AsRef<Path>>) -> Result<(), MaxMindError> {
        let databases = Databases::read(country_db.as_ref(), asn_db)?;
        self.databases.store(Arc::new(databases));
        Ok(())
    }

    /// Like [`reload`](Self::reload), from database contents already in memory.
    ///
    /// # Errors
    ///
    /// As for [`from_bytes`](Self::from_bytes).
    pub fn reload_from_bytes(&self, country_db: Vec<u8>, asn_db: Option<Vec<u8>>) -> Result<(), MaxMindError> {
        self.databases.store(Arc::new(Databases::parse(country_db, asn_db)?));
        Ok(())
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
        f.debug_struct("MaxMindIntel")
            .field("country", &databases.country.metadata().database_type)
            .field("asn", &databases.asn.as_ref().map(|r| &r.metadata().database_type))
            .finish()
    }
}

#[cfg(test)]
#[path = "maxmind_tests.rs"]
mod tests;
