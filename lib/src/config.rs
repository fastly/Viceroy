//! Fastly-specific configuration utilities.

use {
    self::{
        backends::BackendsConfig, dictionaries::DictionariesConfig,
        object_store::ObjectStoreConfig, secret_store::SecretStoreConfig,
    },
    crate::error::FastlyConfigError,
    serde_derive::Deserialize,
    std::{collections::HashMap, convert::TryInto, fs, path::Path, str::FromStr, sync::Arc},
    toml::value::Table,
};

/// Unit tests for the [`FastlyConfig`] and [`TestingConfig`] types.
#[cfg(test)]
mod unit_tests;

/// Fastly limits
mod limits;

/// Types and deserializers for dictionaries configuration settings.
mod dictionaries;

pub use self::dictionaries::{Dictionary, LoadedDictionary};

pub type Dictionaries = HashMap<String, Dictionary>;

/// Types and deserializers for backend configuration settings.
mod backends;

pub use self::backends::{Backend, ClientCertError, ClientCertInfo};

pub type Backends = HashMap<String, Arc<Backend>>;

/// Types and deserializers for device detection configuration settings.
mod device_detection;

pub use self::device_detection::DeviceDetection;

/// Types and deserializers for geolocation configuration settings.
mod geolocation;

pub use self::geolocation::Geolocation;

/// Types and deserializers for object store configuration settings.
mod object_store;

pub use crate::object_store::ObjectStores;

/// Types and deserializers for secret store configuration settings.
mod secret_store;
pub use crate::secret_store::SecretStores;

/// Fastly-specific configuration information.
///
/// This `struct` represents the fields and values in a Compute package's `fastly.toml`.
#[derive(Debug, Clone)]
pub struct FastlyConfig {
    name: String,
    description: String,
    authors: Vec<String>,
    language: String,
    local_server: LocalServerConfig,
}

impl FastlyConfig {
    /// Get a reference to the package name.
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// Get a reference to the package description.
    pub fn description(&self) -> &str {
        self.description.as_str()
    }

    /// Get a reference to the package authors.
    pub fn authors(&self) -> &[String] {
        self.authors.as_ref()
    }

    /// Get a reference to the package language.
    pub fn language(&self) -> &str {
        self.language.as_str()
    }

    /// Get the backend configuration.
    pub fn backends(&self) -> &Backends {
        &self.local_server.backends.0
    }

    /// Get the device detection configuration.
    pub fn device_detection(&self) -> &DeviceDetection {
        &self.local_server.device_detection
    }

    /// Get the geolocation configuration.
    pub fn geolocation(&self) -> &Geolocation {
        &self.local_server.geolocation
    }

    /// Get the dictionaries configuration.
    pub fn dictionaries(&self) -> &Dictionaries {
        &self.local_server.dictionaries.0
    }

    /// Get the object store configuration.
    pub fn object_stores(&self) -> &ObjectStores {
        &self.local_server.object_stores.0
    }

    /// Get the secret store configuration.
    pub fn secret_stores(&self) -> &SecretStores {
        &self.local_server.secret_stores.0
    }

    /// Parse a `fastly.toml` file into a `FastlyConfig`.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, FastlyConfigError> {
        fs::read_to_string(path.as_ref())
            .map_err(|err| FastlyConfigError::IoError {
                path: path.as_ref().display().to_string(),
                err,
            })
            .and_then(Self::from_str)
    }

    /// Parse a string containing TOML data into a `FastlyConfig`.
    fn from_str(toml: impl AsRef<str>) -> Result<Self, FastlyConfigError> {
        toml::from_str::<'_, TomlFastlyConfig>(toml.as_ref())
            .map_err(Into::into)
            .and_then(TryInto::try_into)
    }
}

impl FromStr for FastlyConfig {
    type Err = FastlyConfigError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_str(s)
    }
}

/// Internal deserializer used to read data from a `fastly.toml` file.
///
/// Once a TOML file has been read using [`toml::from_str`][from-str], this can be converted into
/// a [`FastlyConfig`][conf].
///
/// [conf]: struct.FastlyConfig.html
/// [fromt-str]: https://docs.rs/toml/latest/toml/de/fn.from_str.html
#[derive(Deserialize)]
struct TomlFastlyConfig {
    local_server: Option<RawLocalServerConfig>,
    // AJT 2020.03.10: the following fields are marked as optional because, for the time being,
    // we are not expecting to actually use the fastly.toml manifest, but instead use a separate
    // TOML file for backend configuration.
    //
    // See https://github.com/fastly/Viceroy/issues/109 for additional context.
    name: Option<String>,
    description: Option<String>,
    authors: Option<Vec<String>>,
    language: Option<String>,
}

impl TryInto<FastlyConfig> for TomlFastlyConfig {
    type Error = FastlyConfigError;
    fn try_into(self) -> Result<FastlyConfig, Self::Error> {
        let Self {
            name,
            description,
            authors,
            language,
            local_server,
        } = self;
        let local_server = local_server
            .map(TryInto::try_into)
            .transpose()?
            .unwrap_or_default();
        Ok(FastlyConfig {
            name: name.unwrap_or_default(),
            description: description.unwrap_or_default(),
            authors: authors.unwrap_or_default(),
            language: language.unwrap_or_default(),
            local_server,
        })
    }
}

/// Configuration settings used for tests.
///
/// This represents all of the `fastly.toml` fields whose keys begin with `testing`. Currently this
/// section of the manifest is only used for providing backend definitions, but additional fields
/// may be added in the future.
#[derive(Clone, Debug, Default)]
pub struct LocalServerConfig {
    backends: BackendsConfig,
    device_detection: DeviceDetection,
    geolocation: Geolocation,
    dictionaries: DictionariesConfig,
    object_stores: ObjectStoreConfig,
    secret_stores: SecretStoreConfig,
}

/// Enum of available (experimental) wasi modules
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ExperimentalModule {
    WasiNn,
}

/// Internal deserializer used to read the `[testing]` section of a `fastly.toml` file.
///
/// Once a TOML file has been read using [`toml::from_str`], this can be converted into
/// a [`LocalServerConfig`] with [`TryInto::try_into`].
#[derive(Deserialize)]
struct RawLocalServerConfig {
    backends: Option<Table>,
    device_detection: Option<Table>,
    geolocation: Option<Table>,
    #[serde(alias = "config_stores")]
    dictionaries: Option<Table>,
    #[serde(alias = "object_store", alias = "kv_stores")]
    object_stores: Option<Table>,
    secret_stores: Option<Table>,
}

impl TryInto<LocalServerConfig> for RawLocalServerConfig {
    type Error = FastlyConfigError;
    fn try_into(self) -> Result<LocalServerConfig, Self::Error> {
        let Self {
            backends,
            device_detection,
            geolocation,
            dictionaries,
            object_stores,
            secret_stores,
        } = self;
        let backends = if let Some(backends) = backends {
            backends.try_into()?
        } else {
            BackendsConfig::default()
        };
        let device_detection = if let Some(device_detection) = device_detection {
            device_detection.try_into()?
        } else {
            DeviceDetection::default()
        };
        let geolocation = if let Some(geolocation) = geolocation {
            geolocation.try_into()?
        } else {
            Geolocation::default()
        };
        let dictionaries = if let Some(dictionaries) = dictionaries {
            dictionaries.try_into()?
        } else {
            DictionariesConfig::default()
        };
        let object_stores = if let Some(object_store) = object_stores {
            object_store.try_into()?
        } else {
            ObjectStoreConfig::default()
        };
        let secret_stores = if let Some(secret_store) = secret_stores {
            secret_store.try_into()?
        } else {
            SecretStoreConfig::default()
        };

        Ok(LocalServerConfig {
            backends,
            device_detection,
            geolocation,
            dictionaries,
            object_stores,
            secret_stores,
        })
    }
}

#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum, Hash)]
pub enum UnknownImportBehavior {
    /// Unknown imports are rejected at link time (default behavior)
    #[default]
    LinkError,
    /// Unknown imports trap when called
    Trap,
    /// Unknown imports return zero or a null pointer, depending on the type
    ZeroOrNull,
}
