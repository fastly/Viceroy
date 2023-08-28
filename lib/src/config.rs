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

pub use self::dictionaries::Dictionary;
pub use self::dictionaries::DictionaryName;

pub type Dictionaries = HashMap<DictionaryName, Dictionary>;

/// Types and deserializers for backend configuration settings.
mod backends;

pub use self::backends::{Backend, ClientCertError, ClientCertInfo};

pub type Backends = HashMap<String, Arc<Backend>>;

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
/// This `struct` represents the fields and values in a Compute@Edge package's `fastly.toml`.
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
            geolocation,
            dictionaries,
            object_stores,
            secret_stores,
        })
    }
}

#[test]
fn client_certs_parse() {
    let basic = r#"
description = "a test case"
language = "foul"
manifest_version = 2

[local_server]
[local_server.backends]
[local_server.backends.origin]
url = "https://127.0.0.1:443"
"#;

    let basic_parsed = FastlyConfig::from_str(basic).unwrap();
    let basic_origin = basic_parsed.local_server.backends.0.get("origin").unwrap();
    assert!(basic_origin.client_cert.is_none());

    let files = r#"
description = "a test case"
language = "foul"
manifest_version = 2

[local_server]
[local_server.backends]
[local_server.backends.origin]
url = "https://127.0.0.1:443"
[local_server.backends.origin.client_certificate]
certificate_file = "../test-fixtures/data/client.crt"
key_file = "../test-fixtures/data/client.key"
"#;

    let files_parsed = FastlyConfig::from_str(files).unwrap();
    let files_origin = files_parsed.local_server.backends.0.get("origin").unwrap();
    assert!(files_origin.client_cert.is_some());

    let inline = r#"
description = "a test case"
language = "foul"
manifest_version = 2

[local_server]
[local_server.backends]
[local_server.backends.origin]
url = "https://127.0.0.1:443"
[local_server.backends.origin.client_certificate]
key = """
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAz27x1GpD46K6b9/3PNyZYKgTL9GBbpLAVF8Uebd34ftUfnWZ
3ER+x6A1YbacHnL112diPPevyYkpXuiujwCeswYNrZHEtiRfAvrzBRhnhL8owQTx
jOcG4EOzR7Je556FTq8kNth5iHckORjmXiV9ZahbLv/zBFpkXpDeze62zd8y9chP
NEqcrLZBOb4UoKXmOt1lIdeo23nysR4rC6XemWNSFcZv9zagUzliMeca3XN2RIUA
FZv4o+gYPqqXQi+0a+OOq0jnKpawW+avn2UG7wzXGlLcVOvLe5BOCA1RfWtR8w03
MFdvoBAesXJ4xGX1ROUzelldedmpqtvORdhmGQIDAQABAoIBAQCsbu6KhDehMDHJ
NCWjK0I4zh78/iyZDVbiDBPKRpBag4GuifX329yD95LIgnNvAGOKxz8rrT4sy19f
rQ8Ggx5pdVvDcExUmRF+Obvw/WN4PywSoBhn59iYbs7Gh+lKo0Tvrrns+bC1l0y+
RguiMYn3CqeZ/1w1vyp2TflYuNqvcR4zMzJ4dN474CCLPIUX9OfK21Lbv/UMdguF
Rs/BuStucqaCzEtTLyZYlxQc1i8S8Uy2yukXR6TYWJOsWZj0KIgH/YI7ZgzvTIxL
ax4Hn4jIHPFSJ+vl2ehDKffkQQ0lzm60ASkjaJY6GsFoTQzsmuafpLIAoJbDbZR1
txPSFC+BAoGBAPbp6+LsXoEY+4RfStg4c/oLWmK3aTxzQzMY90vxnMm6SJTwTPAm
pO+Pp2UGyEGHV7hg3d+ItWpM9QGVmsjm+punIfc0W/0+AVUonjPLfv44dz7+geYt
/oeMv4RTqCclROvtQTqV6hHn4E3Xg061miEe6OxYmqfZuLD2nv2VlsQRAoGBANcR
GAqeClQtraTnu+yU9U+FJZfvSxs1yHr7XItCMtwxeU6+nipa+3pXNnKu0dKKekUG
PCdUipXgggA6OUm2YFKPUhiXJUNoHCj45Tkv2NshGplW33U3NcCkDqL7vvZoBBfP
OPxEVRVEIlwp/WzEambs9MjWoecEaOe7/3UCVumJAoGANlfVquQLCK7O7JtshZon
LGlDQ2bKqptTtvNPuk87CssNHnqk9FYNBwy+8uVDPejjzZjEPGaCRxsY8XhT0NPF
ZGysdRP5CwuSj4OZDh1DngAffqXVQSvuUTcRD7a506PIP4TATnygP8ChBYDhTXl6
qr961EnMABVTKN+eroE15YECgYEAv+YLyqV71+KuNx9i6lV7kcnfYnNtU8koqruQ
tt2Jnjoy4JVrcaWfEGmzNp9Qr4lKUj6e/AUOZ29c8DEDnwcxaVliynhLEptZzSFQ
/zb3S4d9QWdnmiJ6Pvrj6H+yxBDJ3ijT0xxxwrj547y/2QZlXpN+U5pX+ldP974i
0dgVjukCgYEArxv0dO2VEguWLx5YijHiN72nDDI+skbfkQkvWQjA7x8R9Xx1SWUl
WeyeaaV5rqfJZF1wBCK5VJndjbOGhPh6u/0mpeYw4Ty3+CKN2WoikQO27qYfMZW5
vvT7m9ZR+gkm2TjZ+pZuilz2gqu/yMJKl8Fi8Q7dsb8eWedWQXjbUZg=
-----END RSA PRIVATE KEY-----
"""
certificate = """
-----BEGIN CERTIFICATE-----
MIIDvjCCAqagAwIBAgIUOp97gvMlYdBYI/3yrpDeHbdx5RgwDQYJKoZIhvcNAQEL
BQAwZDELMAkGA1UEBhMCVVMxDzANBgNVBAgMBk9yZWdvbjERMA8GA1UEBwwIUG9y
dGxhbmQxEDAOBgNVBAoMB1ZpY2Vyb3kxHzAdBgkqhkiG9w0BCQEWEGF3aWNrQGZh
c3RseS5jb20wHhcNMjMwNzI3MDAxOTU0WhcNMzMwNzI0MDAxOTU0WjB1MQswCQYD
VQQGEwJVUzEPMA0GA1UECAwGT3JlZ29uMREwDwYDVQQHDAhQb3J0bGFuZDEQMA4G
A1UECgwHVmljZXJveTEPMA0GA1UECwwGQ2xpZW50MR8wHQYJKoZIhvcNAQkBFhBh
d2lja0BmYXN0bHkuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
z27x1GpD46K6b9/3PNyZYKgTL9GBbpLAVF8Uebd34ftUfnWZ3ER+x6A1YbacHnL1
12diPPevyYkpXuiujwCeswYNrZHEtiRfAvrzBRhnhL8owQTxjOcG4EOzR7Je556F
Tq8kNth5iHckORjmXiV9ZahbLv/zBFpkXpDeze62zd8y9chPNEqcrLZBOb4UoKXm
Ot1lIdeo23nysR4rC6XemWNSFcZv9zagUzliMeca3XN2RIUAFZv4o+gYPqqXQi+0
a+OOq0jnKpawW+avn2UG7wzXGlLcVOvLe5BOCA1RfWtR8w03MFdvoBAesXJ4xGX1
ROUzelldedmpqtvORdhmGQIDAQABo1cwVTAfBgNVHSMEGDAWgBRmDOh4T/Mmde3l
8OZzn0Pe9btZfTAJBgNVHRMEAjAAMAsGA1UdDwQEAwIE8DAaBgNVHREEEzARggls
b2NhbGhvc3SHBH8AAAEwDQYJKoZIhvcNAQELBQADggEBAJ84GzmmqsmmtqXcmZIH
i644p8wIc/DXPqb7zzAVm9FXpFgW3mN4xu1JYWu+rb1sge8uIm7Vt5Isd4CZ89XI
F2Q2DS/rKMQmjgSDReWm9G+qZROwuhNDzK85e73Rw2EdX6cXtAGR1h3IdOTIv1FC
UElFER31U8i4J9pxUZF/FTzlPEA1agqMsO6hQlj/A9B6TtzL7SSxCFBBaFbNCLMC
D/WCrIoklNV5TwutYG80EYZhJlfUJPDQBphkcetDBI0L/KL/n20bg8OR/epGD5++
qKIulxf9iUR5QHm2fWKdTLOuADmV+lc925gIqGhFhjVvpNPOcdckecQUp3vCNu2/
HrM=
-----END CERTIFICATE-----
"""
"#;

    let inline_parsed = FastlyConfig::from_str(inline).unwrap();
    let inline_origin = inline_parsed.local_server.backends.0.get("origin").unwrap();
    assert!(inline_origin.client_cert.is_some());

    assert_eq!(files_origin.client_cert, inline_origin.client_cert);
}