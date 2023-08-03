mod client_cert_info;

use {
    hyper::{header::HeaderValue, Uri},
    std::{collections::HashMap, sync::Arc},
};

pub use self::client_cert_info::{ClientCertError, ClientCertInfo};

/// A single backend definition.
#[derive(Clone, Debug)]
pub struct Backend {
    pub uri: Uri,
    pub override_host: Option<HeaderValue>,
    pub cert_host: Option<String>,
    pub use_sni: bool,
    pub client_cert: Option<ClientCertInfo>,
}

/// A map of [`Backend`] definitions, keyed by their name.
#[derive(Clone, Debug, Default)]
pub struct BackendsConfig(pub HashMap<String, Arc<Backend>>);

/// This module contains [`TryFrom`] implementations used when deserializing a `fastly.toml`.
///
/// These implementations are called indirectly by [`FastlyConfig::from_file`][super::FastlyConfig],
/// and help validate that we have been given an appropriate TOML schema. If the configuration is
/// not valid, a [`FastlyConfigError`] will be returned.
mod deserialization {
    use {
        super::{Backend, BackendsConfig},
        crate::error::{BackendConfigError, FastlyConfigError},
        hyper::{header::HeaderValue, Uri},
        std::sync::Arc,
        toml::value::{Table, Value},
    };

    /// Helper function for converting a TOML [`Value`] into a [`Table`].
    ///
    /// This function checks that a value is a [`Value::Table`] variant and returns the underlying
    /// [`Table`], or returns an error if the given value was not of the right type — e.g., a
    /// [`Boolean`][Value::Boolean] or a [`String`][Value::String]).
    fn into_table(value: Value) -> Result<Table, BackendConfigError> {
        match value {
            Value::Table(table) => Ok(table),
            _ => Err(BackendConfigError::InvalidEntryType),
        }
    }

    /// Return an [`BackendConfigError::UnrecognizedKey`] error if any unrecognized keys are found.
    ///
    /// This should be called after we have removed and validated the keys we expect in a [`Table`].
    fn check_for_unrecognized_keys(table: &Table) -> Result<(), BackendConfigError> {
        if let Some(key) = table.keys().next() {
            // While other keys might still exist, we can at least return a helpful error including
            // the name of *one* unrecognized keys we found.
            Err(BackendConfigError::UnrecognizedKey(key.to_owned()))
        } else {
            Ok(())
        }
    }

    impl TryFrom<Table> for BackendsConfig {
        type Error = FastlyConfigError;
        fn try_from(toml: Table) -> Result<Self, Self::Error> {
            /// Process a backend's definitions, or return a [`FastlyConfigError`].
            fn process_entry(
                (name, defs): (String, Value),
            ) -> Result<(String, Arc<Backend>), FastlyConfigError> {
                into_table(defs)
                    .and_then(Backend::try_from)
                    .map_err(|err| FastlyConfigError::InvalidBackendDefinition {
                        name: name.clone(),
                        err,
                    })
                    .map(|def| (name, Arc::new(def)))
            }

            toml.into_iter()
                .map(process_entry)
                .collect::<Result<_, _>>()
                .map(Self)
        }
    }

    impl TryFrom<Table> for Backend {
        type Error = BackendConfigError;
        fn try_from(mut toml: Table) -> Result<Self, Self::Error> {
            let uri = toml
                .remove("url")
                .ok_or(BackendConfigError::MissingUrl)
                .and_then(|url| match url {
                    Value::String(url) => url.parse::<Uri>().map_err(BackendConfigError::from),
                    _ => Err(BackendConfigError::InvalidUrlEntry),
                })?;

            let override_host = toml
                .remove("override_host")
                .map(|override_host| match override_host {
                    Value::String(override_host) if !override_host.trim().is_empty() => {
                        HeaderValue::from_str(&override_host).map_err(BackendConfigError::from)
                    }
                    Value::String(_) => Err(BackendConfigError::EmptyOverrideHost),
                    _ => Err(BackendConfigError::InvalidOverrideHostEntry),
                })
                .transpose()?;

            let cert_host = toml
                .remove("cert_host")
                .map(|cert_host| match cert_host {
                    Value::String(cert_host) if !cert_host.trim().is_empty() => Ok(cert_host),
                    Value::String(_) => Err(BackendConfigError::EmptyCertHost),
                    _ => Err(BackendConfigError::InvalidCertHostEntry),
                })
                .transpose()?;

            let use_sni = toml
                .remove("use_sni")
                .map(|use_sni| {
                    if let Value::Boolean(use_sni) = use_sni {
                        Ok(use_sni)
                    } else {
                        Err(BackendConfigError::InvalidUseSniEntry)
                    }
                })
                .transpose()?
                .unwrap_or(true);

            check_for_unrecognized_keys(&toml)?;

            Ok(Self {
                uri,
                override_host,
                cert_host,
                use_sni,
                // NOTE: Update when we support client certs in static backends
                client_cert: None,
            })
        }
    }
}
