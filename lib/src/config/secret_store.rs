use {
    crate::{
        error::{FastlyConfigError, SecretStoreConfigError},
        secret_store::{SecretStore, SecretStores},
    },
    std::{convert::TryFrom, fs},
    toml::value::Table,
};

#[derive(Clone, Debug, Default)]
pub struct SecretStoreConfig(pub(crate) SecretStores);

impl TryFrom<Table> for SecretStoreConfig {
    type Error = FastlyConfigError;
    fn try_from(toml: Table) -> Result<Self, Self::Error> {
        let mut stores = SecretStores::new();

        for (store_name, items) in toml.iter() {
            if !is_valid_name(store_name) {
                return Err(FastlyConfigError::InvalidSecretStoreDefinition {
                    name: store_name.to_string(),
                    err: SecretStoreConfigError::InvalidSecretStoreName(store_name.to_string()),
                });
            }

            let items = items.as_array().ok_or_else(|| {
                FastlyConfigError::InvalidSecretStoreDefinition {
                    name: store_name.to_string(),
                    err: SecretStoreConfigError::NotAnArray,
                }
            })?;

            let mut secret_store = SecretStore::new();
            for item in items.iter() {
                let item = item.as_table().ok_or_else(|| {
                    FastlyConfigError::InvalidSecretStoreDefinition {
                        name: store_name.to_string(),
                        err: SecretStoreConfigError::NotATable,
                    }
                })?;

                let key = item
                    .get("key")
                    .ok_or_else(|| FastlyConfigError::InvalidSecretStoreDefinition {
                        name: store_name.to_string(),
                        err: SecretStoreConfigError::NoKey,
                    })?
                    .as_str()
                    .ok_or_else(|| FastlyConfigError::InvalidSecretStoreDefinition {
                        name: store_name.to_string(),
                        err: SecretStoreConfigError::KeyNotAString,
                    })?;

                if !is_valid_name(key) {
                    return Err(FastlyConfigError::InvalidSecretStoreDefinition {
                        name: store_name.to_string(),
                        err: SecretStoreConfigError::InvalidSecretName(key.to_string()),
                    });
                }

                let bytes = match (item.get("file"), item.get("data")) {
                    (None, None) => {
                        return Err(FastlyConfigError::InvalidSecretStoreDefinition {
                            name: store_name.to_string(),
                            err: SecretStoreConfigError::NoFileOrData(key.to_string()),
                        })
                    }
                    (Some(_), Some(_)) => {
                        return Err(FastlyConfigError::InvalidSecretStoreDefinition {
                            name: store_name.to_string(),
                            err: SecretStoreConfigError::FileAndData(key.to_string()),
                        })
                    }
                    (Some(path), None) => {
                        let path = path.as_str().ok_or_else(|| {
                            FastlyConfigError::InvalidSecretStoreDefinition {
                                name: store_name.to_string(),
                                err: SecretStoreConfigError::FileNotAString(key.to_string()),
                            }
                        })?;
                        fs::read(path)
                            .map_err(|e| FastlyConfigError::InvalidSecretStoreDefinition {
                                name: store_name.to_string(),
                                err: SecretStoreConfigError::IoError(e),
                            })?
                            .into()
                    }
                    (None, Some(data)) => data
                        .as_str()
                        .ok_or_else(|| FastlyConfigError::InvalidSecretStoreDefinition {
                            name: store_name.to_string(),
                            err: SecretStoreConfigError::DataNotAString(key.to_string()),
                        })?
                        .to_owned()
                        .into(),
                };
                secret_store.add_secret(key.to_string(), bytes);
            }
            stores.add_store(store_name.clone(), secret_store);
        }
        Ok(SecretStoreConfig(stores))
    }
}

/// Human-readable names for Secret Stores and Secrets "must contain
/// only letters, numbers, dashes (-), underscores (_), and periods (.)"
/// They also have a maximum length of 255 bytes.
fn is_valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
}
