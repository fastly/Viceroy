use {
    crate::{
        error::{FastlyConfigError, SecretStoreConfigError},
        secret_store::{SecretStore, SecretStores},
    },
    std::{collections::HashMap, convert::TryFrom, fs},
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

            // Either the items here are from a top-level file with
            // "file" and "format" keys or it's an inline array.
            // We try to parse either one of them to the same Vec<toml::Value>
            // to allow them to run through the same validation path further down.
            let file_path = items
                .as_table()
                .and_then(|table| table.get("file"))
                .and_then(|file| file.as_str());
            let file_format = items
                .as_table()
                .and_then(|table| table.get("format"))
                .and_then(|format| format.as_str());

            let items: Vec<toml::Value> = match (file_path, file_format) {
                (Some(file_path), Some(file_type)) => {
                    if file_type != "json" {
                        return Err(FastlyConfigError::InvalidSecretStoreDefinition {
                            name: store_name.to_string(),
                            err: SecretStoreConfigError::InvalidFileFormat(file_type.to_string()),
                        });
                    }

                    let json = read_json_contents(&file_path).map_err(|e| {
                        FastlyConfigError::InvalidSecretStoreDefinition {
                            name: store_name.to_string(),
                            err: e,
                        }
                    })?;

                    let toml: Vec<toml::Value> = json
                        .into_iter()
                        .map(|(key, value)| {
                            toml::toml! {
                                key = key
                                data = value
                            }
                        })
                        .collect();

                    toml
                }
                (None, None) => {
                    // No file or format specified, parse the TOML as an array
                    items
                        .as_array()
                        .ok_or_else(|| FastlyConfigError::InvalidSecretStoreDefinition {
                            name: store_name.to_string(),
                            err: SecretStoreConfigError::NotAnArray,
                        })?
                        .clone()
                }
                // This means that *either* `format` or `file` is set, which isn't allowed
                // we need both or neither.
                (_, _) => {
                    return Err(FastlyConfigError::InvalidSecretStoreDefinition {
                        name: store_name.to_string(),
                        err: SecretStoreConfigError::OnlyOneFormatOrFileSet,
                    });
                }
            };

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

                let file = item.get("file");
                let data = item.get("data");
                let env = item.get("env");

                let sources = [file.is_some(), data.is_some(), env.is_some()];
                let count = sources.iter().filter(|&&b| b).count();

                let bytes = match count {
                    0 => {
                        return Err(FastlyConfigError::InvalidSecretStoreDefinition {
                            name: store_name.to_string(),
                            err: SecretStoreConfigError::FileDataEnvNotSet(key.to_string()),
                        });
                    }
                    1 => {
                        if let Some(path) = file {
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
                        } else if let Some(data) = data {
                            data.as_str()
                                .ok_or_else(|| FastlyConfigError::InvalidSecretStoreDefinition {
                                    name: store_name.to_string(),
                                    err: SecretStoreConfigError::DataNotAString(key.to_string()),
                                })?
                                .to_owned()
                                .into()
                        } else if let Some(env) = env {
                            // env branch
                            let var = env.as_str().ok_or_else(|| {
                                FastlyConfigError::InvalidSecretStoreDefinition {
                                    name: store_name.to_string(),
                                    err: SecretStoreConfigError::EnvNotAString(key.to_string()),
                                }
                            })?;
                            std::env::var(var)
                                .unwrap_or_else(|_| String::new())
                                .into_bytes()
                        } else {
                            unreachable!()
                        }
                    }
                    _ => {
                        return Err(FastlyConfigError::InvalidSecretStoreDefinition {
                            name: store_name.to_string(),
                            err: SecretStoreConfigError::FileDataEnvExclusive(key.to_string()),
                        });
                    }
                };
                secret_store.add_secret(key.to_string(), bytes.into());
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

fn read_json_contents(filename: &str) -> Result<HashMap<String, String>, SecretStoreConfigError> {
    let data = fs::read_to_string(filename).map_err(SecretStoreConfigError::IoError)?;
    let map: HashMap<String, String> =
        serde_json::from_str(&data).map_err(|_| SecretStoreConfigError::FileWrongFormat)?;
    Ok(map)
}
