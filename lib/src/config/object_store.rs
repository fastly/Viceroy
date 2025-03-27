use std::collections::HashMap;
use std::path::{Path, PathBuf};
use toml::Value;
use {
    crate::{
        error::{FastlyConfigError, ObjectStoreConfigError},
        object_store::{ObjectKey, ObjectStoreKey, ObjectStores},
        wiggle_abi::types::KvInsertMode,
    },
    std::fs,
    toml::value::Table,
};

#[derive(Debug)]
struct ObjectStoreEntry {
    data: String,
    metadata: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct ObjectStoreConfig(pub(crate) ObjectStores);

impl TryFrom<Table> for ObjectStoreConfig {
    type Error = FastlyConfigError;
    fn try_from(toml: Table) -> Result<Self, Self::Error> {
        let obj_store = ObjectStores::new();
        for (store, items) in toml.iter() {
            // Either the items here is from a top-level file with "file" and "format" keys
            // or it's an inline array.
            // We try to parse either one of them to the same Vec<toml::Value>
            // to allow them to run through the same validation path further down
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
                        return Err(FastlyConfigError::InvalidObjectStoreDefinition {
                            name: store.to_string(),
                            err: ObjectStoreConfigError::InvalidFileFormat(file_type.to_string()),
                        });
                    }

                    let path = PathBuf::from(&file_path);

                    let json = read_json_contents(&path).map_err(|err| {
                        FastlyConfigError::InvalidObjectStoreDefinition {
                            name: store.to_string(),
                            err,
                        }
                    })?;

                    let toml: Vec<Value> = json
                        .into_iter()
                        .map(|(key, entry)| {
                            let mut table = toml::value::Table::new();
                            table.insert("key".to_string(), toml::Value::String(key));
                            table.insert("data".to_string(), toml::Value::String(entry.data));
                            if let Some(meta) = entry.metadata {
                                table.insert("metadata".to_string(), toml::Value::String(meta));
                            }
                            toml::Value::Table(table)
                        })
                        .collect();

                    toml
                }
                (None, None) => {
                    // No file or format specified, parse the TOML as an array
                    items
                        .as_array()
                        .ok_or_else(|| FastlyConfigError::InvalidObjectStoreDefinition {
                            name: store.to_string(),
                            err: ObjectStoreConfigError::NotAnArray,
                        })?
                        .clone()
                }
                // This means that *either* `format` or `file` is set, which isn't allowed
                // we need both or neither.
                (_, _) => {
                    return Err(FastlyConfigError::InvalidObjectStoreDefinition {
                        name: store.to_string(),
                        err: ObjectStoreConfigError::OnlyOneFormatOrFileSet,
                    });
                }
            };

            // Handle the case where there are no items to insert, but the store
            // exists and needs to be in the ObjectStore
            if items.is_empty() {
                obj_store
                    .insert_empty_store(ObjectStoreKey::new(store))
                    .map_err(|err| FastlyConfigError::InvalidObjectStoreDefinition {
                        name: store.to_string(),
                        err: err.into(),
                    })?;
                continue;
            }
            for item in items.iter() {
                let item = item.as_table().ok_or_else(|| {
                    FastlyConfigError::InvalidObjectStoreDefinition {
                        name: store.to_string(),
                        err: ObjectStoreConfigError::NotATable,
                    }
                })?;

                let key = item
                    .get("key")
                    .ok_or_else(|| FastlyConfigError::InvalidObjectStoreDefinition {
                        name: store.to_string(),
                        err: ObjectStoreConfigError::NoKey,
                    })?
                    .as_str()
                    .ok_or_else(|| FastlyConfigError::InvalidObjectStoreDefinition {
                        name: store.to_string(),
                        err: ObjectStoreConfigError::KeyNotAString,
                    })?;

                // Previously the "file" key was named "path".  We want
                // to continue supporting the old name.
                let file = match (item.get("file"), item.get("path")) {
                    (None, None) => None,
                    (Some(file), _) => Some(file),
                    (None, Some(path)) => Some(path),
                };

                let bytes = match (file, item.get("data")) {
                    (None, None) => {
                        return Err(FastlyConfigError::InvalidObjectStoreDefinition {
                            name: store.to_string(),
                            err: ObjectStoreConfigError::NoFileOrData(key.to_string()),
                        })
                    }
                    (Some(_), Some(_)) => {
                        return Err(FastlyConfigError::InvalidObjectStoreDefinition {
                            name: store.to_string(),
                            err: ObjectStoreConfigError::FileAndData(key.to_string()),
                        })
                    }
                    (Some(path), None) => {
                        let path = path.as_str().ok_or_else(|| {
                            FastlyConfigError::InvalidObjectStoreDefinition {
                                name: store.to_string(),
                                err: ObjectStoreConfigError::FileNotAString(key.to_string()),
                            }
                        })?;
                        fs::read(path).map_err(|e| {
                            FastlyConfigError::InvalidObjectStoreDefinition {
                                name: store.to_string(),
                                err: ObjectStoreConfigError::IoError(e),
                            }
                        })?
                    }
                    (None, Some(data)) => data
                        .as_str()
                        .ok_or_else(|| FastlyConfigError::InvalidObjectStoreDefinition {
                            name: store.to_string(),
                            err: ObjectStoreConfigError::DataNotAString(key.to_string()),
                        })?
                        .as_bytes()
                        .to_vec(),
                };

                let metadata_bytes = match item.get("metadata") {
                    Some(metadata) => Some(
                        metadata
                            .as_str()
                            .ok_or_else(|| FastlyConfigError::InvalidObjectStoreDefinition {
                                name: store.to_string(),
                                err: ObjectStoreConfigError::MetadataNotAString(key.to_string()),
                            })?
                            .as_bytes()
                            .to_vec(),
                    ),
                    None => None,
                };

                obj_store
                    .insert(
                        ObjectStoreKey::new(store),
                        ObjectKey::new(key).map_err(|err| {
                            FastlyConfigError::InvalidObjectStoreDefinition {
                                name: store.to_string(),
                                err: err.into(),
                            }
                        })?,
                        bytes,
                        KvInsertMode::Overwrite,
                        None,
                        metadata_bytes,
                        None,
                    )
                    .expect("Lock was not poisoned");
            }
        }

        Ok(ObjectStoreConfig(obj_store))
    }
}

fn read_json_contents(
    file: &Path,
) -> Result<HashMap<String, ObjectStoreEntry>, ObjectStoreConfigError> {
    // Read the contents of the given file.
    let data = fs::read_to_string(file).map_err(ObjectStoreConfigError::IoError)?;

    // Deserialize the contents of the given JSON file.
    let json =
        match serde_json::from_str(&data).map_err(|_| ObjectStoreConfigError::FileWrongFormat)? {
            // Check that we were given an object.
            serde_json::Value::Object(obj) => obj,
            _ => {
                return Err(ObjectStoreConfigError::FileWrongFormat);
            }
        };

    let mut contents = HashMap::with_capacity(json.len());

    // Check that each KV Store entry has either a string value or an object with data and metadata
    // fields.
    for (key, value) in json {
        let entry = match value {
            serde_json::Value::String(s) => ObjectStoreEntry {
                data: s,
                metadata: None,
            },
            serde_json::Value::Object(obj) => {
                let data = obj.get("data").ok_or_else(|| {
                    ObjectStoreConfigError::FileValueWrongFormat { key: key.clone() }
                })?;

                let data = data
                    .as_str()
                    .ok_or_else(|| ObjectStoreConfigError::FileValueWrongFormat {
                        key: key.clone(),
                    })?
                    .to_string();

                let metadata = match obj.get("metadata") {
                    Some(val) => Some(
                        val.as_str()
                            .ok_or_else(|| ObjectStoreConfigError::FileValueWrongFormat {
                                key: key.clone(),
                            })?
                            .to_string(),
                    ),
                    None => None,
                };

                ObjectStoreEntry { data, metadata }
            }
            _ => return Err(ObjectStoreConfigError::FileValueWrongFormat { key: key.clone() }),
        };

        contents.insert(key, entry);
    }

    Ok(contents)
}
