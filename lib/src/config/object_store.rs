use {
    crate::{
        error::{FastlyConfigError, ObjectStoreConfigError},
        object_store::{ObjectKey, ObjectStore, ObjectStoreKey},
    },
    std::fs,
    toml::value::Table,
};

#[derive(Clone, Debug, Default)]
pub struct ObjectStoreConfig(pub(crate) ObjectStore);

impl TryFrom<Table> for ObjectStoreConfig {
    type Error = FastlyConfigError;
    fn try_from(toml: Table) -> Result<Self, Self::Error> {
        let obj_store = ObjectStore::new();
        for (store, items) in toml.iter() {
            let items = items.as_array().ok_or_else(|| {
                FastlyConfigError::InvalidObjectStoreDefinition {
                    name: store.to_string(),
                    err: ObjectStoreConfigError::NotAnArray,
                }
            })?;
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
                let bytes = match (item.get("file"), item.get("data")) {
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
                    )
                    .expect("Lock was not poisoned");
            }
        }
        Ok(ObjectStoreConfig(obj_store))
    }
}
