use {
    crate::{
        error::{FastlyConfigError, ObjectStoreConfigError},
        object_store::{ObjectStoreKey, ObjectStores},
    },
    toml::value::Table,
};

#[derive(Clone, Debug, Default)]
pub struct ObjectStoreConfig(pub(crate) ObjectStores);

impl TryFrom<Table> for ObjectStoreConfig {
    type Error = FastlyConfigError;
    fn try_from(toml: Table) -> Result<Self, Self::Error> {
        let obj_store = ObjectStores::new();
        for (name, destination) in toml.iter() {
            let destination = destination.as_str().ok_or_else(|| {
                FastlyConfigError::InvalidObjectStoreDefinition {
                    name: name.to_string(),
                    err: ObjectStoreConfigError::NotATable,
                }
            })?;
            obj_store
                .insert_empty_store(ObjectStoreKey::new(name), destination)
                .map_err(|err| FastlyConfigError::InvalidObjectStoreDefinition {
                    name: name.to_string(),
                    err: err.into(),
                })?;
        }
        Ok(ObjectStoreConfig(obj_store))
    }
}
