use {
    crate::wiggle_abi::types::FastlyStatus,
    std::{
        collections::BTreeMap,
        sync::{Arc, RwLock},
    },
};

#[derive(Clone, Debug, Default)]
pub struct ObjectStore {
    stores: Arc<RwLock<BTreeMap<ObjectStoreKey, BTreeMap<ObjectKey, Vec<u8>>>>>,
}

impl ObjectStore {
    pub fn new() -> Self {
        Self {
            stores: Arc::new(RwLock::new(BTreeMap::new())),
        }
    }
    pub fn lookup(
        &self,
        obj_store_key: &ObjectStoreKey,
        obj_key: &ObjectKey,
    ) -> Result<Vec<u8>, ObjectStoreError> {
        self.stores
            .read()
            .map_err(|_| ObjectStoreError::PoisonedLock)?
            .get(obj_store_key)
            .and_then(|map| map.get(obj_key).map(|obj| obj.clone()))
            .ok_or_else(|| ObjectStoreError::MissingObject)
    }

    pub fn insert(
        &self,
        obj_store_key: ObjectStoreKey,
        obj_key: ObjectKey,
        obj: Vec<u8>,
    ) -> Result<(), ObjectStoreError> {
        self.stores
            .write()
            .map_err(|_| ObjectStoreError::PoisonedLock)?
            .entry(obj_store_key)
            .and_modify(|store| {
                store.insert(obj_key.clone(), obj.clone());
            })
            .or_insert_with(|| {
                let mut store = BTreeMap::new();
                store.insert(obj_key, obj);
                store
            });

        Ok(())
    }
}

#[derive(Debug, PartialOrd, Ord, PartialEq, Eq, Clone, Default)]
pub struct ObjectStoreKey(String);

impl ObjectStoreKey {
    pub fn new(key: impl ToString) -> Self {
        Self(key.to_string())
    }
}

#[derive(Debug, PartialOrd, Ord, PartialEq, Eq, Clone, Default)]
pub struct ObjectKey(String);

impl ObjectKey {
    pub fn new(key: impl ToString) -> Self {
        Self(key.to_string())
    }
}

#[derive(Debug, PartialOrd, Ord, PartialEq, Eq, thiserror::Error)]
pub enum ObjectStoreError {
    #[error("lol it's missing ya dingus")]
    MissingObject,
    #[error("Viceroy's ObjectStore lock was poisoned")]
    PoisonedLock,
}

impl From<&ObjectStoreError> for FastlyStatus {
    fn from(e: &ObjectStoreError) -> Self {
        use ObjectStoreError::*;
        match e {
            MissingObject => FastlyStatus::None,
            PoisonedLock => panic!("{}", e),
        }
    }
}
