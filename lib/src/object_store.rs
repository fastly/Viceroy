use {
    crate::wiggle_abi::types::{FastlyStatus, KvError, KvInsertMode},
    base64::prelude::*,
    serde::Serialize,
    std::{
        collections::BTreeMap,
        sync::{Arc, RwLock},
        time::SystemTime,
    },
};

#[derive(Debug, Clone)]
pub struct ObjectValue {
    pub body: Vec<u8>,
    pub metadata: Vec<u8>,
    pub metadata_len: usize,
    pub generation: u64,
    pub expiration: Option<SystemTime>,
}

#[derive(Clone, Debug, Default)]
pub struct ObjectStores {
    #[allow(clippy::type_complexity)]
    stores: Arc<RwLock<BTreeMap<ObjectStoreKey, BTreeMap<ObjectKey, ObjectValue>>>>,
}

impl ObjectStores {
    pub fn new() -> Self {
        Self {
            stores: Arc::new(RwLock::new(BTreeMap::new())),
        }
    }

    pub(crate) fn store_exists(&self, obj_store_key: &str) -> Result<bool, ObjectStoreError> {
        Ok(self
            .stores
            .read()
            .map_err(|_| ObjectStoreError::PoisonedLock)?
            .get(&ObjectStoreKey::new(obj_store_key))
            .is_some())
    }

    pub fn lookup(
        &self,
        obj_store_key: ObjectStoreKey,
        obj_key: ObjectKey,
    ) -> Result<ObjectValue, KvStoreError> {
        let mut res = Err(KvStoreError::Uninitialized);

        self.stores
            .write()
            .map_err(|_| KvStoreError::InternalError)?
            .entry(obj_store_key)
            .and_modify(|store| match store.get(&obj_key) {
                Some(val) => {
                    res = Ok(val.clone());
                    // manages ttl
                    if let Some(exp) = val.expiration {
                        if SystemTime::now() >= exp {
                            store.remove(&obj_key);
                            res = Err(KvStoreError::NotFound);
                        }
                    }
                }
                None => {
                    res = Err(KvStoreError::NotFound);
                }
            });

        res
    }

    pub(crate) fn insert_empty_store(
        &self,
        obj_store_key: ObjectStoreKey,
    ) -> Result<(), ObjectStoreError> {
        self.stores
            .write()
            .map_err(|_| ObjectStoreError::PoisonedLock)?
            .entry(obj_store_key)
            .and_modify(|_| {})
            .or_insert_with(BTreeMap::new);

        Ok(())
    }

    pub fn insert(
        &self,
        obj_store_key: ObjectStoreKey,
        obj_key: ObjectKey,
        obj: Vec<u8>,
        mode: KvInsertMode,
        generation: Option<u64>,
        metadata: Option<Vec<u8>>,
        ttl: Option<std::time::Duration>,
    ) -> Result<(), KvStoreError> {
        // manages ttl
        let existing = self.lookup(obj_store_key.clone(), obj_key.clone());

        if let Some(g) = generation {
            if let Ok(val) = &existing {
                if val.generation != g {
                    return Err(KvStoreError::PreconditionFailed);
                }
            }
        }

        let out_obj = match mode {
            KvInsertMode::Overwrite => obj,
            KvInsertMode::Add => {
                if existing.is_ok() {
                    // key exists, add fails
                    return Err(KvStoreError::PreconditionFailed);
                }
                obj
            }
            KvInsertMode::Append => {
                let mut out_obj;
                match existing {
                    Err(KvStoreError::NotFound) => {
                        out_obj = obj;
                    }
                    Err(_) => return Err(KvStoreError::InternalError),
                    Ok(v) => {
                        out_obj = v.body;
                        out_obj.append(&mut obj.clone());
                    }
                }
                out_obj
            }
            KvInsertMode::Prepend => {
                let mut out_obj;
                match existing {
                    Err(KvStoreError::NotFound) => {
                        out_obj = obj;
                    }
                    Err(_) => return Err(KvStoreError::InternalError),
                    Ok(mut v) => {
                        out_obj = obj;
                        out_obj.append(&mut v.body);
                    }
                }
                out_obj
            }
        };

        let exp = ttl.map(|t| SystemTime::now() + t);

        let mut obj_val = ObjectValue {
            body: out_obj,
            metadata: vec![],
            metadata_len: 0,
            generation: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64,
            expiration: exp,
        };

        // magic number hack to ensure a case for integration tests
        if obj_val.generation == 1337 {
            obj_val.generation = 1338;
        }

        if let Some(m) = metadata {
            obj_val.metadata_len = m.len();
            obj_val.metadata = m;
        }

        self.stores
            .write()
            .map_err(|_| KvStoreError::InternalError)?
            .entry(obj_store_key)
            .and_modify(|store| {
                store.insert(obj_key.clone(), obj_val.clone());
            })
            .or_insert_with(|| {
                let mut store = BTreeMap::new();
                store.insert(obj_key, obj_val);
                store
            });

        Ok(())
    }

    pub fn delete(
        &self,
        obj_store_key: ObjectStoreKey,
        obj_key: ObjectKey,
    ) -> Result<(), KvStoreError> {
        let mut res = Ok(());

        self.stores
            .write()
            .map_err(|_| KvStoreError::InternalError)?
            .entry(obj_store_key)
            .and_modify(|store| match store.get(&obj_key) {
                // 404 if the key doesn't exist, otherwise delete
                Some(val) => {
                    // manages ttl
                    if let Some(exp) = val.expiration {
                        if SystemTime::now() >= exp {
                            res = Err(KvStoreError::NotFound);
                        }
                    }
                    store.remove(&obj_key);
                }
                None => {
                    res = Err(KvStoreError::NotFound);
                }
            });

        res
    }

    pub fn list(
        &self,
        obj_store_key: ObjectStoreKey,
        cursor: Option<String>,
        prefix: Option<String>,
        limit: u32,
    ) -> Result<Vec<u8>, KvStoreError> {
        let mut res = Err(KvStoreError::InternalError);

        let cursor = match cursor {
            Some(c) => {
                let cursor_bytes = BASE64_STANDARD
                    .decode(c)
                    .map_err(|_| KvStoreError::BadRequest)?;
                let decoded =
                    String::from_utf8(cursor_bytes).map_err(|_| KvStoreError::BadRequest)?;
                Some(decoded)
            }
            None => None,
        };

        self.stores
            .write()
            .map_err(|_| KvStoreError::InternalError)?
            .entry(obj_store_key.clone())
            .and_modify(|store| {
                // manages ttl
                // a bit wasteful to run this loop twice, but we need mutable access to store,
                // and it's already claimed in the filters below
                let ttl_list = store.iter_mut().map(|(k, _)| k.clone()).collect::<Vec<_>>();
                ttl_list.into_iter().for_each(|k| {
                    let val = store.get(&k);
                    if let Some(v) = val {
                        if let Some(exp) = v.expiration {
                            if SystemTime::now() >= exp {
                                store.remove(&k);
                            }
                        }
                    }
                });

                let mut list = store
                    .iter_mut()
                    .filter(|(k, _)| {
                        if let Some(c) = &cursor {
                            &k.0 > c
                        } else {
                            true
                        }
                    })
                    .filter(|(k, _)| {
                        if let Some(p) = &prefix {
                            k.0.starts_with(p)
                        } else {
                            true
                        }
                    })
                    .map(|(k, _)| String::from_utf8(k.0.as_bytes().to_vec()).unwrap())
                    .collect::<Vec<_>>();

                // limit
                let old_len = list.len();
                list.truncate(limit as usize);
                let new_len = list.len();

                let next_cursor = match old_len != new_len {
                    true => Some(BASE64_STANDARD.encode(&list[new_len - 1])),
                    false => None,
                };

                #[derive(Serialize)]
                struct Metadata {
                    limit: u32,
                    #[serde(skip_serializing_if = "Option::is_none")]
                    prefix: Option<String>,
                    #[serde(skip_serializing_if = "Option::is_none")]
                    next_cursor: Option<String>,
                }
                #[derive(Serialize)]
                struct JsonOutput {
                    data: Vec<String>,
                    meta: Metadata,
                }

                let body = JsonOutput {
                    data: list,
                    meta: Metadata {
                        limit,
                        prefix,
                        next_cursor,
                    },
                };

                match serde_json::to_string(&body).map_err(|_| KvStoreError::InternalError) {
                    Ok(s) => res = Ok(s.as_bytes().to_vec()),
                    Err(e) => res = Err(e),
                };
            });
        res
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
    pub fn new(key: impl ToString) -> Result<Self, KeyValidationError> {
        let key = key.to_string();
        is_valid_key(&key)?;
        Ok(Self(key))
    }
}

#[derive(Debug, PartialOrd, Ord, PartialEq, Eq, thiserror::Error)]
pub enum ObjectStoreError {
    #[error("The object was not in the store")]
    MissingObject,
    #[error("Viceroy's ObjectStore lock was poisoned")]
    PoisonedLock,
    /// An Object Store with the given name was not found.
    #[error("Unknown object-store: {0}")]
    UnknownObjectStore(String),
}

impl From<&ObjectStoreError> for FastlyStatus {
    fn from(e: &ObjectStoreError) -> Self {
        use ObjectStoreError::*;
        match e {
            MissingObject => FastlyStatus::None,
            PoisonedLock => panic!("{}", e),
            UnknownObjectStore(_) => FastlyStatus::Inval,
        }
    }
}

#[derive(Debug, PartialOrd, Ord, PartialEq, Eq, thiserror::Error)]
pub enum KvStoreError {
    #[error("The error was not set")]
    Uninitialized,
    #[error("There was no error")]
    Ok,
    #[error("KV store cannot or will not process the request due to something that is perceived to be a client error")]
    BadRequest,
    #[error("KV store cannot find the requested resource")]
    NotFound,
    #[error("KV store cannot fulfill the request, as definied by the client's prerequisites (ie. if-generation-match)")]
    PreconditionFailed,
    #[error("The size limit for a KV store key was exceeded")]
    PayloadTooLarge,
    #[error("The system encountered an unexpected internal error")]
    InternalError,
    #[error("Too many requests have been made to the KV store")]
    TooManyRequests,
}

impl From<&KvError> for KvStoreError {
    fn from(e: &KvError) -> Self {
        match e {
            KvError::Uninitialized => KvStoreError::Uninitialized,
            KvError::Ok => KvStoreError::Ok,
            KvError::BadRequest => KvStoreError::BadRequest,
            KvError::NotFound => KvStoreError::NotFound,
            KvError::PreconditionFailed => KvStoreError::PreconditionFailed,
            KvError::PayloadTooLarge => KvStoreError::PayloadTooLarge,
            KvError::InternalError => KvStoreError::InternalError,
            KvError::TooManyRequests => KvStoreError::TooManyRequests,
        }
    }
}

impl From<&KvStoreError> for KvError {
    fn from(e: &KvStoreError) -> Self {
        match e {
            KvStoreError::Uninitialized => KvError::Uninitialized,
            KvStoreError::Ok => KvError::Ok,
            KvStoreError::BadRequest => KvError::BadRequest,
            KvStoreError::NotFound => KvError::NotFound,
            KvStoreError::PreconditionFailed => KvError::PreconditionFailed,
            KvStoreError::PayloadTooLarge => KvError::PayloadTooLarge,
            KvStoreError::InternalError => KvError::InternalError,
            KvStoreError::TooManyRequests => KvError::TooManyRequests,
        }
    }
}

impl From<&KvStoreError> for ObjectStoreError {
    fn from(e: &KvStoreError) -> Self {
        match e {
            // the only real one
            KvStoreError::NotFound => ObjectStoreError::MissingObject,
            _ => ObjectStoreError::UnknownObjectStore("".to_string()),
        }
    }
}

impl From<&KvStoreError> for FastlyStatus {
    fn from(e: &KvStoreError) -> Self {
        match e {
            KvStoreError::Uninitialized => panic!("{}", e),
            KvStoreError::Ok => FastlyStatus::Ok,
            KvStoreError::BadRequest => FastlyStatus::Inval,
            KvStoreError::NotFound => FastlyStatus::None,
            KvStoreError::PreconditionFailed => FastlyStatus::Inval,
            KvStoreError::PayloadTooLarge => FastlyStatus::Inval,
            KvStoreError::InternalError => FastlyStatus::Inval,
            KvStoreError::TooManyRequests => FastlyStatus::Inval,
        }
    }
}

/// Keys in the Object Store must follow the following rules:
///
///   * Keys can contain any sequence of valid Unicode characters, of length 1-1024 bytes when
///     UTF-8 encoded.
///   * Keys cannot contain Carriage Return or Line Feed characters.
///   * Keys cannot start with `.well-known/acme-challenge/`.
///   * Keys cannot be named `.` or `..`.
///   * Keys cannot use Unicode characters 0 through 32, 65534 and 65535 as
///     single-character key names.  (0x0 through 0x20, 0xFFFE and 0xFFFF)
fn is_valid_key(key: &str) -> Result<(), KeyValidationError> {
    let len = key.as_bytes().len();
    if len < 1 {
        return Err(KeyValidationError::EmptyKey);
    } else if len > 1024 {
        return Err(KeyValidationError::Over1024Bytes);
    }

    if key.starts_with(".well-known/acme-challenge") {
        return Err(KeyValidationError::StartsWithWellKnown);
    }

    if key.eq("..") {
        return Err(KeyValidationError::ContainsDotDot);
    } else if key.eq(".") {
        return Err(KeyValidationError::ContainsDot);
    } else if key.contains('\r') {
        return Err(KeyValidationError::Contains("\r".to_owned()));
    } else if key.contains('\n') {
        return Err(KeyValidationError::Contains("\n".to_owned()));
    } else if key.contains('#') {
        return Err(KeyValidationError::Contains("#".to_owned()));
    } else if key.contains(';') {
        return Err(KeyValidationError::Contains(";".to_owned()));
    } else if key.contains('?') {
        return Err(KeyValidationError::Contains("?".to_owned()));
    } else if key.contains('^') {
        return Err(KeyValidationError::Contains("^".to_owned()));
    } else if key.contains('|') {
        return Err(KeyValidationError::Contains("|".to_owned()));
    }

    if key.len() == 1 {
        let k = key.chars().next().unwrap();
        match k {
            '\u{0}'..='\u{20}' => {
                return Err(KeyValidationError::Contains(k.escape_unicode().to_string()));
            }
            '\u{FFFE}'..='\u{FFFF}' => {
                return Err(KeyValidationError::Contains(k.escape_unicode().to_string()));
            }
            _ => {}
        }
    }

    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum KeyValidationError {
    #[error("Keys for objects cannot be empty")]
    EmptyKey,
    #[error("Keys for objects cannot be over 1024 bytes in size")]
    Over1024Bytes,
    #[error("Keys for objects cannot start with `.well-known/acme-challenge`")]
    StartsWithWellKnown,
    #[error("Keys for objects cannot be named `.`")]
    ContainsDot,
    #[error("Keys for objects cannot be named `..`")]
    ContainsDotDot,
    #[error("Keys for objects cannot contain a `{0}`")]
    Contains(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    const STORE_NAME: &'static str = "test_store";

    #[test]
    fn test_kv_store_exists() {
        let stores = ObjectStores::default();
        stores
            .insert_empty_store(ObjectStoreKey(STORE_NAME.to_string()))
            .unwrap();

        let res = stores.store_exists(STORE_NAME);
        match res {
            Ok(true) => {}
            _ => panic!("should have been OK(true)"),
        }
    }

    #[test]
    fn test_kv_store_basics() {
        let stores = ObjectStores::default();
        stores
            .insert_empty_store(ObjectStoreKey(STORE_NAME.to_string()))
            .unwrap();

        let key = "insert_key".to_string();
        let val1 = "val1".to_string();

        // insert
        let res = stores.insert(
            ObjectStoreKey(STORE_NAME.to_string()),
            ObjectKey(key.clone()),
            val1.clone().into(),
            KvInsertMode::Overwrite,
            None,
            None,
            None,
        );
        match res {
            Err(_) => panic!("should have been OK"),
            _ => {}
        }

        // lookup
        let res = stores.lookup(
            ObjectStoreKey(STORE_NAME.to_string()),
            ObjectKey(key.clone()),
        );
        match res {
            Ok(ov) => {
                assert_eq!(ov.body, val1.as_bytes().to_vec())
            }
            Err(_) => panic!("should have been OK"),
        }

        // list
        let limit = 1000;
        let res = stores.list(ObjectStoreKey(STORE_NAME.to_string()), None, None, limit);
        match res {
            Ok(ov) => {
                let val = format!(r#"{{"data":["{key}"],"meta":{{"limit":{limit}}}}}"#);
                assert_eq!(std::str::from_utf8(&ov).unwrap(), val)
            }
            Err(_) => panic!("should have been OK"),
        }

        // delete
        let res = stores.delete(
            ObjectStoreKey(STORE_NAME.to_string()),
            ObjectKey(key.clone()),
        );
        match res {
            Ok(_) => {}
            Err(_) => panic!("should have been OK"),
        }
    }

    #[test]
    fn test_kv_store_item_404s() {
        let stores = ObjectStores::default();
        stores
            .insert_empty_store(ObjectStoreKey(STORE_NAME.to_string()))
            .unwrap();

        let res = stores.lookup(
            ObjectStoreKey(STORE_NAME.to_string()),
            ObjectKey("bad_key".to_string()),
        );
        match res {
            Ok(_) => panic!("should not have been OK"),
            Err(e) => assert_eq!(e, KvStoreError::NotFound),
        }

        let res = stores.delete(
            ObjectStoreKey(STORE_NAME.to_string()),
            ObjectKey("bad_key".to_string()),
        );
        match res {
            Ok(_) => panic!("should not have been OK"),
            Err(e) => assert_eq!(e, KvStoreError::NotFound),
        }
    }

    #[test]
    fn test_kv_store_item_insert_modes() {
        let stores = ObjectStores::default();
        stores
            .insert_empty_store(ObjectStoreKey(STORE_NAME.to_string()))
            .unwrap();

        let key = "insert_key".to_string();
        let val1 = "val1".to_string();
        let val2 = "val2".to_string();
        let val3 = "val3".to_string();

        let res = stores.insert(
            ObjectStoreKey(STORE_NAME.to_string()),
            ObjectKey(key.clone()),
            val1.clone().into(),
            KvInsertMode::Add,
            None,
            None,
            None,
        );
        assert!(res.is_ok());
        // fail on Add, because key already exists
        let res = stores.insert(
            ObjectStoreKey(STORE_NAME.to_string()),
            ObjectKey(key.clone()),
            val1.clone().into(),
            KvInsertMode::Add,
            None,
            None,
            None,
        );
        match res {
            Ok(_) => panic!("should not have been OK"),
            Err(e) => assert_eq!(e, KvStoreError::PreconditionFailed),
        }
        // prepend val2
        let res = stores.insert(
            ObjectStoreKey(STORE_NAME.to_string()),
            ObjectKey(key.clone()),
            val2.clone().into(),
            KvInsertMode::Prepend,
            None,
            None,
            None,
        );
        match res {
            Err(_) => panic!("should have been OK"),
            _ => {}
        }
        // append val3
        let res = stores.insert(
            ObjectStoreKey(STORE_NAME.to_string()),
            ObjectKey(key.clone()),
            val3.clone().into(),
            KvInsertMode::Append,
            None,
            None,
            None,
        );
        match res {
            Err(_) => panic!("should have been OK"),
            _ => {}
        }
        let res = stores.lookup(
            ObjectStoreKey(STORE_NAME.to_string()),
            ObjectKey(key.clone()),
        );
        match res {
            Ok(ov) => {
                let val = format!("{val2}{val1}{val3}");
                assert_eq!(ov.body, val.as_bytes().to_vec())
            }
            Err(_) => panic!("should have been OK"),
        }

        // overwrite val3
        let res = stores.insert(
            ObjectStoreKey(STORE_NAME.to_string()),
            ObjectKey(key.clone()),
            val3.clone().into(),
            KvInsertMode::Overwrite,
            None,
            Some(val2.as_bytes().to_vec()),
            None,
        );
        match res {
            Err(_) => panic!("should have been OK"),
            _ => {}
        }

        // test overwrite
        let res = stores.lookup(
            ObjectStoreKey(STORE_NAME.to_string()),
            ObjectKey(key.clone()),
        );
        match res {
            Ok(ov) => {
                assert_eq!(ov.body, val3.as_bytes().to_vec());
                assert_eq!(ov.metadata, val2.as_bytes().to_vec());
            }
            Err(_) => panic!("should have been OK"),
        }
    }

    #[test]
    fn test_kv_store_item_insert_generation() {
        let stores = ObjectStores::default();
        stores
            .insert_empty_store(ObjectStoreKey(STORE_NAME.to_string()))
            .unwrap();

        let key = "insert_key".to_string();
        let val1 = "val1".to_string();

        // insert val1
        let res = stores.insert(
            ObjectStoreKey(STORE_NAME.to_string()),
            ObjectKey(key.clone()),
            val1.clone().into(),
            KvInsertMode::Overwrite,
            None,
            None,
            None,
        );
        match res {
            Err(_) => panic!("should have been OK"),
            _ => {}
        }

        // test overwrite, get gen
        let generation;
        let res = stores.lookup(
            ObjectStoreKey(STORE_NAME.to_string()),
            ObjectKey(key.clone()),
        );
        match res {
            Ok(ov) => {
                assert_eq!(ov.body, val1.as_bytes().to_vec());
                generation = ov.generation;
            }
            Err(_) => panic!("should have been OK"),
        }

        // test generation match failure
        let res = stores.insert(
            ObjectStoreKey(STORE_NAME.to_string()),
            ObjectKey(key.clone()),
            val1.clone().into(),
            KvInsertMode::Overwrite,
            Some(1337),
            None,
            None,
        );
        match res {
            Err(KvStoreError::PreconditionFailed) => {}
            _ => panic!("should have been Err(KvStoreError::PreconditionFailed)"),
        }

        // test generation match positive
        let res = stores.insert(
            ObjectStoreKey(STORE_NAME.to_string()),
            ObjectKey(key.clone()),
            val1.clone().into(),
            KvInsertMode::Overwrite,
            Some(generation),
            None,
            None,
        );
        match res {
            Ok(_) => {}
            _ => panic!("should have been OK"),
        }

        // check result
        let res = stores.lookup(
            ObjectStoreKey(STORE_NAME.to_string()),
            ObjectKey(key.clone()),
        );
        match res {
            Ok(ov) => {
                assert_eq!(ov.body, val1.as_bytes().to_vec());
            }
            Err(_) => panic!("should have been OK"),
        }
    }

    #[test]
    fn test_kv_store_item_list_advanced() {
        let stores = ObjectStores::default();
        stores
            .insert_empty_store(ObjectStoreKey(STORE_NAME.to_string()))
            .unwrap();

        let key = "insert_key".to_string();
        let prefix = "key".to_string();
        let key1 = format!("{prefix}1").to_string();
        let key2 = format!("{prefix}2").to_string();
        let key3 = format!("{prefix}3").to_string();
        let val1 = "val1".to_string();
        let val2 = "val2".to_string();
        let val3 = "val3".to_string();

        // insert insert_key
        let res = stores.insert(
            ObjectStoreKey(STORE_NAME.to_string()),
            ObjectKey(key.clone()),
            val1.clone().into(),
            KvInsertMode::Overwrite,
            None,
            None,
            None,
        );
        match res {
            Err(_) => panic!("should have been OK"),
            _ => {}
        }

        // insert val1
        let res = stores.insert(
            ObjectStoreKey(STORE_NAME.to_string()),
            ObjectKey(key1.clone()),
            val1.clone().into(),
            KvInsertMode::Overwrite,
            None,
            None,
            None,
        );
        match res {
            Err(_) => panic!("should have been OK"),
            _ => {}
        }
        // insert val2
        let res = stores.insert(
            ObjectStoreKey(STORE_NAME.to_string()),
            ObjectKey(key2.clone()),
            val2.clone().into(),
            KvInsertMode::Overwrite,
            None,
            None,
            None,
        );
        match res {
            Err(_) => panic!("should have been OK"),
            _ => {}
        }
        // insert val3
        let res = stores.insert(
            ObjectStoreKey(STORE_NAME.to_string()),
            ObjectKey(key3.clone()),
            val3.clone().into(),
            KvInsertMode::Overwrite,
            None,
            None,
            None,
        );
        match res {
            Err(_) => panic!("should have been OK"),
            _ => {}
        }

        // list
        let limit = 1000;
        let res = stores.list(ObjectStoreKey(STORE_NAME.to_string()), None, None, limit);
        match res {
            Ok(ov) => {
                let val = format!(
                    r#"{{"data":["{key}","{key1}","{key2}","{key3}"],"meta":{{"limit":{limit}}}}}"#
                );
                assert_eq!(std::str::from_utf8(&ov).unwrap(), val)
            }
            Err(_) => panic!("should have been OK"),
        }

        // list w/prefix
        let limit = 1000;
        let res = stores.list(
            ObjectStoreKey(STORE_NAME.to_string()),
            None,
            Some(prefix.clone()),
            limit,
        );
        match res {
            Ok(ov) => {
                let val = format!(
                    r#"{{"data":["{key1}","{key2}","{key3}"],"meta":{{"limit":{limit},"prefix":"{prefix}"}}}}"#
                );
                assert_eq!(std::str::from_utf8(&ov).unwrap(), val)
            }
            Err(_) => panic!("should have been OK"),
        }

        // list w/prefix&limit
        let limit = 1;
        let res = stores.list(
            ObjectStoreKey(STORE_NAME.to_string()),
            None,
            Some(prefix.clone()),
            limit,
        );
        match res {
            Ok(ov) => {
                let next_cursor = BASE64_STANDARD.encode(key1.clone());
                let val = format!(
                    r#"{{"data":["{key1}"],"meta":{{"limit":{limit},"prefix":"{prefix}","next_cursor":"{next_cursor}"}}}}"#
                );
                assert_eq!(std::str::from_utf8(&ov).unwrap(), val)
            }
            Err(_) => panic!("should have been OK"),
        }

        // list w/prefix&limit&cursor
        let limit = 1;
        let last_cursor = BASE64_STANDARD.encode(key1.clone());
        let res = stores.list(
            ObjectStoreKey(STORE_NAME.to_string()),
            Some(last_cursor),
            Some(prefix.clone()),
            limit,
        );
        match res {
            Ok(ov) => {
                let next_cursor = BASE64_STANDARD.encode(key2.clone());
                let val = format!(
                    r#"{{"data":["{key2}"],"meta":{{"limit":{limit},"prefix":"{prefix}","next_cursor":"{next_cursor}"}}}}"#
                );
                assert_eq!(std::str::from_utf8(&ov).unwrap(), val)
            }
            Err(_) => panic!("should have been OK"),
        }

        // list w/prefix&limit&cursor
        let limit = 1;
        let last_cursor = BASE64_STANDARD.encode(key2.clone());
        let res = stores.list(
            ObjectStoreKey(STORE_NAME.to_string()),
            Some(last_cursor),
            Some(prefix.clone()),
            limit,
        );
        match res {
            Ok(ov) => {
                let val = format!(
                    r#"{{"data":["{key3}"],"meta":{{"limit":{limit},"prefix":"{prefix}"}}}}"#
                );
                assert_eq!(std::str::from_utf8(&ov).unwrap(), val)
            }
            Err(_) => panic!("should have been OK"),
        }
    }
}
