use crate::wiggle_abi::types;
use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
    time::Instant,
};

struct CacheEntry {
    /// The cached bytes.
    body: Vec<u8>,

    /// Vary used to create this entry.
    vary: BTreeMap<String, String>,

    /// Max-age this entry has been created with.
    max_age: Option<u64>,

    /// Stale-while-revalidate this entry has been created with.
    swr: Option<u64>,

    /// Instant this entry has been created.
    created_at: Instant,

    /// The user metadata stored alongside the cache.
    user_metadata: Vec<u8>,
}

#[derive(Clone, Default)]
pub struct CacheState {
    // #[allow(clippy::type_complexity)]
    // Cache key to entry map.
    cache_entries: Arc<RwLock<BTreeMap<Vec<u8>, CacheEntry>>>,

    /// Handle to cache key for ABI interop.
    handle_map: Arc<RwLock<BTreeMap<types::CacheHandle, Vec<u8>>>>,
}

impl CacheState {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}
