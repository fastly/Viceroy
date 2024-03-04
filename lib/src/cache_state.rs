use cranelift_entity::PrimaryMap;
use http::HeaderMap;

use crate::{body::Body, session::Session, wiggle_abi::types};
use std::{
    collections::{BTreeMap, HashMap},
    sync::{
        atomic::{AtomicI32, AtomicU32, Ordering},
        Arc, RwLock,
    },
    time::Instant,
};

/// Handle used for a non-existing cache entry.
pub fn not_found_handle() -> types::CacheHandle {
    types::CacheHandle::from(u32::MAX)
}

type PrimaryCacheKey = Vec<u8>;

#[derive(Debug)]
pub struct CacheKey {
    /// The primary bytes of the cache key.
    primary: Vec<u8>,

    /// A list of secondary keys (based on vary).
    /// Note that, right now, this list must be ordered in order to map the same entry.
    secondary: Vec<String>,
}

#[derive(Debug)]
pub struct CacheEntry {
    /// The cached bytes.
    pub body: types::BodyHandle,

    /// Vary used to create this entry.
    pub vary: BTreeMap<String, String>,

    /// Max-age this entry has been created with.
    pub max_age: Option<u64>,

    /// Stale-while-revalidate this entry has been created with.
    pub swr: Option<u64>,

    /// Instant this entry has been created.
    pub created_at: Instant,

    /// The user metadata stored alongside the cache.
    pub user_metadata: Vec<u8>,
}

impl CacheEntry {
    pub fn vary_matches(&self, headers: &HeaderMap) -> bool {
        self.vary.iter().all(|(vary_key, vary_value)| {
            headers
                .get(vary_key)
                .map(|v| v == vary_value)
                .unwrap_or(false)
        })
    }
}

#[derive(Clone, Default, Debug)]
pub struct CacheState {
    /// Cache entries, indexable by handle.
    pub cache_entries: Arc<RwLock<PrimaryMap<types::CacheHandle, CacheEntry>>>,

    /// Primary cache key to a list of variants.
    pub key_candidates: Arc<RwLock<BTreeMap<PrimaryCacheKey, Vec<types::CacheHandle>>>>,
    // cache_entries: Arc<RwLock<HashMap<types::CacheHandle, CacheEntry>>>,
    // /// Sequence
    // handle_sequence: Arc<AtomicU32>,
}

// Requires:
// - lookup: key to handle
// - insert: key to bodyhandle
// - state: handle to state
// - body: handle to body handle

impl CacheState {
    pub fn new() -> Self {
        // 0 is reserved for missing cache entries.
        // let handle_sequence = Arc::new(AtomicU32::new(1));

        Self {
            // handle_sequence,
            ..Default::default()
        }
    }
}

//     /// Get handle for the given key.
//     /// Will return the empty handle (0) if no entry is found.
//     pub(crate) fn get_handle(&self, key: &Vec<u8>) -> types::CacheHandle {
//         self.handles
//             .read()
//             .unwrap()
//             .get(key)
//             .map(ToOwned::to_owned)
//             .unwrap_or(none_handle())
//     }

//     pub(crate) fn get_state(&self, key: &types::CacheHandle) -> CacheLookupState {
//         self.cache_entries.read().unwrap().get(key).map(|entry| {
//             // check:
//             // - expired (STALE)
//             // - Not found (MUST_INSERT_OR_UPDATE)
//             // - Found and usable (USABLE)
//             // - ??? (FOUND)
//         })

//         // handle: types::CacheHandle

//         // self.handles
//         //     .read()
//         //     .expect("[Get] Handle lookup to succeed")
//         //     .get(&handle.inner())
//         //     .and_then(|key| {
//         //         self.cache_entries
//         //             .read()
//         //             .expect("[Get] Entry lookup to succeed")
//         //             .get(key)
//         //     })
//         // todo!()
//     }

//     pub(crate) fn insert(
//         &self,
//         key: Vec<u8>,
//         max_age: u64,
//         body_handle: types::BodyHandle,
//     ) -> types::CacheHandle {
//         let entry = CacheEntry {
//             body: body_handle,
//             vary: BTreeMap::new(),
//             max_age: Some(max_age),
//             swr: None,
//             created_at: Instant::now(),
//             user_metadata: vec![],
//         };

//         todo!()

//         // let handle_index = self.handle_sequence.fetch_add(1, Ordering::Relaxed);
//         // self.handles
//         //     .write()
//         //     .expect("[Insert] Handle lookup to succeed")
//         //     .insert(handle_index, key.clone());

//         // self.cache_entries
//         //     .write()
//         //     .expect("[Insert] Cache entry lock to succeed")
//         //     .insert(key, entry);

//         // types::CacheHandle::from(handle_index)
//     }
// }
