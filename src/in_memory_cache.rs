use crate::wiggle_abi::types;
use crate::Error;
use http::{request::Parts, HeaderMap};
use std::{
    collections::{btree_map::Entry, BTreeMap, HashMap, HashSet},
    fmt::Display,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc, RwLock,
    },
    time::Instant,
};
use tracing::{event, Level};

pub fn not_found_handle() -> types::CacheHandle {
    types::CacheHandle::from(u32::MAX)
}

type PrimaryCacheKey = Vec<u8>;

#[derive(Clone, Default, Debug)]
pub struct InMemoryCache {
    /// Cache entries, indexable by handle ID.
    pub cache_entries: Arc<RwLock<HashMap<u32, Option<CacheEntry>>>>,
    /// Next handle ID to assign.
    next_handle_id: Arc<AtomicU32>,
    /// Primary cache key to a list of variants.
    pub key_candidates: Arc<RwLock<BTreeMap<PrimaryCacheKey, Vec<types::CacheHandle>>>>,
    /// Pending transaction markers.
    pub pending_tx: Arc<RwLock<HashMap<types::CacheHandle, PrimaryCacheKey>>>,
}

impl InMemoryCache {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn purge(&self, surrogates: Vec<String>) {
        let mut cache_entries = self.cache_entries.write().unwrap();
        let surrogates_to_purge: HashSet<String> = surrogates.into_iter().collect();
        for (_handle_id, handle_entry) in cache_entries.iter_mut() {
            if let Some(entry) = handle_entry {
                if entry.surrogate_keys.intersection(&surrogates_to_purge).count() != 0 {
                    handle_entry.take();
                }
            }
        }
    }

    pub fn get_entry(&self, key: &PrimaryCacheKey, headers: &HeaderMap) -> Option<types::CacheHandle> {
        let candidates_lock = self.key_candidates.read().unwrap();
        candidates_lock.get(key).and_then(|candidates| {
            let entry_lock = self.cache_entries.write().unwrap();
            candidates.iter().find_map(|candidate_handle| {
                let handle_id: u32 = (*candidate_handle).into();
                entry_lock.get(&handle_id).and_then(|candidate_entry| {
                    candidate_entry.as_ref().and_then(|entry| {
                        (entry.vary_matches(headers) && entry.is_usable()).then(|| *candidate_handle)
                    })
                })
            })
        })
    }

    /// Insert a cache entry with pre-extracted options.
    pub fn insert_with_options(
        &self,
        key: PrimaryCacheKey,
        max_age_ns: u64,
        swr_ns: Option<u64>,
        initial_age_ns: Option<u64>,
        surrogate_keys: Vec<String>,
        user_metadata: Vec<u8>,
        vary: BTreeMap<String, Option<String>>,
        request_parts: Option<&Parts>,
    ) -> Result<types::CacheHandle, Error> {
        let _ = request_parts; // May be used for vary matching in the future

        let entry = CacheEntry {
            key: key.clone(),
            body_bytes: vec![],
            vary,
            initial_age_ns,
            max_age_ns: Some(max_age_ns),
            swr_ns,
            created_at: Instant::now(),
            user_metadata,
            surrogate_keys: surrogate_keys.into_iter().collect(),
        };

        let existing_entry_handle = self.get_entry(
            &key,
            request_parts.map(|p| &p.headers).unwrap_or(&HeaderMap::new()),
        );

        let entry_handle = match existing_entry_handle {
            Some(handle) => {
                event!(Level::TRACE, "Overwriting cache entry {}", handle);
                let handle_id: u32 = handle.into();
                self.cache_entries.write().unwrap().get_mut(&handle_id).map(|old_entry| old_entry.replace(entry));
                handle
            }
            None => {
                // Write new entry.
                let new_handle_id = self.next_handle_id.fetch_add(1, Ordering::SeqCst);
                let new_entry_handle = types::CacheHandle::from(new_handle_id);
                self.cache_entries.write().unwrap().insert(new_handle_id, Some(entry));
                event!(Level::TRACE, "Wrote new cache entry {}", new_entry_handle);
                match self.key_candidates.write().unwrap().entry(key) {
                    Entry::Vacant(vacant) => { vacant.insert(vec![new_entry_handle]); }
                    Entry::Occupied(mut occupied) => { occupied.get_mut().push(new_entry_handle); }
                }
                new_entry_handle
            }
        };
        Ok(entry_handle)
    }
}

#[derive(Debug)]
pub struct CacheEntry {
    pub key: PrimaryCacheKey,
    pub body_bytes: Vec<u8>,
    pub vary: BTreeMap<String, Option<String>>,
    pub surrogate_keys: HashSet<String>,
    pub initial_age_ns: Option<u64>,
    pub max_age_ns: Option<u64>,
    pub swr_ns: Option<u64>,
    pub created_at: Instant,
    pub user_metadata: Vec<u8>,
}

impl CacheEntry {
    pub fn vary_matches(&self, headers: &HeaderMap) -> bool {
        self.vary.iter().all(|(vary_key, vary_value)| {
            headers.get(vary_key).and_then(|h| h.to_str().ok()) == vary_value.as_deref()
        })
    }

    pub fn age_ns(&self) -> u64 {
        self.created_at.elapsed().as_nanos().try_into().ok()
            .and_then(|age_ns: u64| age_ns.checked_add(self.initial_age_ns.unwrap_or(0)))
            .unwrap_or(u64::MAX)
    }

    pub fn is_stale(&self) -> bool {
        let age = self.age_ns();
        match (self.max_age_ns, self.swr_ns) {
            (Some(max_age), Some(_)) => age > max_age && age < self.total_ttl_ns(),
            _ => false,
        }
    }

    pub fn is_usable(&self) -> bool {
        self.age_ns() < self.total_ttl_ns()
    }

    fn total_ttl_ns(&self) -> u64 {
        self.max_age_ns.unwrap_or(0) + self.swr_ns.unwrap_or(0)
    }
}

impl Display for InMemoryCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Cache State:")?;
        for (handle_id, entry) in self.cache_entries.read().unwrap().iter() {
            let handle = types::CacheHandle::from(*handle_id);
            match entry {
                Some(e) => writeln!(f, "  [{}]: key={:?}", handle, e.key)?,
                None => writeln!(f, "  [{}]: Purged", handle)?,
            }
        }
        Ok(())
    }
}
