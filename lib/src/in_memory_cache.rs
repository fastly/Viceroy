use crate::{wiggle_abi::types, Error};
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

/// Handle used for a non-existing cache entry.
pub fn not_found_handle() -> types::CacheHandle {
    types::CacheHandle::from(u32::MAX)
}

type PrimaryCacheKey = Vec<u8>;

#[derive(Clone, Default, Debug)]
pub struct InMemoryCache {
    /// Cache entries, indexable by handle.
    /// `None` indicates a deleted entry OR a tx marker.
    pub cache_entries: Arc<RwLock<HashMap<u32, Option<CacheEntry>>>>,

    /// Next handle ID to assign
    next_handle_id: Arc<AtomicU32>,

    /// Primary cache key to a list of variants.
    pub key_candidates: Arc<RwLock<BTreeMap<PrimaryCacheKey, Vec<types::CacheHandle>>>>,

    // CacheHandle markers for pending transactions. Since we need to retrieve the cache key for
    // a tx insert, this map maps the pending handle the the key used to look it up.
    pub pending_tx: Arc<RwLock<HashMap<types::CacheHandle, PrimaryCacheKey>>>,
}

impl InMemoryCache {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn purge(&self, surrogates: Vec<String>) {
        let mut cache_entries = self.cache_entries.write().unwrap();
        let surrogates_to_purge: HashSet<String> = surrogates.into_iter().collect();

        // Simplistic implementation: Just go over all cache entries and kick out matching ones.
        for (_handle, handle_entry) in cache_entries.iter_mut() {
            if let Some(entry) = handle_entry {
                if entry
                    .surrogate_keys
                    .intersection(&surrogates_to_purge)
                    .count()
                    != 0
                {
                    // Drop the content of the cache entry.
                    handle_entry.take();
                }
            }
        }
    }

    /// Attempts to retrieve a cache entry by primary key.
    /// Matches vary rules against the given headers to retrieve the correct variant.
    pub fn get_entry(
        &self,
        key: &PrimaryCacheKey,
        headers: &HeaderMap,
    ) -> Option<types::CacheHandle> {
        let candidates_lock = self.key_candidates.read().unwrap();
        candidates_lock.get(key).and_then(|candidates| {
            let entry_lock = self.cache_entries.write().unwrap();

            candidates.iter().find_map(|candidate_handle| {
                let handle_id: u32 = (*candidate_handle).into();
                entry_lock
                    .get(&handle_id)
                    .and_then(|candidate_entry| {
                        candidate_entry.as_ref().and_then(|entry| {
                            (entry.vary_matches(headers) && entry.is_usable())
                                .then(|| *candidate_handle)
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

        // Check for and perform overwrites or write a new entry.
        let existing_entry_handle = self.get_entry(
            &key,
            request_parts
                .map(|p| &p.headers)
                .unwrap_or(&HeaderMap::new()),
        );

        let entry_handle = match existing_entry_handle {
            Some(handle) => {
                // Overwrite entry.
                event!(Level::TRACE, "Overwriting cache entry {}", handle);

                let handle_id: u32 = handle.into();
                self.cache_entries
                    .write()
                    .unwrap()
                    .get_mut(&handle_id)
                    .map(|old_entry| old_entry.replace(entry));

                handle
            }

            None => {
                // Write new entry.
                let new_handle_id = self.next_handle_id.fetch_add(1, Ordering::SeqCst);
                let new_entry_handle = types::CacheHandle::from(new_handle_id);
                self.cache_entries.write().unwrap().insert(new_handle_id, Some(entry));
                event!(Level::TRACE, "Wrote new cache entry {}", new_entry_handle);

                // Write handle key candidate mapping.
                match self.key_candidates.write().unwrap().entry(key) {
                    Entry::Vacant(vacant) => {
                        vacant.insert(vec![new_entry_handle]);
                    }
                    Entry::Occupied(mut occupied) => {
                        occupied.get_mut().push(new_entry_handle);
                    }
                }

                new_entry_handle
            }
        };

        Ok(entry_handle)
    }
}

#[derive(Debug)]
pub struct CacheEntry {
    /// Key the entry was created with.
    /// Here for convenience, entries are retrieved via handles.
    pub key: PrimaryCacheKey,

    /// The raw bytes of the cached entry.
    pub body_bytes: Vec<u8>,

    // The cached bytes.
    // pub body_handle: types::BodyHandle,
    /// Vary used to create this entry.
    pub vary: BTreeMap<String, Option<String>>,

    /// Surrogates attached to this cache entry.
    pub surrogate_keys: HashSet<String>,

    /// Initial age of the cache entry.
    pub initial_age_ns: Option<u64>,

    /// Max-age this entry has been created with.
    pub max_age_ns: Option<u64>,

    /// Stale-while-revalidate this entry has been created with.
    pub swr_ns: Option<u64>,

    /// Instant this entry has been created.
    pub created_at: Instant,

    /// The user metadata stored alongside the cache.
    pub user_metadata: Vec<u8>,
}

impl CacheEntry {
    pub fn vary_matches(&self, headers: &HeaderMap) -> bool {
        self.vary.iter().all(|(vary_key, vary_value)| {
            headers.get(vary_key).and_then(|h| h.to_str().ok()) == vary_value.as_deref()
        })
    }

    pub fn age_ns(&self) -> u64 {
        self.created_at
            .elapsed()
            .as_nanos()
            .try_into()
            .ok()
            .and_then(|age_ns: u64| age_ns.checked_add(self.initial_age_ns.unwrap_or(0)))
            .unwrap_or(u64::MAX)
    }

    /// Stale: Is within max-age + ttl, but only if there's an swr given.
    pub fn is_stale(&self) -> bool {
        let age = self.age_ns();
        let total_ttl = self.total_ttl_ns();

        match (self.max_age_ns, self.swr_ns) {
            (Some(max_age), Some(_)) => age > max_age && age < total_ttl,
            _ => false,
        }
    }

    /// Usable: Age is smaller than max-age + swr.
    pub fn is_usable(&self) -> bool {
        let total_ttl = self.total_ttl_ns();
        let age = self.age_ns();

        age < total_ttl
    }

    /// Max-age + swr of the cache entry.
    fn total_ttl_ns(&self) -> u64 {
        let mut total_ttl = 0;
        if let Some(max_age) = self.max_age_ns {
            total_ttl += max_age;
        };

        if let Some(swr) = self.swr_ns {
            total_ttl += swr;
        };

        total_ttl
    }
}

pub const NS_TO_S_FACTOR: u64 = 1_000_000_000;

impl Display for InMemoryCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Cache State:")?;
        writeln!(f, "{}Entries:", Self::indent(1))?;

        for (handle_id, entry) in self.cache_entries.read().unwrap().iter() {
            let handle = types::CacheHandle::from(*handle_id);
            match entry {
                Some(entry) => self.fmt_entry(f, handle, entry)?,
                None => writeln!(f, "{}[{}]: Purged", Self::indent(2), handle,)?,
            }
        }

        Ok(())
    }
}

impl InMemoryCache {
    fn indent(level: usize) -> String {
        "  ".repeat(level)
    }

    fn fmt_entry(
        &self,
        f: &mut std::fmt::Formatter<'_>,
        handle: types::CacheHandle,
        entry: &CacheEntry,
    ) -> std::fmt::Result {
        writeln!(
            f,
            "{}[{}]: {}",
            Self::indent(2),
            handle,
            entry
                .key
                .iter()
                .map(|x| format!("{x:X}"))
                .collect::<Vec<_>>()
                .join("")
        )?;

        writeln!(f, "{}TTLs (in seconds):", Self::indent(3),)?;
        writeln!(
            f,
            "{}Age: {}",
            Self::indent(4),
            entry.age_ns() / NS_TO_S_FACTOR
        )?;
        writeln!(
            f,
            "{}Inital age: {:?}",
            Self::indent(4),
            entry.initial_age_ns.map(|ia| ia / NS_TO_S_FACTOR)
        )?;
        writeln!(
            f,
            "{}Max-age: {:?}",
            Self::indent(4),
            entry.max_age_ns.map(|x| x / NS_TO_S_FACTOR)
        )?;
        writeln!(
            f,
            "{}Swr: {:?}",
            Self::indent(4),
            entry.swr_ns.map(|x| x / NS_TO_S_FACTOR)
        )?;

        writeln!(f, "{}Vary:", Self::indent(3))?;
        for (key, value) in entry.vary.iter() {
            writeln!(f, "{}{key}: {:?}", Self::indent(4), value)?;
        }

        writeln!(f, "{}Surrogate keys:", Self::indent(3))?;
        let mut surrogates: Vec<&String> = entry.surrogate_keys.iter().collect();
        surrogates.sort();

        for surrogate in surrogates {
            writeln!(f, "{}{surrogate}", Self::indent(4))?;
        }

        writeln!(f, "{}User Metadata:", Self::indent(3))?;
        writeln!(
            f,
            "{}{}",
            Self::indent(4),
            std::str::from_utf8(&entry.user_metadata).unwrap_or("Invalid UITF-8")
        )?;

        writeln!(f, "{}Body:", Self::indent(3))?;
        writeln!(
            f,
            "{}{}",
            Self::indent(4),
            std::str::from_utf8(&entry.body_bytes).unwrap_or("<Invalid UTF8 body>")
        )?;

        Ok(())
    }
}
