use crate::{body::Body, wiggle_abi::types, Error};
use cranelift_entity::PrimaryMap;
use http::{request::Parts, HeaderMap};
use std::{
    collections::{btree_map::Entry, BTreeMap, HashMap},
    fmt::Display,
    sync::{Arc, RwLock},
    time::Instant,
};
use tracing::{event, Level};

/// Handle used for a non-existing cache entry.
/// TODO: Is this needed? Seems to work without checking it.
pub fn not_found_handle() -> types::CacheHandle {
    types::CacheHandle::from(u32::MAX)
}

type PrimaryCacheKey = Vec<u8>;

// #[derive(Debug)]
// pub enum CacheEntry {
//     PendingTxInsert(PrimaryCacheKey),
//     Entry(CacheEntry),
// }

// impl CacheEntry {
//     pub fn as_entry_panicking(&self) -> &CacheEntry {
//         match self {
//             CacheEntry::Entry(e) => e,
//             CacheEntry::PendingTxInsert(_) => panic!("Entry is not a cache entry, but pending tx"),
//         }
//     }
// }

// #[derive(Clone, Debug)]
// pub enum PendingTxState {
//     Insert(PrimaryCacheKey),
//     Overwrite(types::CacheHandle),
// }

#[derive(Clone, Default, Debug)]
pub struct CacheState {
    /// Cache entries, indexable by handle.
    pub cache_entries: Arc<RwLock<PrimaryMap<types::CacheHandle, CacheEntry>>>,

    /// Primary cache key to a list of variants.
    pub key_candidates: Arc<RwLock<BTreeMap<PrimaryCacheKey, Vec<types::CacheHandle>>>>,

    pub surrogates_to_handles: Arc<RwLock<BTreeMap<String, Vec<types::CacheHandle>>>>,

    /// The way cache bodies are handled makes it super hard to move cache state between
    /// executions. We can't fork the SDK, so we need to abide by the interface.
    ///
    /// We change the session to be aware of `CacheState`, which will write a copy of the body when
    /// execution ends. On load, these bodies will be written back into the next session.
    pub bodies: Arc<RwLock<HashMap<types::BodyHandle, Option<Body>>>>,

    /// CacheHandle markers for pending transactions. Handles received for TX operataions
    /// always point into this map instead of the entries.
    //
    // TODO this is probably a crime, since two cache handle primary maps may lead to
    // fun bugs, but as we're not in need to really testing tx, we can just hack it.
    pub pending_tx: Arc<RwLock<PrimaryMap<types::CacheHandle, PrimaryCacheKey>>>,
}

impl CacheState {
    pub fn new() -> Self {
        Default::default()
    }

    // TODO: Purge

    pub fn match_entry(&self, key: &Vec<u8>, headers: &HeaderMap) -> Option<types::CacheHandle> {
        let candidates_lock = self.key_candidates.read().unwrap();

        candidates_lock.get(key).and_then(|candidates| {
            let entry_lock = self.cache_entries.write().unwrap();

            candidates.iter().find_map(|candidate_handle| {
                entry_lock
                    .get(*candidate_handle)
                    .and_then(|candidate_entry| {
                        candidate_entry
                            .vary_matches(headers)
                            .then(|| *candidate_handle)
                    })
            })
        })
    }

    pub fn insert<'a>(
        &self,
        key: Vec<u8>,
        options_mask: types::CacheWriteOptionsMask,
        options: types::CacheWriteOptions,
        request_parts: Option<&Parts>,
        body_to_use: types::BodyHandle,
    ) -> Result<(), Error> {
        // Cache write must contain max-age.
        let max_age_ns = options.max_age_ns;

        // Swr might not be set, check bitmask for. Else we'd always get Some(0).
        let swr_ns = options_mask
            .contains(types::CacheWriteOptionsMask::STALE_WHILE_REVALIDATE_NS)
            .then(|| options.stale_while_revalidate_ns);

        let surrogate_keys = if options_mask.contains(types::CacheWriteOptionsMask::SURROGATE_KEYS)
        {
            if options.surrogate_keys_len == 0 {
                return Err(Error::InvalidArgument);
            }

            let byte_slice = options
                .surrogate_keys_ptr
                .as_array(options.surrogate_keys_len)
                .to_vec()?;

            match String::from_utf8(byte_slice) {
                Ok(s) => s
                    .split_whitespace()
                    .map(ToOwned::to_owned)
                    .collect::<Vec<_>>(),

                Err(_) => return Err(Error::InvalidArgument),
            }
        } else {
            vec![]
        };

        let user_metadata = if options_mask.contains(types::CacheWriteOptionsMask::USER_METADATA) {
            if options.user_metadata_len == 0 {
                return Err(Error::InvalidArgument);
            }

            let byte_slice = options
                .user_metadata_ptr
                .as_array(options.user_metadata_len)
                .to_vec()?;

            byte_slice
        } else {
            vec![]
        };

        let vary = if options_mask.contains(types::CacheWriteOptionsMask::VARY_RULE) {
            if options.vary_rule_len == 0 {
                return Err(Error::InvalidArgument);
            }

            let byte_slice = options
                .vary_rule_ptr
                .as_array(options.vary_rule_len)
                .to_vec()?;

            let vary_rules = match String::from_utf8(byte_slice) {
                Ok(s) => s
                    .split_whitespace()
                    .map(ToOwned::to_owned)
                    .collect::<Vec<_>>(),

                Err(_) => return Err(Error::InvalidArgument),
            };

            if let Some(req_parts) = request_parts {
                let mut map = BTreeMap::new();

                // Extract necessary vary headers.
                for vary in vary_rules {
                    // If you think this sucks... then you'd be right. Just supposed to work right now.
                    let value = req_parts
                        .headers
                        .get(&vary)
                        .map(|h| h.to_str().unwrap().to_string());

                    map.insert(vary, value);
                }

                map
            } else {
                // Or invalid argument?
                BTreeMap::new()
            }
        } else {
            BTreeMap::new()
        };

        let initial_age_ns = options_mask
            .contains(types::CacheWriteOptionsMask::INITIAL_AGE_NS)
            .then(|| options.initial_age_ns);

        let mut entry = CacheEntry {
            key: key.clone(),
            body_handle: body_to_use,
            vary,
            initial_age_ns,
            max_age_ns: Some(max_age_ns),
            swr_ns: swr_ns,
            created_at: Instant::now(),
            user_metadata,
        };

        // Check for and perform overwrites.
        let mut candidates_lock = self.key_candidates.write().unwrap();
        let candidates = candidates_lock.get_mut(&key);
        let headers = request_parts.map(|p| &p.headers);

        let (entry_handle, overwrite) = candidates
            .and_then(|candidates| {
                let entry_lock = self.cache_entries.write().unwrap();

                candidates.iter_mut().find_map(|candidate_handle| {
                    entry_lock
                        .get(*candidate_handle)
                        .and_then(|mut candidate_entry| {
                            candidate_entry
                                .vary_matches(&headers.unwrap_or(&HeaderMap::new()))
                                .then(|| {
                                    event!(
                                        Level::TRACE,
                                        "Overwriting cache entry {}",
                                        candidate_handle
                                    );

                                    let _ = std::mem::replace(&mut candidate_entry, &mut entry);
                                    (*candidate_handle, true)
                                })
                        })
                })
            })
            .unwrap_or_else(|| {
                // Write new entry.
                let entry_handle = self.cache_entries.write().unwrap().push(entry);
                event!(
                    Level::TRACE,
                    "Wrote new cache entry {} with body handle {}",
                    entry_handle,
                    body_to_use
                );
                (entry_handle, false)
            });

        drop(candidates_lock);

        if !overwrite {
            // Write handle key candidate mapping.
            match self.key_candidates.write().unwrap().entry(key) {
                Entry::Vacant(vacant) => {
                    vacant.insert(vec![entry_handle]);
                }
                Entry::Occupied(mut occupied) => {
                    occupied.get_mut().push(entry_handle);
                }
            }
        }

        // Write surrogates (we don't really need to care about the overwrite case here for now).
        let mut surrogates_write_lock = self.surrogates_to_handles.write().unwrap();
        for surrogate_key in surrogate_keys {
            match surrogates_write_lock.entry(surrogate_key) {
                Entry::Vacant(vacant) => {
                    vacant.insert(vec![entry_handle]);
                }
                Entry::Occupied(mut occupied) => {
                    occupied.get_mut().push(entry_handle);
                }
            };
        }

        Ok(())
    }

    // This handling is necessary due to incredibly painful body handling.
    pub async fn format_pretty(&self) -> String {
        let formatted_bodies = self.format_bodies().await;
        let formatter = CacheStateFormatter {
            state: self,
            formatted_bodies,
        };

        formatter.to_string()
    }

    async fn format_bodies(&self) -> HashMap<types::BodyHandle, String> {
        let mut formatted_bodies = HashMap::new();
        let mut new_bodies = HashMap::new();

        // We need to remove all bodies once, read them into byte vectors in order to format them,
        // then recreate the bodies and write them back into the map. Excellent.
        let bodies = self.bodies.write().unwrap().drain().collect::<Vec<_>>();
        for (key, body) in bodies {
            if let Some(body) = body {
                let formatted = match body.read_into_vec().await {
                    Ok(bytes) => {
                        new_bodies.insert(key, Some(Body::from(bytes.clone())));
                        String::from_utf8(bytes).unwrap_or("Invalid UTF-8".to_owned())
                    }
                    Err(err) => format!("Invalid body: {err}"),
                };

                formatted_bodies.insert(key, formatted);
            } else {
                new_bodies.insert(key, None);
            }
        }

        // Write back the bodies.
        self.bodies.write().unwrap().extend(new_bodies);
        formatted_bodies
    }
}

#[derive(Debug)]
pub struct CacheEntry {
    /// Key the entry was created with.
    /// Here for convenience.
    pub key: Vec<u8>,

    /// The cached bytes.
    pub body_handle: types::BodyHandle,

    /// Vary used to create this entry.
    pub vary: BTreeMap<String, Option<String>>,

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
            (Some(max_age), Some(swr)) => age > max_age && age < total_ttl,
            _ => false,
        }
    }

    /// Usable: Age is smaller than max-age + swr.
    pub fn is_usable(&self) -> bool {
        let mut total_ttl = self.total_ttl_ns();
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

struct CacheStateFormatter<'state> {
    state: &'state CacheState,
    formatted_bodies: HashMap<types::BodyHandle, String>,
}

impl<'state> Display for CacheStateFormatter<'state> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Cache State:")?;
        writeln!(f, "{}Entries:", Self::indent(1))?;

        for (handle, entry) in self.state.cache_entries.read().unwrap().iter() {
            self.fmt_entry(f, handle, entry)?;
        }

        Ok(())
    }
}

pub const NS_TO_S_FACTOR: u64 = 1_000_000_000;

impl<'state> CacheStateFormatter<'state> {
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

        writeln!(f, "{}User Metadata:", Self::indent(3))?;
        writeln!(
            f,
            "{}{}",
            Self::indent(4),
            std::str::from_utf8(&entry.user_metadata).unwrap_or("Invalid UITF-8")
        )?;

        writeln!(f, "{}Body:", Self::indent(3))?;

        let body = self
            .formatted_bodies
            .get(&entry.body_handle)
            .map(|s| s.as_str())
            .unwrap_or("<Unset>");

        writeln!(f, "{}{}", Self::indent(4), body)
    }
}
