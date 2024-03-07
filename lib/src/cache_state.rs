use crate::{body::Body, wiggle_abi::types};
use cranelift_entity::PrimaryMap;
use http::HeaderMap;
use std::{
    collections::{BTreeMap, HashMap},
    fmt::Display,
    sync::{Arc, RwLock},
    time::Instant,
};

/// Handle used for a non-existing cache entry.
pub fn not_found_handle() -> types::CacheHandle {
    types::CacheHandle::from(u32::MAX)
}

type PrimaryCacheKey = Vec<u8>;

#[derive(Debug)]
pub struct CacheEntry {
    /// The cached bytes.
    pub body_handle: types::BodyHandle,

    /// Vary used to create this entry.
    pub vary: BTreeMap<String, Option<String>>,

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
            headers.get(vary_key).and_then(|h| h.to_str().ok()) == vary_value.as_deref()
        })
    }
}

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
}

// Requires:
// - lookup: key to handle
// - insert: key to bodyhandle
// - state: handle to state
// - body: handle to body handle

impl CacheState {
    pub fn new() -> Self {
        Default::default()
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

struct CacheStateFormatter<'state> {
    state: &'state CacheState,
    formatted_bodies: HashMap<types::BodyHandle, String>,
}

impl<'state> Display for CacheStateFormatter<'state> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fn indent(level: usize) -> String {
            "  ".repeat(level)
        }

        dbg!(&self.formatted_bodies);

        writeln!(f, "Cache State:")?;
        writeln!(f, "{}Entries:", indent(1))?;

        for (handle, entry) in self.state.cache_entries.read().unwrap().iter() {
            writeln!(
                f,
                "{}[{}]: {:?} | {:?}",
                indent(2),
                handle,
                entry.max_age,
                entry.swr
            )?;
            writeln!(f, "{}Vary:", indent(3))?;

            for (key, value) in entry.vary.iter() {
                writeln!(f, "{}{key}: {:?}", indent(4), value)?;
            }

            writeln!(f, "{}User Metadata:", indent(3))?;
            writeln!(
                f,
                "{}{}",
                indent(4),
                std::str::from_utf8(&entry.user_metadata).unwrap_or("Invalid UITF-8")
            )?;

            writeln!(f, "{}Body:", indent(3))?;

            let body = self
                .formatted_bodies
                .get(&entry.body_handle)
                .map(|s| s.as_str())
                .unwrap_or("<Unset>");

            writeln!(f, "{}{}", indent(4), body)?;
        }

        Ok(())
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
