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
/// TODO: Is this needed? Seems to work without checking it.
pub fn not_found_handle() -> types::CacheHandle {
    types::CacheHandle::from(u32::MAX)
}

type PrimaryCacheKey = Vec<u8>;

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
        fn indent(level: usize) -> String {
            "  ".repeat(level)
        }

        writeln!(f, "Cache State:")?;
        writeln!(f, "{}Entries:", indent(1))?;

        for (handle, entry) in self.state.cache_entries.read().unwrap().iter() {
            writeln!(
                f,
                "{}[{}]: {}",
                indent(2),
                handle,
                entry
                    .key
                    .iter()
                    .map(|x| format!("{x:X}"))
                    .collect::<Vec<_>>()
                    .join("")
            )?;

            writeln!(f, "{}TTLs (sec):", indent(3),)?;
            writeln!(f, "{}Age: {}", indent(4), entry.age_ns() / 1_000_000_000)?;
            writeln!(
                f,
                "{}Inital age: {:?}",
                indent(4),
                entry.initial_age_ns.map(|ia| ia / 1_000_000_000)
            )?;
            writeln!(f, "{}Max-age: {:?}", indent(4), entry.max_age)?;
            writeln!(f, "{}Swr: {:?}", indent(4), entry.swr)?;

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
