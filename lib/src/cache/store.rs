//! Data structures & implementation details for the Viceroy cache.

use crate::cache::variance::VaryRule;
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use http::HeaderMap;

use crate::{body::Body, collecting_body::CollectingBody, Error};

use super::{variance::Variant, WriteOptions};

/// Metadata associated with a particular object on insert.
#[derive(Debug)]
pub struct ObjectMeta {
    /// The time at which the object was inserted into this cache.
    ///
    /// This may be later than the time at which the object was created, i.e. the object's age;
    /// include `initial_age` in any calculations that require the absolute age.
    ///
    /// We use Instant here rather than a calendar datetime (e.g. `chrono`) to ensure monotonicity.
    /// All of the external interfaces & cache semantics are in terms of relative offsets (age),
    /// not absolute timestamps; we should not be sensitive to resyncing the system clock.
    inserted: Instant,
    /// Initial age, if provided during setup.
    initial_age: Duration,
    /// Freshness lifetime
    max_age: Duration,

    request_headers: HeaderMap,
    vary_rule: VaryRule,
    // TODO: cceckman-at-fastly: for future work!
    /*
    never_cache: bool, // Aka "hit for pass"
    stale_while_revalidate_until: Option<Instant>,
    edge_ok_until: Option<Instant>,

    surrogate_keys: HashSet<String>,
    length: Option<usize>,
    user_metadata: Option<Bytes>,
    sensitive_data: Option<bool>,
    */
}

impl ObjectMeta {
    /// Retrieve the current age of this object.
    pub fn age(&self) -> Duration {
        // Age in this cache, plus age upon insertion
        Instant::now().duration_since(self.inserted) + self.initial_age
    }

    /// Maximum fresh age of this object.
    pub fn max_age(&self) -> Duration {
        self.max_age
    }

    /// Return true if the entry is fresh at the current time.
    pub fn is_fresh(&self) -> bool {
        self.age() < self.max_age
    }

    /// The request headers associated with this request.
    pub fn request_headers(&self) -> &HeaderMap {
        &self.request_headers
    }

    /// The vary rule associated with this request.
    pub fn vary_rule(&self) -> &VaryRule {
        &self.vary_rule
    }

    /// The variant rule associated with this request.
    pub fn variant(&self) -> Variant {
        self.vary_rule.variant(&self.request_headers)
    }
}

impl From<WriteOptions> for ObjectMeta {
    fn from(value: WriteOptions) -> Self {
        let inserted = Instant::now();
        let initial_age = value.initial_age.unwrap_or(Duration::ZERO);
        let WriteOptions {
            request_headers,
            vary_rule,
            max_age,
            ..
        } = value;
        ObjectMeta {
            inserted,
            initial_age,
            max_age,
            request_headers,
            vary_rule,
        }
    }
}

/// Object(s) indexed by a CacheKey.
#[derive(Default)]
pub struct CacheKeyObjects(Mutex<CacheKeyObjectsInner>);

impl CacheKeyObjects {
    /// Get the applicable CacheData, if available.
    ///
    // TODO: cceckman-at-fastly 2025-02-26:
    // Implement vary_by here
    pub fn get(&self, request_headers: &HeaderMap) -> Option<Arc<CacheData>> {
        let key_objects = self.0.lock().expect("failed to lock CacheKeyObjects");

        for vary_rule in key_objects.vary_rules.iter() {
            let response_key = vary_rule.variant(request_headers);
            if let Some(object) = key_objects.objects.get(&response_key) {
                let lock = object.inner.lock().unwrap();
                match &lock.transactional {
                    TransactionState::Present(v) => return Some(Arc::clone(v)),
                    _ => continue,
                }
            }
        }
        None
    }

    // TODO: cceckman-at-fastly,
    // get_or_obligate, for transactional API

    /// Insert into the given CacheData.
    pub fn insert(&self, options: WriteOptions, body: Body) {
        let meta: ObjectMeta = options.into();

        let mut cache_key_objects = self.0.lock().expect("failed to lock CacheKeyObjects");
        if !cache_key_objects.vary_rules.contains(meta.vary_rule()) {
            // Insert at the front, run through the rules in order, so we tend towards fresher
            // responses.
            cache_key_objects
                .vary_rules
                .push_front(meta.vary_rule().clone());
        }

        let body = CollectingBody::new(body);
        let variant = meta.variant();
        let object = Arc::new(CacheData { body, meta });

        let entry = cache_key_objects.objects.entry(variant).or_default();
        let mut response_object = entry.inner.lock().unwrap();
        response_object.transactional = TransactionState::Present(object);
        response_object.generation += 1;

        // TODO: cceckman-at-fastly:
        // When implementing transactional API, notify waiters.
    }
}

#[derive(Default)]
struct CacheKeyObjectsInner {
    /// All the vary rules that might apply.
    /// Most-recent at the front, so we tend towards fresher responses.
    vary_rules: VecDeque<VaryRule>,
    objects: HashMap<Variant, Arc<CacheValue>>,
}

/// Fully-indexed cache value, including request and response keys.
#[derive(Default)]
struct CacheValue {
    inner: Mutex<CacheValueInner>,
}

#[derive(Default)]
struct CacheValueInner {
    /// Generation ID for this response-key'd object.
    ///
    /// We hold on to a generation ID so that if an obligation is dropped-
    /// e.g. a session terminates without completing a GoGet-
    /// we can go from Obligated -> Missing *if* nothing else has filled it
    /// in the mean time.
    /// We don't want to go from Present -> Missing on a GoGet::drop,
    /// e.g. if a non-transactional insert has raced.
    ///
    /// Note: this _can_ reset upon eviction from the cache,
    /// but that will result in a new object. If you're dealing with a CacheValueInner, hold on to
    /// your Arc!
    generation: usize,
    transactional: TransactionState,
}

/// The current state of this CacheValue.
#[derive(Default)]
enum TransactionState {
    /// No data, no obligation to fetch
    #[default]
    Missing,
    /// The metadata is present in the cache; the content is available, possibly only as streaming
    /// content.
    Present(Arc<CacheData>),
}

/// The data stored in cache for a metadata-complete entry.
#[derive(Debug)]
pub(crate) struct CacheData {
    // TODO: cceckman-at-fastly
    // - surrogate keys
    meta: ObjectMeta,
    body: CollectingBody,
}

impl CacheData {
    /// Get a Body to read the cached object with.
    pub(crate) fn get_body(&self) -> Result<Body, Error> {
        self.body.read()
    }

    /// Access to object's metadata
    pub(crate) fn get_meta(&self) -> &ObjectMeta {
        &self.meta
    }
}
