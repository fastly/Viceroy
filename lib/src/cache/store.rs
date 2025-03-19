//! Data structures & implementation details for the Viceroy cache.

use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use crate::{body::Body, collecting_body::CollectingBody, Error};

use super::WriteOptions;

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
    // TODO: cceckman-at-fastly: for future work!
    /*
    stale_while_revalidate_until: Option<Instant>,
    edge_ok_until: Option<Instant>,

    request_headers: Option<HeaderMap>,
    vary_rule: Option<VaryRule>,
    surrogate_keys: HashSet<String>,
    length: Option<usize>,
    user_metadata: Option<Bytes>,
    sensitive_data: Option<bool>,
    */
}

impl ObjectMeta {
    /// Create a new ObjectMeta.
    pub fn new(max_age: Duration) -> Self {
        ObjectMeta {
            inserted: Instant::now(),
            initial_age: Duration::ZERO,
            max_age,
        }
    }

    /// Assign an initial age to the object.
    pub fn with_initial_age(self, initial_age: Duration) -> Self {
        ObjectMeta {
            initial_age,
            ..self
        }
    }

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
}

impl From<WriteOptions> for ObjectMeta {
    fn from(value: WriteOptions) -> Self {
        ObjectMeta::new(value.max_age).with_initial_age(value.initial_age.unwrap_or(Duration::ZERO))
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
    pub fn get(&self) -> Option<Arc<CacheData>> {
        let key_objects = self.0.lock().expect("failed to lock CacheKeyObjects");
        let response_object = key_objects
            .object
            .inner
            .lock()
            .expect("failed to lock ResponseKeyObjects");
        match &response_object.transactional {
            TransactionState::Present(v) => Some(Arc::clone(v)),
            _ => None,
        }
    }

    // TODO: cceckman-at-fastly 2025-02-26:
    // get_or_obligate

    /// Insert into the given CacheData.
    // TODO: cceckman-at-fastly:
    // Implement vary_by here
    pub fn insert(&self, options: WriteOptions, body: Body) {
        let key_objects = self.0.lock().expect("failed to lock CacheKeyObjects");
        let mut response_object = key_objects
            .object
            .inner
            .lock()
            .expect("failed to lock ResponseKeyObjects");
        let meta = options.into();
        let body = CollectingBody::new(body);
        response_object.transactional =
            TransactionState::Present(Arc::new(CacheData { body, meta }));
        response_object.generation += 1;

        // TODO: cceckman-at-fastly, 2025-02-26:
        // Claim waiters for future notification.
    }
}

#[derive(Default)]
struct CacheKeyObjectsInner {
    // TODO: cceckman-at-fastly, 2025-02-26:
    // - multiple inner objects, to vary_by
    // - vary rules
    object: Arc<CacheValue>,
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
    // - vary rule
    // - response headers
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
