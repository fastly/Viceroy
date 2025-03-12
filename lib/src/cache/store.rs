//! Data structures & implementation details for the Viceroy cache.

use std::sync::{Arc, Mutex};

use crate::{body::Body, collecting_body::CollectingBody, Error};

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
    pub fn insert(&self, body: Body) {
        let key_objects = self.0.lock().expect("failed to lock CacheKeyObjects");
        let mut response_object = key_objects
            .object
            .inner
            .lock()
            .expect("failed to lock ResponseKeyObjects");
        let body = CollectingBody::new(body);
        response_object.transactional = TransactionState::Present(Arc::new(CacheData { body }));
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
    // - age; use to compute Expiry
    // - response headers
    // - surrogate keys
    body: CollectingBody,
}

impl CacheData {
    /// Get a Body to read the cached object with.
    pub(crate) fn get_body(&self) -> Result<Body, Error> {
        self.body.read()
    }
}
