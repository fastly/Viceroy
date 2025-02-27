//! Data structures & implementation details for the Viceroy cache.

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use fastly_shared::FastlyStatus;

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
    // TODO: cceckman-at-fastly 2025-02-26:
    // Implement vary_by here
    pub fn insert(&self, body: Bytes) {
        let key_objects = self.0.lock().expect("failed to lock CacheKeyObjects");
        let mut response_object = key_objects
            .object
            .inner
            .lock()
            .expect("failed to lock ResponseKeyObjects");
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
    /// Some session is obligated to fetch;
    /// the predicted response key is this entry's key.
    Obligated,
    /// The metadata is present in the cache; the content is available, possibly only as streaming
    /// content.
    Present(Arc<CacheData>),
}

/// The data stored in cache for a metadata-complete entry.
pub(crate) struct CacheData {
    // TODO: cceckman-at-fastly 2025-02-26
    // - streaming body
    // - vary rule
    // - age; use to compute Expiry
    // - response headers
    // - surrogate keys
    pub(crate) body: Bytes,
}

#[cfg(test)]
impl CacheData {
    // TODO: cceckman-at-fastly: Testonly, until we have a more proper streaming body
    pub(crate) async fn collect_body(&self) -> Result<Bytes, FastlyStatus> {
        Ok(self.body.clone())
    }
}

impl std::fmt::Debug for CacheData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CacheData")
            .field("body", &format!("[{} bytes]", self.body.len()))
            .finish()
    }
}
