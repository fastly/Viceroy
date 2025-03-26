//! Data structures & implementation details for the Viceroy cache.

use crate::cache::variance::VaryRule;
use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::watch;

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
        self.inserted.elapsed() + self.initial_age
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

impl ObjectMeta {
    fn new(value: WriteOptions, request_headers: HeaderMap) -> Self {
        let inserted = Instant::now();
        let WriteOptions {
            vary_rule,
            max_age,
            initial_age,
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
pub struct CacheKeyObjects(watch::Sender<CacheKeyObjectsInner>);

impl CacheKeyObjects {
    /// Get the applicable CacheData, if available.
    pub fn get(&self, request_headers: &HeaderMap) -> Option<Arc<CacheData>> {
        let key_objects = self.0.borrow();

        for vary_rule in key_objects.vary_rules.iter() {
            let response_key = vary_rule.variant(request_headers);
            if let Some(object) = key_objects.objects.get(&response_key) {
                match &object.transactional {
                    TransactionState::Present(v) => return Some(Arc::clone(v)),
                    _ => continue,
                }
            }
        }
        None
    }

    /// Perform a transactional lookup-or-obligate:
    /// - If an appropriate response is already available, return that response (Ok)
    /// - If no task is currently fetching an appropriate response, return an obligation to fetch
    ///     (Err)
    /// - Otherwise, await the completion of an appropriate response, possibly obligating ourselves
    ///     to fetch in the future if no active task winds up fetching something appropriate.
    pub async fn transaction_get_or_obligate(
        self: Arc<Self>,
        request_headers: &HeaderMap,
    ) -> Result<Arc<CacheData>, Obligation> {
        let mut sub = self.0.subscribe();

        // We may be waked by inappropriate responses multiple times. Stay in the loop until we get
        // an obligation or we get what we want.
        loop {
            let key_objects = sub.borrow_and_update();
            let mut present = Vec::new();
            let mut waiting = 0;

            let response_keys: Vec<_> = key_objects
                .vary_rules
                .iter()
                .map(|v| v.variant(request_headers))
                .collect();
            for response_key in &response_keys {
                if let Some(object) = key_objects.objects.get(&response_key) {
                    match &object.transactional {
                        TransactionState::Present(v) => present.push(Arc::clone(v)),
                        TransactionState::Pending => waiting += 1,
                    }
                }
            }

            // TODO: cceckman-at-fastly: Here and in get(), prioritize based on staleness and
            // stale-while-revalidate ("remaining TTL", perhaps?)
            // Something to deal with alon with stale-while-revalidate.
            if let Some(v) = present.into_iter().next() {
                // We have a result in cache.
                return Ok(v);
            }

            // We'll either need to wait for changed() or take the write lockc;
            // either way, we don't need the read lock any more.
            std::mem::drop(key_objects);
            if waiting > 0 {
                // There is a request in-flight that will likely fulfill our request.
                // Wait for it, then retry.
                let _ = sub.changed().await;
                continue;
            }

            // There's nothing acceptable in cache, and there's no one going out to fetch it.
            // If you want something cached right, you have to fetch it yourself.
            let mut obligated: Option<Obligation> = None;
            self.0.send_if_modified(|key_objects| {
                // Now under the write lock. This wasn't a "promotion", though, so we have to scan
                // again.
                let response_keys: Vec<_> = key_objects
                    .vary_rules
                    .iter()
                    .map(|v| v.variant(request_headers))
                    .collect();
                // Early-exit if we find a match; return to the read-locked portion at the top.
                for response_key in &response_keys {
                    if let Some(object) = key_objects.objects.get(&response_key) {
                        match &object.transactional {
                            TransactionState::Present(_) => return false,
                            TransactionState::Pending => return false,
                        }
                    }
                }
                // Obligate ourselves to perform a fetch.
                let response_key = match response_keys.into_iter().next() {
                    Some(v) => v,
                    None => {
                        // Ensure there's a blank vary rule to catch the Pending we're about to make.
                        // If the actual response comes back with a Vary:, that's fine-
                        // we'll only insert a Present response into the objects table if the *response*
                        // has an empty vary rule.
                        key_objects.vary_rules.push_front(VaryRule::default());
                        VaryRule::default().variant(request_headers)
                    }
                };
                let pending = Arc::new(CacheValue {
                    transactional: TransactionState::Pending,
                });
                key_objects.objects.insert(response_key.clone(), pending);
                obligated = Some(Obligation {
                    object: Arc::clone(&self),
                    variant: response_key,
                });

                // Even though we have modified the table, we don't need to issue a notification.
                // All waiters are waiting on *completion* of a fetch, not on the *obligation* of
                // one-- so, we return 'false' here to avoid the spurious wakeup.
                return false;
            });

            // Now outside of the lock:
            match obligated {
                // We are obliged to perform a fetch. Return that to the caller, for them to
                // perform.
                Some(v) => return Err(v),
                // Or, someone beat us to the punch: they inserted or obliged in between our read
                // and write phases. That's fine; loop around again into a read phase.
                None => continue,
            }
        }
    }

    /// Insert into the given CacheData.
    pub fn insert(&self, request_headers: HeaderMap, options: WriteOptions, body: Body) {
        let meta = ObjectMeta::new(options, request_headers);

        self.0.send_modify(|cache_key_objects| {
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
            let value = Arc::new(CacheValue {
                transactional: TransactionState::Present(object),
            });

            cache_key_objects.objects.insert(variant, value);
        });
    }
}

#[derive(Default)]
struct CacheKeyObjectsInner {
    /// All the vary rules that might apply.
    /// Most-recent at the front, so we tend towards fresher responses.
    vary_rules: VecDeque<VaryRule>,

    /// The variants that may be served.
    /// Each CacheValue may have its headers complete (completed or streaming body),
    /// or may represent a task with an Obligation to fetch the corresponding object.
    //
    // INVARIANT: There is exactly one Obligation for each TransactionState::Pending.
    // There may be an Obligation without a corresponding TransactionState::Pending
    // (if the Obligation has been fulfilled).
    objects: HashMap<Variant, Arc<CacheValue>>,
}

/// Fully-indexed cache value, including request and response keys.
#[derive(Debug)]
struct CacheValue {
    transactional: TransactionState,
}

/// The current state of this CacheValue.
#[derive(Debug)]
enum TransactionState {
    /// The metadata is present in the cache; the content is available, possibly only as streaming
    /// content.
    Present(Arc<CacheData>),
    /// Some task has taken the obligation to perform a request that will *likely* use this
    /// response key.
    Pending,
}

/// An obligation to fetch & update the cache.
struct Obligation {
    object: Arc<CacheKeyObjects>,
    variant: Variant,
}

impl Drop for Obligation {
    fn drop(&mut self) {
        // INVARIANT: There is exactly one Obligation for each TransactionState::Pending.
        //
        // To maintain this, when the Obligation is dropped, we need to check the TransactionState
        // and clear the entry iff it is Pending.
        // Per the above invariant, this is the only Obligation that can clear that Pending.
        self.object.0.send_if_modified(|key_objects| {
            if let Some(v) = key_objects.objects.get(&self.variant) {
                if let TransactionState::Pending = v.transactional {
                    key_objects.objects.remove(&self.variant);
                    // We did actually perform a modification;
                    // notify waiters, so that another one can generate an Obligation.
                    return true;
                }
            }
            // Either the Obligation was fulfilled (TransactionState::Present)
            // or the entry was deleted (??).
            // Either way, we didn't modify anything, so we don't need to wake any waiters.
            return false;
        });
    }
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
