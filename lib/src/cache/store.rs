//! Data structures & implementation details for the Viceroy cache.

use crate::cache::variance::VaryRule;
use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::watch;

use http::HeaderMap;

use crate::{body::Body, collecting_body::CollectingBody};

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
#[derive(Debug, Default)]
pub struct CacheKeyObjects(watch::Sender<CacheKeyObjectsInner>);

impl CacheKeyObjects {
    /// Get the applicable CacheData, if available.
    pub fn get(&self, request_headers: &HeaderMap) -> Option<Arc<CacheData>> {
        let key_objects = self.0.borrow();

        for vary_rule in key_objects.vary_rules.iter() {
            let response_key = vary_rule.variant(request_headers);
            if let Some(object) = key_objects
                .objects
                .get(&response_key)
                .and_then(|v| v.present.clone())
            {
                return Some(object);
            }
        }
        None
    }

    /// Perform a transactional lookup.
    ///
    /// Returns a CacheData if existing data were found (even if stale),
    /// and returns an Obligaton if the data need to be freshened.
    ///
    /// If !ok_to_wait, returns a result immediately, without waiting for outstanding Obligations
    /// to complete.
    /// If ok_to_wait, this may await another task to complete or abandon its Obligation.
    pub async fn transaction_get(
        self: &Arc<Self>,
        request_headers: &HeaderMap,
        ok_to_wait: bool,
    ) -> (Option<Arc<CacheData>>, Option<Obligation>) {
        let mut sub = self.0.subscribe();

        loop {
            // We set this flag if we find an obligation that we can wait on,
            // i.e. whose vary rule matches our request headers.
            // Note that if we find a completed request while computing this value,
            // we return immediately.
            let mut awaitable = false;
            {
                // The read-locked portion.
                // Note, this returns only fresh responses.
                let key_objects = sub.borrow_and_update();

                let response_values = key_objects
                    .vary_rules
                    .iter()
                    .map(|v| v.variant(request_headers))
                    .filter_map(|key| key_objects.objects.get(&key));
                for cache_value in response_values {
                    if let Some(data) = &cache_value.present {
                        if data.meta.is_fresh() {
                            // We have fresh data; no need to generate an obligaton.
                            return (Some(Arc::clone(data)), None);
                        }
                    }
                    awaitable = awaitable || cache_value.obligated;
                }
            }
            // Done computing awaitable, make it read-only:
            let awaitable = awaitable;

            // TODO: cceckman-at-fastly: Stale-while-revalidate is slightly subtle, here.
            // If one of the entries above was within the SWR period *and* had an obligation,
            // we could go ahead and return it without generating an obligation.
            // However, we have to proceed to the write lock to produce an obligation.
            // So, expect some change to the above control flow in the SWR implementation.

            // If we found an acceptable in-progress request while under the read lock,
            // we can await. The subscription ensures that, even though we're
            // "waiting outside of the lock", we'll still see the updated version.
            if awaitable && ok_to_wait {
                let _ = sub.changed().await;
                continue;
            }

            // There's nothing fresh in the cache, and no obligation we can wait on.
            // Take the write lock with the intention of generating our own obligation.
            let mut obligated: Option<Obligation> = None;
            let mut data: Option<Arc<CacheData>> = None;
            // Note that, even if this does modify the data table, we don't generate a
            // notification: no task "waits" on a new obligation appearing, only on obligations
            // being fulfilled.
            self.0.send_if_modified(|key_objects| {
                // Now under the write lock.
                // We might have a stale result, or someone else might have an obligaton;
                // pick the best we can.
                let response_keys: Vec<_> = key_objects
                    .vary_rules
                    .iter()
                    .map(|v| v.variant(request_headers))
                    .collect();
                // These are the existing cache entries that would be valid for this request,
                // taking into account vary rules.
                // They may be stale or not-yet-filled (i.e. obligation-only); let's see what we
                // can get out of them.
                let response_keyed_objects: Vec<_> = response_keys
                    .iter()
                    .filter_map(|v| key_objects.objects.get(v))
                    .collect();

                // First, if we have fresh data, we can immediately short-circuit.
                if let Some(fresh) = response_keyed_objects
                    .iter()
                    .filter_map(|cache_value| cache_value.present.as_ref())
                    .filter(|cache_data| cache_data.meta.is_fresh())
                    .next()
                {
                    data = Some(Arc::clone(fresh));
                    // We have fresh data
                    return false;
                }

                // TODO: cceckman-at-fastly: stale-while-revalidate:
                // In a second pass over response_keyed_objects, we should check for stale data
                // that can be revalidated, and return it- generating an obligation specifically
                // for the key returned if we do so.
                // For now, we just check if there's an existing obligation in any of them.

                // Second, if we raced to produce an obligation, defer in favor of the existing
                // obligation, without generating a new one.
                if response_keyed_objects.iter().any(|data| data.obligated) {
                    return false;
                }

                // Finally, generate an obligation based on the most recent vary rule
                // (or an empty default if there have been no vary rules so far.
                let response_key = response_keys.into_iter().next().unwrap_or_else(|| {
                    key_objects.vary_rules.push_front(VaryRule::default());
                    VaryRule::default().variant(request_headers)
                });
                let pending = CacheValue {
                    obligated: true,
                    present: None,
                };
                key_objects.objects.insert(response_key.clone(), pending);
                obligated = Some(Obligation {
                    object: Arc::clone(&self),
                    variant: response_key,
                    request_headers: request_headers.clone(),
                    completed: false,
                });

                // TODO: If there is a stale-while-revalidate result above, include it as well.

                // We have modified the table. In theory we don't need to issue a notification,
                // since any task waiting would be waiting on the *completion* of an obligation
                // rather than the fulfillment.
                return false;
            });

            // Now outside of the lock: return what we have.
            if data.is_some() || obligated.is_some() || !ok_to_wait {
                return (data, obligated);
            }

            // Return back to the top of the loop: look for the obligation we missed in the first
            // read pass.
        }
    }

    /// Insert into the corresponding entry.
    ///
    /// If a clear_obligation is provided, clear the "obligated" bit on that Variant in the same
    /// transaction (so there's only one wakeup). Note the clear_obligation variant may differ from
    /// the variant inserted: we place the obligation marker based on the _existing_ Vary rules,
    /// but we insert based on the Vary rule received in the response.
    pub fn insert(
        &self,
        request_headers: HeaderMap,
        options: WriteOptions,
        body: Body,
        clear_obligation: Option<Variant>,
    ) {
        let meta = ObjectMeta::new(options, request_headers);

        self.0.send_modify(|cache_key_objects| {
            if let Some(clear_obligation) = clear_obligation {
                if let Some(v) = cache_key_objects.objects.get_mut(&clear_obligation) {
                    v.obligated = false;
                }
            }

            // Update the position of the vary rule: this is the most-recent-inserted, so keep it at the front.
            let vary_rule = if let Some((i, _)) = cache_key_objects
                .vary_rules
                .iter()
                .enumerate()
                .find(|&(_, rule)| rule == &meta.vary_rule)
            {
                cache_key_objects
                    .vary_rules
                    .remove(i)
                    .expect("index of a found item must be a valid index")
            } else {
                meta.vary_rule.clone()
            };
            cache_key_objects.vary_rules.push_front(vary_rule);

            let variant = meta.variant();
            let body = CollectingBody::new(body);
            let object = Arc::new(CacheData { body, meta });

            cache_key_objects
                .objects
                .entry(variant)
                .or_default()
                .present = Some(object);
        });
    }
}

#[derive(Debug, Default)]
struct CacheKeyObjectsInner {
    /// All the vary rules that might apply.
    /// Most-recent at the front, so we tend towards fresher responses.
    vary_rules: VecDeque<VaryRule>,

    /// The variants that may be served.
    /// Each CacheValue may have its headers complete (completed or streaming body),
    /// or may represent a task with an Obligation to fetch the corresponding object.
    //
    // INVARIANT: There is exactly one Obligation for each CacheValue::obligated.
    objects: HashMap<Variant, CacheValue>,
}

/// Fully-indexed cache value, keyed by request (e.g. URL) and response (vary).
///
/// - Present but not obligated: e.g. fetched and fresh, stale and waiting an update
/// - Present and obligated: e.g. stale, with a pending update
/// - Obligated but not present: e.g. first fetch is transactional
/// - Neither present nor obligated: e.g. transactional fetch was not completed
#[derive(Debug, Default)]
struct CacheValue {
    /// If this entry has been filled, the most recent data that has been inserted.
    present: Option<Arc<CacheData>>,

    /// Whether there is an outstanding Obligation to freshen this entry.
    obligated: bool,
}

/// An obligation to fetch & update the cache.
#[derive(Debug)]
pub struct Obligation {
    object: Arc<CacheKeyObjects>,
    request_headers: HeaderMap,
    variant: Variant,
    completed: bool,
}

impl Obligation {
    /// Fulfill the obligation by providing write options and a body.
    pub fn complete(mut self, options: WriteOptions, body: Body) {
        let request_headers = std::mem::take(&mut self.request_headers);
        let variant = std::mem::take(&mut self.variant);
        self.object
            .insert(request_headers, options, body, Some(variant));
        // Mild optimization: avoid re-acquiring the lock when we drop.
        // We've already cleared the obligation flag.
        self.completed = true;
    }
}

impl Drop for Obligation {
    fn drop(&mut self) {
        if self.completed {
            // Obligation was already completed.
            // Don't bother acquiring the notifier's lock.
            return;
        }
        // Obligation was dropped without being completed.
        // Remove our tracking bit from the map, along with a notification.
        self.object.0.send_if_modified(|key_objects| {
            if let Some(v) = key_objects.objects.get_mut(&self.variant) {
                v.obligated = false;
                return true;
            }
            // Something odd happened -- our variant is no longer in the map.
            // In this case, we didn't change anything, so avoid a spurious wakeup.
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
    pub(crate) fn get_body(&self) -> Result<Body, crate::Error> {
        self.body.read()
    }

    /// Access to object's metadata
    pub(crate) fn get_meta(&self) -> &ObjectMeta {
        &self.meta
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use bytes::Bytes;
    use http::{HeaderMap, HeaderName};

    use crate::{
        body::{Body, Chunk},
        cache::{VaryRule, WriteOptions},
    };

    use super::CacheKeyObjects;

    #[tokio::test]
    async fn single_obligation() {
        let objects = Arc::new(CacheKeyObjects::default());

        let mut set = tokio::task::JoinSet::new();
        for _ in 0..4 {
            set.spawn({
                let ko = Arc::clone(&objects);

                async move {
                    let (found, obligation) = ko.transaction_get(&HeaderMap::default(), true).await;
                    // Either have the obligation to fetch, or was blocked until the obligation
                    // completed.
                    assert!(found.is_some() != obligation.is_some());

                    if let Some(obligation) = obligation {
                        let body: Body = "hello".as_bytes().into();
                        obligation.complete(WriteOptions::new(Duration::from_secs(100)), body);
                    }
                    if let Some(found) = found {
                        let body = found.body.read().unwrap().read_into_string().await.unwrap();
                        assert_eq!(&body, "hello");
                    }
                }
            });
        }
        let _ = set.join_all().await;
        assert!(objects.get(&HeaderMap::default()).is_some())
    }

    #[tokio::test]
    async fn test_obligaton_when_stale() {
        let objects = Arc::new(CacheKeyObjects::default());
        let body: Body = "hello".as_bytes().into();

        objects.insert(
            HeaderMap::default(),
            WriteOptions::new(Duration::ZERO),
            body,
            None,
        );
        let (_, obligation) = objects.transaction_get(&HeaderMap::default(), true).await;
        // TODO: stale-while-revalidate: check that the stale data are provided
        assert!(obligation.is_some());
    }

    #[tokio::test]
    async fn obligation_by_vary_key() {
        let objects = Arc::new(CacheKeyObjects::default());
        let make_body = |s: &str| s.as_bytes().into();

        let header_name = HeaderName::from_static("x-fastly-test");

        let vary = VaryRule::new([&header_name].into_iter());
        let h1: HeaderMap = [(header_name.clone(), "assert".try_into().unwrap())]
            .into_iter()
            .collect();
        let h2: HeaderMap = [(header_name.clone(), "assume".try_into().unwrap())]
            .into_iter()
            .collect();
        let h3: HeaderMap = [(header_name.clone(), "verify".try_into().unwrap())]
            .into_iter()
            .collect();

        objects.insert(
            h3,
            WriteOptions {
                max_age: Duration::from_secs(100),
                initial_age: Duration::ZERO,
                vary_rule: vary.clone(),
            },
            make_body(""),
            None,
        );
        let (found1, obligation1) = objects.transaction_get(&h1, true).await;
        assert!(found1.is_none());
        assert!(obligation1.is_some());
        let (found2, obligation2) = objects.transaction_get(&h2, true).await;
        assert!(found2.is_none());
        assert!(obligation2.is_some());

        // Anotehr transaction on the same headers should pick up the same result:
        let busy1 = objects.transaction_get(&h1, true);
        let busy2 = objects.transaction_get(&h2, true);
        obligation2.unwrap().complete(
            WriteOptions {
                vary_rule: vary.clone(),
                max_age: Duration::from_secs(100),
                ..Default::default()
            },
            make_body("object 2"),
        );
        obligation1.unwrap().complete(
            WriteOptions {
                vary_rule: vary.clone(),
                max_age: Duration::from_secs(100),
                ..Default::default()
            },
            make_body("object 1"),
        );
        if let (Some(found), None) = busy1.await {
            let s = found.get_body().unwrap().read_into_string().await.unwrap();
            assert_eq!(&s, "object 1");
        } else {
            panic!("expected to block on object 1")
        }
        if let (Some(found), None) = busy2.await {
            let s = found.get_body().unwrap().read_into_string().await.unwrap();
            assert_eq!(&s, "object 2");
        } else {
            panic!("expected to block on object 2")
        }
    }

    #[tokio::test]
    async fn modified_vary() {
        let objects = Arc::new(CacheKeyObjects::default());
        let make_body = |s: &str| s.as_bytes().into();

        let header_name = HeaderName::from_static("x-fastly-test");
        let h1: HeaderMap = [(header_name.clone(), "assert".try_into().unwrap())]
            .into_iter()
            .collect();
        let h2: HeaderMap = [(header_name.clone(), "assume".try_into().unwrap())]
            .into_iter()
            .collect();
        let vary = VaryRule::new([&header_name].into_iter());

        // No vary known in the original request:
        let (found1, obligation1) = objects.transaction_get(&h1, true).await;
        assert!(found1.is_none());
        let obligation1 = obligation1.unwrap();
        obligation1.complete(
            WriteOptions {
                max_age: Duration::from_secs(100),
                vary_rule: vary.clone(),
                ..Default::default()
            },
            make_body("object 1"),
        );

        // A second query with the same headers should match:
        assert!(objects.get(&h1).is_some());

        // But not with different headers:
        let (found2, obligaton2) = objects.transaction_get(&h2, true).await;
        assert!(found2.is_none());
        assert!(obligaton2.is_some());
    }

    #[tokio::test]
    async fn drop_obligation() {
        let ko = Arc::new(CacheKeyObjects::default());
        let empty_headers = HeaderMap::default();

        let (_not_found, obligation1) = ko.transaction_get(&empty_headers, true).await;
        assert!(obligation1.is_some());
        // This future won't resolve yet, while the obligation is outstanding:
        let busy2 = ko.transaction_get(&empty_headers, true);
        // But once we drop the first obligation...
        std::mem::drop(obligation1);
        // ... we should pick up another:
        let (found2, obligation2) = busy2.await;
        assert!(obligation2.is_some());
        assert!(found2.is_none());
    }

    #[tokio::test]
    async fn immediate_with_no_results() {
        // The "immediate" invocation should return without blocking on obligations completing.
        let ko = Arc::new(CacheKeyObjects::default());
        let empty_headers = HeaderMap::default();

        let (None, Some(obligation)) = ko.transaction_get(&empty_headers, false).await else {
            panic!("unexpected value")
        };

        // This should resolve immediately, even though there's an outstanding obligation:
        let (not_found, not_obligated) = ko.transaction_get(&empty_headers, false).await;
        assert!(not_found.is_none());
        assert!(not_obligated.is_none());

        let c: Chunk = Bytes::new().into();
        let b: Body = c.into();
        obligation.complete(WriteOptions::new(Duration::from_secs(100)), b);
        let (Some(_), None) = ko.transaction_get(&empty_headers, false).await else {
            panic!("unexpected value")
        };
    }
}
