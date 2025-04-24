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
    /// Return a CacheData if existing data were found (even if stale),
    /// and return an Obligaton if the data need to be freshened.
    pub async fn transaction_get(
        self: &Arc<Self>,
        request_headers: &HeaderMap,
    ) -> (Option<Arc<CacheData>>, Option<Obligation>) {
        let mut sub = self.0.subscribe();

        loop {
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
            // TODO: cceckman-at-fastly: Stale-while-revalidate is slightly subtle, here.
            // If one of the entries above was within the SWR period *and* had an obligation,
            // we could go ahead and return it without generating an obligation.
            // However, we have to proceed to the write lock to produce an obligation.
            // So, expect some change to the above control flow in the SWR implementation.

            // If we found an acceptable in-progress request while under the read lock,
            // we can await. The subscription ensures that, even though we're
            // "waiting outside of the lock", we'll still see the updated version.
            if awaitable {
                let _ = sub.changed().await;
                continue;
            }

            // There's nothing fresh in the cache, and no obligation we can wait on.
            // Take the write lock with the intention of generating our own obligation.
            let mut obligated: Option<Obligation> = None;
            let mut data: Option<Arc<CacheData>> = None;
            self.0.send_if_modified(|key_objects| {
                // Now under the write lock.
                // We might have a stale result, or someone else might have an obligaton;
                // pick the best we can.
                let response_keys: Vec<_> = key_objects
                    .vary_rules
                    .iter()
                    .map(|v| v.variant(request_headers))
                    .collect();
                let response_keyed_objects: Vec<_> = response_keys
                    .iter()
                    .filter_map(|v| key_objects.objects.get(v))
                    .collect();
                // First, if we raced to produce an obligation, defer in favor of the other.
                if response_keyed_objects.iter().any(|data| data.obligated) {
                    return false;
                }

                // Done dealing with other obligations; now we just deal with results that we have.
                // Pick a fresh result if we now have it:
                // fresh or stale.
                if let Some(fresh) = response_keyed_objects
                    .into_iter()
                    .filter_map(|cache_value| cache_value.present.as_ref())
                    .filter(|cache_data| cache_data.meta.is_fresh())
                    .next()
                {
                    data = Some(Arc::clone(fresh));
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
            if data.is_some() || obligated.is_some() {
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
    /// the variant inserted.
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

            if !cache_key_objects.vary_rules.contains(meta.vary_rule()) {
                // Insert at the front, run through the rules in order, so we tend towards fresher
                // responses.
                cache_key_objects
                    .vary_rules
                    .push_front(meta.vary_rule().clone());
            }
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
        let mut request_headers = HeaderMap::default();
        let mut variant = Variant::default();
        std::mem::swap(&mut self.request_headers, &mut request_headers);
        std::mem::swap(&mut self.variant, &mut variant);
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

    use http::{HeaderMap, HeaderName};

    use crate::{
        body::Body,
        cache::{VaryRule, WriteOptions},
    };

    use super::CacheKeyObjects;

    #[tokio::test]
    async fn single_obligation() {
        let ko = Arc::new(CacheKeyObjects::default());

        let mut set = tokio::task::JoinSet::new();
        for _ in 0..4 {
            set.spawn({
                let ko = Arc::clone(&ko);

                async move {
                    let (found, obligation) = ko.transaction_get(&HeaderMap::default()).await;
                    // Either have the obligation to fetch, or was blocked until the obligation
                    // completed.
                    assert!(found.is_some() != obligation.is_some());

                    if let Some(o) = obligation {
                        let b: Body = "hello".as_bytes().into();
                        o.complete(WriteOptions::new(Duration::from_secs(100)), b);
                    }
                    if let Some(f) = found {
                        let body = f.body.read().unwrap().read_into_string().await.unwrap();
                        assert_eq!(&body, "hello");
                    }
                }
            });
        }
        let _ = set.join_all().await;
        assert!(ko.get(&HeaderMap::default()).is_some())
    }

    #[tokio::test]
    async fn test_obligaton_when_stale() {
        let ko = Arc::new(CacheKeyObjects::default());
        let body: Body = "hello".as_bytes().into();

        ko.insert(
            HeaderMap::default(),
            WriteOptions::new(Duration::ZERO),
            body,
            None,
        );
        let (_, obligation) = ko.transaction_get(&HeaderMap::default()).await;
        // TODO: stale-while-revalidate: check that the stale data are provided
        assert!(obligation.is_some());
    }

    #[tokio::test]
    async fn obligation_by_vary_key() {
        let ko = Arc::new(CacheKeyObjects::default());
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

        ko.insert(
            h3,
            WriteOptions {
                max_age: Duration::from_secs(100),
                initial_age: Duration::ZERO,
                vary_rule: vary.clone(),
            },
            make_body(""),
            None,
        );
        let (f1, o1) = ko.transaction_get(&h1).await;
        assert!(f1.is_none());
        assert!(o1.is_some());
        let (f2, o2) = ko.transaction_get(&h2).await;
        assert!(f2.is_none());
        assert!(o2.is_some());

        // Anotehr transaction on the same headers should pick up the same result:
        let fut1 = ko.transaction_get(&h1);
        let fut2 = ko.transaction_get(&h2);
        o2.unwrap().complete(
            WriteOptions {
                vary_rule: vary.clone(),
                max_age: Duration::from_secs(100),
                ..Default::default()
            },
            make_body("object 2"),
        );
        o1.unwrap().complete(
            WriteOptions {
                vary_rule: vary.clone(),
                max_age: Duration::from_secs(100),
                ..Default::default()
            },
            make_body("object 1"),
        );
        if let (Some(v), None) = fut1.await {
            let s = v.get_body().unwrap().read_into_string().await.unwrap();
            assert_eq!(&s, "object 1");
        } else {
            panic!("expected to block on object 1")
        }
        if let (Some(v), None) = fut2.await {
            let s = v.get_body().unwrap().read_into_string().await.unwrap();
            assert_eq!(&s, "object 2");
        } else {
            panic!("expected to block on object 2")
        }
    }

    #[tokio::test]
    async fn modified_vary() {
        let ko = Arc::new(CacheKeyObjects::default());
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
        let (f1, o1) = ko.transaction_get(&h1).await;
        assert!(f1.is_none());
        let o1 = o1.unwrap();
        o1.complete(
            WriteOptions {
                max_age: Duration::from_secs(100),
                vary_rule: vary.clone(),
                ..Default::default()
            },
            make_body("object 1"),
        );

        // A second query with the same headers should match:
        assert!(ko.get(&h1).is_some());

        // But not with different headers:
        let (f2, o2) = ko.transaction_get(&h2).await;
        assert!(f2.is_none());
        assert!(o2.is_some());
    }

    #[tokio::test]
    async fn drop_obligation() {
        let ko = Arc::new(CacheKeyObjects::default());
        let empty_headers = HeaderMap::default();

        let (_, o1) = ko.transaction_get(&empty_headers).await;
        assert!(o1.is_some());
        // This future won't resolve yet, while the obligation is outstanding:
        let fut = ko.transaction_get(&empty_headers);
        // But once we drop the first obligation...
        std::mem::drop(o1);
        // ... we should pick up another:
        let (f, o2) = fut.await;
        assert!(o2.is_some());
        assert!(f.is_none());
    }
}
