//! Data structures & implementation details for the Viceroy cache.

use crate::cache::{Error, variance::VaryRule};
use bytes::Bytes;
use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, Instant},
};
use tokio::sync::watch;

use http::HeaderMap;

use crate::{body::Body, collecting_body::CollectingBody};

use super::{Found, SurrogateKeySet, WriteOptions, variance::Variant};

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
    /// stale-while-revalidate period; after max_age.
    stale_while_revalidate: Duration,

    request_headers: HeaderMap,
    vary_rule: VaryRule,

    user_metadata: Bytes,

    length: Option<u64>,
    surrogate_keys: SurrogateKeySet,

    // Soft-purge bit: atomic so we don't have to wrap the whole thing in a lock.
    // This can only transition false -> true.
    soft_purge: AtomicBool,
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
        !self.soft_purge.load(std::sync::atomic::Ordering::SeqCst) && (self.age() < self.max_age)
    }

    /// Return true if the entry is usable even if stale.
    pub fn is_usable(&self) -> bool {
        self.age() < (self.max_age + self.stale_while_revalidate)
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

    pub fn user_metadata(&self) -> Bytes {
        self.user_metadata.clone()
    }
}

impl ObjectMeta {
    fn new(value: WriteOptions, request_headers: HeaderMap) -> Self {
        let inserted = Instant::now();
        let WriteOptions {
            vary_rule,
            max_age,
            initial_age,
            stale_while_revalidate,
            user_metadata,
            length,
            // There is no API that returns whether a cache entry has sensitive data.
            // Viceroy doesn't change any behavior w/rt sensitive data; so, we ignore it here.
            sensitive_data: _,
            // Similarly, edge_max_age has no effect and cannot be read.
            edge_max_age: _,
            surrogate_keys,
            ..
        } = value;
        ObjectMeta {
            inserted,
            initial_age,
            stale_while_revalidate,
            max_age,
            request_headers,
            vary_rule,
            user_metadata,
            length,
            surrogate_keys,
            soft_purge: AtomicBool::new(false),
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
                        if data.meta.is_usable() && cache_value.obligated {
                            // It's not fresh, but it's within SWR, and someone has already been
                            // obligated to freshen it.
                            // So we can go ahead and use the current data, without generating an
                            // obligation.
                            return (Some(Arc::clone(data)), None);
                        }
                    }
                    // Not usable, but if there's an obligation for it, we can wait on that
                    // obligation.
                    awaitable = awaitable || cache_value.obligated;
                }
            }
            // Done computing awaitable, make it read-only:
            let awaitable = awaitable;

            // If we found an acceptable in-progress request while under the read lock,
            // we can await. The subscription ensures that, even though we're
            // "waiting outside of the lock", we'll still see the updated version.
            if awaitable && ok_to_wait {
                let _ = sub.changed().await;
                continue;
            }

            // There's nothing usable in the cache, and no obligation we can wait on.
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
                    .filter_map(|k| key_objects.objects.get(k).map(|v| (k, v)))
                    .collect();

                // First, if we have fresh data, we can immediately short-circuit.
                if let Some(fresh) = response_keyed_objects
                    .iter()
                    .filter_map(|(_, cache_value)| cache_value.present.as_ref())
                    .filter(|cache_data| cache_data.meta.is_fresh())
                    .next()
                {
                    data = Some(Arc::clone(fresh));
                    // Return without modifying anything.
                    return false;
                }

                // If we have _stale but revalidatable_ entries, we can try to revalidate them
                // instead.
                if let Some((variant, revalidatable)) = response_keyed_objects
                    .iter()
                    .filter(|(_, cache_value)| {
                        cache_value
                            .present
                            .as_ref()
                            .is_some_and(|data| data.meta.is_usable())
                    })
                    .next()
                {
                    let d = revalidatable.present.as_ref().unwrap();
                    data = Some(Arc::clone(d));
                    // Already an obligation? We've captured the data to return, so we're done.
                    if revalidatable.obligated {
                        return false;
                    }
                    let variant = Variant::clone(variant);

                    key_objects.objects.insert(
                        variant.clone(),
                        CacheValue {
                            obligated: true,
                            present: Some(Arc::clone(d)),
                        },
                    );

                    obligated = Some(Obligation {
                        object: Arc::clone(&self),
                        variant,
                        request_headers: request_headers.clone(),
                        completed: false,
                        present: data.clone(),
                    });
                    // We did modify the state of things; be honest, return true.
                    // This may lead to an unnecessary wakeups and a small performance penalty; oh
                    // well.
                    return true;
                }

                // Nothing existing is usable, even with revalidation.
                // We'll do an insert (or wait for one).

                // We may have raced to produce an obligation to insert.
                // Defer in favor of the existing obligation, without generating a new one.
                if response_keyed_objects
                    .iter()
                    .any(|(_, value)| value.obligated)
                {
                    return false;
                }

                // Finally, generate an obligation to insert based on the most recent vary rule
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
                    present: None,
                });

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
    ///
    /// Returns the CacheData of the updated entry.
    pub fn insert(
        &self,
        request_headers: HeaderMap,
        options: WriteOptions,
        body: Body,
        clear_obligation: Option<Variant>,
    ) -> Arc<CacheData> {
        let meta = ObjectMeta::new(options, request_headers);
        let vary_rule = meta.vary_rule().clone();

        let variant = meta.variant();
        let body = CollectingBody::new(body, meta.length);
        let object = Arc::new(CacheData { body, meta });

        // We return the updated object as well
        let result = Arc::clone(&object);

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
                .find(|&(_, rule)| rule == &vary_rule)
            {
                cache_key_objects
                    .vary_rules
                    .remove(i)
                    .expect("index of a found item must be a valid index")
            } else {
                vary_rule
            };
            cache_key_objects.vary_rules.push_front(vary_rule);

            cache_key_objects
                .objects
                .entry(variant)
                .or_default()
                .present = Some(object);
        });

        result
    }

    /// Purge all variants associated with the given key.
    ///
    /// Returns the number of variants purged.
    pub fn purge(&self, key: &super::SurrogateKey, soft_purge: bool) -> usize {
        // This _shouldn't_ ever need a send- since we're only removing things, and only those
        // which don't have obligations.
        // But, we do it anyway, if we actually modified things.
        let mut count = 0;
        self.0.send_if_modified(|cache_key_objects| {
            cache_key_objects.objects = cache_key_objects
                .objects
                .drain()
                .filter_map(|(variant, value)| {
                    let Some(present) = value.present.as_ref() else {
                        // We may be considering an entry which is obligated, but not yet written.
                        // In this case, we don't know its surrogate keys, so we leave it in the
                        // set.
                        return Some((variant, value));
                    };

                    if !present.get_meta().surrogate_keys.0.contains(key) {
                        // Doesn't have this surrogate key; keep it.
                        return Some((variant, value));
                    }

                    // Purge or soft purge. Either way:
                    count += 1;

                    if soft_purge {
                        present
                            .meta
                            .soft_purge
                            .store(true, std::sync::atomic::Ordering::SeqCst);
                        Some((variant, value))
                    } else if value.obligated {
                        // This value has an outstanding obligation.
                        // We don't want to clobber that, otherwise the obligee will be Confused;
                        // So, keep the CacheValue but remove the "present".
                        Some((
                            variant,
                            CacheValue {
                                present: None,
                                obligated: true,
                            },
                        ))
                    } else {
                        // By failing to insert the CacheValue again, we purge the whole key.
                        // There's nothing to preserve.
                        None
                    }
                })
                .collect();

            // Notifications matter (only) to tasks waiting on an obligation,
            // if the obligation was fulfilled or abandoned.
            // We neither fulfilled nor abandoned any obligations, so we don't need to send
            // an unnecessary notification.
            false
        });
        count
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
    present: Option<Arc<CacheData>>,
    completed: bool,
}

impl Obligation {
    /// Fulfill the obligation by providing a new entire entry.
    ///
    /// Returns a Found for the entry inserted.
    pub fn insert(mut self, options: WriteOptions, body: Body) -> Found {
        let request_headers = std::mem::take(&mut self.request_headers);
        let variant = std::mem::take(&mut self.variant);
        let data = self
            .object
            .insert(request_headers, options, body, Some(variant));
        // Mild optimization: avoid re-acquiring the lock when we drop.
        // We've already cleared the obligation flag.
        self.completed = true;
        data.into()
    }

    /// Fulfill the obligation by freshening the existing entry.
    pub(super) async fn update(
        mut self,
        options: WriteOptions,
    ) -> Result<(), (Self, crate::Error)> {
        let Some(present) = &self.present else {
            return Err((self, Error::NotRevalidatable.into()));
        };
        let body = match present.body().build().await {
            Ok(body) => body,
            Err(e) => return Err((self, e)),
        };
        let request_headers = std::mem::take(&mut self.request_headers);
        let variant = std::mem::take(&mut self.variant);
        let _ = self
            .object
            .insert(request_headers, options, body, Some(variant));
        // Mild optimization: avoid re-acquiring the lock when we drop.
        // We've already cleared the obligation flag.
        self.completed = true;
        Ok(())
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
    meta: ObjectMeta,
    body: CollectingBody,
}

/// A holder for the get_body options.
pub struct GetBodyBuilder<'a> {
    cache_data: &'a CacheData,
    from: Option<u64>,
    to: Option<u64>,
    always_use_requested_range: bool,
}

impl GetBodyBuilder<'_> {
    /// Add range bounds to the body.
    ///
    /// If "from" is provided, "to" indicates an offset from the start of the cached item.
    /// If "to" is provided but not "from", "to" indicates an offset from the end of the cached
    /// item.
    pub fn with_range(self, from: Option<u64>, to: Option<u64>) -> Self {
        Self { from, to, ..self }
    }

    pub fn with_always_use_requested_range(self, always_use_requested_range: bool) -> Self {
        Self {
            always_use_requested_range,
            ..self
        }
    }
}

impl<'a> GetBodyBuilder<'a> {
    /// Access the body of this cached item.
    ///
    /// In some cases (streaming), the Future may not become ready until the first byte of output is available.
    pub fn build(self) -> impl Future<Output = Result<Body, crate::Error>> + use<'a> {
        async move {
            // Early "return whole body" cases:
            // "ignore requested range when length is unknown", the old default:
            let ignore_requested_range =
                !self.always_use_requested_range && self.cache_data.length().is_none();
            // No requested range provided:
            let no_range_provided = self.from.is_none() && self.to.is_none();
            // Known length and invalid range:
            let valid_range = match (self.cache_data.length(), self.from, self.to) {
                (None, _, _) => true,
                (Some(length), None, Some(to)) if !(1..=length).contains(&to) => false,
                (Some(length), Some(from), _) if !(0..length).contains(&from) => false,
                (Some(length), Some(from), Some(to)) if !(from..length).contains(&to) => false,
                _ => true,
            };

            // In each of these cases, we return the body immediately,
            // without waiting for any body to exist.
            if ignore_requested_range || no_range_provided || !valid_range {
                return self.cache_data.body.read();
            }

            // At least one of (start, end) is provided.

            let (start, end) = if let (None, Some(end)) = (self.from, self.to) {
                // We need to convert from "from the end" to "from the start".
                // To do that, we need a known or expected length.
                if self.cache_data.length().is_none() {
                    // We don't have an expected length; we have to wait for the end of input.
                    self.cache_data.body.known_length().await?;
                }

                let length = self
                    .cache_data
                    .length()
                    .expect("unknown length after waiting");
                if end > length {
                    // Asked for more bytes than are available.
                    // In the case of an invalid range, Compute returns the entire body
                    // (as in HTTP).
                    return self.cache_data.body.read();
                }
                // Convert to a (start, ...) sequence:
                (Some(length - end), None)
            } else {
                (self.from, self.to)
            };

            let start = start.unwrap_or(0);

            // If the length is not known up-front,
            // wait for the first byte to exist before returning a body.
            // Yes, this only applies when the length is unknown.
            if self.cache_data.length().is_none() {
                self.cache_data.body.wait_length(start + 1).await?;
            }

            // Convert from inclusive bounds (GetBodyBuilder) to exclusive (read_range),
            // and provide the body.
            self.cache_data
                .body
                .read_range(start, end.map(|end| end + 1))
        }
    }
}

impl CacheData {
    /// Get a Body to read the cached object with.
    pub(crate) fn body(&self) -> GetBodyBuilder<'_> {
        GetBodyBuilder {
            cache_data: self,
            from: None,
            to: None,
            always_use_requested_range: false,
        }
    }

    /// Access to object's metadata
    pub(crate) fn get_meta(&self) -> &ObjectMeta {
        &self.meta
    }

    /// Return the length of this object, if the final or expected length is known.
    pub fn length(&self) -> Option<u64> {
        self.body.length().or_else(|| self.meta.length)
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
                        obligation.insert(WriteOptions::new(Duration::from_secs(100)), body);
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
    async fn obligaton_when_stale() {
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
                vary_rule: vary.clone(),
                ..Default::default()
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

        // Another transaction on the same headers should pick up the same result:
        let busy1 = objects.transaction_get(&h1, true);
        let busy2 = objects.transaction_get(&h2, true);
        obligation2.unwrap().insert(
            WriteOptions {
                vary_rule: vary.clone(),
                max_age: Duration::from_secs(100),
                ..Default::default()
            },
            make_body("object 2"),
        );
        obligation1.unwrap().insert(
            WriteOptions {
                vary_rule: vary.clone(),
                max_age: Duration::from_secs(100),
                ..Default::default()
            },
            make_body("object 1"),
        );
        match busy1.await {
            (Some(found), None) => {
                let s = found
                    .body()
                    .build()
                    .await
                    .unwrap()
                    .read_into_string()
                    .await
                    .unwrap();
                assert_eq!(&s, "object 1");
            }
            _ => {
                panic!("expected to block on object 1")
            }
        }
        match busy2.await {
            (Some(found), None) => {
                let s = found
                    .body()
                    .build()
                    .await
                    .unwrap()
                    .read_into_string()
                    .await
                    .unwrap();
                assert_eq!(&s, "object 2");
            }
            _ => {
                panic!("expected to block on object 2")
            }
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
        obligation1.insert(
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
        obligation.insert(WriteOptions::new(Duration::from_secs(100)), b);
        let (Some(_), None) = ko.transaction_get(&empty_headers, false).await else {
            panic!("unexpected value")
        };
    }

    #[tokio::test]
    async fn returns_written_object() {
        let objects = Arc::new(CacheKeyObjects::default());
        let body: Body = "hello".as_bytes().into();

        let e = objects.insert(
            HeaderMap::default(),
            WriteOptions::new(Duration::ZERO),
            body,
            None,
        );

        let body = e.body().build().await.expect("can read completed body");
        let s = body
            .read_into_string()
            .await
            .expect("can collect completed body");
        assert_eq!(&s, "hello");
    }
}
