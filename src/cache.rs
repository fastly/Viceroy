use core::str;
use std::{collections::HashSet, sync::Arc, time::Duration};

use bytes::Bytes;
#[cfg(test)]
use proptest_derive::Arbitrary;

use crate::{
    body::Body,
    component::bindings::fastly::compute::types::Error as ComponentError,
    wiggle_abi::types::{BodyHandle, CacheOverrideTag, FastlyStatus},
};

use http::{HeaderMap, HeaderValue};

mod store;
mod variance;

use store::{CacheData, CacheKeyObjects, GetBodyBuilder, ObjectMeta, Obligation};
pub use variance::VaryRule;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("invalid key")]
    InvalidKey,

    #[error("handle is not writeable")]
    CannotWrite,

    #[error("no entry for key in cache")]
    Missing,

    #[error("invalid argument: {0}")]
    InvalidArgument(&'static str),

    #[error("cache entry's body is currently being read by another body")]
    HandleBodyUsed,

    #[error("cache entry is not revalidatable")]
    NotRevalidatable,
}

impl From<Error> for crate::Error {
    fn from(value: Error) -> Self {
        crate::Error::CacheError(value)
    }
}

impl From<&Error> for FastlyStatus {
    fn from(value: &Error) -> Self {
        match value {
            // TODO: cceckman-at-fastly: These may not correspond to the same errors as the compute
            // platform uses. Check!
            Error::InvalidKey => FastlyStatus::Inval,
            Error::InvalidArgument(_) => FastlyStatus::Inval,
            Error::CannotWrite => FastlyStatus::Badf,
            Error::Missing => FastlyStatus::None,
            Error::HandleBodyUsed => FastlyStatus::Badf,
            Error::NotRevalidatable => FastlyStatus::Badf,
        }
    }
}

impl From<Error> for ComponentError {
    fn from(value: Error) -> Self {
        match value {
            // TODO: cceckman-at-fastly: These may not correspond to the same errors as the compute
            // platform uses. Check!
            Error::InvalidKey => ComponentError::InvalidArgument,
            Error::InvalidArgument(_) => ComponentError::InvalidArgument,
            Error::CannotWrite => ComponentError::AuxiliaryError,
            Error::Missing => ComponentError::CannotRead,
            Error::HandleBodyUsed => ComponentError::AuxiliaryError,
            Error::NotRevalidatable => ComponentError::AuxiliaryError,
        }
    }
}

/// Primary cache key: an up-to-4KiB buffer.
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(test, derive(Arbitrary))]
pub struct CacheKey(
    #[cfg_attr(test, proptest(filter = "|f| f.len() <= CacheKey::MAX_LENGTH"))] Vec<u8>,
);

impl CacheKey {
    /// The maximum size of a cache key is 4KiB.
    pub const MAX_LENGTH: usize = 4096;
}

impl TryFrom<&Vec<u8>> for CacheKey {
    type Error = Error;

    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        value.as_slice().try_into()
    }
}

impl TryFrom<Vec<u8>> for CacheKey {
    type Error = Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() > Self::MAX_LENGTH {
            Err(Error::InvalidKey)
        } else {
            Ok(CacheKey(value))
        }
    }
}

impl TryFrom<&[u8]> for CacheKey {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() > CacheKey::MAX_LENGTH {
            Err(Error::InvalidKey)
        } else {
            Ok(CacheKey(value.to_owned()))
        }
    }
}

impl TryFrom<&str> for CacheKey {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.as_bytes().try_into()
    }
}

/// The result of a lookup: the object (if found), and/or an obligation to fetch.
#[derive(Debug)]
pub struct CacheEntry {
    key: CacheKey,
    found: Option<Found>,
    go_get: Option<Obligation>,

    /// Respect the range in body() even when the body length is not yet known.
    ///
    /// When a cached item is Found, the length of the cached item may or may not be known:
    /// if no expected length was provided and the body is still streaming, the length is unknown.
    ///
    /// When always_use_requested_range is false, and the length is unknown,
    /// body() returns the full body regardless of the requested range.
    /// When always_use_requested_range is true, and the length is unknown,
    /// body() blocks until the start of the range is available.
    always_use_requested_range: bool,
}

impl CacheEntry {
    /// Set the always_use_requested_range flag.
    /// This applies to all subsequent lookups from this CacheEntry or future entries derived from it.
    pub fn with_always_use_requested_range(self, always_use_requested_range: bool) -> Self {
        Self {
            always_use_requested_range,
            ..self
        }
    }

    /// Return a stub entry to hold in CacheBusy.
    pub fn stub(&self) -> CacheEntry {
        Self {
            key: self.key.clone(),
            found: None,
            go_get: None,
            always_use_requested_range: false,
        }
    }

    /// Returns the key used to generate this CacheEntry.
    pub fn key(&self) -> &CacheKey {
        &self.key
    }
    /// Returns the data found in the cache, if any was present.
    pub fn found(&self) -> Option<&Found> {
        self.found.as_ref()
    }

    /// Returns the data found in the cache, if any was present.
    pub fn found_mut(&mut self) -> Option<&mut Found> {
        self.found.as_mut()
    }

    /// Returns the obligation to fetch, if required
    pub fn go_get(&self) -> Option<&Obligation> {
        self.go_get.as_ref()
    }

    /// Ignore the obligation to fetch, if present.
    /// Returns true if it actually canceled an obligation.
    pub fn cancel(&mut self) -> bool {
        self.go_get.take().is_some()
    }

    /// Access the body of the cached item, if available.
    pub async fn body(&self, from: Option<u64>, to: Option<u64>) -> Result<Body, crate::Error> {
        let found = self
            .found
            .as_ref()
            .ok_or(crate::Error::CacheError(Error::Missing))?;
        found
            .get_body()
            .with_range(from, to)
            .with_always_use_requested_range(self.always_use_requested_range)
            .build()
            .await
    }

    /// Insert the provided body into the cache.
    ///
    /// Returns a CacheEntry where the new item is Found.
    pub fn insert(
        &mut self,
        options: WriteOptions,
        body: Body,
    ) -> Result<CacheEntry, crate::Error> {
        let go_get = self.go_get.take().ok_or(Error::NotRevalidatable)?;
        let found = go_get.insert(options, body);
        Ok(CacheEntry {
            key: self.key.clone(),
            found: Some(found),
            go_get: None,
            always_use_requested_range: self.always_use_requested_range,
        })
    }

    /// Freshen the existing cache item according to the new write options,
    /// without changing the body.
    pub async fn update(&mut self, options: WriteOptions) -> Result<(), crate::Error> {
        let go_get = self.go_get.take().ok_or(Error::NotRevalidatable)?;
        match go_get.update(options).await {
            Ok(()) => Ok(()),
            Err((go_get, err)) => {
                // On failure, preserve the obligation.
                self.go_get = Some(go_get);
                Err(err)
            }
        }
    }
}

/// How a `replace` operation coordinates with other writers of the same object.
///
/// See <https://docs.rs/fastly/latest/fastly/cache/core/enum.ReplaceStrategy.html>.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ReplaceStrategy {
    /// Read the existing object, if any, and leave it in place. The replacement is an ordinary
    /// last-writer-wins insert.
    #[default]
    Immediate,
    /// As `Immediate`, except that the existing object immediately stops being findable by lookups.
    ImmediateForceMiss,
    /// Wait for any in-flight write of this object to complete, then block other writers until this
    /// replace inserts its replacement (or is abandoned).
    Wait,
}

impl ReplaceStrategy {
    /// Convert from the representation used across the ABI boundary.
    ///
    /// Returns `None` if the value is not a recognized strategy.
    pub fn from_abi(value: u32) -> Option<Self> {
        match value {
            1 => Some(Self::Immediate),
            2 => Some(Self::ImmediateForceMiss),
            3 => Some(Self::Wait),
            _ => None,
        }
    }
}

/// An in-progress replace operation: the object currently in the cache (if any), plus the
/// permission to write a replacement for it.
#[derive(Debug)]
pub struct ReplaceEntry {
    key: CacheKey,

    /// The request headers the replace was begun with.
    ///
    /// Used to compute the variant of the replacement, unless the guest provides its own headers at
    /// insert time (which `Replace::header()` does).
    request_headers: HeaderMap,

    /// The object(s) under this cache key, for the insert path that doesn't hold an obligation.
    objects: Arc<CacheKeyObjects>,

    existing: Option<Found>,
    obligation: Option<Obligation>,

    /// See [`CacheEntry::always_use_requested_range`].
    always_use_requested_range: bool,
}

impl ReplaceEntry {
    /// Set the always_use_requested_range flag.
    pub fn with_always_use_requested_range(self, always_use_requested_range: bool) -> Self {
        Self {
            always_use_requested_range,
            ..self
        }
    }

    /// Returns the key used to begin this replace.
    pub fn key(&self) -> &CacheKey {
        &self.key
    }

    /// Returns the object that was in the cache when the replace began, if any.
    ///
    /// This object may be stale: `replace` returns whatever is present, and leaves it to the guest
    /// to decide what to do about freshness.
    pub fn existing(&self) -> Option<&Found> {
        self.existing.as_ref()
    }

    /// Returns the object that was in the cache when the replace began, if any.
    pub fn existing_mut(&mut self) -> Option<&mut Found> {
        self.existing.as_mut()
    }

    /// Access the body of the existing object, if there is one.
    pub async fn body(&self, from: Option<u64>, to: Option<u64>) -> Result<Body, crate::Error> {
        let existing = self
            .existing
            .as_ref()
            .ok_or(crate::Error::CacheError(Error::Missing))?;
        existing
            .get_body()
            .with_range(from, to)
            .with_always_use_requested_range(self.always_use_requested_range)
            .build()
            .await
    }

    /// Write the replacement object, consuming this replace operation.
    ///
    /// If `request_headers` is provided it replaces the headers the operation was begun with, for
    /// the purposes of computing the variant to insert under.
    pub fn insert(self, request_headers: Option<HeaderMap>, options: WriteOptions, body: Body) {
        let request_headers = request_headers.unwrap_or(self.request_headers);
        if let Some(obligation) = self.obligation {
            // Fulfilling the obligation also releases it, waking anyone waiting on this object.
            obligation.insert_with_headers(request_headers, options, body);
        } else {
            // No obligation: a plain, racing, last-writer-wins insert.
            self.objects.insert(request_headers, options, body, None);
        }
    }
}

/// A successful retrieval of an item from the cache.
#[derive(Debug)]
pub struct Found {
    data: CacheData,

    /// The handle for the last body used to read from this Found.
    ///
    /// Only one Body may be outstanding from a given Found at a time.
    /// (This is an implementation restriction within the compute platform).
    /// We mirror the BodyHandle here when we create it; we can later check whether the handle is
    /// still valid, to find an outstanding read.
    pub last_body_handle: Option<BodyHandle>,
}

impl From<CacheData> for Found {
    fn from(data: CacheData) -> Self {
        Found {
            data,
            last_body_handle: None,
        }
    }
}

impl Found {
    fn get_body(&self) -> GetBodyBuilder<'_> {
        self.data.body()
    }

    /// Access the metadata of the cached object.
    pub fn meta(&self) -> &ObjectMeta {
        self.data.get_meta()
    }

    /// The length of the cached object, if known at lookup time.
    pub fn length(&self) -> Option<u64> {
        self.data.get_meta().length()
    }
}

/// Cache for a service.
///
// TODO: cceckman-at-fastly:
// Explain some about how this works:
// - Request collapsing
// - Stale-while-revalidate
pub struct Cache {
    inner: moka::future::Cache<CacheKey, Arc<CacheKeyObjects>>,
}

impl Default for Cache {
    fn default() -> Self {
        // TODO: cceckman-at-fastly:
        // Weight by size, allow a cap on max size?
        let inner = moka::future::Cache::builder()
            .eviction_listener(|key, _value, cause| {
                tracing::info!("cache eviction of {key:?}: {cause:?}")
            })
            .build();
        Cache { inner }
    }
}

impl Cache {
    /// Perform a non-transactional lookup.
    pub async fn lookup(&self, key: &CacheKey, headers: &HeaderMap) -> CacheEntry {
        let found = self
            .inner
            .get_with_by_ref(key, async { Default::default() })
            .await
            .get(headers)
            .map(|data| Found::from((*data).clone()));
        CacheEntry {
            key: key.clone(),
            found,
            go_get: None,
            always_use_requested_range: false,
        }
    }

    /// Perform a transactional lookup.
    pub async fn transaction_lookup(
        &self,
        key: &CacheKey,
        headers: &HeaderMap,
        ok_to_wait: bool,
    ) -> CacheEntry {
        let (found, obligation) = self
            .inner
            .get_with_by_ref(key, async { Default::default() })
            .await
            .transaction_get(headers, ok_to_wait)
            .await;
        CacheEntry {
            key: key.clone(),
            found: found.map(|v| Found::from((*v).clone())),
            go_get: obligation,
            always_use_requested_range: false,
        }
    }

    /// Begin a replace operation: read the object currently in the cache (if any), and acquire the
    /// right to write a replacement for it.
    pub async fn replace(
        &self,
        key: &CacheKey,
        request_headers: HeaderMap,
        strategy: ReplaceStrategy,
    ) -> ReplaceEntry {
        let objects = self
            .inner
            .get_with_by_ref(key, async { Default::default() })
            .await;
        let (existing, obligation) = objects.replace(&request_headers, strategy).await;
        ReplaceEntry {
            key: key.clone(),
            request_headers,
            objects,
            existing: existing.map(|v| Found::from((*v).clone())),
            obligation,
            always_use_requested_range: false,
        }
    }

    /// Perform a non-transactional lookup for the given cache key.
    /// Note: races with other insertions, including transactional insertions.
    /// Last writer wins!
    pub async fn insert(
        &self,
        key: &CacheKey,
        request_headers: HeaderMap,
        options: WriteOptions,
        body: Body,
    ) {
        self.inner
            .get_with_by_ref(key, async { Default::default() })
            .await
            .insert(request_headers, options, body, None);
    }

    /// Purge/soft-purge all cache entries corresponding to the given surrogate key.
    /// Returns the number of entries (variants) purged.
    ///
    /// Note: this does not block concurrent reads _or inserts_; an insertion can race with the
    /// purge.
    pub fn purge(&self, key: SurrogateKey, soft_purge: bool) -> usize {
        self.inner
            .iter()
            .map(|(_, entry)| entry.purge(&key, soft_purge))
            .sum()
    }
}

/// Options that can be applied to a write, e.g. insert or transaction_insert.
#[derive(Default, Clone)]
pub struct WriteOptions {
    pub max_age: Duration,
    pub initial_age: Duration,
    pub stale_while_revalidate: Duration,
    pub vary_rule: VaryRule,
    pub user_metadata: Bytes,
    pub length: Option<u64>,
    pub sensitive_data: bool,
    pub edge_max_age: Duration,
    pub surrogate_keys: SurrogateKeySet,
}

impl WriteOptions {
    pub fn new(max_age: Duration) -> Self {
        WriteOptions {
            max_age,
            initial_age: Duration::ZERO,
            stale_while_revalidate: Duration::ZERO,
            vary_rule: VaryRule::default(),
            user_metadata: Bytes::new(),
            length: None,
            sensitive_data: false,
            edge_max_age: max_age,
            surrogate_keys: Default::default(),
        }
    }
}

/// Optional override for response caching behavior.
#[derive(Clone, Debug, Default)]
pub enum CacheOverride {
    /// Do not override the behavior specified in the origin response's cache control headers.
    #[default]
    None,
    /// Do not cache the response to this request, regardless of the origin response's headers.
    Pass,
    /// Override particular cache control settings.
    ///
    /// The origin response's cache control headers will be used for ttl and stale_while_revalidate if `None`.
    Override {
        ttl: Option<u32>,
        stale_while_revalidate: Option<u32>,
        pci: bool,
        surrogate_key: Option<HeaderValue>,
        lookup_timeout_ms: Option<u32>,
    },
}

impl CacheOverride {
    pub fn is_pass(&self) -> bool {
        matches!(self, Self::Pass)
    }

    /// Convert from the representation suitable for passing across the ABI boundary.
    ///
    /// Returns `None` if the tag is not recognized. Depending on the tag, some of the values may be
    /// ignored.
    pub fn from_abi(
        tag: u32,
        ttl: u32,
        swr: u32,
        surrogate_key: Option<HeaderValue>,
        lookup_timeout_ms: u32,
    ) -> Option<Self> {
        CacheOverrideTag::from_bits(tag).map(|tag| {
            if tag.contains(CacheOverrideTag::PASS) {
                return CacheOverride::Pass;
            }
            if tag.is_empty() && surrogate_key.is_none() {
                return CacheOverride::None;
            }
            let ttl = if tag.contains(CacheOverrideTag::TTL) {
                Some(ttl)
            } else {
                None
            };
            let stale_while_revalidate = if tag.contains(CacheOverrideTag::STALE_WHILE_REVALIDATE) {
                Some(swr)
            } else {
                None
            };
            let lookup_timeout_ms = if tag.contains(CacheOverrideTag::LOOKUP_TIMEOUT) {
                Some(lookup_timeout_ms)
            } else {
                None
            };
            let pci = tag.contains(CacheOverrideTag::PCI);
            CacheOverride::Override {
                ttl,
                stale_while_revalidate,
                pci,
                surrogate_key,
                lookup_timeout_ms,
            }
        })
    }
}

/// Maximum length of surrogate keys (when combined with spaces).
const MAX_SURROGATE_KEYS_LENGTH: usize = 16 * 1024;
/// Maximum length of a single surrogate key.
const MAX_SURROGATE_KEY_LENGTH: usize = 1024;

#[derive(Debug, Default, Clone)]
pub struct SurrogateKeySet(HashSet<SurrogateKey>);

impl std::fmt::Display for SurrogateKeySet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{")?;
        for (i, item) in self.0.iter().enumerate() {
            if i == 0 {
                write!(f, "{item}")?;
            } else {
                write!(f, " {item}")?;
            }
        }
        write!(f, "}}")
    }
}

impl TryFrom<&[u8]> for SurrogateKeySet {
    type Error = crate::Error;

    fn try_from(s: &[u8]) -> Result<Self, Self::Error> {
        if s.len() > MAX_SURROGATE_KEYS_LENGTH {
            return Err(
                Error::InvalidArgument("surrogate key set exceeds maximum length (16Ki)").into(),
            );
        }
        let result: Result<HashSet<_>, _> = s
            .split(|c| *c == b' ')
            .filter(|sk| !sk.is_empty())
            .map(SurrogateKey::try_from)
            .collect();
        Ok(SurrogateKeySet(result?))
    }
}

impl std::str::FromStr for SurrogateKeySet {
    type Err = crate::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.as_bytes().try_into()
    }
}

/// A validated surrogate key: a non-empty string containing only visible ASCII characters.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct SurrogateKey(String);

impl std::fmt::Display for SurrogateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl TryFrom<&[u8]> for SurrogateKey {
    type Error = Error;

    fn try_from(b: &[u8]) -> Result<Self, Self::Error> {
        if b.len() > MAX_SURROGATE_KEY_LENGTH {
            return Err(Error::InvalidArgument(
                "surrogate key exceeds maximum length (1024)",
            ));
        }

        if !b.iter().all(|c| c.is_ascii_graphic()) {
            return Err(Error::InvalidArgument(
                "surrogate key contains characters other than graphical ASCII",
            ));
        }
        let s = unsafe {
            // All graphic ASCII characters are equivalent to the corresponding UTF-8 codepoints.
            str::from_utf8_unchecked(b)
        };
        Ok(SurrogateKey(s.to_owned()))
    }
}

impl std::str::FromStr for SurrogateKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.as_bytes().try_into()
    }
}

#[cfg(test)]
mod tests {
    use std::rc::Rc;

    use http::HeaderName;
    use proptest::prelude::*;

    use super::*;

    proptest! {
        #[test]
        fn reject_cache_key_too_long(l in 4097usize..5000) {
            let mut v : Vec<u8> = Vec::new();
            v.resize(l, 0);
            CacheKey::try_from(&v).unwrap_err();
        }
    }

    proptest! {
        #[test]
        fn accept_valid_cache_key_len(l in 0usize..4096) {
            let mut v : Vec<u8> = Vec::new();
            v.resize(l, 0);
            let _ = CacheKey::try_from(&v).unwrap();
        }
    }

    proptest! {
        #[test]
        fn nontransactional_insert_lookup(
                key in any::<CacheKey>(),
                max_age in any::<u32>(),
                initial_age in any::<u32>(),
                value in any::<Vec<u8>>()) {
            let cache = Cache::default();

            // We can't use tokio::test and proptest! together; both alter the signature of the
            // test function, and are not aware of each other enough for it to pass.
            let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
            rt.block_on(async {
                let empty = cache.lookup(&key, &HeaderMap::default()).await;
                assert!(empty.found().is_none());
                // The non-transactional case does not produce an obligation (go_get)
                assert!(empty.go_get().is_none());

                let write_options = WriteOptions {
                    max_age: Duration::from_secs(max_age as u64),
                    initial_age: Duration::from_secs(initial_age as u64),
                    ..Default::default()
                };

                cache.insert(&key, HeaderMap::default(), write_options, value.clone().into()).await;

                let nonempty = cache.lookup(&key, &HeaderMap::default()).await;
                let found = nonempty.found().expect("should have found inserted key");
                let got = found.get_body().build().await.unwrap().read_into_vec().await.unwrap();
                assert_eq!(got, value);
            });
        }
    }

    #[test]
    fn parse_surrogate_keys() {
        let keys: SurrogateKeySet = "keyA keyB".parse().unwrap();
        let key_a: SurrogateKey = "keyA".parse().unwrap();
        let key_b: SurrogateKey = "keyB".parse().unwrap();
        assert_eq!(keys.0.len(), 2);
        assert!(keys.0.contains(&key_a));
        assert!(keys.0.contains(&key_b));
    }

    #[tokio::test]
    async fn insert_immediately_stale() {
        let cache = Cache::default();
        let key = ([1u8].as_slice()).try_into().unwrap();

        // Insert an already-stale entry:
        let write_options = WriteOptions {
            max_age: Duration::from_secs(1),
            initial_age: Duration::from_secs(2),
            ..Default::default()
        };

        let mut body = Body::empty();
        body.push_back([1u8].as_slice());

        cache
            .insert(&key, HeaderMap::default(), write_options, body)
            .await;

        let nonempty = cache.lookup(&key, &HeaderMap::default()).await;
        let found = nonempty.found().expect("should have found inserted key");
        assert!(!found.meta().is_fresh());
    }

    #[tokio::test]
    async fn test_vary() {
        let cache = Cache::default();
        let key = ([1u8].as_slice()).try_into().unwrap();

        let header_name = HeaderName::from_static("x-viceroy-test");
        let request_headers: HeaderMap = [(header_name.clone(), HeaderValue::from_static("test"))]
            .into_iter()
            .collect();

        let write_options = WriteOptions {
            max_age: Duration::from_secs(100),
            vary_rule: VaryRule::new([&header_name].into_iter()),
            ..Default::default()
        };
        let body = Body::empty();
        cache
            .insert(&key, request_headers.clone(), write_options, body)
            .await;

        let empty_headers = cache.lookup(&key, &HeaderMap::default()).await;
        assert!(empty_headers.found().is_none());

        let matched_headers = cache.lookup(&key, &request_headers).await;
        assert!(matched_headers.found.is_some());

        let r2_headers: HeaderMap = [(header_name.clone(), HeaderValue::from_static("assert"))]
            .into_iter()
            .collect();
        let mismatched_headers = cache.lookup(&key, &r2_headers).await;
        assert!(mismatched_headers.found.is_none());
    }

    #[tokio::test]
    async fn insert_stale_while_revalidate() {
        let cache = Cache::default();
        let key = ([1u8].as_slice()).try_into().unwrap();

        // Insert an already-stale entry, with an SWR period:
        let write_options = WriteOptions {
            max_age: Duration::from_secs(1),
            initial_age: Duration::from_secs(2),
            stale_while_revalidate: Duration::from_secs(10),
            ..Default::default()
        };

        let mut body = Body::empty();
        body.push_back([1u8].as_slice());
        cache
            .insert(&key, HeaderMap::default(), write_options, body)
            .await;

        let nonempty = cache.lookup(&key, &HeaderMap::default()).await;
        let found = nonempty.found().expect("should have found inserted key");
        assert!(!found.meta().is_fresh());
        assert!(found.meta().is_usable());
    }

    #[tokio::test]
    async fn insert_and_revalidate() {
        let cache = Cache::default();
        let key = ([1u8].as_slice()).try_into().unwrap();

        // Insert an already-stale entry, with an SWR period:
        let write_options = WriteOptions {
            max_age: Duration::from_secs(1),
            initial_age: Duration::from_secs(2),
            stale_while_revalidate: Duration::from_secs(10),
            ..Default::default()
        };

        let mut body = Body::empty();
        body.push_back([1u8].as_slice());
        cache
            .insert(&key, HeaderMap::default(), write_options, body)
            .await;

        let mut txn1 = cache
            .transaction_lookup(&key, &HeaderMap::default(), true)
            .await;
        let found = txn1.found().expect("should have found inserted key");
        assert!(!found.meta().is_fresh());
        assert!(found.meta().is_usable());

        assert!(txn1.go_get().is_some());

        // Another lookup should not get the obligation *or* block
        {
            let txn2 = cache
                .transaction_lookup(&key, &HeaderMap::default(), true)
                .await;
            let found = txn2.found().expect("should have found inserted key");
            assert!(!found.meta().is_fresh());
            assert!(found.meta().is_usable());
            assert!(txn2.go_get().is_none());
        }

        txn1.update(WriteOptions {
            max_age: Duration::from_secs(10),
            stale_while_revalidate: Duration::from_secs(10),
            ..WriteOptions::default()
        })
        .await
        .unwrap();

        // After this, should get the new response:
        let txn3 = cache
            .transaction_lookup(&key, &HeaderMap::default(), true)
            .await;
        assert!(txn3.go_get().is_none());
        let found = txn3.found().expect("should find updated entry");
        assert!(found.meta().is_usable());
        assert!(found.meta().is_fresh());
    }

    #[tokio::test]
    async fn cannot_revalidate_first_insert() {
        let cache = Cache::default();
        let key = ([1u8].as_slice()).try_into().unwrap();

        let mut txn1 = cache
            .transaction_lookup(&key, &HeaderMap::default(), false)
            .await;
        assert!(txn1.found().is_none());
        let opts = WriteOptions {
            max_age: Duration::from_secs(10),
            stale_while_revalidate: Duration::from_secs(10),
            ..WriteOptions::default()
        };
        txn1.update(opts.clone()).await.unwrap_err();

        // But we should still be able to insert.
        txn1.insert(opts.clone(), Body::empty()).unwrap();
    }

    #[tokio::test]
    async fn purge_by_surrogate_key() {
        let cache = Cache::default();
        let key: CacheKey = ([1u8].as_slice()).try_into().unwrap();

        let surrogate_keys: SurrogateKeySet = "one two three".parse().unwrap();
        let opts = WriteOptions {
            max_age: Duration::from_secs(100),
            surrogate_keys: surrogate_keys.clone(),
            ..WriteOptions::default()
        };

        cache
            .insert(&key, HeaderMap::default(), opts.clone(), Body::empty())
            .await;
        let result = cache.lookup(&key, &HeaderMap::default()).await;
        assert!(result.found().is_some());

        assert_eq!(cache.purge("two".parse().unwrap(), false), 1);
        let result = cache.lookup(&key, &HeaderMap::default()).await;
        assert!(result.found().is_none());
    }

    #[tokio::test]
    async fn purge_variant_by_surrogate_key() {
        let cache = Rc::new(Cache::default());
        let key: CacheKey = ([1u8].as_slice()).try_into().unwrap();

        // "Introduction and Variations on a Theme by Mozart, Op. 9, is one of Fernando Sor's most
        // famous works for guitar."
        let vary_header = HeaderName::from_static("opus-9");
        let insert = {
            let cache = cache.clone();
            let key = key.clone();

            move |surrogate_keys: &str, variation: &str| {
                let mut headers = HeaderMap::new();
                headers.insert(vary_header.clone(), variation.try_into().unwrap());
                let surrogate_keys: SurrogateKeySet = surrogate_keys.parse().unwrap();
                let opts = WriteOptions {
                    max_age: Duration::from_secs(100),
                    surrogate_keys: surrogate_keys.clone(),
                    vary_rule: VaryRule::new([&vary_header]),
                    ..WriteOptions::default()
                };
                let cache = cache.clone();
                let key = key.clone();
                async move {
                    cache
                        .insert(&key, headers.clone(), opts.clone(), Body::empty())
                        .await;
                    headers
                }
            }
        };

        let h1 = insert("one two three", "twinkle twinkle").await;
        let h2 = insert("one three", "abcdefg").await;
        assert!(cache.lookup(&key, &h1).await.found().is_some());
        assert!(cache.lookup(&key, &h2).await.found().is_some());

        assert_eq!(cache.purge("two".parse().unwrap(), false), 1);
        assert!(cache.lookup(&key, &h1).await.found().is_none());
        assert!(cache.lookup(&key, &h2).await.found().is_some());
    }

    #[tokio::test]
    async fn soft_purge() {
        let cache = Cache::default();
        let key: CacheKey = ([1u8].as_slice()).try_into().unwrap();

        let surrogate_keys: SurrogateKeySet = "one two three".parse().unwrap();
        let opts = WriteOptions {
            max_age: Duration::from_secs(100),
            surrogate_keys: surrogate_keys.clone(),
            ..WriteOptions::default()
        };

        cache
            .insert(&key, HeaderMap::default(), opts.clone(), Body::empty())
            .await;
        let result = cache.lookup(&key, &HeaderMap::default()).await;
        assert!(result.found().is_some());

        assert_eq!(cache.purge("two".parse().unwrap(), true), 1);
        let result = cache
            .transaction_lookup(&key, &HeaderMap::default(), false)
            .await;
        let found = result.found().unwrap();
        assert!(!found.meta().is_fresh());
        assert!(found.meta().is_usable());
        assert!(result.go_get().is_some());
    }

    /// Insert `body` at `key` with a 100s TTL, non-transactionally.
    async fn insert_fresh(cache: &Cache, key: &CacheKey, body: &str) {
        cache
            .insert(
                key,
                HeaderMap::default(),
                WriteOptions::new(Duration::from_secs(100)),
                body.as_bytes().into(),
            )
            .await;
    }

    async fn read_body(entry: &ReplaceEntry) -> String {
        entry
            .body(None, None)
            .await
            .unwrap()
            .read_into_string()
            .await
            .unwrap()
    }

    async fn lookup_body(cache: &Cache, key: &CacheKey) -> Option<String> {
        let entry = cache.lookup(key, &HeaderMap::default()).await;
        entry.found()?;
        Some(
            entry
                .body(None, None)
                .await
                .unwrap()
                .read_into_string()
                .await
                .unwrap(),
        )
    }

    #[tokio::test]
    async fn replace_immediate_leaves_existing_visible() {
        let cache = Cache::default();
        let key: CacheKey = ([1u8].as_slice()).try_into().unwrap();
        insert_fresh(&cache, &key, "old").await;

        let entry = cache
            .replace(&key, HeaderMap::default(), ReplaceStrategy::Immediate)
            .await;
        assert_eq!(read_body(&entry).await, "old");

        // `Immediate` does not disturb the existing object...
        assert_eq!(lookup_body(&cache, &key).await.as_deref(), Some("old"));

        entry.insert(
            None,
            WriteOptions::new(Duration::from_secs(100)),
            "new".as_bytes().into(),
        );

        // ...but the replacement wins once it's written.
        assert_eq!(lookup_body(&cache, &key).await.as_deref(), Some("new"));
    }

    #[tokio::test]
    async fn replace_no_existing_object() {
        let cache = Cache::default();
        let key: CacheKey = ([1u8].as_slice()).try_into().unwrap();

        let entry = cache
            .replace(&key, HeaderMap::default(), ReplaceStrategy::Wait)
            .await;
        assert!(entry.existing().is_none());

        entry.insert(
            None,
            WriteOptions::new(Duration::from_secs(100)),
            "new".as_bytes().into(),
        );
        assert_eq!(lookup_body(&cache, &key).await.as_deref(), Some("new"));
    }

    #[tokio::test]
    async fn replace_force_miss_hides_existing() {
        let cache = Arc::new(Cache::default());
        let key: CacheKey = ([1u8].as_slice()).try_into().unwrap();
        insert_fresh(&cache, &key, "old").await;

        let entry = cache
            .replace(
                &key,
                HeaderMap::default(),
                ReplaceStrategy::ImmediateForceMiss,
            )
            .await;
        // The replace still gets to read the object it displaced...
        assert_eq!(read_body(&entry).await, "old");
        // ...but nobody else can find it.
        assert!(
            cache
                .lookup(&key, &HeaderMap::default())
                .await
                .found()
                .is_none()
        );

        // A transactional lookup blocks on our obligation rather than missing.
        let waiter = tokio::task::spawn({
            let cache = Arc::clone(&cache);
            let key = key.clone();
            async move {
                cache
                    .transaction_lookup(&key, &HeaderMap::default(), true)
                    .await
            }
        });

        entry.insert(
            None,
            WriteOptions::new(Duration::from_secs(100)),
            "new".as_bytes().into(),
        );

        let waited = tokio::time::timeout(Duration::from_secs(5), waiter)
            .await
            .expect("waiter should be woken by the replacement insert")
            .unwrap();
        assert!(waited.go_get().is_none());
        assert_eq!(
            waited
                .body(None, None)
                .await
                .unwrap()
                .read_into_string()
                .await
                .unwrap(),
            "new"
        );
    }

    #[tokio::test]
    async fn replace_wait_serializes() {
        let cache = Arc::new(Cache::default());
        let key: CacheKey = ([1u8].as_slice()).try_into().unwrap();
        insert_fresh(&cache, &key, "1").await;

        // The read-modify-write ("counter") pattern: each task reads the current value, adds one,
        // and writes it back. `Wait` is what makes this safe.
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..4 {
            set.spawn({
                let cache = Arc::clone(&cache);
                let key = key.clone();
                async move {
                    let entry = cache
                        .replace(&key, HeaderMap::default(), ReplaceStrategy::Wait)
                        .await;
                    let count: u32 = read_body(&entry).await.parse().unwrap();
                    entry.insert(
                        None,
                        WriteOptions::new(Duration::from_secs(100)),
                        format!("{}", count + 1).into_bytes().into(),
                    );
                }
            });
        }
        tokio::time::timeout(Duration::from_secs(10), set.join_all())
            .await
            .expect("`Wait` replaces should not deadlock");

        assert_eq!(lookup_body(&cache, &key).await.as_deref(), Some("5"));
    }

    #[tokio::test]
    async fn replace_abandoned_releases_obligation() {
        let cache = Cache::default();
        let key: CacheKey = ([1u8].as_slice()).try_into().unwrap();
        insert_fresh(&cache, &key, "old").await;

        let entry = cache
            .replace(
                &key,
                HeaderMap::default(),
                ReplaceStrategy::ImmediateForceMiss,
            )
            .await;
        drop(entry);

        // The obligation is gone, so a new transaction gets to take it on rather than waiting
        // forever on the abandoned replace.
        let txn = cache
            .transaction_lookup(&key, &HeaderMap::default(), false)
            .await;
        assert!(txn.found().is_none());
        assert!(txn.go_get().is_some());
    }

    #[tokio::test]
    async fn replace_with_new_vary_rule() {
        let cache = Cache::default();
        let key: CacheKey = ([1u8].as_slice()).try_into().unwrap();

        let header_name = HeaderName::from_static("x-viceroy-test");
        let request_headers: HeaderMap = [(header_name.clone(), HeaderValue::from_static("test"))]
            .into_iter()
            .collect();

        cache
            .insert(
                &key,
                request_headers.clone(),
                WriteOptions {
                    vary_rule: VaryRule::new([&header_name].into_iter()),
                    ..WriteOptions::new(Duration::from_secs(100))
                },
                "old".as_bytes().into(),
            )
            .await;

        let entry = cache
            .replace(&key, request_headers.clone(), ReplaceStrategy::Wait)
            .await;
        assert_eq!(read_body(&entry).await, "old");

        // Write the replacement without a vary rule: the obligation was taken against the *old*
        // variant, but the new object lands under a new one.
        entry.insert(
            None,
            WriteOptions::new(Duration::from_secs(100)),
            "new".as_bytes().into(),
        );

        assert_eq!(lookup_body(&cache, &key).await.as_deref(), Some("new"));
        let matched = cache.lookup(&key, &request_headers).await;
        assert!(matched.found().is_some());
    }

    #[tokio::test]
    async fn hits_and_stale_while_revalidate() {
        let cache = Cache::default();
        let key: CacheKey = ([1u8].as_slice()).try_into().unwrap();

        cache
            .insert(
                &key,
                HeaderMap::default(),
                WriteOptions {
                    stale_while_revalidate: Duration::from_secs(10),
                    ..WriteOptions::new(Duration::from_secs(100))
                },
                "old".as_bytes().into(),
            )
            .await;

        let first = cache.lookup(&key, &HeaderMap::default()).await;
        let found = first.found().unwrap();
        assert_eq!(found.meta().hits(), 1);
        assert_eq!(
            found.meta().stale_while_revalidate(),
            Duration::from_secs(10)
        );

        // The counter is shared with the object still in the cache, so a second delivery is visible
        // through the first `Found` as well.
        let second = cache.lookup(&key, &HeaderMap::default()).await;
        assert_eq!(second.found().unwrap().meta().hits(), 2);
        assert_eq!(found.meta().hits(), 2);

        // Beginning a replace is not a delivery, so it doesn't count as a hit.
        let entry = cache
            .replace(&key, HeaderMap::default(), ReplaceStrategy::Immediate)
            .await;
        let existing = entry.existing().unwrap();
        assert_eq!(existing.meta().hits(), 2);
        assert_eq!(
            existing.meta().stale_while_revalidate(),
            Duration::from_secs(10)
        );
    }
}
