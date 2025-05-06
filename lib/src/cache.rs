use std::{sync::Arc, time::Duration};

use bytes::Bytes;
#[cfg(test)]
use proptest_derive::Arbitrary;

use crate::{
    body::Body,
    component::fastly::api::types::Error as ComponentError,
    wiggle_abi::types::{BodyHandle, CacheOverrideTag, FastlyStatus},
};

use http::{HeaderMap, HeaderValue};

mod store;
mod variance;

use store::{CacheData, CacheKeyObjects, ObjectMeta, Obligation};
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

    #[error("cache entry's body is currently being read by another body")]
    HandleBodyUsed,
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
            Error::CannotWrite => FastlyStatus::Badf,
            Error::Missing => FastlyStatus::None,
            Error::HandleBodyUsed => FastlyStatus::Badf,
        }
    }
}

impl From<Error> for ComponentError {
    fn from(value: Error) -> Self {
        match value {
            // TODO: cceckman-at-fastly: These may not correspond to the same errors as the compute
            // platform uses. Check!
            Error::InvalidKey => ComponentError::InvalidArgument,
            Error::CannotWrite => ComponentError::BadHandle,
            Error::Missing => ComponentError::OptionalNone,
            Error::HandleBodyUsed => ComponentError::BadHandle,
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
}

impl CacheEntry {
    /// Return a stub entry to hold in CacheBusy.
    pub fn stub(&self) -> CacheEntry {
        Self {
            key: self.key.clone(),
            found: None,
            go_get: None,
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

    /// Extract the write obligation, if present.
    pub fn take_go_get(&mut self) -> Option<Obligation> {
        self.go_get.take()
    }
}

/// A successful retrieval of an item from the cache.
#[derive(Debug)]
pub struct Found {
    data: Arc<CacheData>,

    /// The handle for the last body used to read from this Found.
    ///
    /// Only one Body may be outstanding from a given Found at a time.
    /// (This is an implementation restriction within the compute platform).
    /// We mirror the BodyHandle here when we create it; we can later check whether the handle is
    /// still valid, to find an outstanding read.
    pub last_body_handle: Option<BodyHandle>,
}

impl Found {
    /// Access the body of the cached object.
    pub fn body(&self) -> Result<Body, crate::Error> {
        self.data.as_ref().get_body()
    }

    /// Access the metadata of the cached object.
    pub fn meta(&self) -> &ObjectMeta {
        self.data.get_meta()
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
            .get_with_by_ref(&key, async { Default::default() })
            .await
            .get(headers)
            .map(|data| Found {
                data,
                last_body_handle: None,
            });
        CacheEntry {
            key: key.clone(),
            found,
            go_get: None,
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
            .get_with_by_ref(&key, async { Default::default() })
            .await
            .transaction_get(headers, ok_to_wait)
            .await;
        CacheEntry {
            key: key.clone(),
            found: found.map(|data| Found {
                data,
                last_body_handle: None,
            }),
            go_get: obligation,
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
            .get_with_by_ref(&key, async { Default::default() })
            .await
            .insert(request_headers, options, body, None);
    }
}

/// Options that can be applied to a write, e.g. insert or transaction_insert.
#[derive(Default)]
pub struct WriteOptions {
    pub max_age: Duration,
    pub initial_age: Duration,
    pub vary_rule: VaryRule,
    pub user_metadata: Bytes,
}

impl WriteOptions {
    pub fn new(max_age: Duration) -> Self {
        WriteOptions {
            max_age,
            initial_age: Duration::ZERO,
            vary_rule: VaryRule::default(),
            user_metadata: Bytes::new(),
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
    },
}

impl CacheOverride {
    pub fn is_pass(&self) -> bool {
        if let Self::Pass = self {
            true
        } else {
            false
        }
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
            let pci = tag.contains(CacheOverrideTag::PCI);
            CacheOverride::Override {
                ttl,
                stale_while_revalidate,
                pci,
                surrogate_key,
            }
        })
    }
}

#[cfg(test)]
mod tests {
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
                // TODO: cceckman-at-fastly -- check GoGet

                let write_options = WriteOptions {
                    max_age: Duration::from_secs(max_age as u64),
                    initial_age: Duration::from_secs(initial_age as u64),
                    ..Default::default()
                };

                cache.insert(&key, HeaderMap::default(), write_options, value.clone().into()).await;

                let nonempty = cache.lookup(&key, &HeaderMap::default()).await;
                let found = nonempty.found().expect("should have found inserted key");
                let got = found.body().unwrap().read_into_vec().await.unwrap();
                assert_eq!(got, value);
            });
        }
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
}
