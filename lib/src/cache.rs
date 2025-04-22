use std::sync::Arc;

#[cfg(test)]
use proptest_derive::Arbitrary;

use crate::{
    body::Body,
    session::Session,
    wiggle_abi::types::{BodyHandle, CacheOverrideTag},
    Error,
};
use fastly_shared::FastlyStatus;
use http::HeaderValue;

mod store;

use store::{CacheData, CacheKeyObjects};

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
    type Error = FastlyStatus;

    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        value.as_slice().try_into()
    }
}

impl TryFrom<Vec<u8>> for CacheKey {
    type Error = FastlyStatus;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() > Self::MAX_LENGTH {
            Err(FastlyStatus::BUFLEN)
        } else {
            Ok(CacheKey(value))
        }
    }
}

impl TryFrom<&[u8]> for CacheKey {
    type Error = FastlyStatus;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() > CacheKey::MAX_LENGTH {
            Err(FastlyStatus::BUFLEN)
        } else {
            Ok(CacheKey(value.to_owned()))
        }
    }
}

impl TryFrom<&str> for CacheKey {
    type Error = FastlyStatus;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.as_bytes().try_into()
    }
}

/// The result of a lookup: the object (if found), or an obligation to get it (if not).
#[derive(Debug)]
pub struct CacheEntry {
    key: CacheKey,
    found: Option<Found>,
    // TODO: cceckman-at-fastly 2025-02-26: GoGet
}

impl CacheEntry {
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
    pub fn body(&self) -> Result<Body, Error> {
        self.data.as_ref().get_body()
    }
}

/// Cache for a service.
///
// TODO: cceckman-at-fastly:
// Explain some about how this works:
// - Request-keyed vs. response-keyed items; variance
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
    /// Perform a non-transactional lookup for the given cache key.
    // TODO: cceckman-at-fastly:
    // - use request headers; vary_by
    pub async fn lookup(&self, key: &CacheKey) -> CacheEntry {
        let found = self
            .inner
            .get_with_by_ref(&key, async { Default::default() })
            .await
            .get()
            .map(|data| Found {
                data,
                last_body_handle: None,
            });
        CacheEntry {
            key: key.clone(),
            found,
        }
    }

    /// Perform a non-transactional lookup for the given cache key.
    /// Note: races with other insertions, including transactional insertions.
    /// Last writer wins!
    // TODO: cceckman-at-fastly 2025-02-26:
    // - use request headers; vary_by; streaming body
    pub async fn insert(&self, key: &CacheKey, body: Body) {
        self.inner
            .get_with_by_ref(&key, async { Default::default() })
            .await
            .insert(body);
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
        fn nontransactional_insert_lookup(key in any::<CacheKey>(), value in any::<Vec<u8>>()) {
            let cache = Cache::default();

            // We can't use tokio::test and proptest! together; both alter the signature of the
            // test function, and are not aware of each other enough for it to pass.
            let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
            rt.block_on(async {
                let empty = cache.lookup(&key).await;
                assert!(empty.found().is_none());
                // TODO: cceckman-at-fastly -- check GoGet

                cache.insert(&key, value.clone().into()).await;

                let nonempty = cache.lookup(&key).await;
                let found = nonempty.found().expect("should have found inserted key");
                let got = found.body().unwrap().read_into_vec().await.unwrap();
                assert_eq!(got, value);
            });
        }
    }
}
