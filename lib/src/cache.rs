use std::sync::Arc;

use bytes::Bytes;
use http::HeaderMap;
use tokio::sync::RwLock;

use crate::Error;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CacheKey(Bytes);

const MAX_CACHE_KEY_LEN: usize = 4096;

impl<'a> TryFrom<&'a [u8]> for CacheKey {
    type Error = Error;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        if value.len() > MAX_CACHE_KEY_LEN {
            Err(Error::InvalidArgument)
        } else {
            Ok(CacheKey(Bytes::copy_from_slice(value)))
        }
    }
}

#[derive(Debug)]
pub struct CacheEntry {
    found: Option<Found>,
}

#[derive(Debug)]
pub struct Found {}

#[derive(Clone, Debug)]
pub struct Cache {
    inner: Arc<RwLock<Inner>>,
}

impl Cache {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(Inner::new())),
        }
    }
}

#[derive(Debug)]
pub struct LookupOptions {
    pub request_headers: Option<HeaderMap>,
}

impl Cache {
    pub async fn lookup(
        &self,
        _key: CacheKey,
        _options: LookupOptions,
    ) -> Result<CacheEntry, Error> {
        // TODO: support actual lookups
        Ok(CacheEntry { found: None })
    }
}

#[derive(Debug)]
struct Inner {}

impl Inner {
    fn new() -> Self {
        Self {}
    }
}
