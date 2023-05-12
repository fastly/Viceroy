use sha2::{Digest, Sha256};
use wiggle::GuestPtr;

use crate::cache::{CacheKey, LookupOptions};
use crate::session::{PeekableTask, Session};

use super::fastly_cache::FastlyCache;
use super::{types, Error};

fn salt_cache_key(unsalted: &[u8]) -> Result<CacheKey, Error> {
    const LOW_LEVEL_CACHED_SALT: &'static [u8] = b"viceroy_lib::wiggle_abi::cache";
    let salted = Sha256::new()
        .chain(LOW_LEVEL_CACHED_SALT)
        .chain(unsalted)
        .finalize();
    salted.as_slice().try_into()
}

impl LookupOptions {
    fn from_guest(
        session: &Session,
        options_mask: types::CacheLookupOptionsMask,
        options: &GuestPtr<types::CacheLookupOptions>,
    ) -> Result<Self, Error> {
        let options = options.read()?;
        let request_headers =
            if options_mask.contains(types::CacheLookupOptionsMask::REQUEST_HEADERS) {
                Some(
                    session
                        .request_parts(options.request_headers.into())?
                        .headers
                        .clone(),
                )
            } else {
                None
            };

        Ok(Self { request_headers })
    }
}

#[allow(unused_variables)]
#[wiggle::async_trait]
impl FastlyCache for Session {
    async fn lookup<'a>(
        &mut self,
        cache_key: &GuestPtr<'a, [u8]>,
        options_mask: types::CacheLookupOptionsMask,
        options: &GuestPtr<'a, types::CacheLookupOptions>,
    ) -> Result<types::CacheHandle, Error> {
        let unsalted = cache_key.as_slice()?.ok_or(Error::SharedMemory)?;
        let cache_key = salt_cache_key(&unsalted)?;
        let options = LookupOptions::from_guest(self, options_mask, options)?;
        let cache = self.cache().clone();
        let entry_task =
            PeekableTask::spawn(async move { cache.lookup(cache_key, options).await }).await;
        Ok(self.insert_cache_entry(entry_task).into())
    }

    fn insert<'a>(
        &mut self,
        cache_key: &GuestPtr<'a, [u8]>,
        options_mask: types::CacheWriteOptionsMask,
        options: &GuestPtr<'a, types::CacheWriteOptions<'a>>,
    ) -> Result<types::BodyHandle, Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        })
    }

    fn transaction_lookup<'a>(
        &mut self,
        cache_key: &GuestPtr<'a, [u8]>,
        options_mask: types::CacheLookupOptionsMask,
        options: &GuestPtr<'a, types::CacheLookupOptions>,
    ) -> Result<types::CacheHandle, Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        })
    }

    fn transaction_insert<'a>(
        &mut self,
        handle: types::CacheHandle,
        options_mask: types::CacheWriteOptionsMask,
        options: &GuestPtr<'a, types::CacheWriteOptions<'a>>,
    ) -> Result<types::BodyHandle, Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        })
    }

    fn transaction_insert_and_stream_back<'a>(
        &mut self,
        handle: types::CacheHandle,
        options_mask: types::CacheWriteOptionsMask,
        options: &GuestPtr<'a, types::CacheWriteOptions<'a>>,
    ) -> Result<(types::BodyHandle, types::CacheHandle), Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        })
    }

    fn transaction_update<'a>(
        &mut self,
        handle: types::CacheHandle,
        options_mask: types::CacheWriteOptionsMask,
        options: &GuestPtr<'a, types::CacheWriteOptions<'a>>,
    ) -> Result<(), Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        })
    }

    fn transaction_cancel(&mut self, handle: types::CacheHandle) -> Result<(), Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        })
    }

    fn close(&mut self, handle: types::CacheHandle) -> Result<(), Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        })
    }

    fn get_state(&mut self, handle: types::CacheHandle) -> Result<types::CacheLookupState, Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        })
    }

    fn get_user_metadata<'a>(
        &mut self,
        handle: types::CacheHandle,
        user_metadata_out_ptr: &GuestPtr<'a, u8>,
        user_metadata_out_len: u32,
        nwritten_out: &GuestPtr<'a, u32>,
    ) -> Result<(), Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        })
    }

    fn get_body(
        &mut self,
        handle: types::CacheHandle,
        options_mask: types::CacheGetBodyOptionsMask,
        options: &types::CacheGetBodyOptions,
    ) -> Result<types::BodyHandle, Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        })
    }

    fn get_length(
        &mut self,
        handle: types::CacheHandle,
    ) -> Result<types::CacheObjectLength, Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        })
    }

    fn get_max_age_ns(
        &mut self,
        handle: types::CacheHandle,
    ) -> Result<types::CacheDurationNs, Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        })
    }

    fn get_stale_while_revalidate_ns(
        &mut self,
        handle: types::CacheHandle,
    ) -> Result<types::CacheDurationNs, Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        })
    }

    fn get_age_ns(&mut self, handle: types::CacheHandle) -> Result<types::CacheDurationNs, Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        })
    }

    fn get_hits(&mut self, handle: types::CacheHandle) -> Result<types::CacheHitCount, Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        })
    }
}
