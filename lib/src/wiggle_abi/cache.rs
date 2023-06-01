use crate::session::Session;

use super::fastly_cache::FastlyCache;
use super::{types, Error};

#[allow(unused_variables)]
impl FastlyCache for Session {
    fn lookup<'a>(
        &mut self,
        cache_key: &wiggle::GuestPtr<'a, [u8]>,
        options_mask: types::CacheLookupOptionsMask,
        options: &wiggle::GuestPtr<'a, types::CacheLookupOptions>,
    ) -> Result<types::CacheHandle, Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        })
    }

    fn insert<'a>(
        &mut self,
        cache_key: &wiggle::GuestPtr<'a, [u8]>,
        options_mask: types::CacheWriteOptionsMask,
        options: &wiggle::GuestPtr<'a, types::CacheWriteOptions<'a>>,
    ) -> Result<types::BodyHandle, Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        })
    }

    fn transaction_lookup<'a>(
        &mut self,
        cache_key: &wiggle::GuestPtr<'a, [u8]>,
        options_mask: types::CacheLookupOptionsMask,
        options: &wiggle::GuestPtr<'a, types::CacheLookupOptions>,
    ) -> Result<types::CacheHandle, Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        })
    }

    fn transaction_insert<'a>(
        &mut self,
        handle: types::CacheHandle,
        options_mask: types::CacheWriteOptionsMask,
        options: &wiggle::GuestPtr<'a, types::CacheWriteOptions<'a>>,
    ) -> Result<types::BodyHandle, Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        })
    }

    fn transaction_insert_and_stream_back<'a>(
        &mut self,
        handle: types::CacheHandle,
        options_mask: types::CacheWriteOptionsMask,
        options: &wiggle::GuestPtr<'a, types::CacheWriteOptions<'a>>,
    ) -> Result<(types::BodyHandle, types::CacheHandle), Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        })
    }

    fn transaction_update<'a>(
        &mut self,
        handle: types::CacheHandle,
        options_mask: types::CacheWriteOptionsMask,
        options: &wiggle::GuestPtr<'a, types::CacheWriteOptions<'a>>,
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
        user_metadata_out_ptr: &wiggle::GuestPtr<'a, u8>,
        user_metadata_out_len: u32,
        nwritten_out: &wiggle::GuestPtr<'a, u32>,
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
