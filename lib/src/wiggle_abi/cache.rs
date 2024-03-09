use super::{
    fastly_cache::FastlyCache,
    types::{self},
    Error,
};
use crate::{body::Body, cache_state::not_found_handle, error::HandleError, session::Session};
use tracing::{event, Level};

// pub struct CacheWriteOptions<'a> {
//     pub max_age_ns: CacheDurationNs,
//     pub request_headers: RequestHandle,
//     pub vary_rule_ptr: wiggle::GuestPtr<'a, u8>,
//     pub vary_rule_len: u32,
//     pub initial_age_ns: CacheDurationNs,
//     pub stale_while_revalidate_ns: CacheDurationNs,
//     pub surrogate_keys_ptr: wiggle::GuestPtr<'a, u8>,
//     pub surrogate_keys_len: u32,
//     pub length: CacheObjectLength,
//     pub user_metadata_ptr: wiggle::GuestPtr<'a, u8>,
//     pub user_metadata_len: u32,
// }

// Q: What does this do? Indicate which fields are safe to read?
// pub struct CacheWriteOptionsMask(
//     <CacheWriteOptionsMask as ::bitflags::__private::PublicFlags>::Internal,
// );
// impl CacheWriteOptionsMask {
//     #[allow(deprecated, non_upper_case_globals)]
//     pub const RESERVED: Self = Self::from_bits_retain(1);
//     #[allow(deprecated, non_upper_case_globals)]
//     pub const REQUEST_HEADERS: Self = Self::from_bits_retain(2);
//     #[allow(deprecated, non_upper_case_globals)]
//     pub const VARY_RULE: Self = Self::from_bits_retain(4);
//     #[allow(deprecated, non_upper_case_globals)]
//     pub const INITIAL_AGE_NS: Self = Self::from_bits_retain(8);
//     #[allow(deprecated, non_upper_case_globals)]
//     pub const STALE_WHILE_REVALIDATE_NS: Self = Self::from_bits_retain(16);
//     #[allow(deprecated, non_upper_case_globals)]
//     pub const SURROGATE_KEYS: Self = Self::from_bits_retain(32);
//     #[allow(deprecated, non_upper_case_globals)]
//     pub const LENGTH: Self = Self::from_bits_retain(64);
//     #[allow(deprecated, non_upper_case_globals)]
//     pub const USER_METADATA: Self = Self::from_bits_retain(128);
//     #[allow(deprecated, non_upper_case_globals)]
//     pub const SENSITIVE_DATA: Self = Self::from_bits_retain(256);
// }

// pub struct CacheLookupOptionsMask(
//     <CacheLookupOptionsMask as ::bitflags::__private::PublicFlags>::Internal,
// );
// impl CacheLookupOptionsMask {
//     #[allow(deprecated, non_upper_case_globals)]
//     pub const RESERVED: Self = Self::from_bits_retain(1);
//     #[allow(deprecated, non_upper_case_globals)]
//     pub const REQUEST_HEADERS: Self = Self::from_bits_retain(2);
// }

// pub struct CacheLookupOptions {
//     pub request_headers: RequestHandle,
// }

// pub struct CacheGetBodyOptions {
//     pub from: u64,
//     pub to: u64,
// }

// pub struct CacheGetBodyOptionsMask(
//     <CacheGetBodyOptionsMask as ::bitflags::__private::PublicFlags>::Internal,
// );
// impl CacheGetBodyOptionsMask {
//     #[allow(deprecated, non_upper_case_globals)]
//     pub const RESERVED: Self = Self::from_bits_retain(1);
//     #[allow(deprecated, non_upper_case_globals)]
//     pub const FROM: Self = Self::from_bits_retain(2);
//     #[allow(deprecated, non_upper_case_globals)]
//     pub const TO: Self = Self::from_bits_retain(4);
// }
#[allow(unused_variables)]
impl FastlyCache for Session {
    fn lookup<'a>(
        &mut self,
        cache_key: &wiggle::GuestPtr<'a, [u8]>,
        options_mask: types::CacheLookupOptionsMask,
        options: &wiggle::GuestPtr<'a, types::CacheLookupOptions>,
    ) -> Result<types::CacheHandle, Error> {
        let primary_key: Vec<u8> = cache_key.as_slice().unwrap().unwrap().to_vec();
        let options: types::CacheLookupOptions = options.read().unwrap();
        let req_parts = self.request_parts(options.request_headers)?;

        Ok(self
            .cache_state
            .match_entry(&primary_key, &req_parts.headers)
            .unwrap_or(not_found_handle()))
    }

    fn insert<'a>(
        &mut self,
        cache_key: &wiggle::GuestPtr<'a, [u8]>,
        options_mask: types::CacheWriteOptionsMask,
        options: &wiggle::GuestPtr<'a, types::CacheWriteOptions<'a>>,
    ) -> Result<types::BodyHandle, Error> {
        // TODO: Skipped over all the sanity checks usually done by similar code (see `req_impl`).
        let options: types::CacheWriteOptions = options.read().unwrap();
        let key: Vec<u8> = cache_key.as_slice().unwrap().unwrap().to_vec();
        let parts = if options_mask.contains(types::CacheWriteOptionsMask::REQUEST_HEADERS) {
            Some(self.request_parts(options.request_headers)?)
        } else {
            None
        };

        let cache_handle = self.cache_state.insert(key, options_mask, options, parts)?;
        Ok(self.insert_cache_body(cache_handle))
    }

    /// Stub delegating to regular lookup.
    fn transaction_lookup<'a>(
        &mut self,
        cache_key: &wiggle::GuestPtr<'a, [u8]>,
        options_mask: types::CacheLookupOptionsMask,
        options: &wiggle::GuestPtr<'a, types::CacheLookupOptions>,
    ) -> Result<types::CacheHandle, Error> {
        // TODO: This is a plain hack, not a working implementation: Parallel tx etc, are simply not required.
        //       -> This will fall apart immediately if tx are used as actual transactions.
        let key: Vec<u8> = cache_key.as_slice().unwrap().unwrap().to_vec();
        Ok(self.cache_state.pending_tx.write().unwrap().push(key))
    }

    /// Stub delegating to regular insert.
    fn transaction_insert<'a>(
        &mut self,
        handle: types::CacheHandle,
        options_mask: types::CacheWriteOptionsMask,
        options: &wiggle::GuestPtr<'a, types::CacheWriteOptions<'a>>,
    ) -> Result<types::BodyHandle, Error> {
        let key = self
            .cache_state
            .pending_tx
            .read()
            .unwrap()
            .get(handle)
            .map(ToOwned::to_owned);

        if let Some(pending_tx_key) = key {
            let options: types::CacheWriteOptions = options.read().unwrap();
            let parts = if options_mask.contains(types::CacheWriteOptionsMask::REQUEST_HEADERS) {
                Some(self.request_parts(options.request_headers)?)
            } else {
                None
            };

            let cache_handle =
                self.cache_state
                    .insert(pending_tx_key.to_owned(), options_mask, options, parts)?;

            Ok(self.insert_cache_body(cache_handle))
        } else {
            Err(HandleError::InvalidCacheHandle(handle).into())
        }
    }

    fn transaction_insert_and_stream_back<'a>(
        &mut self,
        handle: types::CacheHandle,
        options_mask: types::CacheWriteOptionsMask,
        options: &wiggle::GuestPtr<'a, types::CacheWriteOptions<'a>>,
    ) -> Result<(types::BodyHandle, types::CacheHandle), Error> {
        event!(Level::ERROR, "Tx insert and stream back not implemented");
        Err(Error::Unsupported {
            msg: "Tx insert and stream back not implemented",
        })
    }

    fn transaction_update<'a>(
        &mut self,
        handle: types::CacheHandle,
        options_mask: types::CacheWriteOptionsMask,
        options: &wiggle::GuestPtr<'a, types::CacheWriteOptions<'a>>,
    ) -> Result<(), Error> {
        event!(Level::ERROR, "Tx update not implemented");
        Err(Error::Unsupported {
            msg: "Tx update not implemented",
        })
    }

    fn transaction_cancel(&mut self, handle: types::CacheHandle) -> Result<(), Error> {
        event!(Level::ERROR, "Tx cancel not implemented");
        Err(Error::Unsupported {
            msg: "Tx cancel not implemented",
        })
    }

    fn close(&mut self, handle: types::CacheHandle) -> Result<(), Error> {
        Ok(())
    }

    fn get_state(&mut self, handle: types::CacheHandle) -> Result<types::CacheLookupState, Error> {
        if let Some(Some(entry)) = self.cache_state.cache_entries.read().unwrap().get(handle) {
            // Entry found.
            let mut state = types::CacheLookupState::FOUND;

            if entry.is_stale() {
                state |= types::CacheLookupState::STALE
            } else {
                // If stale, entry must be updated.
                state |= types::CacheLookupState::MUST_INSERT_OR_UPDATE
            }

            if entry.is_usable() {
                state |= types::CacheLookupState::USABLE;
            } else {
                // If not usable, caller must insert / refresh the cache entry.
                state |= types::CacheLookupState::MUST_INSERT_OR_UPDATE
            }

            Ok(state)
        } else {
            // Entry not found, entry must be inserted.
            Ok(types::CacheLookupState::MUST_INSERT_OR_UPDATE)
        }
    }

    fn get_user_metadata<'a>(
        &mut self,
        handle: types::CacheHandle,
        user_metadata_out_ptr: &wiggle::GuestPtr<'a, u8>,
        user_metadata_out_len: u32, // TODO: Is this the maximum allowed length?
        nwritten_out: &wiggle::GuestPtr<'a, u32>,
    ) -> Result<(), Error> {
        if let Some(Some(entry)) = self.cache_state.cache_entries.read().unwrap().get(handle) {
            if entry.user_metadata.len() > user_metadata_out_len as usize {
                nwritten_out.write(entry.user_metadata.len().try_into().unwrap_or(0))?;
                return Err(Error::BufferLengthError {
                    buf: "user_metadata_out",
                    len: "user_metadata_out_len",
                });
            }

            let user_metadata_len = u32::try_from(entry.user_metadata.len())
                .expect("smaller than user_metadata_out_len means it must fit");

            let mut metadata_out = user_metadata_out_ptr
                .as_array(user_metadata_len)
                .as_slice_mut()?
                .ok_or(Error::SharedMemory)?;

            metadata_out.copy_from_slice(&entry.user_metadata);
            nwritten_out.write(user_metadata_len)?;

            Ok(())
        } else {
            Err(HandleError::InvalidCacheHandle(handle).into())
        }
    }

    fn get_body(
        &mut self,
        handle: types::CacheHandle,
        options_mask: types::CacheGetBodyOptionsMask,
        options: &types::CacheGetBodyOptions,
    ) -> Result<types::BodyHandle, Error> {
        let body = self
            .cache_state
            .cache_entries
            .read()
            .unwrap()
            .get(handle)
            .and_then(|entry| entry.as_ref().map(|entry| entry.body_bytes.clone()));

        if let Some(body) = body {
            // Re-insert a body into the session to allow subsequent reads.
            let body_handle = self.insert_body(Body::from(body));
            Ok(body_handle)
        } else {
            Err(HandleError::InvalidCacheHandle(handle).into())
        }
    }

    fn get_length(
        &mut self,
        handle: types::CacheHandle,
    ) -> Result<types::CacheObjectLength, Error> {
        event!(Level::ERROR, "Cache entry length get not implemented.");
        Err(Error::Unsupported {
            msg: "Cache entry length get not implemented.",
        })
    }

    fn get_max_age_ns(
        &mut self,
        handle: types::CacheHandle,
    ) -> Result<types::CacheDurationNs, Error> {
        if let Some(Some(entry)) = self.cache_state.cache_entries.read().unwrap().get(handle) {
            Ok(types::CacheDurationNs::from(entry.max_age_ns.unwrap_or(0)))
        } else {
            Err(HandleError::InvalidCacheHandle(handle).into())
        }
    }

    fn get_stale_while_revalidate_ns(
        &mut self,
        handle: types::CacheHandle,
    ) -> Result<types::CacheDurationNs, Error> {
        if let Some(Some(entry)) = self.cache_state.cache_entries.read().unwrap().get(handle) {
            Ok(types::CacheDurationNs::from(entry.swr_ns.unwrap_or(0)))
        } else {
            Err(HandleError::InvalidCacheHandle(handle).into())
        }
    }

    fn get_age_ns(&mut self, handle: types::CacheHandle) -> Result<types::CacheDurationNs, Error> {
        if let Some(Some(entry)) = self.cache_state.cache_entries.read().unwrap().get(handle) {
            Ok(types::CacheDurationNs::from(entry.age_ns()))
        } else {
            Err(HandleError::InvalidCacheHandle(handle).into())
        }
    }

    fn get_hits(&mut self, handle: types::CacheHandle) -> Result<types::CacheHitCount, Error> {
        event!(Level::ERROR, "Cache entry get_hits not implemented.");
        Err(Error::Unsupported {
            msg: "Cache entry get_hits not implemented.",
        })
    }
}
