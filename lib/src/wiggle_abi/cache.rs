use core::str;
use std::sync::Arc;
use std::time::Duration;

use http::HeaderMap;
use wiggle::GuestError;

use crate::body::Body;
use crate::cache::{CacheKey, WriteOptions};
use crate::session::{PeekableTask, PendingCacheTask, Session};
use crate::wiggle_abi::types::CacheWriteOptionsMask;

use super::fastly_cache::FastlyCache;
use super::{types, Error};

fn load_cache_key(
    memory: &wiggle::GuestMemory<'_>,
    cache_key: wiggle::GuestPtr<[u8]>,
) -> Result<CacheKey, Error> {
    let bytes = memory.as_slice(cache_key)?.ok_or(Error::SharedMemory)?;
    let key: CacheKey = bytes.try_into().map_err(|_| Error::InvalidArgument)?;
    Ok(key)
}

fn load_write_options(
    session: &Session,
    memory: &wiggle::GuestMemory<'_>,
    options_mask: types::CacheWriteOptionsMask,
    options: types::CacheWriteOptions,
) -> Result<WriteOptions, Error> {
    let max_age = Duration::from_nanos(options.max_age_ns);
    let initial_age = if options_mask.contains(CacheWriteOptionsMask::INITIAL_AGE_NS) {
        Some(Duration::from_nanos(options.initial_age_ns))
    } else {
        None
    };
    let request_headers = if options_mask.contains(CacheWriteOptionsMask::REQUEST_HEADERS) {
        let handle = options.request_headers;
        let parts = session.request_parts(handle)?;
        parts.headers.clone()
    } else {
        HeaderMap::default()
    };
    let vary_rule = if options_mask.contains(CacheWriteOptionsMask::VARY_RULE) {
        let slice = options.vary_rule_ptr.as_array(options.vary_rule_len);
        let vary_rule_bytes = memory.as_slice(slice)?.ok_or(Error::SharedMemory)?;
        let vary_rule_str = str::from_utf8(vary_rule_bytes).map_err(|e| Error::Utf8Expected(e))?;
        Some(vary_rule_str.parse()?)
    } else {
        None
    };

    Ok(WriteOptions {
        max_age,
        initial_age,
        request_headers,
        vary_rule,
    })
}

#[allow(unused_variables)]
#[wiggle::async_trait]
impl FastlyCache for Session {
    async fn lookup(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        cache_key: wiggle::GuestPtr<[u8]>,
        options_mask: types::CacheLookupOptionsMask,
        options: wiggle::GuestPtr<types::CacheLookupOptions>,
    ) -> Result<types::CacheHandle, Error> {
        // TODO: cceckman-at-fastly: Handle options,
        // then remove this guard.
        if !std::env::var("ENABLE_EXPERIMENTAL_CACHE_API").is_ok_and(|v| v == "1") {
            return Err(Error::NotAvailable("Cache API primitives"));
        }

        let key = load_cache_key(memory, cache_key)?;
        let cache = Arc::clone(self.cache());

        let task = PeekableTask::spawn(Box::pin(async move { Ok(cache.lookup(&key).await) })).await;
        let task = PendingCacheTask::new(task);
        let handle = self.insert_cache_op(task);
        Ok(handle)
    }

    async fn insert(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        cache_key: wiggle::GuestPtr<[u8]>,
        options_mask: types::CacheWriteOptionsMask,
        options: wiggle::GuestPtr<types::CacheWriteOptions>,
    ) -> Result<types::BodyHandle, Error> {
        // TODO: cceckman-at-fastly: Handle options,
        // then remove this guard.
        if !std::env::var("ENABLE_EXPERIMENTAL_CACHE_API").is_ok_and(|v| v == "1") {
            return Err(Error::NotAvailable("Cache API primitives"));
        }
        let key = load_cache_key(memory, cache_key)?;
        let options = load_write_options(self, memory, options_mask, memory.read(options)?)?;
        let cache = Arc::clone(self.cache());

        // TODO: cceckman-at-fastly - handle options
        let handle = self.insert_body(Body::empty());
        let read_body = self.begin_streaming(handle)?;
        cache.insert(&key, options, read_body).await;
        Ok(handle)
    }

    async fn replace(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        cache_key: wiggle::GuestPtr<[u8]>,
        options_mask: types::CacheReplaceOptionsMask,
        abi_options: wiggle::GuestPtr<types::CacheReplaceOptions>,
    ) -> Result<types::CacheReplaceHandle, Error> {
        Err(Error::NotAvailable("Cache API primitives"))
    }

    async fn replace_get_age_ns(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        cache_handle: types::CacheReplaceHandle,
    ) -> Result<types::CacheDurationNs, Error> {
        Err(Error::NotAvailable("Cache API primitives"))
    }

    async fn replace_get_body(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        cache_handle: types::CacheReplaceHandle,
        options_mask: types::CacheGetBodyOptionsMask,
        options: &types::CacheGetBodyOptions,
    ) -> Result<types::BodyHandle, Error> {
        Err(Error::NotAvailable("Cache API primitives"))
    }

    async fn replace_get_hits(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        cache_handle: types::CacheReplaceHandle,
    ) -> Result<u64, Error> {
        Err(Error::NotAvailable("Cache API primitives"))
    }

    async fn replace_get_length(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        cache_handle: types::CacheReplaceHandle,
    ) -> Result<u64, Error> {
        Err(Error::NotAvailable("Cache API primitives"))
    }

    async fn replace_get_max_age_ns(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        cache_handle: types::CacheReplaceHandle,
    ) -> Result<types::CacheDurationNs, Error> {
        Err(Error::NotAvailable("Cache API primitives"))
    }

    async fn replace_get_stale_while_revalidate_ns(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        cache_handle: types::CacheReplaceHandle,
    ) -> Result<types::CacheDurationNs, Error> {
        Err(Error::NotAvailable("Cache API primitives"))
    }

    async fn replace_get_state(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        cache_handle: types::CacheReplaceHandle,
    ) -> Result<types::CacheLookupState, Error> {
        Err(Error::NotAvailable("Cache API primitives"))
    }

    async fn replace_get_user_metadata(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        cache_handle: types::CacheReplaceHandle,
        out_ptr: wiggle::GuestPtr<u8>,
        out_len: u32,
        nwritten_out: wiggle::GuestPtr<u32>,
    ) -> Result<(), Error> {
        Err(Error::NotAvailable("Cache API primitives"))
    }

    async fn replace_insert(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        cache_handle: types::CacheReplaceHandle,
        options_mask: types::CacheWriteOptionsMask,
        abi_options: wiggle::GuestPtr<types::CacheWriteOptions>,
    ) -> Result<types::BodyHandle, Error> {
        Err(Error::NotAvailable("Cache API primitives"))
    }

    async fn transaction_lookup(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        cache_key: wiggle::GuestPtr<[u8]>,
        options_mask: types::CacheLookupOptionsMask,
        options: wiggle::GuestPtr<types::CacheLookupOptions>,
    ) -> Result<types::CacheHandle, Error> {
        Err(Error::NotAvailable("Cache API primitives"))
    }

    async fn transaction_lookup_async(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        cache_key: wiggle::GuestPtr<[u8]>,
        options_mask: types::CacheLookupOptionsMask,
        options: wiggle::GuestPtr<types::CacheLookupOptions>,
    ) -> Result<types::CacheBusyHandle, Error> {
        Err(Error::NotAvailable("Cache API primitives"))
    }

    async fn cache_busy_handle_wait(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        handle: types::CacheBusyHandle,
    ) -> Result<types::CacheHandle, Error> {
        Err(Error::NotAvailable("Cache API primitives"))
    }

    async fn transaction_insert(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        handle: types::CacheHandle,
        options_mask: types::CacheWriteOptionsMask,
        options: wiggle::GuestPtr<types::CacheWriteOptions>,
    ) -> Result<types::BodyHandle, Error> {
        Err(Error::NotAvailable("Cache API primitives"))
    }

    async fn transaction_insert_and_stream_back(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        handle: types::CacheHandle,
        options_mask: types::CacheWriteOptionsMask,
        options: wiggle::GuestPtr<types::CacheWriteOptions>,
    ) -> Result<(types::BodyHandle, types::CacheHandle), Error> {
        Err(Error::NotAvailable("Cache API primitives"))
    }

    async fn transaction_update(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        handle: types::CacheHandle,
        options_mask: types::CacheWriteOptionsMask,
        options: wiggle::GuestPtr<types::CacheWriteOptions>,
    ) -> Result<(), Error> {
        Err(Error::NotAvailable("Cache API primitives"))
    }

    async fn transaction_cancel(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        handle: types::CacheHandle,
    ) -> Result<(), Error> {
        Err(Error::NotAvailable("Cache API primitives"))
    }

    async fn close_busy(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        handle: types::CacheBusyHandle,
    ) -> Result<(), Error> {
        Err(Error::NotAvailable("Cache API primitives"))
    }

    /// Wait for the lookup to be complete, then discard the results.
    async fn close(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        handle: types::CacheHandle,
    ) -> Result<(), Error> {
        let _ = self.take_cache_entry(handle)?.task().recv().await?;
        Ok(())
    }

    async fn get_state(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        handle: types::CacheHandle,
    ) -> Result<types::CacheLookupState, Error> {
        let entry = self.cache_entry_mut(handle).await?;

        let mut state = types::CacheLookupState::empty();
        if let Some(found) = entry.found() {
            state |= types::CacheLookupState::FOUND;

            if !found.meta().is_fresh() {
                state |= types::CacheLookupState::STALE;
            }
            // TODO:: stale-while-revalidate and go_get obligation.
            // For now, usable if fresh.
            if found.meta().is_fresh() {
                state |= types::CacheLookupState::USABLE;
            }
        }

        Ok(state)
    }

    async fn get_user_metadata(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        handle: types::CacheHandle,
        user_metadata_out_ptr: wiggle::GuestPtr<u8>,
        user_metadata_out_len: u32,
        nwritten_out: wiggle::GuestPtr<u32>,
    ) -> Result<(), Error> {
        Err(Error::NotAvailable("Cache API primitives"))
    }

    async fn get_body(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        handle: types::CacheHandle,
        options_mask: types::CacheGetBodyOptionsMask,
        options: &types::CacheGetBodyOptions,
    ) -> Result<types::BodyHandle, Error> {
        // TODO: cceckman-at-fastly: Handle options,
        // then remove this guard.
        if !std::env::var("ENABLE_EXPERIMENTAL_CACHE_API").is_ok_and(|v| v == "1") {
            return Err(Error::NotAvailable("Cache API primitives"));
        }

        // We wind up re-borrowing `found` and `self.session` several times here, to avoid
        // borrowing the both of them at once. Ultimately it is possible that inserting a body
        // would change the address of Found, by re-shuffling the AsyncItems table; once again,
        // borrowck wins the day.
        //
        // We have an exclusive borrow &mut self.session for the lifetime of this call,
        // so even though we're re-borrowing/repeating lookups, we know we won't run into TOCTOU.

        let found = self
            .cache_entry(handle.into())
            .await?
            .found()
            .ok_or_else(|| Error::CacheError("key was not found in cache".to_owned()))?;
        // Preemptively (optimistically) start a read. Don't worry, the Drop impl for Body will
        // clean up the copying task.
        // We have to do this to allow `found`'s lifetime to end before self.session.body, which
        // has to re-borrow self.self.session.
        let body = found.body()?;

        if let Some(prev_handle) = found.last_body_handle {
            // Check if they're still reading the previous handle.
            if self.body(prev_handle).is_ok() {
                // TODO: cceckman-at-fastly: more precise error types
                return Err(Error::CacheError(
                    format!("Found has a read outstanding already (BodyHandle {prev_handle}). Close this handle before reading")
            ).into());
            }
        };

        let body_handle = self.insert_body(body);
        // Finalize by committing the handle as "the last read".
        // We have to borrow `found` again, this time as mutable.
        self.cache_entry_mut(handle.into())
            .await?
            .found_mut()
            .unwrap()
            .last_body_handle = Some(body_handle.into());

        Ok(body_handle.into())
    }

    async fn get_length(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        handle: types::CacheHandle,
    ) -> Result<types::CacheObjectLength, Error> {
        Err(Error::NotAvailable("Cache API primitives"))
    }

    async fn get_max_age_ns(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        handle: types::CacheHandle,
    ) -> Result<types::CacheDurationNs, Error> {
        let entry = self.cache_entry_mut(handle).await?;
        if let Some(found) = entry.found() {
            Ok(found.meta().max_age().as_nanos().try_into().unwrap())
        } else {
            Err(Error::CacheError(
                "Attempted to read metadata from CacheHandle that was not Found".to_owned(),
            ))
        }
    }

    async fn get_stale_while_revalidate_ns(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        handle: types::CacheHandle,
    ) -> Result<types::CacheDurationNs, Error> {
        Err(Error::NotAvailable("Cache API primitives"))
    }

    async fn get_age_ns(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        handle: types::CacheHandle,
    ) -> Result<types::CacheDurationNs, Error> {
        let entry = self.cache_entry_mut(handle).await?;
        if let Some(found) = entry.found() {
            Ok(found.meta().age().as_nanos().try_into().unwrap())
        } else {
            Err(Error::CacheError(
                "Attempted to read metadata from CacheHandle that was not Found".to_owned(),
            ))
        }
    }

    async fn get_hits(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        handle: types::CacheHandle,
    ) -> Result<types::CacheHitCount, Error> {
        Err(Error::NotAvailable("Cache API primitives"))
    }
}
