use core::str;
use std::sync::Arc;
use std::time::Duration;

use http::HeaderMap;

use crate::body::Body;
use crate::cache::{CacheKey, VaryRule, WriteOptions};
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
    memory: &wiggle::GuestMemory<'_>,
    options_mask: types::CacheWriteOptionsMask,
    options: &types::CacheWriteOptions,
) -> Result<WriteOptions, Error> {
    let max_age = Duration::from_nanos(options.max_age_ns);
    let initial_age = if options_mask.contains(CacheWriteOptionsMask::INITIAL_AGE_NS) {
        Duration::from_nanos(options.initial_age_ns)
    } else {
        Duration::ZERO
    };
    let vary_rule = if options_mask.contains(CacheWriteOptionsMask::VARY_RULE) {
        let slice = options.vary_rule_ptr.as_array(options.vary_rule_len);
        let vary_rule_bytes = memory.as_slice(slice)?.ok_or(Error::SharedMemory)?;
        let vary_rule_str = str::from_utf8(vary_rule_bytes).map_err(|e| Error::Utf8Expected(e))?;
        vary_rule_str.parse()?
    } else {
        VaryRule::default()
    };

    Ok(WriteOptions {
        max_age,
        initial_age,
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
        let options = memory.read(options)?;
        let headers = if options_mask.contains(types::CacheLookupOptionsMask::REQUEST_HEADERS) {
            let handle = options.request_headers;
            let parts = self.request_parts(handle)?;
            parts.headers.clone()
        } else {
            HeaderMap::default()
        };
        if options_mask.contains(types::CacheLookupOptionsMask::SERVICE_ID) {
            // TODO: Support service-ID-keyed hashes, for testing internal services at Fastly
            return Err(Error::Unsupported {
                msg: "service ID in cache lookup",
            });
        }

        let key = load_cache_key(memory, cache_key)?;
        let cache = Arc::clone(self.cache());

        let task = PeekableTask::spawn(Box::pin(
            async move { Ok(cache.lookup(&key, &headers).await) },
        ))
        .await;
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
        // TODO: cceckman-at-fastly: Handle all options,
        // then remove this guard.
        if !std::env::var("ENABLE_EXPERIMENTAL_CACHE_API").is_ok_and(|v| v == "1") {
            return Err(Error::NotAvailable("Cache API primitives"));
        }
        let key = load_cache_key(memory, cache_key)?;
        let guest_options = memory.read(options)?;
        let options = load_write_options(memory, options_mask, &guest_options)?;
        let cache = Arc::clone(self.cache());
        // This is the only method that accepts REQUEST_HEADERS in the optons mask.
        let request_headers = if options_mask.contains(CacheWriteOptionsMask::REQUEST_HEADERS) {
            let handle = guest_options.request_headers;
            let parts = self.request_parts(handle)?;
            parts.headers.clone()
        } else {
            HeaderMap::default()
        };

        // TODO: cceckman-at-fastly - handle options
        let handle = self.insert_body(Body::empty());
        let read_body = self.begin_streaming(handle)?;
        cache
            .insert(&key, request_headers, options, read_body)
            .await;
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
        // TODO: cceckman-at-fastly ; options
        let entry = self.cache_entry_mut(handle).await?;

        let Some(found) = entry.found() else {
            return Err(Error::CacheError("key was not found in cache".to_owned()));
        };
        let body = found.body()?;

        Ok(self.insert_body(body))
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
