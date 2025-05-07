use core::str;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::HeaderMap;

use crate::body::Body;
use crate::cache::{CacheKey, VaryRule, WriteOptions};
use crate::error::HandleError;
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
    let user_metadata = if options_mask.contains(CacheWriteOptionsMask::USER_METADATA) {
        let slice = options
            .user_metadata_ptr
            .as_array(options.user_metadata_len);
        let user_metadata_bytes = memory.as_slice(slice)?.ok_or(Error::SharedMemory)?;
        Bytes::copy_from_slice(user_metadata_bytes)
    } else {
        Bytes::new()
    };
    let length = if options_mask.contains(CacheWriteOptionsMask::LENGTH) {
        Some(options.length)
    } else {
        None
    };

    let sensitive_data = options_mask.contains(CacheWriteOptionsMask::SENSITIVE_DATA);

    // SERVICE_ID differences are observable- but we don't implement that behavior. Error explicitly.
    if options_mask.contains(CacheWriteOptionsMask::SERVICE_ID) {
        return Err(Error::Unsupported {
            msg: "cache on_behalf_of is not supported in Viceroy",
        });
    }

    Ok(WriteOptions {
        max_age,
        initial_age,
        vary_rule,
        user_metadata,
        length,
        sensitive_data,
    })
}

fn load_lookup_options(
    session: &Session,
    memory: &wiggle::GuestMemory<'_>,
    options_mask: types::CacheLookupOptionsMask,
    options: wiggle::GuestPtr<types::CacheLookupOptions>,
) -> Result<HeaderMap, Error> {
    let options = memory.read(options)?;
    let headers = if options_mask.contains(types::CacheLookupOptionsMask::REQUEST_HEADERS) {
        let handle = options.request_headers;
        let parts = session.request_parts(handle)?;
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
    Ok(headers)
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
        let headers = load_lookup_options(self, memory, options_mask, options)?;
        let key = load_cache_key(memory, cache_key)?;
        let cache = Arc::clone(self.cache());

        let task = PeekableTask::spawn(Box::pin(
            async move { Ok(cache.lookup(&key, &headers).await) },
        ))
        .await;
        let task = PendingCacheTask::new(task);
        let handle = self.insert_cache_op(task);
        Ok(handle.into())
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
        // This is the only method that accepts REQUEST_HEADERS in the options mask.
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
        let h = self
            .transaction_lookup_async(memory, cache_key, options_mask, options)
            .await?;
        self.cache_busy_handle_wait(memory, h).await
    }

    async fn transaction_lookup_async(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        cache_key: wiggle::GuestPtr<[u8]>,
        options_mask: types::CacheLookupOptionsMask,
        options: wiggle::GuestPtr<types::CacheLookupOptions>,
    ) -> Result<types::CacheBusyHandle, Error> {
        let headers = load_lookup_options(self, memory, options_mask, options)?;
        let key = load_cache_key(memory, cache_key)?;
        let cache = Arc::clone(self.cache());

        // Look up once, joining the transaction only if obligated:
        let e = cache.transaction_lookup(&key, &headers, false).await;
        let ready = e.found().is_some() || e.go_get().is_some();
        // If we already got _something_, we can provide an already-complete PeekableTask.
        // Otherwise we need to spawn it and let it block in the background.
        let task = if ready {
            PeekableTask::complete(e)
        } else {
            PeekableTask::spawn(Box::pin(async move {
                Ok(cache.transaction_lookup(&key, &headers, true).await)
            }))
            .await
        };

        let task = PendingCacheTask::new(task);
        let handle = self.insert_cache_op(task);
        Ok(handle.into())
    }

    async fn cache_busy_handle_wait(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        handle: types::CacheBusyHandle,
    ) -> Result<types::CacheHandle, Error> {
        let handle = handle.into();
        // Swap out for a distinct handle, so we don't hit a repeated `close`+`close_busy`:
        let entry = self.cache_entry_mut(handle).await?;
        let mut other_entry = entry.stub();
        std::mem::swap(entry, &mut other_entry);
        let task = PeekableTask::spawn(Box::pin(async move { Ok(other_entry) })).await;
        Ok(self.insert_cache_op(PendingCacheTask::new(task)).into())
    }

    async fn transaction_insert(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        handle: types::CacheHandle,
        options_mask: types::CacheWriteOptionsMask,
        options: wiggle::GuestPtr<types::CacheWriteOptions>,
    ) -> Result<types::BodyHandle, Error> {
        let (body, cache_handle) = self
            .transaction_insert_and_stream_back(memory, handle, options_mask, options)
            .await?;
        let _ = self.take_cache_entry(cache_handle)?;
        Ok(body)
    }

    async fn transaction_insert_and_stream_back(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        handle: types::CacheHandle,
        options_mask: types::CacheWriteOptionsMask,
        options: wiggle::GuestPtr<types::CacheWriteOptions>,
    ) -> Result<(types::BodyHandle, types::CacheHandle), Error> {
        // TODO: cceckman-at-fastly: Handle all options,
        // then remove this guard.
        if !std::env::var("ENABLE_EXPERIMENTAL_CACHE_API").is_ok_and(|v| v == "1") {
            return Err(Error::NotAvailable("Cache API primitives"));
        }

        let guest_options = memory.read(options)?;
        let options = load_write_options(memory, options_mask, &guest_options)?;
        // No request headers here; request headers come from the original lookup.
        if options_mask.contains(CacheWriteOptionsMask::REQUEST_HEADERS) {
            return Err(Error::InvalidArgument);
        }

        let entry = self.cache_entry_mut(handle).await?;
        // The path here is:
        // InvalidCacheHandle -> FastlyStatus::BADF -> (ABI boundary) ->
        // CacheError::InvalidOperation
        let obligation = entry
            .take_go_get()
            .ok_or(Error::HandleError(HandleError::InvalidCacheHandle(handle)))?;

        let body_handle = self.insert_body(Body::empty());
        let read_body = self.begin_streaming(body_handle)?;

        obligation.complete(options, read_body);
        Ok((body_handle, handle))
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
        let entry = self.cache_entry_mut(handle.into()).await?;
        if let Some(_) = entry.take_go_get() {
            Ok(())
        } else {
            Err(Error::CacheError(crate::cache::Error::CannotWrite).into())
        }
    }

    async fn close_busy(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        handle: types::CacheBusyHandle,
    ) -> Result<(), Error> {
        // Don't wait for the transaction to complete; drop the future to cancel.
        let _ = self.take_cache_entry(handle.into())?;
        Ok(())
    }

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
            // TODO:: stale-while-revalidate.
            // For now, usable if fresh.
            if found.meta().is_fresh() {
                state |= types::CacheLookupState::USABLE;
            }
        }
        if entry.go_get().is_some() {
            state |= types::CacheLookupState::MUST_INSERT_OR_UPDATE
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
        let entry = self.cache_entry(handle.into()).await?;

        let md_bytes = entry
            .found()
            .map(|found| found.meta().user_metadata())
            .ok_or(crate::Error::CacheError(crate::cache::Error::Missing))?;
        let len: u32 = md_bytes
            .len()
            .try_into()
            .expect("user metadata must be shorter than u32 can indicate");
        if len > user_metadata_out_len {
            memory.write(nwritten_out, len)?;
            return Err(Error::BufferLengthError {
                buf: "user_metadata_out_ptr",
                len: "user_metadata_out_len",
            });
        }
        let user_metadata = memory
            .as_slice_mut(user_metadata_out_ptr.as_array(user_metadata_out_len))?
            .ok_or(Error::SharedMemory)?;
        user_metadata[..(len as usize)].copy_from_slice(&md_bytes);
        memory.write(nwritten_out, len)?;

        Ok(())
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
            .ok_or(Error::CacheError(crate::cache::Error::Missing))?;
        // Preemptively (optimistically) start a read. Don't worry, the Drop impl for Body will
        // clean up the copying task.
        // We have to do this to allow `found`'s lifetime to end before self.session.body, which
        // has to re-borrow self.self.session.
        let body = found.body()?;

        if let Some(prev_handle) = found.last_body_handle {
            // Check if they're still reading the previous handle.
            if self.body(prev_handle).is_ok() {
                return Err(Error::CacheError(crate::cache::Error::HandleBodyUsed));
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
        let found = self
            .cache_entry(handle.into())
            .await?
            .found()
            .ok_or(Error::CacheError(crate::cache::Error::Missing))?;
        found
            .length()
            .ok_or(Error::CacheError(crate::cache::Error::Missing))
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
            Err(Error::CacheError(crate::cache::Error::Missing))
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
            Err(Error::CacheError(crate::cache::Error::Missing))
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
