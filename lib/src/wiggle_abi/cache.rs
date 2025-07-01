use core::str;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::HeaderMap;

use crate::body::Body;
use crate::cache::{CacheKey, SurrogateKeySet, VaryRule, WriteOptions};
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
    mut options_mask: types::CacheWriteOptionsMask,
    options: &types::CacheWriteOptions,
) -> Result<WriteOptions, Error> {
    // Headers must be handled before this:
    assert!(
        !options_mask.contains(CacheWriteOptionsMask::REQUEST_HEADERS),
        "Viceroy bug! headers must be handled before load_write_options"
    );

    // Clear each bit of options_mask as we handle it, to make sure we catch any unknown options.
    let max_age = Duration::from_nanos(options.max_age_ns);

    let initial_age = if options_mask.contains(CacheWriteOptionsMask::INITIAL_AGE_NS) {
        Duration::from_nanos(options.initial_age_ns)
    } else {
        Duration::ZERO
    };

    options_mask &= !CacheWriteOptionsMask::INITIAL_AGE_NS;

    let stale_while_revalidate =
        if options_mask.contains(CacheWriteOptionsMask::STALE_WHILE_REVALIDATE_NS) {
            Duration::from_nanos(options.stale_while_revalidate_ns)
        } else {
            Duration::ZERO
        };
    options_mask &= !CacheWriteOptionsMask::STALE_WHILE_REVALIDATE_NS;

    let vary_rule = if options_mask.contains(CacheWriteOptionsMask::VARY_RULE) {
        let slice = options.vary_rule_ptr.as_array(options.vary_rule_len);
        let vary_rule_bytes = memory.as_slice(slice)?.ok_or(Error::SharedMemory)?;
        let vary_rule_str = str::from_utf8(vary_rule_bytes).map_err(|e| Error::Utf8Expected(e))?;
        vary_rule_str.parse()?
    } else {
        VaryRule::default()
    };
    options_mask &= !CacheWriteOptionsMask::VARY_RULE;

    let user_metadata = if options_mask.contains(CacheWriteOptionsMask::USER_METADATA) {
        let slice = options
            .user_metadata_ptr
            .as_array(options.user_metadata_len);
        let user_metadata_bytes = memory.as_slice(slice)?.ok_or(Error::SharedMemory)?;
        Bytes::copy_from_slice(user_metadata_bytes)
    } else {
        Bytes::new()
    };
    options_mask &= !CacheWriteOptionsMask::USER_METADATA;

    let length = if options_mask.contains(CacheWriteOptionsMask::LENGTH) {
        Some(options.length)
    } else {
        None
    };
    options_mask &= !CacheWriteOptionsMask::LENGTH;

    let sensitive_data = options_mask.contains(CacheWriteOptionsMask::SENSITIVE_DATA);
    options_mask &= !CacheWriteOptionsMask::SENSITIVE_DATA;

    // SERVICE_ID differences are observable- but we don't implement that behavior. Error explicitly.
    if options_mask.contains(CacheWriteOptionsMask::SERVICE_ID) {
        return Err(Error::Unsupported {
            msg: "cache on_behalf_of is not supported in Viceroy",
        });
    }
    options_mask &= !CacheWriteOptionsMask::SERVICE_ID;

    let edge_max_age = if options_mask.contains(CacheWriteOptionsMask::EDGE_MAX_AGE_NS) {
        Duration::from_nanos(options.edge_max_age_ns)
    } else {
        max_age
    };
    if edge_max_age > max_age {
        tracing::error!(
            "deliver node max age {} must be less than TTL {}",
            edge_max_age.as_secs(),
            max_age.as_secs()
        );
        return Err(Error::InvalidArgument);
    }
    options_mask &= !CacheWriteOptionsMask::EDGE_MAX_AGE_NS;

    let surrogate_keys = if options_mask.contains(CacheWriteOptionsMask::SURROGATE_KEYS) {
        let slice = options
            .surrogate_keys_ptr
            .as_array(options.surrogate_keys_len);
        let surrogate_keys_bytes = memory.as_slice(slice)?.ok_or(Error::SharedMemory)?;
        surrogate_keys_bytes.try_into()?
    } else {
        SurrogateKeySet::default()
    };
    options_mask &= !CacheWriteOptionsMask::SURROGATE_KEYS;

    if !options_mask.is_empty() {
        return Err(Error::NotAvailable("unknown cache write option"));
    }

    Ok(WriteOptions {
        max_age,
        initial_age,
        stale_while_revalidate,
        vary_rule,
        user_metadata,
        length,
        sensitive_data,
        edge_max_age,
        surrogate_keys,
    })
}

fn load_lookup_options(
    session: &Session,
    memory: &wiggle::GuestMemory<'_>,
    mut options_mask: types::CacheLookupOptionsMask,
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

    options_mask &= !types::CacheLookupOptionsMask::REQUEST_HEADERS;

    if options_mask.contains(types::CacheLookupOptionsMask::SERVICE_ID) {
        // TODO: Support service-ID-keyed hashes, for testing internal services at Fastly
        return Err(Error::Unsupported {
            msg: "service ID in cache lookup is not supported in Viceroy",
        });
    }

    if !options_mask.is_empty() {
        return Err(Error::NotAvailable("unknown cache lookup option"));
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
        let key = load_cache_key(memory, cache_key)?;
        let guest_options = memory.read(options)?;

        // This is the only method that accepts REQUEST_HEADERS in the options mask.
        let request_headers = if options_mask.contains(CacheWriteOptionsMask::REQUEST_HEADERS) {
            let handle = guest_options.request_headers;
            let parts = self.request_parts(handle)?;
            parts.headers.clone()
        } else {
            HeaderMap::default()
        };
        let options = load_write_options(
            memory,
            options_mask & !CacheWriteOptionsMask::REQUEST_HEADERS,
            &guest_options,
        )?;
        let cache = Arc::clone(self.cache());

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
        // Ignore the "stream back" handle
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
        let guest_options = memory.read(options)?;
        // No request headers here; request headers come from the original lookup.
        if options_mask.contains(CacheWriteOptionsMask::REQUEST_HEADERS) {
            return Err(Error::InvalidArgument);
        }
        let options = load_write_options(memory, options_mask, &guest_options)?;

        // Optimistically start a body, so we don't have to reborrow &mut self
        let body_handle = self.insert_body(Body::empty());
        let read_body = self.begin_streaming(body_handle)?;

        let e = self
            .cache_entry_mut(handle)
            .await?
            .insert(options, read_body)?;

        // Return a new handle for the read end.
        let handle = self.insert_cache_op(PendingCacheTask::new(PeekableTask::complete(e)));

        Ok((body_handle, handle.into()))
    }

    async fn transaction_update(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        handle: types::CacheHandle,
        options_mask: types::CacheWriteOptionsMask,
        options: wiggle::GuestPtr<types::CacheWriteOptions>,
    ) -> Result<(), Error> {
        let guest_options = memory.read(options)?;
        // No request headers here; request headers come from the original lookup.
        if options_mask.contains(CacheWriteOptionsMask::REQUEST_HEADERS) {
            return Err(Error::InvalidArgument);
        }
        let options = load_write_options(memory, options_mask, &guest_options)?;

        let entry = self.cache_entry_mut(handle).await?;
        // The path here is:
        // InvalidCacheHandle -> FastlyStatus::BADF -> (ABI boundary) ->
        // CacheError::InvalidOperation
        entry.update(options)?;

        Ok(())
    }

    async fn transaction_cancel(
        &mut self,
        memory: &mut wiggle::GuestMemory<'_>,
        handle: types::CacheHandle,
    ) -> Result<(), Error> {
        let entry = self.cache_entry_mut(handle.into()).await?;
        if entry.cancel() {
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
            if found.meta().is_usable() {
                state |= types::CacheLookupState::USABLE;
            }
        }
        if entry.go_get().is_some() {
            state |= types::CacheLookupState::MUST_INSERT_OR_UPDATE;
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
        if !options_mask.is_empty() {
            return Err(Error::NotAvailable("unknown cache get_body option").into());
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
