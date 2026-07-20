use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use crate::body::{Body, Chunk};
use crate::cache::VaryRule;
use crate::sandbox::{PeekableTask, PendingHttpCacheTask, Sandbox};
use crate::streaming_body::StreamingBodyItem;
use crate::wiggle_abi::types::HttpCacheLookupOptions;

use super::fastly_http_cache::FastlyHttpCache;
use super::{Error, types};

use fst_cache::SurrogateKeySet;
use http::{HeaderMap, HeaderName};
use http_body::Body as HttpBody;
use wiggle::{GuestMemory, GuestPtr};

/// Maximum permitted length of an override cache key, in bytes.
const MAX_OVERRIDE_KEY_LEN: u32 = 32;

/// Maximum length of a vary rule. TODO: check how long this actually is.
const MAX_VARY_RULE_LEN: u32 = 4096;

/// Options that can be set during an HTTP cache lookup
struct LookupOptions {
    /// An overridden cache key
    override_key: Option<Vec<u8>>,
    backend_name: Option<String>,
}

/// Load the lookup options from memory
fn load_lookup_options(
    sandbox: &Sandbox,
    memory: &wiggle::GuestMemory<'_>,
    options_mask: types::HttpCacheLookupOptionsMask,
    options: GuestPtr<types::HttpCacheLookupOptions>,
) -> Result<LookupOptions, Error> {
    let HttpCacheLookupOptions {
        override_key_ptr,
        override_key_len,
        backend_name_ptr,
        backend_name_len,
    } = memory.read(options)?;

    let override_key = if options_mask.contains(types::HttpCacheLookupOptionsMask::OVERRIDE_KEY) {
        if override_key_len >= MAX_OVERRIDE_KEY_LEN {
            return Err(Error::InvalidArgument);
        }
        let v = memory.as_slice(override_key_ptr.as_array(override_key_len))?;
        Some(v.ok_or(Error::SharedMemory).map(ToOwned::to_owned)?)
    } else {
        None
    };
    let backend_name = if options_mask.contains(types::HttpCacheLookupOptionsMask::BACKEND_NAME) {
        let name = memory
            .as_slice(backend_name_ptr.as_array(backend_name_len))?
            .ok_or(Error::SharedMemory)?;
        let name = str::from_utf8(name)?;
        let _ = sandbox.backend(name).ok_or(Error::InvalidArgument)?;
        Some(name.to_owned())
    } else {
        None
    };

    Ok(LookupOptions {
        override_key,
        backend_name,
    })
}

fn load_write_options(
    memory: &wiggle::GuestMemory<'_>,
    options_mask: types::HttpCacheWriteOptionsMask,
    options: GuestPtr<types::HttpCacheWriteOptions>,
) -> Result<fst_http_cache::WriteOptions, Error> {
    let types::HttpCacheWriteOptions {
        max_age_ns,
        vary_rule_ptr,
        vary_rule_len,
        initial_age_ns,
        stale_while_revalidate_ns,
        surrogate_keys_ptr,
        surrogate_keys_len,
        length,
        stale_if_error_ns,
    } = memory.read(options)?;

    let vary_rule: Vec<HeaderName> =
        if options_mask.contains(types::HttpCacheWriteOptionsMask::VARY_RULE) {
            if vary_rule_len > MAX_VARY_RULE_LEN {
                return Err(Error::InvalidArgument)?;
            }
            let slice = vary_rule_ptr.as_array(vary_rule_len);
            let vary_rule_bytes = memory.as_slice(slice)?.ok_or(Error::SharedMemory)?;
            let vary_rule_str = str::from_utf8(vary_rule_bytes).map_err(Error::Utf8Expected)?;
            vary_rule_str.parse()?
        } else {
            VaryRule::default()
        }
        .into();
    // Note: max_age is a required option.
    let max_age = Duration::from_nanos(max_age_ns);
    let age = if options_mask.contains(types::HttpCacheWriteOptionsMask::INITIAL_AGE_NS) {
        Duration::from_nanos(initial_age_ns)
    } else {
        Duration::ZERO
    };
    let stale_while_revalidate =
        if options_mask.contains(types::HttpCacheWriteOptionsMask::STALE_WHILE_REVALIDATE_NS) {
            Duration::from_nanos(stale_while_revalidate_ns)
        } else {
            Duration::ZERO
        };
    let stale_if_error =
        if options_mask.contains(types::HttpCacheWriteOptionsMask::STALE_IF_ERROR_NS) {
            Duration::from_nanos(stale_if_error_ns)
        } else {
            Duration::ZERO
        };
    let length = if options_mask.contains(types::HttpCacheWriteOptionsMask::LENGTH) {
        Some(length)
    } else {
        None
    };

    let surrogate_keys = if options_mask.contains(types::HttpCacheWriteOptionsMask::SURROGATE_KEYS)
    {
        let slice = surrogate_keys_ptr.as_array(surrogate_keys_len);
        let surrogate_keys_bytes = memory.as_slice(slice)?.ok_or(Error::SharedMemory)?;
        let s = str::from_utf8(surrogate_keys_bytes).map_err(Error::Utf8Expected)?;
        SurrogateKeySet::from_str(s).map_err(|e| {
            tracing::warn!("HTTP cache was provided with invalid surrogate keys: {e}");
            Error::InvalidArgument
        })?
    } else {
        SurrogateKeySet::default()
    };

    let cache_object_meta = fst_http_cache::WriteOptions {
        max_age,
        initial_age: age,
        stale_while_revalidate,
        stale_if_error,
        vary_rule,
        length,
        sensitive_data: options_mask.contains(types::HttpCacheWriteOptionsMask::SENSITIVE_DATA),
        surrogate_keys,
    };

    Ok(cache_object_meta)
}

/// Get the number of nanoseconds in a [`Duration`], saturating the conversion to
/// `CacheDurationNs::MAX`.
pub(crate) fn as_nanos_saturating(duration: &Duration) -> types::CacheDurationNs {
    std::cmp::min(types::CacheDurationNs::MAX as u128, duration.as_nanos())
        as types::CacheDurationNs
}

/// Convert a vary rule to its ABI representation.
pub(crate) fn vary_rule_to_abi(vary_rule: &Vec<HeaderName>) -> Vec<u8> {
    let strings: Vec<_> = vary_rule.iter().map(|name| name.as_str()).collect();
    let joined = strings.join(" ");
    joined.into_bytes()
}

pub(crate) fn surrogate_keys_to_abi(surrogate_keys: &SurrogateKeySet) -> Vec<u8> {
    let strings: Vec<&str> = surrogate_keys.iter().map(std::ops::Deref::deref).collect();
    let joined = strings.join(" ");
    joined.into_bytes()
}

pub(crate) async fn into_handles(
    sandbox: &mut Sandbox,
    response: http::Response<impl fst_cache::Body>,
) -> (types::ResponseHandle, types::BodyHandle) {
    let (parts, body) = response.into_parts();
    let response_handle = sandbox.insert_response_parts(parts);

    let (tx, rx) = tokio::sync::mpsc::channel(1);

    // Copy from the ~anonymous body type of Found to a body handle we support.
    tokio::spawn(async move {
        use bytes::Buf;
        let mut body = std::pin::pin!(body);

        while let Some(Ok(mut buf)) = body.data().await {
            while buf.remaining() > 0 {
                let bytes = buf.copy_to_bytes(buf.remaining());
                if tx
                    .send(StreamingBodyItem::Chunk(Chunk::from(bytes)))
                    .await
                    .is_err()
                {
                    return;
                }
            }
        }
        if let Ok(trailers) = body.trailers().await {
            let trailers = trailers.unwrap_or_else(HeaderMap::default);
            if tx
                .send(StreamingBodyItem::Finished(trailers))
                .await
                .is_err()
            {
                return;
            }
        }
    });
    let body: Body = Body::from(rx);
    let body_handle = sandbox.insert_body(body);
    (response_handle, body_handle)
}

#[allow(unused_variables)]
impl FastlyHttpCache for Sandbox {
    async fn lookup(
        &mut self,
        memory: &mut GuestMemory<'_>,
        request: types::RequestHandle,
        options_mask: types::HttpCacheLookupOptionsMask,
        options: GuestPtr<types::HttpCacheLookupOptions>,
    ) -> Result<types::HttpCacheHandle, Error> {
        let req_parts: cache_semantics::RequestParts = self.request_parts(request)?.into();
        let LookupOptions {
            override_key,
            backend_name,
        } = load_lookup_options(self, memory, options_mask, options)?;

        let cache_key = if let Some(override_key) = override_key {
            override_key
        } else {
            self.http_cache().get_suggested_cache_key(&req_parts)?
        };

        let http_cache = self.http_cache().clone();
        let task = PeekableTask::spawn(Box::pin(async move {
            Ok(http_cache.lookup(&cache_key, &req_parts).await?)
        }))
        .await;

        Ok(self
            .insert_http_cache_op(PendingHttpCacheTask::new(task))
            .into())
    }

    async fn transaction_lookup(
        &mut self,
        memory: &mut GuestMemory<'_>,
        request: types::RequestHandle,
        options_mask: types::HttpCacheLookupOptionsMask,
        options: GuestPtr<types::HttpCacheLookupOptions>,
    ) -> Result<types::HttpCacheHandle, Error> {
        let req_parts: cache_semantics::RequestParts = self.request_parts(request)?.into();
        let LookupOptions {
            override_key,
            backend_name,
        } = load_lookup_options(self, memory, options_mask, options)?;

        let cache_key = if let Some(override_key) = override_key {
            override_key
        } else {
            self.http_cache().get_suggested_cache_key(&req_parts)?
        };

        let http_cache = self.http_cache().clone();
        let task = PeekableTask::spawn(Box::pin(async move {
            Ok(http_cache
                .transaction_lookup(&cache_key, &req_parts)
                .await?)
        }))
        .await;

        Ok(self
            .insert_http_cache_op(PendingHttpCacheTask::new(task))
            .into())
    }

    async fn transaction_insert(
        &mut self,
        memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
        response_handle: types::ResponseHandle,
        options_mask: types::HttpCacheWriteOptionsMask,
        abi_options: GuestPtr<types::HttpCacheWriteOptions>,
    ) -> Result<types::BodyHandle, Error> {
        let write_options = load_write_options(memory, options_mask, abi_options)?;

        let body = self.insert_body(Body::empty());
        let read_body = self.begin_streaming(body)?;

        // We have to copy Parts here because we can't borrow the response parts and the cache
        // entry from &self at the same time.
        let response = self.response_parts(response_handle)?;
        let mut response = http::response::Response::new(read_body);
        *response.status_mut() = response.status();
        *response.headers_mut() = response.headers().clone();

        // Get an additional reference to the HTTP cache, so we can borrow the cache entry...
        let http_cache = Arc::clone(self.http_cache());
        let cache_entry = self.http_cache_entry_mut(cache_handle).await?;
        http_cache
            .transaction_insert(cache_entry, response, write_options)
            .await?;
        Ok(body)
    }

    async fn transaction_insert_and_stream_back(
        &mut self,
        memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
        response_handle: types::ResponseHandle,
        options_mask: types::HttpCacheWriteOptionsMask,
        abi_options: GuestPtr<types::HttpCacheWriteOptions>,
    ) -> Result<(types::BodyHandle, types::HttpCacheHandle), Error> {
        let write_options = load_write_options(memory, options_mask, abi_options)?;

        let body = self.insert_body(Body::empty());
        let read_body = self.begin_streaming(body)?;

        // We have to copy Parts here because we can't borrow the response parts and the cache
        // entry from &self at the same time.
        let response = self.response_parts(response_handle)?;
        let mut response = http::response::Response::new(read_body);
        *response.status_mut() = response.status();
        *response.headers_mut() = response.headers().clone();

        // Get an additional reference to the HTTP cache, so we can borrow the cache entry...
        let http_cache = Arc::clone(self.http_cache());
        let cache_entry = self.http_cache_entry_mut(cache_handle).await?;
        let new_cache_entry = http_cache
            .transaction_insert_and_stream_back(cache_entry, response, write_options)
            .await;
        let new_handle = self.insert_http_cache_op(PendingHttpCacheTask::new(
            PeekableTask::Complete(new_cache_entry.map_err(Into::into)),
        ));
        Ok((body, new_handle.into()))
    }

    async fn transaction_update(
        &mut self,
        memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
        response_handle: types::ResponseHandle,
        options_mask: types::HttpCacheWriteOptionsMask,
        abi_options: GuestPtr<types::HttpCacheWriteOptions>,
    ) -> Result<(), Error> {
        let write_options = load_write_options(memory, options_mask, abi_options)?;

        // We have to copy Parts here because we can't borrow the response parts and the cache
        // entry from &self at the same time.
        let response: cache_semantics::ResponseParts = self.response_parts(response_handle)?.into();

        // Get an additional reference to the HTTP cache, so we can borrow the cache entry...
        let http_cache = Arc::clone(self.http_cache());
        let cache_entry = self.http_cache_entry_mut(cache_handle).await?;
        http_cache
            .transaction_update(cache_entry, response, write_options)
            .await?;
        Ok(())
    }

    async fn transaction_update_and_return_fresh(
        &mut self,
        memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
        response_handle: types::ResponseHandle,
        options_mask: types::HttpCacheWriteOptionsMask,
        abi_options: GuestPtr<types::HttpCacheWriteOptions>,
    ) -> Result<types::HttpCacheHandle, Error> {
        let write_options = load_write_options(memory, options_mask, abi_options)?;

        // We have to copy Parts here because we can't borrow the response parts and the cache
        // entry from &self at the same time.
        let response: cache_semantics::ResponseParts = self.response_parts(response_handle)?.into();

        // Get an additional reference to the HTTP cache, so we can borrow the cache entry...
        let http_cache = Arc::clone(self.http_cache());
        let cache_entry = self.http_cache_entry_mut(cache_handle).await?;
        let new_cache_entry = http_cache
            .transaction_update_and_return_fresh(cache_entry, response, write_options)
            .await;
        let new_handle = self.insert_http_cache_op(PendingHttpCacheTask::new(
            PeekableTask::Complete(new_cache_entry.map_err(Into::into)),
        ));
        Ok(new_handle.into())
    }

    async fn transaction_record_not_cacheable(
        &mut self,
        memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
        options_mask: types::HttpCacheWriteOptionsMask,
        abi_options: GuestPtr<types::HttpCacheWriteOptions>,
    ) -> Result<(), Error> {
        let write_options = load_write_options(memory, options_mask, abi_options)?;

        // Get an additional reference to the HTTP cache, so we can borrow the cache entry...
        let http_cache = Arc::clone(self.http_cache());
        let cache_entry = self.http_cache_entry_mut(cache_handle).await?;
        http_cache
            .transaction_record_not_cacheable(cache_entry, write_options)
            .await?;
        Ok(())
    }

    async fn transaction_abandon(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
    ) -> Result<(), Error> {
        let cache_entry = self.http_cache_entry_mut(cache_handle).await?;
        cache_entry.abandon();

        Ok(())
    }

    async fn transaction_choose_stale(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
    ) -> Result<(), Error> {
        let http_cache = Arc::clone(self.http_cache());
        let cache_entry = self.http_cache_entry_mut(cache_handle).await?;
        http_cache.transaction_choose_stale(cache_entry).await?;

        Ok(())
    }

    async fn close(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
    ) -> Result<(), Error> {
        let _ = self.take_http_cache_entry(cache_handle)?;
        Ok(())
    }

    fn is_request_cacheable(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        request_handle: types::RequestHandle,
    ) -> Result<u32, Error> {
        let req_parts = self.request_parts(request_handle)?;
        let is_cacheable = self.http_cache().is_request_cacheable(req_parts);
        Ok(is_cacheable as u32)
    }

    fn get_suggested_cache_key(
        &mut self,
        memory: &mut GuestMemory<'_>,
        request_handle: types::RequestHandle,
        key_out_ptr: GuestPtr<u8>,
        key_out_len: u32,
        nwritten_out: GuestPtr<u32>,
    ) -> Result<(), Error> {
        let req_parts = self.request_parts(request_handle)?;
        let key_out_bytes = self.http_cache().get_suggested_cache_key(req_parts)?;

        if key_out_bytes.len() > key_out_len as usize {
            // Write out the number of bytes necessary to fit the value, or zero on overflow to
            // signal an error condition.
            memory.write(nwritten_out, key_out_bytes.len().try_into().unwrap_or(0))?;
            return Err(Error::BufferLengthError {
                buf: "key_out",
                len: "key_out_max_len",
            });
        }
        let key_out_len =
            u32::try_from(key_out_bytes.len()).expect("smaller u32::MAX means it must fit");

        memory.copy_from_slice(&key_out_bytes, key_out_ptr.as_array(key_out_len))?;
        memory.write(nwritten_out, key_out_len)?;

        Ok(())
    }

    async fn get_suggested_backend_request(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
    ) -> Result<types::RequestHandle, Error> {
        let cache_entry = self.http_cache_entry_mut(cache_handle).await?;
        let parts = cache_entry.get_suggested_backend_request();
        Ok(self.insert_request_parts(parts))
    }

    async fn get_suggested_cache_options(
        &mut self,
        memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
        response_handle: types::ResponseHandle,
        options_wanted: types::HttpCacheWriteOptionsMask,
        pointers: GuestPtr<types::HttpCacheWriteOptions>,
        pointer_mask_out: GuestPtr<types::HttpCacheWriteOptionsMask>,
        options_out: GuestPtr<types::HttpCacheWriteOptions>,
    ) -> Result<(), Error> {
        let response: cache_semantics::ResponseParts = self.response_parts(response_handle)?.into();
        let cache_entry = self.http_cache_entry_mut(cache_handle).await?;
        let suggested_options = cache_entry.get_suggested_write_options(&response)?;

        let mut pointer_mask_to_write = types::HttpCacheWriteOptionsMask::empty();
        let mut buf_len_insufficient = false;

        // max-age is a required parameter; it doesn't have a bit in the mask
        memory.write(
            ptr_to_field!(
                options_out,
                types::HttpCacheWriteOptions::offset_of_max_age_ns(),
                types::CacheDurationNs
            )?,
            as_nanos_saturating(&suggested_options.max_age),
        )?;

        if options_wanted.contains(types::HttpCacheWriteOptionsMask::VARY_RULE) {
            // Flatten out the vary rule into a byte string, with keys interespersed with spaces.
            let abi_vary_rule = vary_rule_to_abi(&suggested_options.vary_rule);

            memory.write(
                ptr_to_field!(
                    options_out,
                    types::HttpCacheWriteOptions::offset_of_vary_rule_len(),
                    u32
                )?,
                abi_vary_rule
                    .len()
                    .try_into()
                    .expect("vary rule too large for ABI"),
            )?;
            pointer_mask_to_write.insert(types::HttpCacheWriteOptionsMask::VARY_RULE);

            let vary_rule_out = ptr_to_slice_from_fields!(
                memory,
                pointers,
                types::HttpCacheWriteOptions::offset_of_vary_rule_ptr(),
                types::HttpCacheWriteOptions::offset_of_vary_rule_len(),
                u8
            );
            let vary_rule_out_len = vary_rule_out.len();
            if (vary_rule_out_len as usize) < abi_vary_rule.len() {
                buf_len_insufficient = true;
            } else {
                memory.copy_from_slice(
                    &abi_vary_rule,
                    // This cast is safe as we know that `abi_vary_rule.len()` is <= a known u32
                    // value, `vary_rule_out_len`.
                    vary_rule_out.as_ptr().as_array(abi_vary_rule.len() as u32),
                )?;
                memory.write(
                    ptr_to_field!(
                        options_out,
                        types::HttpCacheWriteOptions::offset_of_vary_rule_ptr(),
                        u32
                    )?,
                    vary_rule_out.offset_base(),
                )?;
            }
        }

        if options_wanted.contains(types::HttpCacheWriteOptionsMask::INITIAL_AGE_NS) {
            pointer_mask_to_write.insert(types::HttpCacheWriteOptionsMask::INITIAL_AGE_NS);
            memory.write(
                ptr_to_field!(
                    options_out,
                    types::HttpCacheWriteOptions::offset_of_initial_age_ns(),
                    types::CacheDurationNs
                )?,
                as_nanos_saturating(&suggested_options.initial_age),
            )?;
        }

        if options_wanted.contains(types::HttpCacheWriteOptionsMask::STALE_WHILE_REVALIDATE_NS) {
            pointer_mask_to_write
                .insert(types::HttpCacheWriteOptionsMask::STALE_WHILE_REVALIDATE_NS);
            memory.write(
                ptr_to_field!(
                    options_out,
                    types::HttpCacheWriteOptions::offset_of_stale_while_revalidate_ns(),
                    types::CacheDurationNs
                )?,
                as_nanos_saturating(&suggested_options.stale_while_revalidate),
            )?;
        }

        if options_wanted.contains(types::HttpCacheWriteOptionsMask::STALE_IF_ERROR_NS) {
            pointer_mask_to_write.insert(types::HttpCacheWriteOptionsMask::STALE_IF_ERROR_NS);
            memory.write(
                ptr_to_field!(
                    options_out,
                    types::HttpCacheWriteOptions::offset_of_stale_if_error_ns(),
                    types::CacheDurationNs
                )?,
                as_nanos_saturating(&suggested_options.stale_if_error),
            )?;
        }

        if options_wanted.contains(types::HttpCacheWriteOptionsMask::SURROGATE_KEYS) {
            let abi_surrogate_keys = surrogate_keys_to_abi(&suggested_options.surrogate_keys);
            memory.write(
                ptr_to_field!(
                    options_out,
                    types::HttpCacheWriteOptions::offset_of_surrogate_keys_len(),
                    u32
                )?,
                abi_surrogate_keys
                    .len()
                    .try_into()
                    .expect("surrogate keys too large for ABI"),
            )?;
            pointer_mask_to_write.insert(types::HttpCacheWriteOptionsMask::SURROGATE_KEYS);

            let surrogate_keys_out = ptr_to_slice_from_fields!(
                memory,
                pointers,
                types::HttpCacheWriteOptions::offset_of_surrogate_keys_ptr(),
                types::HttpCacheWriteOptions::offset_of_surrogate_keys_len(),
                u8
            );
            let surrogate_keys_out_len = surrogate_keys_out.len();
            if (surrogate_keys_out_len as usize) < abi_surrogate_keys.len() {
                buf_len_insufficient = true;
            } else {
                memory.copy_from_slice(
                    &abi_surrogate_keys,
                    surrogate_keys_out
                        .as_ptr()
                        // This cast is safe as `abi_surrogate_keys.len()` is <= a known u32 value,
                        // `surrogate_keys_out_len`.
                        .as_array(abi_surrogate_keys.len() as u32),
                )?;
                memory.write(
                    ptr_to_field!(
                        options_out,
                        types::HttpCacheWriteOptions::offset_of_surrogate_keys_ptr(),
                        u32
                    )?,
                    surrogate_keys_out.offset_base(),
                )?;
            }
        }

        if options_wanted.contains(types::HttpCacheWriteOptionsMask::LENGTH) {
            if let Some(length) = suggested_options.length {
                pointer_mask_to_write.insert(types::HttpCacheWriteOptionsMask::LENGTH);
                memory.write(
                    ptr_to_field!(
                        options_out,
                        types::HttpCacheWriteOptions::offset_of_length(),
                        types::CacheObjectLength
                    )?,
                    length,
                )?;
            }
        }

        if options_wanted.contains(types::HttpCacheWriteOptionsMask::SENSITIVE_DATA)
            && suggested_options.sensitive_data
        {
            pointer_mask_to_write.insert(types::HttpCacheWriteOptionsMask::SENSITIVE_DATA);
        }

        memory.write(pointer_mask_out, pointer_mask_to_write)?;
        if buf_len_insufficient {
            Err(Error::BufferLengthError {
                buf: "pointers",
                len: "one of the pointers",
            })
        } else {
            Ok(())
        }
    }

    async fn prepare_response_for_storage(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
        response_handle: types::ResponseHandle,
    ) -> Result<(types::HttpStorageAction, types::ResponseHandle), Error> {
        let response: cache_semantics::ResponseParts = self.response_parts(response_handle)?.into();
        let cache_entry = self.http_cache_entry_mut(cache_handle).await?;
        let (action, response) = cache_entry.prepare_response_for_storage(&response)?;

        let abi_action = match action {
            fst_http_cache::StorageAction::Insert => types::HttpStorageAction::Insert,
            fst_http_cache::StorageAction::Update => types::HttpStorageAction::Update,
            fst_http_cache::StorageAction::DoNotStore => types::HttpStorageAction::DoNotStore,
            fst_http_cache::StorageAction::RecordUncacheable => {
                types::HttpStorageAction::RecordUncacheable
            }
        };

        let handle = self.insert_response_parts(response);
        Ok((abi_action, handle))
    }

    async fn get_found_response(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
        transform_for_client: u32,
    ) -> Result<(types::ResponseHandle, types::BodyHandle), Error> {
        let cache_entry = self.http_cache_entry_mut(cache_handle).await?;
        let Some(found) = cache_entry.found_response(transform_for_client == 1).await else {
            return Err(Error::ValueAbsent);
        };
        let handles = into_handles(self, found).await;

        Ok(handles)
    }

    async fn get_state(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
    ) -> Result<types::CacheLookupState, Error> {
        let cache_entry = self.http_cache_entry_mut(cache_handle).await?;

        let mut state = types::CacheLookupState::empty();
        if cache_entry.must_insert_or_update() {
            state |= types::CacheLookupState::MUST_INSERT_OR_UPDATE;
        }
        // TODO: A response can be "usable" if it is streamed back from a request collapse,
        // even if it is "already expired" according to its header data.
        // We don't account for that here.
        if let Some(stage) = cache_entry.lifecycle_stage() {
            match stage {
                fst_cache::LifecycleStage::Fresh => {
                    state |= types::CacheLookupState::FOUND | types::CacheLookupState::USABLE;
                }
                fst_cache::LifecycleStage::StaleWhileRevalidate => {
                    state |= types::CacheLookupState::FOUND
                        | types::CacheLookupState::USABLE
                        | types::CacheLookupState::STALE;
                }
                fst_cache::LifecycleStage::StaleIfError => {
                    state |= types::CacheLookupState::USABLE_IF_ERROR;
                    if !cache_entry.must_insert_or_update() {
                        // We aren't responsible for the revalidation -- so the revalidation must
                        // have already occurred, and we can use this response.
                        state |= types::CacheLookupState::FOUND | types::CacheLookupState::USABLE;
                    }
                }
                fst_cache::LifecycleStage::Expired => {
                    // Note: even though _techincally_ something was FOUND, we don't set the bit
                    // for consistency with the core cache API which always sets FOUND|USABLE
                    // together.
                }
            }
        }

        Ok(state)
    }

    async fn get_length(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
    ) -> Result<types::CacheObjectLength, Error> {
        self.http_cache_entry_mut(cache_handle)
            .await?
            .get_cache_meta()
            .and_then(|meta| meta.length)
            .ok_or(Error::ValueAbsent)
    }

    async fn get_max_age_ns(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
    ) -> Result<types::CacheDurationNs, Error> {
        self.http_cache_entry_mut(cache_handle)
            .await?
            .get_cache_meta()
            .map(|meta| meta.max_age.as_nanos().try_into().unwrap_or(u64::MAX))
            .ok_or(Error::ValueAbsent)
    }

    async fn get_stale_while_revalidate_ns(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
    ) -> Result<types::CacheDurationNs, Error> {
        self.http_cache_entry_mut(cache_handle)
            .await?
            .get_cache_meta()
            .map(|meta| as_nanos_saturating(&meta.stale_while_revalidate))
            .ok_or(Error::ValueAbsent)
    }

    async fn get_stale_if_error_ns(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
    ) -> Result<types::CacheDurationNs, Error> {
        self.http_cache_entry_mut(cache_handle)
            .await?
            .get_cache_meta()
            .map(|meta| as_nanos_saturating(&meta.stale_if_error))
            .ok_or(Error::ValueAbsent)
    }

    async fn get_age_ns(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
    ) -> Result<types::CacheDurationNs, Error> {
        self.http_cache_entry_mut(cache_handle)
            .await?
            .get_cache_meta()
            .map(|meta| as_nanos_saturating(&meta.age))
            .ok_or(Error::ValueAbsent)
    }

    async fn get_hits(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
    ) -> Result<types::CacheHitCount, Error> {
        // We don't keep track of hits.
        self.http_cache_entry_mut(cache_handle)
            .await?
            .get_cache_meta()
            .map(|_meta| 0)
            .ok_or(Error::ValueAbsent)
    }

    async fn get_sensitive_data(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
    ) -> Result<types::IsSensitive, Error> {
        let sensitive_data = self
            .http_cache_entry_mut(cache_handle)
            .await?
            .sensitive_data()
            .ok_or(Error::ValueAbsent)?;
        Ok(sensitive_data as u32)
    }

    async fn get_surrogate_keys(
        &mut self,
        memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
        surrogate_keys_out_ptr: GuestPtr<u8>,
        surrogate_keys_out_len: u32,
        nwritten_out: GuestPtr<u32>,
    ) -> Result<(), Error> {
        let surrogate_keys = self
            .http_cache_entry_mut(cache_handle)
            .await?
            .get_cache_meta()
            .map(|meta| &meta.surrogate_keys)
            .ok_or(Error::ValueAbsent)?;
        let abi_surrogate_keys = surrogate_keys_to_abi(&surrogate_keys);

        let surrogate_keys_out: GuestPtr<[u8]> =
            GuestPtr::new((surrogate_keys_out_ptr.offset(), surrogate_keys_out_len));
        if (surrogate_keys_out_len as usize) < abi_surrogate_keys.len() {
            // Write the value needed, or 0 to indicate overflow.
            memory.write(
                nwritten_out,
                abi_surrogate_keys.len().try_into().unwrap_or(0),
            )?;
            Err(Error::BufferLengthError {
                buf: "surrogate_keys_out",
                len: "surrogate_keys_out_len",
            })
        } else {
            memory.copy_from_slice(
                &abi_surrogate_keys,
                surrogate_keys_out
                    .as_ptr()
                    // This cast is safe as `abi_surrogate_keys.len()` is <= a known u32 value,
                    // `surrogate_keys_out_len`.
                    .as_array(abi_surrogate_keys.len() as u32),
            )?;
            memory.write(nwritten_out, abi_surrogate_keys.len() as u32)?;
            Ok(())
        }
    }

    async fn get_vary_rule(
        &mut self,
        memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
        vary_rule_out_ptr: GuestPtr<u8>,
        vary_rule_out_len: u32,
        nwritten_out: GuestPtr<u32>,
    ) -> Result<(), Error> {
        let vary_rule = self
            .http_cache_entry_mut(cache_handle)
            .await?
            .get_cache_meta()
            .map(|meta| &meta.vary_rule)
            .ok_or(Error::ValueAbsent)?;
        let abi_vary_rule = vary_rule_to_abi(vary_rule);

        let vary_rule_out: GuestPtr<[u8]> =
            GuestPtr::new((vary_rule_out_ptr.offset(), vary_rule_out_len));
        if (vary_rule_out_len as usize) < abi_vary_rule.len() {
            // Write the value needed, or 0 to indicate overflow.
            memory.write(nwritten_out, abi_vary_rule.len().try_into().unwrap_or(0))?;
            Err(Error::BufferLengthError {
                buf: "vary_rule_out",
                len: "vary_rule_out_len",
            })
        } else {
            memory.copy_from_slice(
                &abi_vary_rule,
                vary_rule_out
                    .as_ptr()
                    // This cast is safe as `abi_vary_rule.len()` is <= a known u32 value,
                    // `vary_rule_out_len`.
                    .as_array(abi_vary_rule.len() as u32),
            )?;
            memory.write(nwritten_out, abi_vary_rule.len() as u32)?;
            Ok(())
        }
    }
}
