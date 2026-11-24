use std::str;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use http::{HeaderName, HeaderValue, Response, header};

use crate::body::Body;
use crate::cache::http_semantics::{
    self, HTTP_CACHE_KEY_LENGTH, HttpRequestHead, HttpResponseMeta, StorageAction,
};
use crate::cache::{CacheEntry, CacheKey, SurrogateKeySet, VaryRule, WriteOptions};
use crate::sandbox::{PeekableTask, PendingCacheTask, Sandbox};
use crate::wiggle_abi::types::{
    CacheHandle, HttpCacheLookupOptionsMask, HttpCacheWriteOptionsMask,
};

use super::fastly_http_cache::FastlyHttpCache;
use super::{Error, types};

use wiggle::{GuestMemory, GuestPtr};

fn missing() -> Error {
    Error::CacheError(crate::cache::Error::Missing)
}

fn duration_ns(d: Duration) -> u64 {
    d.as_nanos().try_into().unwrap_or(u64::MAX)
}

/// Parse a space-separated vary rule. An empty rule is valid, and varies on nothing.
fn parse_vary_rule(s: &str) -> Result<VaryRule, Error> {
    let names = s
        .split_ascii_whitespace()
        .map(HeaderName::try_from)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| Error::InvalidArgument)?;
    Ok(VaryRule::new(names.iter()))
}

/// Write `bytes` to a guest buffer, reporting the required length if the buffer is too short.
fn write_buffer(
    memory: &mut GuestMemory<'_>,
    bytes: &[u8],
    out_ptr: GuestPtr<u8>,
    out_len: u32,
    nwritten_out: GuestPtr<u32>,
    buf: &'static str,
    len: &'static str,
) -> Result<(), Error> {
    let needed: u32 = bytes.len().try_into().map_err(|_| Error::InvalidArgument)?;
    memory.write(nwritten_out, needed)?;
    if needed > out_len {
        return Err(Error::BufferLengthError { buf, len });
    }
    let out = memory
        .as_slice_mut(out_ptr.as_array(needed))?
        .ok_or(Error::SharedMemory)?;
    out.copy_from_slice(bytes);
    Ok(())
}

/// HTTP cache write options that are not part of the core cache `WriteOptions`.
struct HttpWriteOptions {
    options: WriteOptions,
    stale_if_error: Duration,
    sensitive_data: bool,
}

fn load_http_write_options(
    memory: &GuestMemory<'_>,
    mut options_mask: HttpCacheWriteOptionsMask,
    options: &types::HttpCacheWriteOptions,
) -> Result<HttpWriteOptions, Error> {
    let mut write_options = WriteOptions::new(Duration::from_nanos(options.max_age_ns));

    if options_mask.contains(HttpCacheWriteOptionsMask::VARY_RULE) {
        let slice = options.vary_rule_ptr.as_array(options.vary_rule_len);
        let bytes = memory.as_slice(slice)?.ok_or(Error::SharedMemory)?;
        let rule = str::from_utf8(bytes).map_err(Error::Utf8Expected)?;
        write_options.vary_rule = parse_vary_rule(rule)?;
    }
    options_mask &= !HttpCacheWriteOptionsMask::VARY_RULE;

    if options_mask.contains(HttpCacheWriteOptionsMask::INITIAL_AGE_NS) {
        write_options.initial_age = Duration::from_nanos(options.initial_age_ns);
    }
    options_mask &= !HttpCacheWriteOptionsMask::INITIAL_AGE_NS;

    if options_mask.contains(HttpCacheWriteOptionsMask::STALE_WHILE_REVALIDATE_NS) {
        write_options.stale_while_revalidate =
            Duration::from_nanos(options.stale_while_revalidate_ns);
    }
    options_mask &= !HttpCacheWriteOptionsMask::STALE_WHILE_REVALIDATE_NS;

    if options_mask.contains(HttpCacheWriteOptionsMask::SURROGATE_KEYS) {
        let slice = options
            .surrogate_keys_ptr
            .as_array(options.surrogate_keys_len);
        let bytes = memory.as_slice(slice)?.ok_or(Error::SharedMemory)?;
        write_options.surrogate_keys = SurrogateKeySet::try_from(bytes)?;
    }
    options_mask &= !HttpCacheWriteOptionsMask::SURROGATE_KEYS;

    if options_mask.contains(HttpCacheWriteOptionsMask::LENGTH) {
        write_options.length = Some(options.length);
    }
    options_mask &= !HttpCacheWriteOptionsMask::LENGTH;

    let sensitive_data = options_mask.contains(HttpCacheWriteOptionsMask::SENSITIVE_DATA);
    write_options.sensitive_data = sensitive_data;
    options_mask &= !HttpCacheWriteOptionsMask::SENSITIVE_DATA;

    let stale_if_error = if options_mask.contains(HttpCacheWriteOptionsMask::STALE_IF_ERROR_NS) {
        Duration::from_nanos(options.stale_if_error_ns)
    } else {
        Duration::ZERO
    };
    options_mask &= !HttpCacheWriteOptionsMask::STALE_IF_ERROR_NS;

    options_mask &= !HttpCacheWriteOptionsMask::RESERVED;
    if !options_mask.is_empty() {
        return Err(Error::NotAvailable("unknown HTTP cache write option"));
    }

    Ok(HttpWriteOptions {
        options: write_options,
        stale_if_error,
        sensitive_data,
    })
}

/// The error returned by every HTTP cache hostcall when the HTTP cache API is disabled.
///
/// SDKs check `is_request_cacheable` for this error to decide whether to fall back to host-side
/// caching.
fn disabled() -> Error {
    Error::Unsupported {
        msg: "the HTTP cache API is disabled; enable it with --enable-http-cache",
    }
}

impl Sandbox {
    fn check_http_cache_enabled(&self) -> Result<(), Error> {
        if self.ctx().enable_http_cache() {
            Ok(())
        } else {
            Err(disabled())
        }
    }

    /// Shared implementation of `lookup` and `transaction_lookup`.
    async fn http_cache_lookup(
        &mut self,
        memory: &mut GuestMemory<'_>,
        request: types::RequestHandle,
        mut options_mask: HttpCacheLookupOptionsMask,
        options: GuestPtr<types::HttpCacheLookupOptions>,
        transactional: bool,
    ) -> Result<types::HttpCacheHandle, Error> {
        self.check_http_cache_enabled()?;
        let head = Arc::new(HttpRequestHead::from_parts(self.request_parts(request)?));

        let override_key = if options_mask.is_empty() {
            None
        } else {
            let options = memory.read(options)?;
            let key = if options_mask.contains(HttpCacheLookupOptionsMask::OVERRIDE_KEY) {
                let slice = options.override_key_ptr.as_array(options.override_key_len);
                let bytes = memory.as_slice(slice)?.ok_or(Error::SharedMemory)?;
                if bytes.len() != HTTP_CACHE_KEY_LENGTH {
                    return Err(Error::InvalidArgument);
                }
                Some(bytes.to_vec())
            } else {
                None
            };
            options_mask &= !HttpCacheLookupOptionsMask::OVERRIDE_KEY;
            // The backend name does not affect lookups in Viceroy.
            options_mask &= !HttpCacheLookupOptionsMask::BACKEND_NAME;
            options_mask &= !HttpCacheLookupOptionsMask::RESERVED;
            if !options_mask.is_empty() {
                return Err(Error::NotAvailable("unknown HTTP cache lookup option"));
            }
            key
        };
        let key: CacheKey = override_key
            .unwrap_or_else(|| http_semantics::suggested_cache_key(&head).to_vec())
            .try_into()?;

        let cache = Arc::clone(self.cache());
        let finish = |entry: CacheEntry, head: Arc<HttpRequestHead>| {
            if let Some(http) = entry.found().and_then(|found| found.meta().http()) {
                http.record_hit();
            }
            entry.with_http_request(head)
        };

        let task = if transactional {
            // Look up once, joining the transaction only if obligated:
            let entry = cache.transaction_lookup(&key, &head.headers, false).await;
            if entry.found().is_some() || entry.go_get().is_some() {
                PeekableTask::complete(finish(entry, head))
            } else {
                PeekableTask::spawn(Box::pin(async move {
                    let entry = cache.transaction_lookup(&key, &head.headers, true).await;
                    Ok(finish(entry, head))
                }))
                .await
            }
        } else {
            let entry = cache.lookup(&key, &head.headers).await;
            PeekableTask::complete(finish(entry, head))
        };

        Ok(self.insert_cache_op(PendingCacheTask::new(task)).into())
    }

    /// Insert a response, returning the body to write and a handle to read the inserted object.
    async fn http_cache_insert(
        &mut self,
        memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
        response_handle: types::ResponseHandle,
        options_mask: HttpCacheWriteOptionsMask,
        abi_options: GuestPtr<types::HttpCacheWriteOptions>,
    ) -> Result<(types::BodyHandle, types::HttpCacheHandle), Error> {
        let guest_options = memory.read(abi_options)?;
        let options =
            self.http_write_options(memory, options_mask, &guest_options, response_handle)?;
        let handle: CacheHandle = cache_handle.into();

        let body_handle = self.insert_body(Body::empty());
        let read_body = self.begin_streaming(body_handle)?;
        let entry = self
            .cache_entry_mut(handle)
            .await?
            .insert(options, read_body)?;
        let handle = self.insert_cache_op(PendingCacheTask::new(PeekableTask::complete(entry)));
        Ok((body_handle, handle.into()))
    }

    /// Build the write options for an insert or update.
    ///
    /// NOTE: The ABI documents that the response is consumed, but guests (e.g. js-compute) keep
    /// using the response handle afterwards, so we only copy it.
    fn http_write_options(
        &mut self,
        memory: &GuestMemory<'_>,
        options_mask: HttpCacheWriteOptionsMask,
        guest_options: &types::HttpCacheWriteOptions,
        response_handle: types::ResponseHandle,
    ) -> Result<WriteOptions, Error> {
        let HttpWriteOptions {
            mut options,
            stale_if_error,
            sensitive_data,
        } = load_http_write_options(memory, options_mask, guest_options)?;
        let response = self.response_parts(response_handle)?;
        options.http = Some(Arc::new(HttpResponseMeta::new(
            response.status,
            response.version,
            response.headers.clone(),
            stale_if_error,
            sensitive_data,
        )));
        Ok(options)
    }

    async fn http_cache_update(
        &mut self,
        memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
        response_handle: types::ResponseHandle,
        options_mask: HttpCacheWriteOptionsMask,
        abi_options: GuestPtr<types::HttpCacheWriteOptions>,
    ) -> Result<(), Error> {
        let guest_options = memory.read(abi_options)?;
        let options =
            self.http_write_options(memory, options_mask, &guest_options, response_handle)?;
        self.cache_entry_mut(cache_handle.into())
            .await?
            .update(options)
            .await?;
        Ok(())
    }

    /// The HTTP metadata of the found object.
    async fn http_found_meta(
        &mut self,
        cache_handle: types::HttpCacheHandle,
    ) -> Result<Arc<HttpResponseMeta>, Error> {
        self.cache_entry(cache_handle.into())
            .await?
            .found()
            .and_then(|found| found.meta().http())
            .cloned()
            .ok_or_else(missing)
    }
}

impl FastlyHttpCache for Sandbox {
    async fn lookup(
        &mut self,
        memory: &mut GuestMemory<'_>,
        request: types::RequestHandle,
        options_mask: types::HttpCacheLookupOptionsMask,
        options: GuestPtr<types::HttpCacheLookupOptions>,
    ) -> Result<types::HttpCacheHandle, Error> {
        self.http_cache_lookup(memory, request, options_mask, options, false)
            .await
    }

    async fn transaction_lookup(
        &mut self,
        memory: &mut GuestMemory<'_>,
        request: types::RequestHandle,
        options_mask: types::HttpCacheLookupOptionsMask,
        options: GuestPtr<types::HttpCacheLookupOptions>,
    ) -> Result<types::HttpCacheHandle, Error> {
        self.http_cache_lookup(memory, request, options_mask, options, true)
            .await
    }

    async fn transaction_insert(
        &mut self,
        memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
        response_handle: types::ResponseHandle,
        options_mask: types::HttpCacheWriteOptionsMask,
        abi_options: GuestPtr<types::HttpCacheWriteOptions>,
    ) -> Result<types::BodyHandle, Error> {
        let (body, stream_back) = self
            .http_cache_insert(
                memory,
                cache_handle,
                response_handle,
                options_mask,
                abi_options,
            )
            .await?;
        // Ignore the "stream back" handle
        let _ = self.take_cache_entry(stream_back.into())?;
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
        self.http_cache_insert(
            memory,
            cache_handle,
            response_handle,
            options_mask,
            abi_options,
        )
        .await
    }

    async fn transaction_update(
        &mut self,
        memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
        response_handle: types::ResponseHandle,
        options_mask: types::HttpCacheWriteOptionsMask,
        abi_options: GuestPtr<types::HttpCacheWriteOptions>,
    ) -> Result<(), Error> {
        self.http_cache_update(
            memory,
            cache_handle,
            response_handle,
            options_mask,
            abi_options,
        )
        .await
    }

    async fn transaction_update_and_return_fresh(
        &mut self,
        memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
        response_handle: types::ResponseHandle,
        options_mask: types::HttpCacheWriteOptionsMask,
        abi_options: GuestPtr<types::HttpCacheWriteOptions>,
    ) -> Result<types::HttpCacheHandle, Error> {
        self.http_cache_update(
            memory,
            cache_handle,
            response_handle,
            options_mask,
            abi_options,
        )
        .await?;
        let entry = self.cache_entry(cache_handle.into()).await?;
        let key = entry.key().clone();
        let head = Arc::clone(entry.http_request().ok_or(Error::InvalidArgument)?);
        let fresh = self
            .cache()
            .lookup(&key, &head.headers)
            .await
            .with_http_request(head);
        Ok(self
            .insert_cache_op(PendingCacheTask::new(PeekableTask::complete(fresh)))
            .into())
    }

    async fn transaction_record_not_cacheable(
        &mut self,
        memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
        options_mask: types::HttpCacheWriteOptionsMask,
        abi_options: GuestPtr<types::HttpCacheWriteOptions>,
    ) -> Result<(), Error> {
        // Validate the options, even though Viceroy does not use them yet.
        let guest_options = memory.read(abi_options)?;
        let _ = load_http_write_options(memory, options_mask, &guest_options)?;
        // NOTE: Compute records a hit-for-pass object here, so that later lookups bypass request
        // collapsing. Viceroy does not have hit-for-pass objects yet; it only releases the
        // obligation, so later lookups will collapse onto (and then retry) the backend request.
        self.cache_entry_mut(cache_handle.into()).await?.cancel();
        Ok(())
    }

    async fn transaction_abandon(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
    ) -> Result<(), Error> {
        if self.cache_entry_mut(cache_handle.into()).await?.cancel() {
            Ok(())
        } else {
            Err(Error::CacheError(crate::cache::Error::CannotWrite))
        }
    }

    async fn transaction_choose_stale(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
    ) -> Result<(), Error> {
        let entry = self.cache_entry_mut(cache_handle.into()).await?;
        if entry.found().is_none() {
            return Err(missing());
        }
        // Complete the collapse without changing the cached state.
        entry.cancel();
        Ok(())
    }

    async fn close(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
    ) -> Result<(), Error> {
        let _ = self
            .take_cache_entry(cache_handle.into())?
            .task()
            .recv()
            .await?;
        Ok(())
    }

    fn is_request_cacheable(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        request_handle: types::RequestHandle,
    ) -> Result<u32, Error> {
        self.check_http_cache_enabled()?;
        let parts = self.request_parts(request_handle)?;
        Ok(http_semantics::is_request_cacheable(&parts.method).into())
    }

    fn get_suggested_cache_key(
        &mut self,
        memory: &mut GuestMemory<'_>,
        request_handle: types::RequestHandle,
        key_out_ptr: GuestPtr<u8>,
        key_out_len: u32,
        nwritten_out: GuestPtr<u32>,
    ) -> Result<(), Error> {
        self.check_http_cache_enabled()?;
        let head = HttpRequestHead::from_parts(self.request_parts(request_handle)?);
        let key = http_semantics::suggested_cache_key(&head);
        write_buffer(
            memory,
            &key,
            key_out_ptr,
            key_out_len,
            nwritten_out,
            "key_out_ptr",
            "key_out_len",
        )
    }

    async fn get_suggested_backend_request(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
    ) -> Result<types::RequestHandle, Error> {
        let entry = self.cache_entry(cache_handle.into()).await?;
        let head = entry.http_request().ok_or(Error::InvalidArgument)?;
        let mut parts = head.to_parts();

        // Fetch the whole object, unconditionally, so that the response can be cached...
        for name in [
            header::RANGE,
            header::IF_NONE_MATCH,
            header::IF_MODIFIED_SINCE,
        ] {
            parts.headers.remove(name);
        }
        // ...unless we are obligated to revalidate a stored response.
        if entry.go_get().is_some()
            && let Some(stored) = entry.found().and_then(|found| found.meta().http())
        {
            for (name, value) in http_semantics::revalidation_headers(stored) {
                parts.headers.insert(name, value);
            }
        }

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
        let request = Arc::clone(
            self.cache_entry(cache_handle.into())
                .await?
                .http_request()
                .ok_or(Error::InvalidArgument)?,
        );
        let headers = &self.response_parts(response_handle)?.headers;
        let suggested =
            http_semantics::suggested_write_options(&request, headers, SystemTime::now());
        let pointers = memory.read(pointers)?;

        let mut mask_out = HttpCacheWriteOptionsMask::empty();
        let mut out = types::HttpCacheWriteOptions {
            max_age_ns: duration_ns(suggested.max_age),
            vary_rule_ptr: pointers.vary_rule_ptr,
            vary_rule_len: 0,
            initial_age_ns: 0,
            stale_while_revalidate_ns: 0,
            surrogate_keys_ptr: pointers.surrogate_keys_ptr,
            surrogate_keys_len: 0,
            length: 0,
            stale_if_error_ns: 0,
        };
        let mut too_short = false;

        let mut write_option = |memory: &mut GuestMemory<'_>,
                                value: &str,
                                ptr: GuestPtr<u8>,
                                capacity: u32|
         -> Result<u32, Error> {
            let len: u32 = value.len().try_into().map_err(|_| Error::InvalidArgument)?;
            if len > capacity {
                too_short = true;
            } else if len > 0 {
                memory
                    .as_slice_mut(ptr.as_array(len))?
                    .ok_or(Error::SharedMemory)?
                    .copy_from_slice(value.as_bytes());
            }
            Ok(len)
        };

        if options_wanted.contains(HttpCacheWriteOptionsMask::VARY_RULE) {
            out.vary_rule_len = write_option(
                memory,
                &suggested.vary_rule,
                pointers.vary_rule_ptr,
                pointers.vary_rule_len,
            )?;
            mask_out |= HttpCacheWriteOptionsMask::VARY_RULE;
        }
        if options_wanted.contains(HttpCacheWriteOptionsMask::SURROGATE_KEYS) {
            out.surrogate_keys_len = write_option(
                memory,
                &suggested.surrogate_keys,
                pointers.surrogate_keys_ptr,
                pointers.surrogate_keys_len,
            )?;
            mask_out |= HttpCacheWriteOptionsMask::SURROGATE_KEYS;
        }
        if options_wanted.contains(HttpCacheWriteOptionsMask::INITIAL_AGE_NS) {
            out.initial_age_ns = duration_ns(suggested.initial_age);
            mask_out |= HttpCacheWriteOptionsMask::INITIAL_AGE_NS;
        }
        if options_wanted.contains(HttpCacheWriteOptionsMask::STALE_WHILE_REVALIDATE_NS) {
            out.stale_while_revalidate_ns = duration_ns(suggested.stale_while_revalidate);
            mask_out |= HttpCacheWriteOptionsMask::STALE_WHILE_REVALIDATE_NS;
        }
        if options_wanted.contains(HttpCacheWriteOptionsMask::STALE_IF_ERROR_NS) {
            out.stale_if_error_ns = duration_ns(suggested.stale_if_error);
            mask_out |= HttpCacheWriteOptionsMask::STALE_IF_ERROR_NS;
        }
        if options_wanted.contains(HttpCacheWriteOptionsMask::LENGTH)
            && let Some(length) = suggested.length
        {
            out.length = length;
            mask_out |= HttpCacheWriteOptionsMask::LENGTH;
        }
        if options_wanted.contains(HttpCacheWriteOptionsMask::SENSITIVE_DATA)
            && suggested.sensitive_data
        {
            mask_out |= HttpCacheWriteOptionsMask::SENSITIVE_DATA;
        }

        memory.write(pointer_mask_out, mask_out)?;
        memory.write(options_out, out)?;
        if too_short {
            return Err(Error::BufferLengthError {
                buf: "options",
                len: "options_mask",
            });
        }
        Ok(())
    }

    async fn prepare_response_for_storage(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
        response_handle: types::ResponseHandle,
    ) -> Result<(types::HttpStorageAction, types::ResponseHandle), Error> {
        let entry = self.cache_entry(cache_handle.into()).await?;
        let request = Arc::clone(entry.http_request().ok_or(Error::InvalidArgument)?);
        // Only a revalidation (an obligation with a stored response) can be updated.
        let stored = if entry.go_get().is_some() {
            entry.found().and_then(|found| found.meta().http()).cloned()
        } else {
            None
        };

        let response = self.response_parts(response_handle)?;
        let prepared = http_semantics::prepare_response_for_storage(
            &request,
            response.status,
            response.version,
            &response.headers,
            stored.as_deref(),
            SystemTime::now(),
        );

        let (mut parts, ()) = Response::builder()
            .status(prepared.status)
            .version(prepared.version)
            .body(())
            .expect("status and version were already valid")
            .into_parts();
        parts.headers = prepared.headers;
        let action = match prepared.action {
            StorageAction::Insert => types::HttpStorageAction::Insert,
            StorageAction::Update => types::HttpStorageAction::Update,
            StorageAction::DoNotStore => types::HttpStorageAction::DoNotStore,
            StorageAction::RecordUncacheable => types::HttpStorageAction::RecordUncacheable,
        };
        Ok((action, self.insert_response_parts(parts)))
    }

    async fn get_found_response(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
        transform_for_client: u32,
    ) -> Result<(types::ResponseHandle, types::BodyHandle), Error> {
        let entry = self.cache_entry(cache_handle.into()).await?;
        let found = entry.found().ok_or_else(missing)?;
        let http = Arc::clone(found.meta().http().ok_or_else(missing)?);
        let age = found.meta().age();
        let not_modified = transform_for_client != 0
            && entry
                .http_request()
                .is_some_and(|request| http_semantics::is_not_modified(&request.headers, &http));
        let (status, body) = if not_modified {
            (http::StatusCode::NOT_MODIFIED, Body::empty())
        } else {
            (http.status, entry.body(None, None).await?)
        };

        let mut response = Response::builder()
            .status(status)
            .version(http.version)
            .body(body)
            .expect("status and version were already valid");
        *response.headers_mut() = http.headers.clone();
        if transform_for_client != 0 {
            // NOTE: Compute also applies range requests here; Viceroy does not yet.
            response
                .headers_mut()
                .insert(header::AGE, HeaderValue::from(age.as_secs()));
            if not_modified {
                response.headers_mut().remove(header::CONTENT_LENGTH);
            }
        }

        Ok(self.insert_response(response))
    }

    async fn get_state(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
    ) -> Result<types::CacheLookupState, Error> {
        let entry = self.cache_entry(cache_handle.into()).await?;

        let mut state = types::CacheLookupState::empty();
        if let Some(found) = entry.found()
            && found.meta().is_usable()
        {
            state |= types::CacheLookupState::USABLE;
            state |= types::CacheLookupState::FOUND;
            if !found.meta().is_fresh() {
                state |= types::CacheLookupState::STALE;
            }
        }
        if entry.go_get().is_some() {
            state |= types::CacheLookupState::MUST_INSERT_OR_UPDATE;
        }
        Ok(state)
    }

    async fn get_length(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
    ) -> Result<types::CacheObjectLength, Error> {
        self.cache_entry(cache_handle.into())
            .await?
            .found()
            .and_then(|found| found.length())
            .ok_or_else(missing)
    }

    async fn get_max_age_ns(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
    ) -> Result<types::CacheDurationNs, Error> {
        let entry = self.cache_entry(cache_handle.into()).await?;
        let found = entry.found().ok_or_else(missing)?;
        Ok(duration_ns(found.meta().max_age()))
    }

    async fn get_stale_while_revalidate_ns(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
    ) -> Result<types::CacheDurationNs, Error> {
        let entry = self.cache_entry(cache_handle.into()).await?;
        let found = entry.found().ok_or_else(missing)?;
        Ok(duration_ns(found.meta().stale_while_revalidate()))
    }

    async fn get_stale_if_error_ns(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
    ) -> Result<types::CacheDurationNs, Error> {
        let http = self.http_found_meta(cache_handle).await?;
        Ok(duration_ns(http.stale_if_error))
    }

    async fn get_age_ns(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
    ) -> Result<types::CacheDurationNs, Error> {
        let entry = self.cache_entry(cache_handle.into()).await?;
        let found = entry.found().ok_or_else(missing)?;
        Ok(duration_ns(found.meta().age()))
    }

    async fn get_hits(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
    ) -> Result<types::CacheHitCount, Error> {
        let http = self.http_found_meta(cache_handle).await?;
        Ok(http.hits())
    }

    async fn get_sensitive_data(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
    ) -> Result<types::IsSensitive, Error> {
        let http = self.http_found_meta(cache_handle).await?;
        Ok(http.sensitive_data.into())
    }

    async fn get_surrogate_keys(
        &mut self,
        memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
        surrogate_keys_out_ptr: GuestPtr<u8>,
        surrogate_keys_out_len: u32,
        nwritten_out: GuestPtr<u32>,
    ) -> Result<(), Error> {
        let entry = self.cache_entry(cache_handle.into()).await?;
        let found = entry.found().ok_or_else(missing)?;
        let keys = found.meta().surrogate_keys().to_space_separated();
        write_buffer(
            memory,
            keys.as_bytes(),
            surrogate_keys_out_ptr,
            surrogate_keys_out_len,
            nwritten_out,
            "surrogate_keys_out_ptr",
            "surrogate_keys_out_len",
        )
    }

    async fn get_vary_rule(
        &mut self,
        memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
        vary_rule_out_ptr: GuestPtr<u8>,
        vary_rule_out_len: u32,
        nwritten_out: GuestPtr<u32>,
    ) -> Result<(), Error> {
        let entry = self.cache_entry(cache_handle.into()).await?;
        let found = entry.found().ok_or_else(missing)?;
        let rule = found
            .meta()
            .vary_rule()
            .headers()
            .iter()
            .map(HeaderName::as_str)
            .collect::<Vec<_>>()
            .join(" ");
        write_buffer(
            memory,
            rule.as_bytes(),
            vary_rule_out_ptr,
            vary_rule_out_len,
            nwritten_out,
            "vary_rule_out_ptr",
            "vary_rule_out_len",
        )
    }
}
