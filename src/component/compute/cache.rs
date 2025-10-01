use {
    crate::component::bindings::fastly::compute::{cache as api, http_body, types},
    crate::{
        body::Body,
        cache::{self, CacheKey, SurrogateKeySet, VaryRule, WriteOptions},
        error::Error,
        linking::{ComponentCtx, SessionView},
        session::{PeekableTask, PendingCacheTask, Session},
        wiggle_abi::types::{CacheBusyHandle, CacheHandle},
    },
    bytes::Bytes,
    http::HeaderMap,
    std::{sync::Arc, time::Duration},
    wasmtime::component::Resource,
};

// Utility for remapping the errors.
fn get_key(key: Vec<u8>) -> Result<CacheKey, types::Error> {
    key.try_into()
        .map_err(|_| types::Error::BufferLen(CacheKey::MAX_LENGTH as u64))
}

fn load_write_options(options: &api::WriteOptions) -> Result<WriteOptions, Error> {
    // Headers must be handled before load_write_options:
    assert!(
        options.request_headers.is_none(),
        "Viceroy bug! headers must be handled before load_write_options"
    );

    let max_age = Duration::from_nanos(options.max_age_ns);

    let initial_age = if let Some(initial_age_ns) = options.initial_age_ns {
        Duration::from_nanos(initial_age_ns)
    } else {
        Duration::ZERO
    };

    let stale_while_revalidate =
        if let Some(stale_while_revalidate_ns) = options.stale_while_revalidate_ns {
            Duration::from_nanos(stale_while_revalidate_ns)
        } else {
            Duration::ZERO
        };

    let vary_rule = if let Some(vary_rule) = &options.vary_rule {
        vary_rule.parse()?
    } else {
        VaryRule::default()
    };

    let user_metadata = if let Some(user_metadata) = &options.user_metadata {
        Bytes::copy_from_slice(user_metadata)
    } else {
        Bytes::new()
    };

    let length = options.length;
    let sensitive_data = options.sensitive_data;

    let edge_max_age = if let Some(edge_max_age_ns) = options.edge_max_age_ns {
        Duration::from_nanos(edge_max_age_ns)
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

    let surrogate_keys = if let Some(surrogate_keys) = &options.surrogate_keys {
        surrogate_keys.as_bytes().try_into()?
    } else {
        SurrogateKeySet::default()
    };

    Ok(WriteOptions {
        max_age,
        initial_age,
        stale_while_revalidate,
        vary_rule,
        user_metadata,
        length,
        sensitive_data,
        surrogate_keys,
        edge_max_age,
    })
}

struct LookupOptions {
    headers: HeaderMap,
    always_use_requested_range: bool,
}

fn load_lookup_options(
    session: &Session,
    options: api::LookupOptions,
) -> Result<LookupOptions, Error> {
    let headers = if let Some(request_headers) = options.request_headers {
        let handle = request_headers;
        let parts = session.request_parts(handle.into())?;
        parts.headers.clone()
    } else {
        HeaderMap::default()
    };

    let always_use_requested_range = options.always_use_requested_range;

    Ok(LookupOptions {
        headers,
        always_use_requested_range,
    })
}

impl api::Host for ComponentCtx {
    async fn insert(
        &mut self,
        key: Vec<u8>,
        mut options: api::WriteOptions,
    ) -> Result<Resource<api::Body>, types::Error> {
        let key: CacheKey = get_key(key)?;
        let cache = Arc::clone(self.session().cache());

        let request_headers = if let Some(handle) = options.request_headers.take() {
            let parts = self.session().request_parts(handle.into())?;
            parts.headers.clone()
        } else {
            HeaderMap::default()
        };
        let options = load_write_options(&options)?;

        let handle = self.session_mut().insert_body(Body::empty());
        let read_body = self.session_mut().begin_streaming(handle)?;
        cache
            .insert(&key, request_headers, options, read_body)
            .await;
        Ok(handle.into())
    }

    async fn replace(
        &mut self,
        key: Vec<u8>,
        _options: api::ReplaceOptions,
    ) -> Result<Resource<api::ReplaceEntry>, types::Error> {
        let _key: CacheKey = get_key(key)?;
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn replace_get_age_ns(
        &mut self,
        _handle: Resource<api::ReplaceEntry>,
    ) -> Result<Option<api::DurationNs>, types::Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn replace_get_body(
        &mut self,
        _handle: Resource<api::ReplaceEntry>,
        _options: api::GetBodyOptions,
    ) -> Result<Option<Resource<http_body::Body>>, types::Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn replace_get_hits(
        &mut self,
        _handle: Resource<api::ReplaceEntry>,
    ) -> Result<Option<u64>, types::Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn replace_get_length(
        &mut self,
        _handle: Resource<api::ReplaceEntry>,
    ) -> Result<Option<u64>, types::Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn replace_get_max_age_ns(
        &mut self,
        _handle: Resource<api::ReplaceEntry>,
    ) -> Result<Option<api::DurationNs>, types::Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn replace_get_stale_while_revalidate_ns(
        &mut self,
        _handle: Resource<api::ReplaceEntry>,
    ) -> Result<Option<api::DurationNs>, types::Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn replace_get_state(
        &mut self,
        _handle: Resource<api::ReplaceEntry>,
    ) -> Result<Option<api::LookupState>, types::Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn replace_get_user_metadata(
        &mut self,
        _handle: Resource<api::ReplaceEntry>,
        _max_len: u64,
    ) -> Result<Option<Vec<u8>>, types::Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn replace_insert(
        &mut self,
        _handle: Resource<api::ReplaceEntry>,
        _options: api::WriteOptions,
    ) -> Result<Resource<api::Body>, types::Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn await_entry(
        &mut self,
        handle: Resource<api::PendingEntry>,
    ) -> Result<Resource<api::Entry>, types::Error> {
        let handle = CacheBusyHandle::from(handle).into();
        // Swap out for a distinct handle, so we don't hit a repeated `close`+`close_busy`:
        let entry = self.session_mut().cache_entry_mut(handle).await?;
        let mut other_entry = entry.stub();
        std::mem::swap(entry, &mut other_entry);
        let task = PeekableTask::spawn(Box::pin(async move { Ok(other_entry) })).await;
        let h: CacheHandle = self
            .session_mut()
            .insert_cache_op(PendingCacheTask::new(task))
            .into();
        Ok(h.into())
    }

    fn close_pending_entry(
        &mut self,
        handle: Resource<api::PendingEntry>,
    ) -> Result<(), types::Error> {
        let handle = CacheBusyHandle::from(handle).into();
        // Don't wait for the transaction to complete; drop the future to cancel.
        let _ = self.session_mut().take_cache_entry(handle)?;
        Ok(())
    }

    async fn close_entry(&mut self, handle: Resource<api::Entry>) -> Result<(), types::Error> {
        let _ = self
            .session_mut()
            .take_cache_entry(handle.into())?
            .task()
            .recv()
            .await?;
        Ok(())
    }
}

impl api::HostEntry for ComponentCtx {
    async fn lookup(
        &mut self,
        key: Vec<u8>,
        options: api::LookupOptions,
    ) -> Result<Resource<api::Entry>, types::Error> {
        let LookupOptions {
            headers,
            always_use_requested_range,
        } = load_lookup_options(self.session(), options)?;

        let key: CacheKey = get_key(key)?;
        let cache = Arc::clone(self.session().cache());

        let task = PeekableTask::spawn(Box::pin(async move {
            Ok(cache
                .lookup(&key, &headers)
                .await
                .with_always_use_requested_range(always_use_requested_range))
        }))
        .await;
        let task = PendingCacheTask::new(task);
        let handle: CacheHandle = self.session_mut().insert_cache_op(task).into();
        Ok(handle.into())
    }

    async fn get_body(
        &mut self,
        handle: Resource<api::Entry>,
        options: api::GetBodyOptions,
    ) -> Result<Resource<http_body::Body>, types::Error> {
        let handle = handle.into();

        let from = options.from;
        let to = options.to;

        // We wind up re-borrowing `found` and `self.session` several times here, to avoid
        // borrowing the both of them at once.
        // (It possible that inserting a body would change the address of Found, by re-shuffling
        // the AsyncItems table; we have to live by borrowck's rules.)
        //
        // We have an exclusive borrow self.session_mut() for the lifetime of this call,
        // so even though we're re-borrowing/repeating lookups, we know we won't run into TOCTOU.

        let entry = self.session_mut().cache_entry(handle).await?;

        // Preemptively (optimistically) start a read. Don't worry, the Drop impl for Body will
        // clean up the copying task.
        // We have to do this to allow `found`'s lifetime to end before self.session().body, which
        // has to re-borrow self.self.session().
        let body = entry.body(from, to).await?;
        let found = entry
            .found()
            .ok_or(Error::CacheError(crate::cache::Error::Missing))?;

        if let Some(prev_handle) = found.last_body_handle {
            // Check if they're still reading the previous handle.
            if self.session().body(prev_handle).is_ok() {
                return Err(Error::CacheError(cache::Error::HandleBodyUsed).into());
            }
        };

        let body_handle = self.session_mut().insert_body(body);

        // Finalize by committing the handle as "the last read".
        // We have to borrow `found` again, this time as mutable.
        self.session_mut()
            .cache_entry_mut(handle)
            .await?
            .found_mut()
            .unwrap()
            .last_body_handle = Some(body_handle);

        Ok(body_handle.into())
    }

    async fn transaction_lookup(
        &mut self,
        key: Vec<u8>,
        options: api::LookupOptions,
    ) -> Result<Resource<api::Entry>, types::Error> {
        let h = self.transaction_lookup_async(key, options).await?;
        api::Host::await_entry(self, h).await
    }

    async fn transaction_lookup_async(
        &mut self,
        key: Vec<u8>,
        options: api::LookupOptions,
    ) -> Result<Resource<api::PendingEntry>, types::Error> {
        let LookupOptions {
            headers,
            always_use_requested_range,
        } = load_lookup_options(self.session(), options)?;

        let key: CacheKey = get_key(key)?;
        let cache = Arc::clone(self.session().cache());

        // Look up once, joining the transaction only if obligated:
        let e = cache
            .transaction_lookup(&key, &headers, false)
            .await
            .with_always_use_requested_range(always_use_requested_range);
        let ready = e.found().is_some() || e.go_get().is_some();
        // If we already got _something_, we can provide an already-complete PeekableTask.
        // Otherwise we need to spawn it and let it block in the background.
        let task = if ready {
            PeekableTask::complete(e)
        } else {
            PeekableTask::spawn(Box::pin(async move {
                Ok(cache
                    .transaction_lookup(&key, &headers, true)
                    .await
                    .with_always_use_requested_range(always_use_requested_range))
            }))
            .await
        };

        let task = PendingCacheTask::new(task);
        let handle: CacheBusyHandle = self.session_mut().insert_cache_op(task).into();
        Ok(handle.into())
    }

    async fn transaction_insert(
        &mut self,
        handle: Resource<api::Entry>,
        options: api::WriteOptions,
    ) -> Result<Resource<http_body::Body>, types::Error> {
        let (body, cache_handle) = self
            .transaction_insert_and_stream_back(handle, options)
            .await?;
        // Ignore the "stream back" handle
        let _ = self.session_mut().take_cache_entry(cache_handle.into())?;
        Ok(body)
    }

    async fn transaction_insert_and_stream_back(
        &mut self,
        handle: Resource<api::Entry>,
        options: api::WriteOptions,
    ) -> Result<(Resource<http_body::Body>, Resource<api::Entry>), types::Error> {
        // No request headers here; request headers come from the original lookup.
        if options.request_headers.is_some() {
            return Err(Error::InvalidArgument.into());
        }
        let options = load_write_options(&options)?;

        // Optimistically start a body, so we don't have to reborrow self.session_mut()
        let body_handle = self.session_mut().insert_body(Body::empty());
        let read_body = self.session_mut().begin_streaming(body_handle)?;

        let e = self
            .session_mut()
            .cache_entry_mut(handle.into())
            .await?
            .insert(options, read_body)?;
        // Return a new handle for the read end.
        let handle: CacheHandle = self
            .session_mut()
            .insert_cache_op(PendingCacheTask::new(PeekableTask::complete(e)))
            .into();

        Ok((body_handle.into(), handle.into()))
    }

    async fn transaction_update(
        &mut self,
        handle: Resource<api::Entry>,
        options: api::WriteOptions,
    ) -> Result<(), types::Error> {
        // No request headers here; request headers come from the original lookup.
        if options.request_headers.is_some() {
            return Err(Error::InvalidArgument.into());
        }
        let options = load_write_options(&options)?;

        let entry = self.session_mut().cache_entry_mut(handle.into()).await?;
        // The path here is:
        // InvalidCacheHandle -> FastlyStatus::BADF -> (ABI boundary) ->
        // CacheError::InvalidOperation
        entry.update(options).await?;
        Ok(())
    }

    async fn transaction_cancel(
        &mut self,
        handle: Resource<api::Entry>,
    ) -> Result<(), types::Error> {
        let entry = self.session_mut().cache_entry_mut(handle.into()).await?;
        if entry.cancel() {
            Ok(())
        } else {
            Err(Error::CacheError(cache::Error::CannotWrite).into())
        }
    }

    async fn get_state(
        &mut self,
        handle: Resource<api::Entry>,
    ) -> Result<api::LookupState, types::Error> {
        let entry = self.session_mut().cache_entry_mut(handle.into()).await?;

        let mut state = api::LookupState::empty();
        if let Some(found) = entry.found() {
            state |= api::LookupState::FOUND;

            if !found.meta().is_fresh() {
                state |= api::LookupState::STALE;
            }
            if found.meta().is_usable() {
                state |= api::LookupState::USABLE;
            }
        }
        if entry.go_get().is_some() {
            state |= api::LookupState::MUST_INSERT_OR_UPDATE
        }

        Ok(state)
    }

    async fn get_user_metadata(
        &mut self,
        handle: Resource<api::Entry>,
        max_len: u64,
    ) -> Result<Option<Vec<u8>>, types::Error> {
        let entry = self.session_mut().cache_entry(handle.into()).await?;

        let md_bytes = entry
            .found()
            .map(|found| found.meta().user_metadata())
            .ok_or(crate::Error::CacheError(crate::cache::Error::Missing))?;
        let len = md_bytes.len() as u64;
        if len > max_len {
            return Err(types::Error::BufferLen(len));
        }
        Ok(Some(md_bytes.into()))
    }

    async fn get_length(
        &mut self,
        handle: Resource<api::Entry>,
    ) -> Result<Option<u64>, types::Error> {
        let Some(found) = self.session_mut().cache_entry(handle.into()).await?.found() else {
            return Ok(None);
        };
        Ok(found.length())
    }

    async fn get_max_age_ns(
        &mut self,
        handle: Resource<api::Entry>,
    ) -> Result<Option<u64>, types::Error> {
        let entry = self.session_mut().cache_entry_mut(handle.into()).await?;
        if let Some(found) = entry.found() {
            Ok(Some(found.meta().max_age().as_nanos().try_into().unwrap()))
        } else {
            Ok(None)
        }
    }

    async fn get_stale_while_revalidate_ns(
        &mut self,
        _handle: Resource<api::Entry>,
    ) -> Result<Option<u64>, types::Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn get_age_ns(
        &mut self,
        handle: Resource<api::Entry>,
    ) -> Result<Option<u64>, types::Error> {
        let entry = self.session_mut().cache_entry_mut(handle.into()).await?;
        if let Some(found) = entry.found() {
            Ok(Some(found.meta().age().as_nanos().try_into().unwrap()))
        } else {
            Ok(None)
        }
    }

    async fn get_hits(
        &mut self,
        _handle: Resource<api::Entry>,
    ) -> Result<Option<u64>, types::Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    fn drop(&mut self, _entry: Resource<api::Entry>) -> wasmtime::Result<()> {
        Ok(())
    }
}

impl api::HostExtraReplaceOptions for ComponentCtx {
    fn new(&mut self) -> wasmtime::Result<Resource<api::ExtraReplaceOptions>> {
        Ok(Resource::<api::ExtraReplaceOptions>::new_own(0))
    }

    fn drop(&mut self, _options: Resource<api::ExtraReplaceOptions>) -> wasmtime::Result<()> {
        Ok(())
    }
}

impl api::HostExtraGetBodyOptions for ComponentCtx {
    fn drop(&mut self, _options: Resource<api::ExtraGetBodyOptions>) -> wasmtime::Result<()> {
        Ok(())
    }
}

impl api::HostExtraWriteOptions for ComponentCtx {
    fn new(&mut self) -> wasmtime::Result<Resource<api::ExtraWriteOptions>> {
        Ok(Resource::<api::ExtraWriteOptions>::new_own(0))
    }

    fn drop(&mut self, _options: Resource<api::ExtraWriteOptions>) -> wasmtime::Result<()> {
        Ok(())
    }
}

impl api::HostExtraLookupOptions for ComponentCtx {
    fn new(&mut self) -> wasmtime::Result<Resource<api::ExtraLookupOptions>> {
        Ok(Resource::<api::ExtraLookupOptions>::new_own(0))
    }

    fn drop(&mut self, _options: Resource<api::ExtraLookupOptions>) -> wasmtime::Result<()> {
        Ok(())
    }
}
