use {
    super::fastly::api::{cache as api, http_types, types},
    crate::{
        body::Body,
        cache::{self, CacheKey, SurrogateKeySet, VaryRule, WriteOptions},
        error::Error,
        linking::ComponentCtx,
        session::{PeekableTask, PendingCacheTask, Session},
        wiggle_abi::types::CacheHandle,
    },
    bytes::Bytes,
    http::HeaderMap,
    std::{sync::Arc, time::Duration},
};

// Utility for remapping the errors.
fn get_key(key: Vec<u8>) -> Result<CacheKey, types::Error> {
    key.try_into()
        .map_err(|_| types::Error::BufferLen(CacheKey::MAX_LENGTH as u64))
}

fn load_write_options(
    mut options_mask: api::WriteOptionsMask,
    options: &api::WriteOptions,
) -> Result<WriteOptions, Error> {
    // Headers must be handled before load_write_options:
    assert!(
        !options_mask.contains(api::WriteOptionsMask::REQUEST_HEADERS),
        "Viceroy bug! headers must be handled before load_write_options"
    );

    // Clear each bit of options_mask as we handle it, to make sure we catch any unknown options.

    let max_age = Duration::from_nanos(options.max_age_ns);

    let initial_age = if options_mask.contains(api::WriteOptionsMask::INITIAL_AGE_NS) {
        Duration::from_nanos(options.initial_age_ns)
    } else {
        Duration::ZERO
    };
    options_mask &= !api::WriteOptionsMask::INITIAL_AGE_NS;

    let stale_while_revalidate =
        if options_mask.contains(api::WriteOptionsMask::STALE_WHILE_REVALIDATE_NS) {
            Duration::from_nanos(options.stale_while_revalidate_ns)
        } else {
            Duration::ZERO
        };
    options_mask &= !api::WriteOptionsMask::STALE_WHILE_REVALIDATE_NS;

    let vary_rule = if options_mask.contains(api::WriteOptionsMask::VARY_RULE) {
        options.vary_rule.parse()?
    } else {
        VaryRule::default()
    };
    options_mask &= !api::WriteOptionsMask::VARY_RULE;

    let user_metadata = if options_mask.contains(api::WriteOptionsMask::USER_METADATA) {
        Bytes::copy_from_slice(&options.user_metadata)
    } else {
        Bytes::new()
    };
    options_mask &= !api::WriteOptionsMask::USER_METADATA;

    let length = if options_mask.contains(api::WriteOptionsMask::LENGTH) {
        Some(options.length)
    } else {
        None
    };
    options_mask &= !api::WriteOptionsMask::LENGTH;

    let sensitive_data = options_mask.contains(api::WriteOptionsMask::SENSITIVE_DATA);
    options_mask &= !api::WriteOptionsMask::SENSITIVE_DATA;

    // SERVICE_ID differences are observable- but we don't implement that behavior. Error explicitly.
    if options_mask.contains(api::WriteOptionsMask::SERVICE_ID) {
        return Err(Error::Unsupported {
            msg: "cache on_behalf_of is not supported in Viceroy",
        });
    }
    options_mask &= !api::WriteOptionsMask::SERVICE_ID;

    let edge_max_age = if options_mask.contains(api::WriteOptionsMask::EDGE_MAX_AGE_NS) {
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
    options_mask &= !api::WriteOptionsMask::EDGE_MAX_AGE_NS;

    let surrogate_keys = if options_mask.contains(api::WriteOptionsMask::SURROGATE_KEYS) {
        options.surrogate_keys.as_bytes().try_into()?
    } else {
        SurrogateKeySet::default()
    };
    options_mask &= !api::WriteOptionsMask::SURROGATE_KEYS;

    if options_mask != api::WriteOptionsMask::empty() {
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
    options_mask: api::LookupOptionsMask,
    options: api::LookupOptions,
) -> Result<LookupOptions, Error> {
    let headers = if options_mask.contains(api::LookupOptionsMask::REQUEST_HEADERS) {
        let handle = options.request_headers;
        let parts = session.request_parts(handle.into())?;
        parts.headers.clone()
    } else {
        HeaderMap::default()
    };
    let options_mask = options_mask & !api::LookupOptionsMask::REQUEST_HEADERS;

    let always_use_requested_range =
        options_mask.contains(api::LookupOptionsMask::ALWAYS_USE_REQUESTED_RANGE);
    let options_mask = options_mask & !api::LookupOptionsMask::ALWAYS_USE_REQUESTED_RANGE;

    if options_mask != api::LookupOptionsMask::empty() {
        return Err(Error::NotAvailable("unknown cache lookup option"));
    }
    Ok(LookupOptions {
        headers,
        always_use_requested_range,
    })
}

#[async_trait::async_trait]
impl api::Host for ComponentCtx {
    async fn lookup(
        &mut self,
        key: Vec<u8>,
        options_mask: api::LookupOptionsMask,
        options: api::LookupOptions,
    ) -> Result<api::Handle, types::Error> {
        let LookupOptions {
            headers,
            always_use_requested_range,
        } = load_lookup_options(&self.session, options_mask, options)?;

        let key: CacheKey = get_key(key)?;
        let cache = Arc::clone(self.session.cache());

        let task = PeekableTask::spawn(Box::pin(async move {
            Ok(cache
                .lookup(&key, &headers)
                .await
                .with_always_use_requested_range(always_use_requested_range))
        }))
        .await;
        let task = PendingCacheTask::new(task);
        let handle: CacheHandle = self.session.insert_cache_op(task).into();
        Ok(handle.into())
    }

    async fn insert(
        &mut self,
        key: Vec<u8>,
        options_mask: api::WriteOptionsMask,
        options: api::WriteOptions,
    ) -> Result<api::BodyHandle, types::Error> {
        let key: CacheKey = get_key(key)?;
        let cache = Arc::clone(self.session.cache());

        let request_headers = if options_mask.contains(api::WriteOptionsMask::REQUEST_HEADERS) {
            let handle = options.request_headers;
            let parts = self.session.request_parts(handle.into())?;
            parts.headers.clone()
        } else {
            HeaderMap::default()
        };
        let options = load_write_options(
            options_mask & !api::WriteOptionsMask::REQUEST_HEADERS,
            &options,
        )?;

        let handle = self.session.insert_body(Body::empty());
        let read_body = self.session.begin_streaming(handle)?;
        cache
            .insert(&key, request_headers, options, read_body)
            .await;
        Ok(handle.into())
    }

    async fn replace(
        &mut self,
        key: Vec<u8>,
        _options_mask: api::ReplaceOptionsMask,
        _options: api::ReplaceOptions,
    ) -> Result<api::ReplaceHandle, types::Error> {
        let _key: CacheKey = get_key(key)?;
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn replace_get_age_ns(
        &mut self,
        _handle: api::ReplaceHandle,
    ) -> Result<api::DurationNs, types::Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn replace_get_body(
        &mut self,
        _handle: api::ReplaceHandle,
        _options_mask: api::GetBodyOptionsMask,
        _options: api::GetBodyOptions,
    ) -> Result<http_types::BodyHandle, types::Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn replace_get_hits(&mut self, _handle: api::ReplaceHandle) -> Result<u64, types::Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn replace_get_length(
        &mut self,
        _handle: api::ReplaceHandle,
    ) -> Result<u64, types::Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn replace_get_max_age_ns(
        &mut self,
        _handle: api::ReplaceHandle,
    ) -> Result<api::DurationNs, types::Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn replace_get_stale_while_revalidate_ns(
        &mut self,
        _handle: api::ReplaceHandle,
    ) -> Result<api::DurationNs, types::Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn replace_get_state(
        &mut self,
        _handle: api::ReplaceHandle,
    ) -> Result<api::LookupState, types::Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn replace_get_user_metadata(
        &mut self,
        _handle: api::ReplaceHandle,
        _max_len: u64,
    ) -> Result<Option<Vec<u8>>, types::Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn replace_insert(
        &mut self,
        _handle: api::ReplaceHandle,
        _options_mask: api::WriteOptionsMask,
        _options: api::WriteOptions,
    ) -> Result<api::BodyHandle, types::Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn get_body(
        &mut self,
        handle: api::Handle,
        mut options_mask: api::GetBodyOptionsMask,
        options: api::GetBodyOptions,
    ) -> Result<http_types::BodyHandle, types::Error> {
        let from = if options_mask.contains(api::GetBodyOptionsMask::FROM) {
            Some(options.from)
        } else {
            None
        };
        options_mask &= !api::GetBodyOptionsMask::FROM;
        let to = if options_mask.contains(api::GetBodyOptionsMask::TO) {
            Some(options.to)
        } else {
            None
        };
        options_mask &= !api::GetBodyOptionsMask::TO;

        if options_mask != api::GetBodyOptionsMask::empty() {
            return Err(Error::NotAvailable("unknown cache get_body option").into());
        }

        // We wind up re-borrowing `found` and `self.session` several times here, to avoid
        // borrowing the both of them at once.
        // (It possible that inserting a body would change the address of Found, by re-shuffling
        // the AsyncItems table; we have to live by borrowck's rules.)
        //
        // We have an exclusive borrow &mut self.session for the lifetime of this call,
        // so even though we're re-borrowing/repeating lookups, we know we won't run into TOCTOU.

        let entry = self.session.cache_entry(handle.into()).await?;

        // Preemptively (optimistically) start a read. Don't worry, the Drop impl for Body will
        // clean up the copying task.
        // We have to do this to allow `found`'s lifetime to end before self.session.body, which
        // has to re-borrow self.self.session.
        let body = entry.body(from, to).await?;
        let found = entry
            .found()
            .ok_or(Error::CacheError(crate::cache::Error::Missing))?;

        if let Some(prev_handle) = found.last_body_handle {
            // Check if they're still reading the previous handle.
            if self.session.body(prev_handle).is_ok() {
                return Err(Error::CacheError(cache::Error::HandleBodyUsed).into());
            }
        };

        let body_handle = self.session.insert_body(body);
        // Finalize by committing the handle as "the last read".
        // We have to borrow `found` again, this time as mutable.
        self.session
            .cache_entry_mut(handle.into())
            .await?
            .found_mut()
            .unwrap()
            .last_body_handle = Some(body_handle.into());

        Ok(body_handle.into())
    }

    async fn transaction_lookup(
        &mut self,
        key: Vec<u8>,
        options_mask: api::LookupOptionsMask,
        options: api::LookupOptions,
    ) -> Result<api::Handle, types::Error> {
        let h = self
            .transaction_lookup_async(key, options_mask, options)
            .await?;
        self.cache_busy_handle_wait(h).await
    }

    async fn transaction_lookup_async(
        &mut self,
        key: Vec<u8>,
        options_mask: api::LookupOptionsMask,
        options: api::LookupOptions,
    ) -> Result<api::BusyHandle, types::Error> {
        let LookupOptions {
            headers,
            always_use_requested_range,
        } = load_lookup_options(&self.session, options_mask, options)?;

        let key: CacheKey = get_key(key)?;
        let cache = Arc::clone(self.session.cache());

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
        let handle: CacheHandle = self.session.insert_cache_op(task).into();
        Ok(handle.into())
    }

    async fn cache_busy_handle_wait(
        &mut self,
        handle: api::BusyHandle,
    ) -> Result<api::Handle, types::Error> {
        let handle = handle.into();
        // Swap out for a distinct handle, so we don't hit a repeated `close`+`close_busy`:
        let entry = self.session.cache_entry_mut(handle).await?;
        let mut other_entry = entry.stub();
        std::mem::swap(entry, &mut other_entry);
        let task = PeekableTask::spawn(Box::pin(async move { Ok(other_entry) })).await;
        let h: CacheHandle = self
            .session
            .insert_cache_op(PendingCacheTask::new(task))
            .into();
        Ok(h.into())
    }

    async fn transaction_insert(
        &mut self,
        handle: api::Handle,
        options_mask: api::WriteOptionsMask,
        options: api::WriteOptions,
    ) -> Result<http_types::BodyHandle, types::Error> {
        let (body, cache_handle) = self
            .transaction_insert_and_stream_back(handle, options_mask, options)
            .await?;
        // Ignore the "stream back" handle
        let _ = self.session.take_cache_entry(cache_handle.into())?;
        Ok(body)
    }

    async fn transaction_insert_and_stream_back(
        &mut self,
        handle: api::Handle,
        options_mask: api::WriteOptionsMask,
        options: api::WriteOptions,
    ) -> Result<(http_types::BodyHandle, api::Handle), types::Error> {
        // No request headers here; request headers come from the original lookup.
        if options_mask.contains(api::WriteOptionsMask::REQUEST_HEADERS) {
            return Err(Error::InvalidArgument.into());
        }
        let options = load_write_options(options_mask, &options)?;

        // Optimistically start a body, so we don't have to reborrow &mut self.session
        let body_handle = self.session.insert_body(Body::empty());
        let read_body = self.session.begin_streaming(body_handle)?;

        let e = self
            .session
            .cache_entry_mut(handle.into())
            .await?
            .insert(options, read_body)?;
        // Return a new handle for the read end.
        let handle: CacheHandle = self
            .session
            .insert_cache_op(PendingCacheTask::new(PeekableTask::complete(e)))
            .into();

        Ok((body_handle.into(), handle.into()))
    }

    async fn transaction_update(
        &mut self,
        handle: api::Handle,
        options_mask: api::WriteOptionsMask,
        options: api::WriteOptions,
    ) -> Result<(), types::Error> {
        // No request headers here; request headers come from the original lookup.
        if options_mask.contains(api::WriteOptionsMask::REQUEST_HEADERS) {
            return Err(Error::InvalidArgument.into());
        }
        let options = load_write_options(options_mask, &options)?;

        let entry = self.session.cache_entry_mut(handle.into()).await?;
        // The path here is:
        // InvalidCacheHandle -> FastlyStatus::BADF -> (ABI boundary) ->
        // CacheError::InvalidOperation
        entry.update(options).await?;
        Ok(())
    }

    async fn transaction_cancel(&mut self, handle: api::Handle) -> Result<(), types::Error> {
        let entry = self.session.cache_entry_mut(handle.into()).await?;
        if entry.cancel() {
            Ok(())
        } else {
            Err(Error::CacheError(cache::Error::CannotWrite).into())
        }
    }

    async fn close_busy(&mut self, handle: api::BusyHandle) -> Result<(), types::Error> {
        // Don't wait for the transaction to complete; drop the future to cancel.
        let _ = self.session.take_cache_entry(handle.into())?;
        Ok(())
    }

    async fn close(&mut self, handle: api::Handle) -> Result<(), types::Error> {
        let _ = self
            .session
            .take_cache_entry(handle.into())?
            .task()
            .recv()
            .await?;
        Ok(())
    }

    async fn get_state(&mut self, handle: api::Handle) -> Result<api::LookupState, types::Error> {
        let entry = self.session.cache_entry_mut(handle.into()).await?;

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

        Ok(state.into())
    }

    async fn get_user_metadata(
        &mut self,
        handle: api::Handle,
        max_len: u64,
    ) -> Result<Option<Vec<u8>>, types::Error> {
        let entry = self.session.cache_entry(handle.into()).await?;

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

    async fn get_length(&mut self, handle: api::Handle) -> Result<u64, types::Error> {
        let found = self
            .session
            .cache_entry(handle.into())
            .await?
            .found()
            .ok_or(Error::CacheError(crate::cache::Error::Missing))?;
        found
            .length()
            .ok_or(Error::CacheError(crate::cache::Error::Missing).into())
    }

    async fn get_max_age_ns(&mut self, handle: api::Handle) -> Result<u64, types::Error> {
        let entry = self.session.cache_entry_mut(handle.into()).await?;
        if let Some(found) = entry.found() {
            Ok(found.meta().max_age().as_nanos().try_into().unwrap())
        } else {
            Err(Error::CacheError(cache::Error::Missing).into())
        }
    }

    async fn get_stale_while_revalidate_ns(
        &mut self,
        _handle: api::Handle,
    ) -> Result<u64, types::Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn get_age_ns(&mut self, handle: api::Handle) -> Result<u64, types::Error> {
        let entry = self.session.cache_entry_mut(handle.into()).await?;
        if let Some(found) = entry.found() {
            Ok(found.meta().age().as_nanos().try_into().unwrap())
        } else {
            Err(Error::CacheError(cache::Error::Missing).into())
        }
    }

    async fn get_hits(&mut self, _handle: api::Handle) -> Result<u64, types::Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }
}
