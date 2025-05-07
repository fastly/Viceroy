use {
    super::fastly::api::{cache as api, http_types, types},
    crate::{
        body::Body,
        cache::{self, CacheKey, VaryRule, WriteOptions},
        error::{Error, HandleError},
        linking::ComponentCtx,
        session::{PeekableTask, PendingCacheTask},
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
    options_mask: api::WriteOptionsMask,
    options: &api::WriteOptions,
) -> Result<WriteOptions, Error> {
    let max_age = Duration::from_nanos(options.max_age_ns);
    let initial_age = if options_mask.contains(api::WriteOptionsMask::INITIAL_AGE_NS) {
        Duration::from_nanos(options.initial_age_ns)
    } else {
        Duration::ZERO
    };
    let vary_rule = if options_mask.contains(api::WriteOptionsMask::VARY_RULE) {
        options.vary_rule.parse()?
    } else {
        VaryRule::default()
    };
    let user_metadata = if options_mask.contains(api::WriteOptionsMask::USER_METADATA) {
        Bytes::copy_from_slice(&options.user_metadata)
    } else {
        Bytes::new()
    };
    let length = if options_mask.contains(api::WriteOptionsMask::LENGTH) {
        Some(options.length)
    } else {
        None
    };
    let sensitive_data = options_mask.contains(api::WriteOptionsMask::SENSITIVE_DATA);

    // SERVICE_ID differences are observable- but we don't implement that behavior. Error explicitly.
    if options_mask.contains(api::WriteOptionsMask::SERVICE_ID) {
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

#[async_trait::async_trait]
impl api::Host for ComponentCtx {
    async fn lookup(
        &mut self,
        key: Vec<u8>,
        options_mask: api::LookupOptionsMask,
        options: api::LookupOptions,
    ) -> Result<api::Handle, types::Error> {
        let headers = if options_mask.contains(api::LookupOptionsMask::REQUEST_HEADERS) {
            let handle = options.request_headers;
            let parts = self.session.request_parts(handle.into())?;
            parts.headers.clone()
        } else {
            HeaderMap::default()
        };

        let key: CacheKey = get_key(key)?;
        let cache = Arc::clone(self.session.cache());

        let task = PeekableTask::spawn(Box::pin(
            async move { Ok(cache.lookup(&key, &headers).await) },
        ))
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
        // TODO: cceckman-at-fastly: Handle options,
        // then remove this guard.
        if !std::env::var("ENABLE_EXPERIMENTAL_CACHE_API").is_ok_and(|v| v == "1") {
            return Err(Error::NotAvailable("Cache API primitives").into());
        }

        let key: CacheKey = get_key(key)?;
        let cache = Arc::clone(self.session.cache());
        let write_options = load_write_options(options_mask, &options)?;

        let request_headers = if options_mask.contains(api::WriteOptionsMask::REQUEST_HEADERS) {
            let handle = options.request_headers;
            let parts = self.session.request_parts(handle.into())?;
            parts.headers.clone()
        } else {
            HeaderMap::default()
        };

        let handle = self.session.insert_body(Body::empty());
        let read_body = self.session.begin_streaming(handle)?;
        cache
            .insert(&key, request_headers, write_options, read_body)
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
        _options_mask: api::GetBodyOptionsMask,
        _options: api::GetBodyOptions,
    ) -> Result<http_types::BodyHandle, types::Error> {
        // TODO: cceckman-at-fastly: Handle options,
        // then remove this guard.
        if !std::env::var("ENABLE_EXPERIMENTAL_CACHE_API").is_ok_and(|v| v == "1") {
            return Err(Error::NotAvailable("Cache API primitives").into());
        }

        // We wind up re-borrowing `found` and `self.session` several times here, to avoid
        // borrowing the both of them at once. Ultimately it is possible that inserting a body
        // would change the address of Found, by re-shuffling the AsyncItems table; once again,
        // borrowck wins the day.
        //
        // We have an exclusive borrow &mut self.session for the lifetime of this call,
        // so even though we're re-borrowing/repeating lookups, we know we won't run into TOCTOU.

        let found = self
            .session
            .cache_entry(handle.into())
            .await?
            .found()
            .ok_or_else(|| Error::CacheError(cache::Error::Missing))?;

        // Preemptively (optimistically) start a read. Don't worry, the Drop impl for Body will
        // clean up the copying task.
        // We have to do this to allow `found`'s lifetime to end before self.session.body, which
        // has to re-borrow self.self.session.
        let body = found.body()?;

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
        let headers = if options_mask.contains(api::LookupOptionsMask::REQUEST_HEADERS) {
            let handle = options.request_headers;
            let parts = self.session.request_parts(handle.into())?;
            parts.headers.clone()
        } else {
            HeaderMap::default()
        };

        let key: CacheKey = get_key(key)?;
        let cache = Arc::clone(self.session.cache());

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
        let _ = self.session.take_cache_entry(cache_handle.into())?;
        Ok(body)
    }

    async fn transaction_insert_and_stream_back(
        &mut self,
        handle: api::Handle,
        options_mask: api::WriteOptionsMask,
        options: api::WriteOptions,
    ) -> Result<(http_types::BodyHandle, api::Handle), types::Error> {
        // TODO: cceckman-at-fastly: Handle options,
        // then remove this guard.
        if !std::env::var("ENABLE_EXPERIMENTAL_CACHE_API").is_ok_and(|v| v == "1") {
            return Err(Error::NotAvailable("Cache API primitives").into());
        }

        let write_options = load_write_options(options_mask, &options)?;
        // No request headers here; request headers come from the original lookup.
        if options_mask.contains(api::WriteOptionsMask::REQUEST_HEADERS) {
            return Err(Error::InvalidArgument.into());
        }

        let entry = self.session.cache_entry_mut(handle.into()).await?;
        // The path here is:
        // InvalidCacheHandle -> FastlyStatus::BADF -> (ABI boundary) ->
        // CacheError::InvalidOperation
        let obligation =
            entry
                .take_go_get()
                .ok_or(Error::HandleError(HandleError::InvalidCacheHandle(
                    handle.into(),
                )))?;

        let body_handle = self.session.insert_body(Body::empty());
        let read_body = self.session.begin_streaming(body_handle)?;

        obligation.complete(write_options, read_body);
        Ok((body_handle.into(), handle))
    }

    async fn transaction_update(
        &mut self,
        _handle: api::Handle,
        _options_mask: api::WriteOptionsMask,
        _options: api::WriteOptions,
    ) -> Result<(), types::Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn transaction_cancel(&mut self, handle: api::Handle) -> Result<(), types::Error> {
        let entry = self.session.cache_entry_mut(handle.into()).await?;
        if let Some(_) = entry.take_go_get() {
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
            // TODO:: stale-while-revalidate.
            // For now, usable if fresh.
            if found.meta().is_fresh() {
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
