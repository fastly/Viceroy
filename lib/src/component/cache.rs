use {
    super::fastly::api::{cache as api, http_types, types},
    crate::{
        body::Body,
        cache::{self, CacheKey, VaryRule, WriteOptions},
        error::{Error, HandleError},
        linking::ComponentCtx,
        session::{PeekableTask, PendingCacheTask},
        wiggle_abi::types::{CacheBusyHandle, CacheHandle},
    },
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

    Ok(WriteOptions {
        max_age,
        initial_age,
        vary_rule,
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
        // TODO: cceckman-at-fastly ; options
        let entry = self.session.cache_entry_mut(handle.into()).await?;

        let Some(found) = entry.found() else {
            return Err(Error::CacheError(cache::Error::Missing).into());
        };
        let body = found.body()?;

        Ok(self.session.insert_body(body).into())
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

        let task = PeekableTask::spawn(Box::pin(async move {
            Ok(cache.transaction_lookup(&key, &headers).await)
        }))
        .await;
        let task = PendingCacheTask::new(task);
        let handle: CacheBusyHandle = self.session.insert_cache_op(task).into();
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
        _handle: api::Handle,
        _max_len: u64,
    ) -> Result<Option<Vec<u8>>, types::Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn get_length(&mut self, _handle: api::Handle) -> Result<u64, types::Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
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
