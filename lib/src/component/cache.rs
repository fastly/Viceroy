use {
    super::fastly::api::{cache, http_types, types},
    crate::{
        body::Body,
        cache::{CacheKey, VaryRule, WriteOptions},
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
    options_mask: cache::WriteOptionsMask,
    options: &cache::WriteOptions,
) -> Result<WriteOptions, Error> {
    let max_age = Duration::from_nanos(options.max_age_ns);
    let initial_age = if options_mask.contains(cache::WriteOptionsMask::INITIAL_AGE_NS) {
        Duration::from_nanos(options.initial_age_ns)
    } else {
        Duration::ZERO
    };
    let vary_rule = if options_mask.contains(cache::WriteOptionsMask::VARY_RULE) {
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
impl cache::Host for ComponentCtx {
    async fn lookup(
        &mut self,
        key: Vec<u8>,
        options_mask: cache::LookupOptionsMask,
        options: cache::LookupOptions,
    ) -> Result<cache::Handle, types::Error> {
        let headers = if options_mask.contains(cache::LookupOptionsMask::REQUEST_HEADERS) {
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
        options_mask: cache::WriteOptionsMask,
        options: cache::WriteOptions,
    ) -> Result<cache::BodyHandle, types::Error> {
        // TODO: cceckman-at-fastly: Handle options,
        // then remove this guard.
        if !std::env::var("ENABLE_EXPERIMENTAL_CACHE_API").is_ok_and(|v| v == "1") {
            return Err(Error::NotAvailable("Cache API primitives").into());
        }

        let key: CacheKey = get_key(key)?;
        let cache = Arc::clone(self.session.cache());
        let write_options = load_write_options(options_mask, &options)?;

        let request_headers = if options_mask.contains(cache::WriteOptionsMask::REQUEST_HEADERS) {
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
        _options_mask: cache::ReplaceOptionsMask,
        _options: cache::ReplaceOptions,
    ) -> Result<cache::ReplaceHandle, types::Error> {
        let _key: CacheKey = get_key(key)?;
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn replace_get_age_ns(
        &mut self,
        _handle: cache::ReplaceHandle,
    ) -> Result<cache::DurationNs, types::Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn replace_get_body(
        &mut self,
        _handle: cache::ReplaceHandle,
        _options_mask: cache::GetBodyOptionsMask,
        _options: cache::GetBodyOptions,
    ) -> Result<http_types::BodyHandle, types::Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn replace_get_hits(
        &mut self,
        _handle: cache::ReplaceHandle,
    ) -> Result<u64, types::Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn replace_get_length(
        &mut self,
        _handle: cache::ReplaceHandle,
    ) -> Result<u64, types::Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn replace_get_max_age_ns(
        &mut self,
        _handle: cache::ReplaceHandle,
    ) -> Result<cache::DurationNs, types::Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn replace_get_stale_while_revalidate_ns(
        &mut self,
        _handle: cache::ReplaceHandle,
    ) -> Result<cache::DurationNs, types::Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn replace_get_state(
        &mut self,
        _handle: cache::ReplaceHandle,
    ) -> Result<cache::LookupState, types::Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn replace_get_user_metadata(
        &mut self,
        _handle: cache::ReplaceHandle,
        _max_len: u64,
    ) -> Result<Option<Vec<u8>>, types::Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn replace_insert(
        &mut self,
        _handle: cache::ReplaceHandle,
        _options_mask: cache::WriteOptionsMask,
        _options: cache::WriteOptions,
    ) -> Result<cache::BodyHandle, types::Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn get_body(
        &mut self,
        handle: cache::Handle,
        _options_mask: cache::GetBodyOptionsMask,
        _options: cache::GetBodyOptions,
    ) -> Result<http_types::BodyHandle, types::Error> {
        // TODO: cceckman-at-fastly ; options
        let entry = self.session.cache_entry_mut(handle.into()).await?;

        let Some(found) = entry.found() else {
            return Err(Error::CacheError("key was not found in cache".to_owned()).into());
        };
        let body = found.body()?;

        Ok(self.session.insert_body(body).into())
    }

    async fn transaction_lookup(
        &mut self,
        key: Vec<u8>,
        options_mask: cache::LookupOptionsMask,
        options: cache::LookupOptions,
    ) -> Result<cache::Handle, types::Error> {
        let h = self
            .transaction_lookup_async(key, options_mask, options)
            .await?;
        self.cache_busy_handle_wait(h).await
    }

    async fn transaction_lookup_async(
        &mut self,
        key: Vec<u8>,
        options_mask: cache::LookupOptionsMask,
        options: cache::LookupOptions,
    ) -> Result<cache::BusyHandle, types::Error> {
        let headers = if options_mask.contains(cache::LookupOptionsMask::REQUEST_HEADERS) {
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
        handle: cache::BusyHandle,
    ) -> Result<cache::Handle, types::Error> {
        let busy_handle: CacheBusyHandle = handle.into();
        let handle: CacheHandle = busy_handle.into();
        let _ = self.session.cache_entry_mut(handle).await?;
        Ok(handle.into())
    }

    async fn transaction_insert(
        &mut self,
        handle: cache::Handle,
        options_mask: cache::WriteOptionsMask,
        options: cache::WriteOptions,
    ) -> Result<http_types::BodyHandle, types::Error> {
        let (body, cache_handle) = self
            .transaction_insert_and_stream_back(handle, options_mask, options)
            .await?;
        let _ = self.session.take_cache_entry(cache_handle.into())?;
        Ok(body)
    }

    async fn transaction_insert_and_stream_back(
        &mut self,
        handle: cache::Handle,
        options_mask: cache::WriteOptionsMask,
        options: cache::WriteOptions,
    ) -> Result<(http_types::BodyHandle, cache::Handle), types::Error> {
        // TODO: cceckman-at-fastly: Handle options,
        // then remove this guard.
        if !std::env::var("ENABLE_EXPERIMENTAL_CACHE_API").is_ok_and(|v| v == "1") {
            return Err(Error::NotAvailable("Cache API primitives").into());
        }

        let write_options = load_write_options(options_mask, &options)?;
        // No request headers here; request headers come from the original lookup.
        if options_mask.contains(cache::WriteOptionsMask::REQUEST_HEADERS) {
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
        _handle: cache::Handle,
        _options_mask: cache::WriteOptionsMask,
        _options: cache::WriteOptions,
    ) -> Result<(), types::Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn transaction_cancel(&mut self, _handle: cache::Handle) -> Result<(), types::Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn close_busy(&mut self, _handle: cache::BusyHandle) -> Result<(), types::Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn close(&mut self, _handle: cache::Handle) -> Result<(), types::Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn get_state(
        &mut self,
        handle: cache::Handle,
    ) -> Result<cache::LookupState, types::Error> {
        let entry = self.session.cache_entry_mut(handle.into()).await?;

        let mut state = cache::LookupState::empty();
        if let Some(found) = entry.found() {
            state |= cache::LookupState::FOUND;

            if !found.meta().is_fresh() {
                state |= cache::LookupState::STALE;
            }
            // TODO:: stale-while-revalidate.
            // For now, usable if fresh.
            if found.meta().is_fresh() {
                state |= cache::LookupState::USABLE;
            }
        }
        if entry.go_get().is_some() {
            state |= cache::LookupState::MUST_INSERT_OR_UPDATE
        }

        Ok(state.into())
    }

    async fn get_user_metadata(
        &mut self,
        _handle: cache::Handle,
        _max_len: u64,
    ) -> Result<Option<Vec<u8>>, types::Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn get_length(&mut self, _handle: cache::Handle) -> Result<u64, types::Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn get_max_age_ns(&mut self, handle: cache::Handle) -> Result<u64, types::Error> {
        let entry = self.session.cache_entry_mut(handle.into()).await?;
        if let Some(found) = entry.found() {
            Ok(found.meta().max_age().as_nanos().try_into().unwrap())
        } else {
            Err(Error::CacheError(
                "Attempted to read metadata from CacheHandle that was not Found".to_owned(),
            )
            .into())
        }
    }

    async fn get_stale_while_revalidate_ns(
        &mut self,
        _handle: cache::Handle,
    ) -> Result<u64, types::Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn get_age_ns(&mut self, handle: cache::Handle) -> Result<u64, types::Error> {
        let entry = self.session.cache_entry_mut(handle.into()).await?;
        if let Some(found) = entry.found() {
            Ok(found.meta().age().as_nanos().try_into().unwrap())
        } else {
            Err(Error::CacheError(
                "Attempted to read metadata from CacheHandle that was not Found".to_owned(),
            )
            .into())
        }
    }

    async fn get_hits(&mut self, _handle: cache::Handle) -> Result<u64, types::Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }
}
