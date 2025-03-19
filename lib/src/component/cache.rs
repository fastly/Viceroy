use {
    super::fastly::api::{cache, http_types, types},
    crate::{
        body::Body,
        cache::{CacheKey, VaryRule, WriteOptions},
        error::Error,
        linking::ComponentCtx,
        session::{PeekableTask, PendingCacheTask, Session},
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
    session: &Session,
    options_mask: cache::WriteOptionsMask,
    options: cache::WriteOptions,
) -> Result<WriteOptions, Error> {
    let max_age = Duration::from_nanos(options.max_age_ns);
    let initial_age = if options_mask.contains(cache::WriteOptionsMask::INITIAL_AGE_NS) {
        Some(Duration::from_nanos(options.initial_age_ns))
    } else {
        None
    };
    let request_headers = if options_mask.contains(cache::WriteOptionsMask::REQUEST_HEADERS) {
        let handle = options.request_headers;
        let parts = session.request_parts(handle.into())?;
        parts.headers.clone()
    } else {
        HeaderMap::default()
    };
    let vary_rule = if options_mask.contains(cache::WriteOptionsMask::VARY_RULE) {
        options.vary_rule.parse()?
    } else {
        VaryRule::default()
    };

    Ok(WriteOptions {
        max_age,
        initial_age,
        request_headers,
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
        let handle = self.session.insert_cache_op(task);
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
        let options = load_write_options(&self.session, options_mask, options)?;

        let handle = self.session.insert_body(Body::empty());
        let read_body = self.session.begin_streaming(handle)?;
        cache.insert(&key, options, read_body).await;
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
            .ok_or_else(|| Error::CacheError("key was not found in cache".to_owned()))?;
        // Preemptively (optimistically) start a read. Don't worry, the Drop impl for Body will
        // clean up the copying task.
        // We have to do this to allow `found`'s lifetime to end before self.session.body, which
        // has to re-borrow self.self.session.
        let body = found.body()?;

        if let Some(prev_handle) = found.last_body_handle {
            // Check if they're still reading the previous handle.
            if self.session.body(prev_handle).is_ok() {
                // TODO: cceckman-at-fastly: more precise error types
                return Err(Error::CacheError(
                    format!("Found has a read outstanding already (BodyHandle {prev_handle}). Close this handle before reading")
            ).into());
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
        _options_mask: cache::LookupOptionsMask,
        _options: cache::LookupOptions,
    ) -> Result<cache::Handle, types::Error> {
        let _key = get_key(key)?;
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn transaction_lookup_async(
        &mut self,
        key: Vec<u8>,
        _options_mask: cache::LookupOptionsMask,
        _options: cache::LookupOptions,
    ) -> Result<cache::BusyHandle, types::Error> {
        let _key = get_key(key)?;
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn cache_busy_handle_wait(
        &mut self,
        _handle: cache::BusyHandle,
    ) -> Result<cache::Handle, types::Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn transaction_insert(
        &mut self,
        _handle: cache::Handle,
        _options_mask: cache::WriteOptionsMask,
        _options: cache::WriteOptions,
    ) -> Result<http_types::BodyHandle, types::Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn transaction_insert_and_stream_back(
        &mut self,
        _handle: cache::Handle,
        _options_mask: cache::WriteOptionsMask,
        _options: cache::WriteOptions,
    ) -> Result<(http_types::BodyHandle, cache::Handle), types::Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
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
            // TODO:: stale-while-revalidate and go_get obligation.
            // For now, usable if fresh.
            if found.meta().is_fresh() {
                state |= cache::LookupState::USABLE;
            }
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
