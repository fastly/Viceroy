use {
    super::fastly::api::{cache, http_types, types},
    crate::{
        body::Body,
        cache::CacheKey,
        error::Error,
        linking::ComponentCtx,
        session::{PeekableTask, PendingCacheTask},
    },
    std::sync::Arc,
};

// Utility for remapping the errors.
fn get_key(key: Vec<u8>) -> Result<CacheKey, types::Error> {
    key.try_into()
        .map_err(|_| types::Error::BufferLen(CacheKey::MAX_LENGTH as u64))
}

#[async_trait::async_trait]
impl cache::Host for ComponentCtx {
    async fn lookup(
        &mut self,
        key: Vec<u8>,
        _options_mask: cache::LookupOptionsMask,
        _options: cache::LookupOptions,
    ) -> Result<cache::Handle, types::Error> {
        let key: CacheKey = get_key(key)?;
        let cache = Arc::clone(self.session.cache());

        // TODO: cceckman-at-fastly - handle options
        let task = PeekableTask::spawn(Box::pin(async move { Ok(cache.lookup(&key).await) })).await;
        let task = PendingCacheTask::new(task);
        let handle = self.session.insert_cache_op(task);
        Ok(handle.into())
    }

    async fn insert(
        &mut self,
        key: Vec<u8>,
        _options_mask: cache::WriteOptionsMask,
        _options: cache::WriteOptions,
    ) -> Result<cache::BodyHandle, types::Error> {
        let key: CacheKey = get_key(key)?;

        let cache = Arc::clone(self.session.cache());

        // TODO: cceckman-at-fastly - handle options
        let handle = self.session.insert_body(Body::empty());
        let read_body = self.session.begin_streaming(handle)?;
        cache.insert(&key, read_body).await;
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
        if entry.found().is_some() {
            state |= cache::LookupState::FOUND;
            // TODO: cceckman-at-fastly: stale vs. usable, go_get obligation
            state |= cache::LookupState::USABLE;
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

    async fn get_max_age_ns(&mut self, _handle: cache::Handle) -> Result<u64, types::Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
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

    async fn get_age_ns(&mut self, _handle: cache::Handle) -> Result<u64, types::Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn get_hits(&mut self, _handle: cache::Handle) -> Result<u64, types::Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }
}
