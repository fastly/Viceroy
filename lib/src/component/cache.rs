use {
    super::fastly::api::{cache, http_types, types},
    crate::{error::Error, session::Session},
};

#[async_trait::async_trait]
impl cache::Host for Session {
    async fn lookup(
        &mut self,
        _key: String,
        _options_mask: cache::LookupOptionsMask,
        _options: cache::LookupOptions,
    ) -> Result<cache::Handle, types::Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn insert(
        &mut self,
        _key: String,
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
        _handle: cache::Handle,
        _options_mask: cache::GetBodyOptionsMask,
        _options: cache::GetBodyOptions,
    ) -> Result<http_types::BodyHandle, types::Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn transaction_lookup(
        &mut self,
        _key: String,
        _options_mask: cache::LookupOptionsMask,
        _options: cache::LookupOptions,
    ) -> Result<cache::Handle, types::Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn transaction_lookup_async(
        &mut self,
        _key: String,
        _options_mask: cache::LookupOptionsMask,
        _options: cache::LookupOptions,
    ) -> Result<cache::BusyHandle, types::Error> {
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
        _handle: cache::Handle,
    ) -> Result<cache::LookupState, types::Error> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
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
