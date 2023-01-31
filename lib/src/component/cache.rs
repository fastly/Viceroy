use {
    super::fastly::compute_at_edge::{cache, http_types, types},
    crate::{error::Error, session::Session},
};

#[async_trait::async_trait]
impl cache::Host for Session {
    async fn lookup(
        &mut self,
        _key: String,
        _options: cache::LookupOptions,
    ) -> Result<cache::Handle, types::FastlyError> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn insert(
        &mut self,
        _key: String,
        _options: cache::WriteOptions,
    ) -> Result<cache::BodyHandle, types::FastlyError> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn get_body(
        &mut self,
        _handle: cache::Handle,
        _options: cache::GetBodyOptions,
    ) -> Result<http_types::BodyHandle, types::FastlyError> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn transaction_lookup(
        &mut self,
        _key: String,
        _options: cache::LookupOptions,
    ) -> Result<cache::Handle, types::FastlyError> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn transaction_insert(
        &mut self,
        _handle: cache::Handle,
        _options: cache::WriteOptions,
    ) -> Result<http_types::BodyHandle, types::FastlyError> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn transaction_insert_and_stream_back(
        &mut self,
        _handle: cache::Handle,
        _options: cache::WriteOptions,
    ) -> Result<(http_types::BodyHandle, cache::Handle), types::FastlyError> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn transaction_update(
        &mut self,
        _handle: cache::Handle,
    ) -> Result<(), types::FastlyError> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn transaction_cancel(
        &mut self,
        _handle: cache::Handle,
    ) -> Result<(), types::FastlyError> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn get_state(
        &mut self,
        _handle: cache::Handle,
    ) -> Result<cache::LookupState, types::FastlyError> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn get_user_metadata(
        &mut self,
        _handle: cache::Handle,
    ) -> Result<String, types::FastlyError> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn get_length(&mut self, _handle: cache::Handle) -> Result<u64, types::FastlyError> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn get_max_age_ns(&mut self, _handle: cache::Handle) -> Result<u64, types::FastlyError> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn get_stale_while_revalidate_ns(
        &mut self,
        _handle: cache::Handle,
    ) -> Result<u64, types::FastlyError> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn get_age_ns(&mut self, _handle: cache::Handle) -> Result<u64, types::FastlyError> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }

    async fn get_hits(&mut self, _handle: cache::Handle) -> Result<u64, types::FastlyError> {
        Err(Error::Unsupported {
            msg: "Cache API primitives not yet supported",
        }
        .into())
    }
}
