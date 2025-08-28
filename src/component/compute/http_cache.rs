use {
    crate::component::fastly::compute::{http_body, http_cache, types},
    crate::{error::Error, linking::ComponentCtx},
    wasmtime::component::Resource,
};

impl http_cache::Host for ComponentCtx {
    async fn is_request_cacheable(
        &mut self,
        _req_handle: Resource<http_cache::Request>,
    ) -> Result<bool, types::Error> {
        Err(Error::Unsupported {
            msg: "HTTP Cache API primitives not yet supported",
        }
        .into())
    }

    async fn get_suggested_cache_key(
        &mut self,
        _req_handle: Resource<http_cache::Request>,
        _max_len: u64,
    ) -> Result<Vec<u8>, types::Error> {
        Err(Error::Unsupported {
            msg: "HTTP Cache API primitives not yet supported",
        }
        .into())
    }

    async fn close(&mut self, _handle: Resource<http_cache::Entry>) -> Result<(), types::Error> {
        Err(Error::Unsupported {
            msg: "HTTP Cache API primitives not yet supported",
        }
        .into())
    }
}

impl http_cache::HostSuggestedWriteOptions for ComponentCtx {
    async fn get_max_age_ns(
        &mut self,
        _rep: Resource<http_cache::SuggestedWriteOptions>,
    ) -> http_cache::DurationNs {
        panic!("HTTP Cache API primitives not yet supported")
    }

    async fn get_vary_rule(
        &mut self,
        _rep: Resource<http_cache::SuggestedWriteOptions>,
        _max_len: u64,
    ) -> Result<String, types::Error> {
        Err(Error::Unsupported {
            msg: "HTTP Cache API primitives not yet supported",
        }
        .into())
    }

    async fn get_initial_age_ns(
        &mut self,
        _rep: Resource<http_cache::SuggestedWriteOptions>,
    ) -> http_cache::DurationNs {
        panic!("HTTP Cache API primitives not yet supported")
    }

    async fn get_stale_while_revalidate_ns(
        &mut self,
        _rep: Resource<http_cache::SuggestedWriteOptions>,
    ) -> http_cache::DurationNs {
        panic!("HTTP Cache API primitives not yet supported")
    }

    async fn get_surrogate_keys(
        &mut self,
        _rep: Resource<http_cache::SuggestedWriteOptions>,
        _max_len: u64,
    ) -> Result<String, types::Error> {
        Err(Error::Unsupported {
            msg: "HTTP Cache API primitives not yet supported",
        }
        .into())
    }

    async fn get_length(
        &mut self,
        _rep: Resource<http_cache::SuggestedWriteOptions>,
    ) -> Option<http_cache::ObjectLength> {
        panic!("HTTP Cache API primitives not yet supported")
    }

    async fn get_sensitive_data(
        &mut self,
        _rep: Resource<http_cache::SuggestedWriteOptions>,
    ) -> bool {
        panic!("HTTP Cache API primitives not yet supported")
    }

    async fn drop(
        &mut self,
        _rep: Resource<http_cache::SuggestedWriteOptions>,
    ) -> wasmtime::Result<()> {
        Ok(())
    }
}

impl http_cache::HostExtraWriteOptions for ComponentCtx {
    async fn drop(&mut self, _h: Resource<http_cache::ExtraWriteOptions>) -> wasmtime::Result<()> {
        Ok(())
    }
}

impl http_cache::HostExtraLookupOptions for ComponentCtx {
    async fn drop(&mut self, _h: Resource<http_cache::ExtraLookupOptions>) -> wasmtime::Result<()> {
        Ok(())
    }
}

impl http_cache::HostEntry for ComponentCtx {
    async fn lookup(
        &mut self,
        _req_handle: Resource<http_cache::Request>,
        _options: http_cache::LookupOptions,
    ) -> Result<Resource<http_cache::Entry>, types::Error> {
        Err(Error::Unsupported {
            msg: "HTTP Cache API primitives not yet supported",
        }
        .into())
    }

    async fn transaction_lookup(
        &mut self,
        _req_handle: Resource<http_cache::Request>,
        _options: http_cache::LookupOptions,
    ) -> Result<Resource<http_cache::Entry>, types::Error> {
        Err(Error::Unsupported {
            msg: "HTTP Cache API primitives not yet supported",
        }
        .into())
    }

    async fn transaction_insert(
        &mut self,
        _handle: Resource<http_cache::Entry>,
        _resp_handle: Resource<http_cache::Response>,
        _options: http_cache::WriteOptions,
    ) -> Result<Resource<http_cache::Body>, types::Error> {
        Err(Error::Unsupported {
            msg: "HTTP Cache API primitives not yet supported",
        }
        .into())
    }

    async fn transaction_insert_and_stream_back(
        &mut self,
        _handle: Resource<http_cache::Entry>,
        _resp_handle: Resource<http_cache::Response>,
        _options: http_cache::WriteOptions,
    ) -> Result<(Resource<http_cache::Body>, Resource<http_cache::Entry>), types::Error> {
        Err(Error::Unsupported {
            msg: "HTTP Cache API primitives not yet supported",
        }
        .into())
    }

    async fn transaction_update(
        &mut self,
        _handle: Resource<http_cache::Entry>,
        _resp_handle: Resource<http_cache::Response>,
        _options: http_cache::WriteOptions,
    ) -> Result<(), types::Error> {
        Err(Error::Unsupported {
            msg: "HTTP Cache API primitives not yet supported",
        }
        .into())
    }

    async fn transaction_update_and_return_fresh(
        &mut self,
        _handle: Resource<http_cache::Entry>,
        _resp_handle: Resource<http_cache::Response>,
        _options: http_cache::WriteOptions,
    ) -> Result<Resource<http_cache::Entry>, types::Error> {
        Err(Error::Unsupported {
            msg: "HTTP Cache API primitives not yet supported",
        }
        .into())
    }

    async fn transaction_record_not_cacheable(
        &mut self,
        _handle: Resource<http_cache::Entry>,
        _options: http_cache::WriteOptions,
    ) -> Result<(), types::Error> {
        Err(Error::Unsupported {
            msg: "HTTP Cache API primitives not yet supported",
        }
        .into())
    }

    async fn get_suggested_backend_request(
        &mut self,
        _handle: Resource<http_cache::Entry>,
    ) -> Result<Resource<http_cache::Request>, types::Error> {
        Err(Error::Unsupported {
            msg: "HTTP Cache API primitives not yet supported",
        }
        .into())
    }

    async fn get_suggested_write_options(
        &mut self,
        _handle: Resource<http_cache::Entry>,
        _response: Resource<http_cache::Response>,
    ) -> Result<Resource<http_cache::SuggestedWriteOptions>, types::Error> {
        Err(Error::Unsupported {
            msg: "HTTP Cache API primitives not yet supported",
        }
        .into())
    }

    async fn prepare_response_for_storage(
        &mut self,
        _handle: Resource<http_cache::Entry>,
        _response: Resource<http_cache::Response>,
    ) -> Result<(http_cache::StorageAction, Resource<http_cache::Response>), types::Error> {
        Err(Error::Unsupported {
            msg: "HTTP Cache API primitives not yet supported",
        }
        .into())
    }

    async fn get_found_response(
        &mut self,
        _handle: Resource<http_cache::Entry>,
        _transform_for_client: u32,
    ) -> Result<(Resource<http_cache::Response>, Resource<http_body::Body>), types::Error> {
        Err(Error::Unsupported {
            msg: "HTTP Cache API primitives not yet supported",
        }
        .into())
    }

    async fn get_state(
        &mut self,
        _handle: Resource<http_cache::Entry>,
    ) -> Result<http_cache::LookupState, types::Error> {
        Err(Error::Unsupported {
            msg: "HTTP Cache API primitives not yet supported",
        }
        .into())
    }

    async fn get_length(
        &mut self,
        _handle: Resource<http_cache::Entry>,
    ) -> Result<http_cache::ObjectLength, types::Error> {
        Err(Error::Unsupported {
            msg: "HTTP Cache API primitives not yet supported",
        }
        .into())
    }

    async fn get_max_age_ns(
        &mut self,
        _handle: Resource<http_cache::Entry>,
    ) -> Result<http_cache::DurationNs, types::Error> {
        Err(Error::Unsupported {
            msg: "HTTP Cache API primitives not yet supported",
        }
        .into())
    }

    async fn get_stale_while_revalidate_ns(
        &mut self,
        _handle: Resource<http_cache::Entry>,
    ) -> Result<http_cache::DurationNs, types::Error> {
        Err(Error::Unsupported {
            msg: "HTTP Cache API primitives not yet supported",
        }
        .into())
    }

    async fn get_age_ns(
        &mut self,
        _handle: Resource<http_cache::Entry>,
    ) -> Result<http_cache::DurationNs, types::Error> {
        Err(Error::Unsupported {
            msg: "HTTP Cache API primitives not yet supported",
        }
        .into())
    }

    async fn get_hits(
        &mut self,
        _handle: Resource<http_cache::Entry>,
    ) -> Result<http_cache::CacheHitCount, types::Error> {
        Err(Error::Unsupported {
            msg: "HTTP Cache API primitives not yet supported",
        }
        .into())
    }

    async fn get_sensitive_data(
        &mut self,
        _handle: Resource<http_cache::Entry>,
    ) -> Result<bool, types::Error> {
        Err(Error::Unsupported {
            msg: "HTTP Cache API primitives not yet supported",
        }
        .into())
    }

    async fn get_surrogate_keys(
        &mut self,
        _handle: Resource<http_cache::Entry>,
        _max_len: u64,
    ) -> Result<String, types::Error> {
        Err(Error::Unsupported {
            msg: "HTTP Cache API primitives not yet supported",
        }
        .into())
    }

    async fn get_vary_rule(
        &mut self,
        _handle: Resource<http_cache::Entry>,
        _max_len: u64,
    ) -> Result<String, types::Error> {
        Err(Error::Unsupported {
            msg: "HTTP Cache API primitives not yet supported",
        }
        .into())
    }

    async fn transaction_abandon(
        &mut self,
        _handle: Resource<http_cache::Entry>,
    ) -> Result<(), types::Error> {
        Err(Error::Unsupported {
            msg: "HTTP Cache API primitives not yet supported",
        }
        .into())
    }

    async fn drop(&mut self, _handle: Resource<http_cache::Entry>) -> wasmtime::Result<()> {
        Err(Error::Unsupported {
            msg: "HTTP Cache API primitives not yet supported",
        }
        .into())
    }
}
