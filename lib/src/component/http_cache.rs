use super::fastly::api::{http_cache, types};
use crate::component::component::Resource;
use crate::linking::ComponentCtx;

#[async_trait::async_trait]
impl http_cache::HostSuggestedCacheOptions for ComponentCtx {
    async fn max_age_ns(
        &mut self,
        _rep: Resource<http_cache::SuggestedCacheOptions>,
    ) -> http_cache::DurationNs {
        0
    }

    async fn vary_rule(
        &mut self,
        _rep: Resource<http_cache::SuggestedCacheOptions>,
        _max_len: u64,
    ) -> Result<Vec<u8>, types::Error> {
        Err(types::Error::Unsupported)
    }

    async fn initial_age_ns(
        &mut self,
        _rep: Resource<http_cache::SuggestedCacheOptions>,
    ) -> http_cache::DurationNs {
        0
    }

    async fn stale_while_revalidate_ns(
        &mut self,
        _rep: Resource<http_cache::SuggestedCacheOptions>,
    ) -> http_cache::DurationNs {
        0
    }

    async fn surrogate_keys(
        &mut self,
        _rep: Resource<http_cache::SuggestedCacheOptions>,
        _max_len: u64,
    ) -> Result<Vec<u8>, types::Error> {
        Err(types::Error::Unsupported)
    }

    async fn length(
        &mut self,
        _rep: Resource<http_cache::SuggestedCacheOptions>,
    ) -> Option<http_cache::ObjectLength> {
        None
    }

    async fn sensitive_data(&mut self, _rep: Resource<http_cache::SuggestedCacheOptions>) -> bool {
        // Since the HTTP cache API is not yet supported, just return that
        // everything is sensative, which is enough to make simple programs work.
        true
    }

    async fn drop(
        &mut self,
        _rep: Resource<http_cache::SuggestedCacheOptions>,
    ) -> anyhow::Result<()> {
        Ok(())
    }
}

#[async_trait::async_trait]
impl http_cache::Host for ComponentCtx {
    async fn is_request_cacheable(
        &mut self,
        _req_handle: http_cache::RequestHandle,
    ) -> Result<bool, types::Error> {
        // Since the HTTP cache API is not yet supported, just return that
        // nothing is cacheable, which is enough to make simple programs work.
        Ok(false)
    }

    async fn get_suggested_cache_key(
        &mut self,
        _req_handle: http_cache::RequestHandle,
        _max_len: u64,
    ) -> Result<Vec<u8>, types::Error> {
        Err(types::Error::Unsupported)
    }

    async fn lookup(
        &mut self,
        _req_handle: http_cache::RequestHandle,
        _options_mask: http_cache::CacheLookupOptionsMask,
        _options: http_cache::CacheLookupOptions,
    ) -> Result<http_cache::CacheHandle, types::Error> {
        Err(types::Error::Unsupported)
    }

    async fn transaction_lookup(
        &mut self,
        _req_handle: http_cache::RequestHandle,
        _options_mask: http_cache::CacheLookupOptionsMask,
        _options: http_cache::CacheLookupOptions,
    ) -> Result<http_cache::CacheHandle, types::Error> {
        Err(types::Error::Unsupported)
    }

    async fn transaction_insert(
        &mut self,
        _handle: http_cache::CacheHandle,
        _resp_handle: http_cache::ResponseHandle,
        _options_mask: http_cache::CacheWriteOptionsMask,
        _options: http_cache::CacheWriteOptions,
    ) -> Result<http_cache::BodyHandle, types::Error> {
        Err(types::Error::Unsupported)
    }

    async fn transaction_insert_and_stream_back(
        &mut self,
        _handle: http_cache::CacheHandle,
        _resp_handle: http_cache::ResponseHandle,
        _options_mask: http_cache::CacheWriteOptionsMask,
        _options: http_cache::CacheWriteOptions,
    ) -> Result<(http_cache::BodyHandle, http_cache::CacheHandle), types::Error> {
        Err(types::Error::Unsupported)
    }

    async fn transaction_update(
        &mut self,
        _handle: http_cache::CacheHandle,
        _resp_handle: http_cache::ResponseHandle,
        _options_mask: http_cache::CacheWriteOptionsMask,
        _options: http_cache::CacheWriteOptions,
    ) -> Result<(), types::Error> {
        Err(types::Error::Unsupported)
    }

    async fn transaction_update_and_return_fresh(
        &mut self,
        _handle: http_cache::CacheHandle,
        _resp_handle: http_cache::ResponseHandle,
        _options_mask: http_cache::CacheWriteOptionsMask,
        _options: http_cache::CacheWriteOptions,
    ) -> Result<http_cache::CacheHandle, types::Error> {
        Err(types::Error::Unsupported)
    }

    async fn transaction_record_not_cacheable(
        &mut self,
        _handle: http_cache::CacheHandle,
        _options_mask: http_cache::CacheWriteOptionsMask,
        _options: http_cache::CacheWriteOptions,
    ) -> Result<(), types::Error> {
        Err(types::Error::Unsupported)
    }

    async fn transaction_abandon(
        &mut self,
        _handle: http_cache::CacheHandle,
    ) -> Result<(), types::Error> {
        Err(types::Error::Unsupported)
    }

    async fn close(&mut self, _handle: http_cache::CacheHandle) -> Result<(), types::Error> {
        Err(types::Error::Unsupported)
    }

    async fn get_suggested_backend_request(
        &mut self,
        _handle: http_cache::CacheHandle,
    ) -> Result<http_cache::RequestHandle, types::Error> {
        Err(types::Error::Unsupported)
    }

    async fn get_suggested_cache_options(
        &mut self,
        _handle: http_cache::CacheHandle,
        _response: http_cache::ResponseHandle,
    ) -> Result<Resource<http_cache::SuggestedCacheOptions>, types::Error> {
        Err(types::Error::Unsupported)
    }

    async fn prepare_response_for_storage(
        &mut self,
        _handle: http_cache::CacheHandle,
        _response: http_cache::ResponseHandle,
    ) -> Result<(http_cache::StorageAction, http_cache::ResponseHandle), types::Error> {
        Err(types::Error::Unsupported)
    }

    async fn get_found_response(
        &mut self,
        _handle: http_cache::CacheHandle,
        _transform_for_client: u32,
    ) -> Result<(http_cache::ResponseHandle, http_cache::BodyHandle), types::Error> {
        Err(types::Error::Unsupported)
    }

    async fn get_state(
        &mut self,
        _handle: http_cache::CacheHandle,
    ) -> Result<http_cache::LookupState, types::Error> {
        Err(types::Error::Unsupported)
    }

    async fn get_length(
        &mut self,
        _handle: http_cache::CacheHandle,
    ) -> Result<http_cache::ObjectLength, types::Error> {
        Err(types::Error::Unsupported)
    }

    async fn get_max_age_ns(
        &mut self,
        _handle: http_cache::CacheHandle,
    ) -> Result<http_cache::DurationNs, types::Error> {
        Err(types::Error::Unsupported)
    }

    async fn get_stale_while_revalidate_ns(
        &mut self,
        _handle: http_cache::CacheHandle,
    ) -> Result<http_cache::DurationNs, types::Error> {
        Err(types::Error::Unsupported)
    }

    async fn get_age_ns(
        &mut self,
        _handle: http_cache::CacheHandle,
    ) -> Result<http_cache::DurationNs, types::Error> {
        Err(types::Error::Unsupported)
    }

    async fn get_hits(
        &mut self,
        _handle: http_cache::CacheHandle,
    ) -> Result<http_cache::CacheHitCount, types::Error> {
        Err(types::Error::Unsupported)
    }

    async fn get_sensitive_data(
        &mut self,
        _handle: http_cache::CacheHandle,
    ) -> Result<bool, types::Error> {
        Err(types::Error::Unsupported)
    }

    async fn get_surrogate_keys(
        &mut self,
        _handle: http_cache::CacheHandle,
        _max_len: u64,
    ) -> Result<Vec<u8>, types::Error> {
        Err(types::Error::Unsupported)
    }

    async fn get_vary_rule(
        &mut self,
        _handle: http_cache::CacheHandle,
        _max_len: u64,
    ) -> Result<Vec<u8>, types::Error> {
        Err(types::Error::Unsupported)
    }
}
