use crate::session::Session;

use super::fastly_http_cache::FastlyHttpCache;
use super::{types, Error};

use wiggle::{GuestMemory, GuestPtr};

#[allow(unused_variables)]
#[wiggle::async_trait]
impl FastlyHttpCache for Session {
    async fn lookup(
        &mut self,
        memory: &mut GuestMemory<'_>,
        request: types::RequestHandle,
        options_mask: types::HttpCacheLookupOptionsMask,
        options: GuestPtr<types::HttpCacheLookupOptions>,
    ) -> Result<types::HttpCacheHandle, Error> {
        Err(Error::NotAvailable("HTTP Cache API primitives"))
    }

    async fn transaction_lookup(
        &mut self,
        memory: &mut GuestMemory<'_>,
        request: types::RequestHandle,
        options_mask: types::HttpCacheLookupOptionsMask,
        options: GuestPtr<types::HttpCacheLookupOptions>,
    ) -> Result<types::HttpCacheHandle, Error> {
        Err(Error::NotAvailable("HTTP Cache API primitives"))
    }

    async fn transaction_insert(
        &mut self,
        memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
        response_handle: types::ResponseHandle,
        options_mask: types::HttpCacheWriteOptionsMask,
        abi_options: GuestPtr<types::HttpCacheWriteOptions>,
    ) -> Result<types::BodyHandle, Error> {
        Err(Error::NotAvailable("HTTP Cache API primitives"))
    }

    async fn transaction_insert_and_stream_back(
        &mut self,
        memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
        response_handle: types::ResponseHandle,
        options_mask: types::HttpCacheWriteOptionsMask,
        abi_options: GuestPtr<types::HttpCacheWriteOptions>,
    ) -> Result<(types::BodyHandle, types::HttpCacheHandle), Error> {
        Err(Error::NotAvailable("HTTP Cache API primitives"))
    }

    async fn transaction_update(
        &mut self,
        memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
        response_handle: types::ResponseHandle,
        options_mask: types::HttpCacheWriteOptionsMask,
        abi_options: GuestPtr<types::HttpCacheWriteOptions>,
    ) -> Result<(), Error> {
        Err(Error::NotAvailable("HTTP Cache API primitives"))
    }

    async fn transaction_update_and_return_fresh(
        &mut self,
        memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
        response_handle: types::ResponseHandle,
        options_mask: types::HttpCacheWriteOptionsMask,
        abi_options: GuestPtr<types::HttpCacheWriteOptions>,
    ) -> Result<types::HttpCacheHandle, Error> {
        Err(Error::NotAvailable("HTTP Cache API primitives"))
    }

    async fn transaction_record_not_cacheable(
        &mut self,
        memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
        options_mask: types::HttpCacheWriteOptionsMask,
        abi_options: GuestPtr<types::HttpCacheWriteOptions>,
    ) -> Result<(), Error> {
        Err(Error::NotAvailable("HTTP Cache API primitives"))
    }

    async fn transaction_abandon(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
    ) -> Result<(), Error> {
        Err(Error::NotAvailable("HTTP Cache API primitives"))
    }

    async fn close(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
    ) -> Result<(), Error> {
        Err(Error::NotAvailable("HTTP Cache API primitives"))
    }

    fn is_request_cacheable(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        request_handle: types::RequestHandle,
    ) -> Result<u32, Error> {
        Err(Error::NotAvailable("HTTP Cache API primitives"))
    }

    fn get_suggested_cache_key(
        &mut self,
        memory: &mut GuestMemory<'_>,
        request_handle: types::RequestHandle,
        key_out_ptr: GuestPtr<u8>,
        key_out_len: u32,
        nwritten_out: GuestPtr<u32>,
    ) -> Result<(), Error> {
        Err(Error::NotAvailable("HTTP Cache API primitives"))
    }

    async fn get_suggested_backend_request(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
    ) -> Result<types::RequestHandle, Error> {
        Err(Error::NotAvailable("HTTP Cache API primitives"))
    }

    async fn get_suggested_cache_options(
        &mut self,
        memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
        response_handle: types::ResponseHandle,
        options_wanted: types::HttpCacheWriteOptionsMask,
        pointers: GuestPtr<types::HttpCacheWriteOptions>,
        pointer_mask_out: GuestPtr<types::HttpCacheWriteOptionsMask>,
        options_out: GuestPtr<types::HttpCacheWriteOptions>,
    ) -> Result<(), Error> {
        Err(Error::NotAvailable("HTTP Cache API primitives"))
    }

    async fn prepare_response_for_storage(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
        response_handle: types::ResponseHandle,
    ) -> Result<(types::HttpStorageAction, types::ResponseHandle), Error> {
        Err(Error::NotAvailable("HTTP Cache API primitives"))
    }

    async fn get_found_response(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
        transform_for_client: u32,
    ) -> Result<(types::ResponseHandle, types::BodyHandle), Error> {
        Err(Error::NotAvailable("HTTP Cache API primitives"))
    }

    async fn get_state(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
    ) -> Result<types::CacheLookupState, Error> {
        Err(Error::NotAvailable("HTTP Cache API primitives"))
    }

    async fn get_length(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
    ) -> Result<types::CacheObjectLength, Error> {
        Err(Error::NotAvailable("HTTP Cache API primitives"))
    }

    async fn get_max_age_ns(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
    ) -> Result<types::CacheDurationNs, Error> {
        Err(Error::NotAvailable("HTTP Cache API primitives"))
    }

    async fn get_stale_while_revalidate_ns(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
    ) -> Result<types::CacheDurationNs, Error> {
        Err(Error::NotAvailable("HTTP Cache API primitives"))
    }

    async fn get_age_ns(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
    ) -> Result<types::CacheDurationNs, Error> {
        Err(Error::NotAvailable("HTTP Cache API primitives"))
    }

    async fn get_hits(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
    ) -> Result<types::CacheHitCount, Error> {
        Err(Error::NotAvailable("HTTP Cache API primitives"))
    }

    async fn get_sensitive_data(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
    ) -> Result<types::IsSensitive, Error> {
        Err(Error::NotAvailable("HTTP Cache API primitives"))
    }

    async fn get_surrogate_keys(
        &mut self,
        memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
        surrogate_keys_out_ptr: GuestPtr<u8>,
        surrogate_keys_out_len: u32,
        nwritten_out: GuestPtr<u32>,
    ) -> Result<(), Error> {
        Err(Error::NotAvailable("HTTP Cache API primitives"))
    }

    async fn get_vary_rule(
        &mut self,
        memory: &mut GuestMemory<'_>,
        cache_handle: types::HttpCacheHandle,
        vary_rule_out_ptr: GuestPtr<u8>,
        vary_rule_out_len: u32,
        nwritten_out: GuestPtr<u32>,
    ) -> Result<(), Error> {
        Err(Error::NotAvailable("HTTP Cache API primitives"))
    }
}
