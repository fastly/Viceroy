use super::{
    BodyHandle, CacheDurationNs, CacheHitCount, CacheLookupState, CacheObjectLength, FastlyStatus,
    RequestHandle, ResponseHandle,
};

pub type HttpCacheHandle = u32;
pub type IsCacheable = u32;
pub type IsSensitive = u32;

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(unused)]
pub enum HttpStorageAction {
    Insert,
    Update,
    DoNotStore,
    RecordUncacheable,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HttpCacheLookupOptions {
    pub override_key_ptr: *const u8,
    pub override_key_len: usize,
}

bitflags::bitflags! {
    #[repr(transparent)]
    pub struct HttpCacheLookupOptionsMask: u32 {
        const _RESERVED = 1 << 0;
        const OVERRIDE_KEY = 1 << 1;
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HttpCacheWriteOptions {
    pub max_age_ns: CacheDurationNs,
    pub vary_rule_ptr: *const u8,
    pub vary_rule_len: usize,
    pub initial_age_ns: CacheDurationNs,
    pub stale_while_revalidate_ns: CacheDurationNs,
    pub surrogate_keys_ptr: *const u8,
    pub surrogate_keys_len: usize,
    pub length: CacheObjectLength,
}

bitflags::bitflags! {
    #[repr(transparent)]
    pub struct HttpCacheWriteOptionsMask: u32 {
        const _RESERVED = 1 << 0;
        const VARY_RULE = 1 << 1;
        const INITIAL_AGE_NS = 1 << 2;
        const STALE_WHILE_REVALIDATE_NS = 1 << 3;
        const SURROGATE_KEYS = 1 << 4;
        const LENGTH = 1 << 5;
        const SENSITIVE_DATA = 1 << 6;
    }
}

#[allow(unused_variables)]
#[allow(clippy::module_inception)]
mod http_cache {
    use super::*;

    #[export_name = "fastly_http_cache#is_request_cacheable"]
    pub fn is_request_cacheable(
        req_handle: RequestHandle,
        is_cacheable_out: *mut IsCacheable,
    ) -> FastlyStatus {
        FastlyStatus::UNSUPPORTED
    }

    #[export_name = "fastly_http_cache#get_suggested_cache_key"]
    pub fn get_suggested_cache_key(
        req_handle: RequestHandle,
        key_out_ptr: *mut u8,
        key_out_len: usize,
        nwritten_out: *mut usize,
    ) -> FastlyStatus {
        FastlyStatus::UNSUPPORTED
    }

    #[export_name = "fastly_http_cache#lookup"]
    pub fn lookup(
        req_handle: RequestHandle,
        options_mask: HttpCacheLookupOptionsMask,
        options: *const HttpCacheLookupOptions,
        cache_handle_out: *mut HttpCacheHandle,
    ) -> FastlyStatus {
        FastlyStatus::UNSUPPORTED
    }

    #[export_name = "fastly_http_cache#transaction_lookup"]
    pub fn transaction_lookup(
        req_handle: RequestHandle,
        options_mask: HttpCacheLookupOptionsMask,
        options: *const HttpCacheLookupOptions,
        cache_handle_out: *mut HttpCacheHandle,
    ) -> FastlyStatus {
        FastlyStatus::UNSUPPORTED
    }

    #[export_name = "fastly_http_cache#transaction_insert"]
    pub fn transaction_insert(
        handle: HttpCacheHandle,
        resp_handle: ResponseHandle,
        options_mask: HttpCacheWriteOptionsMask,
        options: *const HttpCacheWriteOptions,
        body_handle_out: *mut BodyHandle,
    ) -> FastlyStatus {
        FastlyStatus::UNSUPPORTED
    }

    #[export_name = "fastly_http_cache#transaction_insert_and_stream_back"]
    pub fn transaction_insert_and_stream_back(
        handle: HttpCacheHandle,
        resp_handle: ResponseHandle,
        options_mask: HttpCacheWriteOptionsMask,
        options: *const HttpCacheWriteOptions,
        body_handle_out: *mut BodyHandle,
        cache_handle_out: *mut HttpCacheHandle,
    ) -> FastlyStatus {
        FastlyStatus::UNSUPPORTED
    }

    #[export_name = "fastly_http_cache#transaction_update"]
    pub fn transaction_update(
        handle: HttpCacheHandle,
        resp_handle: ResponseHandle,
        options_mask: HttpCacheWriteOptionsMask,
        options: *const HttpCacheWriteOptions,
    ) -> FastlyStatus {
        FastlyStatus::UNSUPPORTED
    }

    #[export_name = "fastly_http_cache#transaction_update_and_return_fresh"]
    pub fn transaction_update_and_return_fresh(
        handle: HttpCacheHandle,
        resp_handle: ResponseHandle,
        options_mask: HttpCacheWriteOptionsMask,
        options: *const HttpCacheWriteOptions,
        cache_handle_out: *mut HttpCacheHandle,
    ) -> FastlyStatus {
        FastlyStatus::UNSUPPORTED
    }

    #[export_name = "fastly_http_cache#transaction_record_not_cacheable"]
    pub fn transaction_record_not_cacheable(
        handle: HttpCacheHandle,
        options_mask: HttpCacheWriteOptionsMask,
        options: *const HttpCacheWriteOptions,
    ) -> FastlyStatus {
        FastlyStatus::UNSUPPORTED
    }

    #[export_name = "fastly_http_cache#transaction_abandon"]
    pub fn transaction_abandon(handle: HttpCacheHandle) -> FastlyStatus {
        FastlyStatus::UNSUPPORTED
    }

    #[export_name = "fastly_http_cache#close"]
    pub fn close(handle: HttpCacheHandle) -> FastlyStatus {
        FastlyStatus::UNSUPPORTED
    }

    #[export_name = "fastly_http_cache#get_suggested_backend_request"]
    pub fn get_suggested_backend_request(
        handle: HttpCacheHandle,
        req_handle_out: *mut RequestHandle,
    ) -> FastlyStatus {
        FastlyStatus::UNSUPPORTED
    }

    #[export_name = "fastly_http_cache#get_suggested_cache_options"]
    pub fn get_suggested_cache_options(
        handle: HttpCacheHandle,
        resp_handle: ResponseHandle,
        requested: HttpCacheWriteOptionsMask,
        options: *const HttpCacheWriteOptions,
        options_mask_out: *mut HttpCacheWriteOptionsMask,
        options_out: *mut HttpCacheWriteOptions,
    ) -> FastlyStatus {
        FastlyStatus::UNSUPPORTED
    }

    #[export_name = "fastly_http_cache#prepare_response_for_storage"]
    pub fn prepare_response_for_storage(
        handle: HttpCacheHandle,
        resp_handle: ResponseHandle,
        http_storage_action_out: *mut HttpStorageAction,
        resp_handle_out: *mut ResponseHandle,
    ) -> FastlyStatus {
        FastlyStatus::UNSUPPORTED
    }

    #[export_name = "fastly_http_cache#get_found_response"]
    pub fn get_found_response(
        handle: HttpCacheHandle,
        transform_for_client: u32,
        resp_handle_out: *mut ResponseHandle,
        body_handle_out: *mut BodyHandle,
    ) -> FastlyStatus {
        FastlyStatus::UNSUPPORTED
    }

    #[export_name = "fastly_http_cache#get_state"]
    pub fn get_state(
        handle: HttpCacheHandle,
        cache_lookup_state_out: *mut CacheLookupState,
    ) -> FastlyStatus {
        FastlyStatus::UNSUPPORTED
    }

    #[export_name = "fastly_http_cache#get_length"]
    pub fn get_length(handle: HttpCacheHandle, length_out: *mut CacheObjectLength) -> FastlyStatus {
        FastlyStatus::UNSUPPORTED
    }

    #[export_name = "fastly_http_cache#get_max_age_ns"]
    pub fn get_max_age_ns(
        handle: HttpCacheHandle,
        duration_out: *mut CacheDurationNs,
    ) -> FastlyStatus {
        FastlyStatus::UNSUPPORTED
    }

    #[export_name = "fastly_http_cache#get_stale_while_revalidate_ns"]
    pub fn get_stale_while_revalidate_ns(
        handle: HttpCacheHandle,
        duration_out: *mut CacheDurationNs,
    ) -> FastlyStatus {
        FastlyStatus::UNSUPPORTED
    }

    #[export_name = "fastly_http_cache#get_age_ns"]
    pub fn get_age_ns(handle: HttpCacheHandle, duration_out: *mut CacheDurationNs) -> FastlyStatus {
        FastlyStatus::UNSUPPORTED
    }

    #[export_name = "fastly_http_cache#get_hits"]
    pub fn get_hits(handle: HttpCacheHandle, hits_out: *mut CacheHitCount) -> FastlyStatus {
        FastlyStatus::UNSUPPORTED
    }

    #[export_name = "fastly_http_cache#get_sensitive_data"]
    pub fn get_sensitive_data(
        handle: HttpCacheHandle,
        sensitive_data_out: *mut IsSensitive,
    ) -> FastlyStatus {
        FastlyStatus::UNSUPPORTED
    }

    #[export_name = "fastly_http_cache#get_surrogate_keys"]
    pub fn get_surrogate_keys(
        handle: HttpCacheHandle,
        surrogate_keys_out_ptr: *mut u8,
        surrogate_keys_out_len: usize,
        nwritten_out: *mut usize,
    ) -> FastlyStatus {
        FastlyStatus::UNSUPPORTED
    }

    #[export_name = "fastly_http_cache#get_vary_rule"]
    pub fn get_vary_rule(
        handle: HttpCacheHandle,
        vary_rule_out_ptr: *mut u8,
        vary_rule_out_len: usize,
        nwritten_out: *mut usize,
    ) -> FastlyStatus {
        FastlyStatus::UNSUPPORTED
    }
}
