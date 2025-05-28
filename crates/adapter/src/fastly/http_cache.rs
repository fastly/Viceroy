use super::{
    convert_result, BodyHandle, CacheDurationNs, CacheHitCount, CacheLookupState,
    CacheObjectLength, FastlyStatus, RequestHandle, ResponseHandle,
};

use crate::{alloc_result, with_buffer, write_bool_result, write_result, TrappingUnwrap};
use core::mem::ManuallyDrop;

pub type HttpCacheHandle = u32;
pub type IsCacheable = u32;
pub type IsSensitive = u32;

pub const INVALID_HTTP_CACHE_HANDLE: HttpCacheHandle = HttpCacheHandle::MAX - 1;

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

mod http_cache {
    use super::*;
    use crate::bindings::fastly::api::http_cache as host;

    impl From<HttpCacheLookupOptionsMask> for host::CacheLookupOptionsMask {
        fn from(value: HttpCacheLookupOptionsMask) -> Self {
            let mut flags = Self::empty();

            flags.set(
                Self::RESERVED,
                value.contains(HttpCacheLookupOptionsMask::_RESERVED),
            );

            flags.set(
                Self::OVERRIDE_KEY,
                value.contains(HttpCacheLookupOptionsMask::OVERRIDE_KEY),
            );

            flags
        }
    }

    fn cache_lookup_options(
        mask: HttpCacheLookupOptionsMask,
        options: *const HttpCacheLookupOptions,
    ) -> (host::CacheLookupOptionsMask, host::CacheLookupOptions) {
        // NOTE: this is only really safe because we never mutate the vectors -- we only need
        // vectors to satisfy the interface produced by the DynamicBackendConfig record,
        // `register_dynamic_backend` will never mutate the vectors it's given.
        macro_rules! make_vec {
            ($ptr_field:ident, $len_field:ident) => {
                unsafe { crate::make_vec!((*options).$ptr_field, (*options).$len_field) }
            };
        }

        let mask = host::CacheLookupOptionsMask::from(mask);

        let override_key = if mask.contains(host::CacheLookupOptionsMask::OVERRIDE_KEY) {
            make_vec!(override_key_ptr, override_key_len)
        } else {
            ManuallyDrop::new(Vec::new())
        };
        let options = host::CacheLookupOptions {
            override_key: ManuallyDrop::into_inner(override_key),
        };

        (mask, options)
    }

    impl From<HttpCacheWriteOptionsMask> for host::CacheWriteOptionsMask {
        fn from(value: HttpCacheWriteOptionsMask) -> Self {
            let mut flags = Self::empty();

            flags.set(
                Self::RESERVED,
                value.contains(HttpCacheWriteOptionsMask::_RESERVED),
            );

            macro_rules! set_flag {
                ($name:ident) => {
                    flags.set(
                        Self::$name,
                        value.contains(HttpCacheWriteOptionsMask::$name),
                    );
                };
            }

            set_flag!(VARY_RULE);
            set_flag!(INITIAL_AGE_NS);
            set_flag!(STALE_WHILE_REVALIDATE_NS);
            set_flag!(SURROGATE_KEYS);
            set_flag!(LENGTH);
            set_flag!(SENSITIVE_DATA);

            flags
        }
    }

    fn cache_write_options(
        mask: HttpCacheWriteOptionsMask,
        options: *const HttpCacheWriteOptions,
    ) -> Result<(host::CacheWriteOptionsMask, host::CacheWriteOptions), FastlyStatus> {
        let mask = host::CacheWriteOptionsMask::from(mask);

        macro_rules! when_enabled {
            ($flag:ident, $value:expr) => {
                if mask.contains(host::CacheWriteOptionsMask::$flag) {
                    #[allow(unused_unsafe)]
                    unsafe {
                        $value
                    }
                } else {
                    Default::default()
                }
            };
        }

        // NOTE: this is only really safe because we never mutate the vectors -- we only need
        // vectors to satisfy the interface produced by the DynamicBackendConfig record,
        // `register_dynamic_backend` will never mutate the vectors it's given.
        macro_rules! make_string {
            ($ptr_field:ident, $len_field:ident) => {
                crate::make_string_result!((*options).$ptr_field, (*options).$len_field)
            };
        }

        let vary_rule = when_enabled!(VARY_RULE, make_string!(vary_rule_ptr, vary_rule_len));
        let surrogate_keys = when_enabled!(
            SURROGATE_KEYS,
            make_string!(surrogate_keys_ptr, surrogate_keys_len)
        );
        let options = host::CacheWriteOptions {
            max_age_ns: unsafe { (*options).max_age_ns },
            vary_rule: ManuallyDrop::into_inner(vary_rule),
            initial_age_ns: when_enabled!(INITIAL_AGE_NS, (*options).initial_age_ns),
            stale_while_revalidate_ns: when_enabled!(
                STALE_WHILE_REVALIDATE_NS,
                (*options).stale_while_revalidate_ns
            ),
            surrogate_keys: ManuallyDrop::into_inner(surrogate_keys),
            length: when_enabled!(LENGTH, (*options).length),
        };

        Ok((mask, options))
    }

    impl From<host::StorageAction> for HttpStorageAction {
        fn from(value: host::StorageAction) -> Self {
            match value {
                host::StorageAction::Insert => Self::Insert,
                host::StorageAction::Update => Self::Update,
                host::StorageAction::DoNotStore => Self::DoNotStore,
                host::StorageAction::RecordUncacheable => Self::RecordUncacheable,
            }
        }
    }

    #[export_name = "fastly_http_cache#is_request_cacheable"]
    pub fn is_request_cacheable(
        req_handle: RequestHandle,
        is_cacheable_out: *mut IsCacheable,
    ) -> FastlyStatus {
        write_bool_result!(host::is_request_cacheable(req_handle), is_cacheable_out)
    }

    #[export_name = "fastly_http_cache#get_suggested_cache_key"]
    pub fn get_suggested_cache_key(
        req_handle: RequestHandle,
        key_out_ptr: *mut u8,
        key_out_len: usize,
        nwritten_out: *mut usize,
    ) -> FastlyStatus {
        alloc_result!(key_out_ptr, key_out_len, nwritten_out, {
            host::get_suggested_cache_key(req_handle, key_out_len.try_into().trapping_unwrap())
        })
    }

    #[export_name = "fastly_http_cache#lookup"]
    pub fn lookup(
        req_handle: RequestHandle,
        options_mask: HttpCacheLookupOptionsMask,
        options: *const HttpCacheLookupOptions,
        cache_handle_out: *mut HttpCacheHandle,
    ) -> FastlyStatus {
        let (options_mask, options) = cache_lookup_options(options_mask, options);
        let res = host::lookup(req_handle, options_mask, &options);
        std::mem::forget(options);
        write_result!(res, cache_handle_out)
    }

    #[export_name = "fastly_http_cache#transaction_lookup"]
    pub fn transaction_lookup(
        req_handle: RequestHandle,
        options_mask: HttpCacheLookupOptionsMask,
        options: *const HttpCacheLookupOptions,
        cache_handle_out: *mut HttpCacheHandle,
    ) -> FastlyStatus {
        let (options_mask, options) = cache_lookup_options(options_mask, options);
        let res = host::transaction_lookup(req_handle, options_mask, &options);
        std::mem::forget(options);
        write_result!(res, cache_handle_out)
    }

    #[export_name = "fastly_http_cache#transaction_insert"]
    pub fn transaction_insert(
        handle: HttpCacheHandle,
        resp_handle: ResponseHandle,
        options_mask: HttpCacheWriteOptionsMask,
        options: *const HttpCacheWriteOptions,
        body_handle_out: *mut BodyHandle,
    ) -> FastlyStatus {
        let (mask, options) = match cache_write_options(options_mask, options) {
            Ok(tuple) => tuple,
            Err(err) => return err,
        };
        let res = host::transaction_insert(handle, resp_handle, mask, &options);
        std::mem::forget(options);
        write_result!(res, body_handle_out)
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
        let (mask, options) = match cache_write_options(options_mask, options) {
            Ok(tuple) => tuple,
            Err(err) => return err,
        };
        let res = host::transaction_insert_and_stream_back(handle, resp_handle, mask, &options);
        std::mem::forget(options);
        match res {
            Ok((body_handle, cache_handle)) => {
                unsafe {
                    *body_handle_out = body_handle;
                    *cache_handle_out = cache_handle;
                }

                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_http_cache#transaction_update"]
    pub fn transaction_update(
        handle: HttpCacheHandle,
        resp_handle: ResponseHandle,
        options_mask: HttpCacheWriteOptionsMask,
        options: *const HttpCacheWriteOptions,
    ) -> FastlyStatus {
        let (mask, options) = match cache_write_options(options_mask, options) {
            Ok(tuple) => tuple,
            Err(err) => return err,
        };
        let res = host::transaction_update(handle, resp_handle, mask, &options);
        std::mem::forget(options);
        convert_result(res)
    }

    #[export_name = "fastly_http_cache#transaction_update_and_return_fresh"]
    pub fn transaction_update_and_return_fresh(
        handle: HttpCacheHandle,
        resp_handle: ResponseHandle,
        options_mask: HttpCacheWriteOptionsMask,
        options: *const HttpCacheWriteOptions,
        cache_handle_out: *mut HttpCacheHandle,
    ) -> FastlyStatus {
        let (mask, options) = match cache_write_options(options_mask, options) {
            Ok(tuple) => tuple,
            Err(err) => return err,
        };
        let res = host::transaction_update_and_return_fresh(handle, resp_handle, mask, &options);
        std::mem::forget(options);
        write_result!(res, cache_handle_out)
    }

    #[export_name = "fastly_http_cache#transaction_record_not_cacheable"]
    pub fn transaction_record_not_cacheable(
        handle: HttpCacheHandle,
        options_mask: HttpCacheWriteOptionsMask,
        options: *const HttpCacheWriteOptions,
    ) -> FastlyStatus {
        let (mask, options) = match cache_write_options(options_mask, options) {
            Ok(tuple) => tuple,
            Err(err) => return err,
        };
        let res = host::transaction_record_not_cacheable(handle, mask, &options);
        std::mem::forget(options);
        convert_result(res)
    }

    #[export_name = "fastly_http_cache#transaction_abandon"]
    pub fn transaction_abandon(handle: HttpCacheHandle) -> FastlyStatus {
        convert_result(host::transaction_abandon(handle))
    }

    #[export_name = "fastly_http_cache#close"]
    pub fn close(handle: HttpCacheHandle) -> FastlyStatus {
        convert_result(host::close(handle))
    }

    #[export_name = "fastly_http_cache#get_suggested_backend_request"]
    pub fn get_suggested_backend_request(
        handle: HttpCacheHandle,
        req_handle_out: *mut RequestHandle,
    ) -> FastlyStatus {
        write_result!(host::get_suggested_backend_request(handle), req_handle_out)
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
        let options_mask_out = unsafe {
            match options_mask_out.as_mut() {
                Some(mask) => mask,
                None => return FastlyStatus::INVALID_ARGUMENT,
            }
        };

        let res = match host::get_suggested_cache_options(handle, resp_handle) {
            Ok(res) => res,
            Err(e) => return e.into(),
        };

        // max_age_ns is not optional
        unsafe {
            (*options_out).max_age_ns = res.max_age_ns();
        }

        let mut buffer_len_error = false;

        if requested.contains(HttpCacheWriteOptionsMask::VARY_RULE) {
            options_mask_out.insert(HttpCacheWriteOptionsMask::VARY_RULE);

            let vary_len = unsafe { (*options).vary_rule_len };
            let vary_nwritten = unsafe { &mut (*options_out).vary_rule_len as *mut _ };

            with_buffer!(
                unsafe { (*options).vary_rule_ptr as *mut _ },
                vary_len,
                { res.vary_rule(vary_len.try_into().trapping_unwrap()) },
                |res| {
                    match res {
                        Ok(res) => {
                            unsafe { *vary_nwritten = res.len() };
                            std::mem::forget(res);
                        }

                        Err(host::Error::BufferLen(len)) => {
                            unsafe { *vary_nwritten = usize::try_from(len).unwrap_or(0) };
                            buffer_len_error = true;
                        }

                        Err(e) => return Err(e.into()),
                    }
                }
            );
        }

        if requested.contains(HttpCacheWriteOptionsMask::SURROGATE_KEYS) {
            options_mask_out.insert(HttpCacheWriteOptionsMask::SURROGATE_KEYS);

            let surrogate_keys_len = unsafe { (*options).surrogate_keys_len };
            let surrogate_keys_nwritten =
                unsafe { &mut (*options_out).surrogate_keys_len as *mut _ };

            with_buffer!(
                unsafe { (*options).surrogate_keys_ptr as *mut _ },
                surrogate_keys_len,
                { res.surrogate_keys(surrogate_keys_len.try_into().trapping_unwrap()) },
                |res| {
                    match res {
                        Ok(res) => {
                            unsafe { *surrogate_keys_nwritten = res.len() };
                            std::mem::forget(res);
                        }

                        Err(host::Error::BufferLen(len)) => {
                            unsafe { *surrogate_keys_nwritten = usize::try_from(len).unwrap_or(0) };
                            buffer_len_error = true;
                        }

                        Err(e) => return Err(e.into()),
                    }
                }
            );
        }

        if requested.contains(HttpCacheWriteOptionsMask::INITIAL_AGE_NS) {
            options_mask_out.insert(HttpCacheWriteOptionsMask::INITIAL_AGE_NS);
            unsafe {
                (*options_out).initial_age_ns = res.initial_age_ns();
            }
        }

        if requested.contains(HttpCacheWriteOptionsMask::STALE_WHILE_REVALIDATE_NS) {
            options_mask_out.insert(HttpCacheWriteOptionsMask::STALE_WHILE_REVALIDATE_NS);
            unsafe {
                (*options_out).stale_while_revalidate_ns = res.stale_while_revalidate_ns();
            }
        }

        if requested.contains(HttpCacheWriteOptionsMask::LENGTH) {
            if let Some(len) = res.length() {
                options_mask_out.insert(HttpCacheWriteOptionsMask::LENGTH);
                unsafe {
                    (*options_out).length = len;
                }
            }
        }

        if requested.contains(HttpCacheWriteOptionsMask::SENSITIVE_DATA) && res.sensitive_data() {
            options_mask_out.insert(HttpCacheWriteOptionsMask::SENSITIVE_DATA);
        }

        if buffer_len_error {
            FastlyStatus::BUFFER_LEN
        } else {
            FastlyStatus::OK
        }
    }

    #[export_name = "fastly_http_cache#prepare_response_for_storage"]
    pub fn prepare_response_for_storage(
        handle: HttpCacheHandle,
        resp_handle: ResponseHandle,
        http_storage_action_out: *mut HttpStorageAction,
        resp_handle_out: *mut ResponseHandle,
    ) -> FastlyStatus {
        match host::prepare_response_for_storage(handle, resp_handle) {
            Ok((action, resp_handle)) => {
                unsafe {
                    *http_storage_action_out = action.into();
                    *resp_handle_out = resp_handle;
                }

                FastlyStatus::OK
            }

            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_http_cache#get_found_response"]
    pub fn get_found_response(
        handle: HttpCacheHandle,
        transform_for_client: u32,
        resp_handle_out: *mut ResponseHandle,
        body_handle_out: *mut BodyHandle,
    ) -> FastlyStatus {
        match host::get_found_response(handle, transform_for_client) {
            Ok((resp_handle, body_handle)) => {
                unsafe {
                    *resp_handle_out = resp_handle;
                    *body_handle_out = body_handle;
                }

                FastlyStatus::OK
            }

            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_http_cache#get_state"]
    pub fn get_state(
        handle: HttpCacheHandle,
        cache_lookup_state_out: *mut CacheLookupState,
    ) -> FastlyStatus {
        match host::get_state(handle) {
            Ok(res) => {
                unsafe {
                    *cache_lookup_state_out = res.into();
                }
                FastlyStatus::OK
            }

            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_http_cache#get_length"]
    pub fn get_length(handle: HttpCacheHandle, length_out: *mut CacheObjectLength) -> FastlyStatus {
        write_result!(host::get_length(handle), length_out)
    }

    #[export_name = "fastly_http_cache#get_max_age_ns"]
    pub fn get_max_age_ns(
        handle: HttpCacheHandle,
        duration_out: *mut CacheDurationNs,
    ) -> FastlyStatus {
        write_result!(host::get_max_age_ns(handle), duration_out)
    }

    #[export_name = "fastly_http_cache#get_stale_while_revalidate_ns"]
    pub fn get_stale_while_revalidate_ns(
        handle: HttpCacheHandle,
        duration_out: *mut CacheDurationNs,
    ) -> FastlyStatus {
        write_result!(host::get_stale_while_revalidate_ns(handle), duration_out)
    }

    #[export_name = "fastly_http_cache#get_age_ns"]
    pub fn get_age_ns(handle: HttpCacheHandle, duration_out: *mut CacheDurationNs) -> FastlyStatus {
        write_result!(host::get_age_ns(handle), duration_out)
    }

    #[export_name = "fastly_http_cache#get_hits"]
    pub fn get_hits(handle: HttpCacheHandle, hits_out: *mut CacheHitCount) -> FastlyStatus {
        write_result!(host::get_hits(handle), hits_out)
    }

    #[export_name = "fastly_http_cache#get_sensitive_data"]
    pub fn get_sensitive_data(
        handle: HttpCacheHandle,
        sensitive_data_out: *mut IsSensitive,
    ) -> FastlyStatus {
        write_bool_result!(host::get_sensitive_data(handle), sensitive_data_out)
    }

    #[export_name = "fastly_http_cache#get_surrogate_keys"]
    pub fn get_surrogate_keys(
        handle: HttpCacheHandle,
        surrogate_keys_out_ptr: *mut u8,
        surrogate_keys_out_len: usize,
        nwritten_out: *mut usize,
    ) -> FastlyStatus {
        alloc_result!(
            surrogate_keys_out_ptr,
            surrogate_keys_out_len,
            nwritten_out,
            {
                host::get_surrogate_keys(
                    handle,
                    surrogate_keys_out_len.try_into().trapping_unwrap(),
                )
            }
        )
    }

    #[export_name = "fastly_http_cache#get_vary_rule"]
    pub fn get_vary_rule(
        handle: HttpCacheHandle,
        vary_rule_out_ptr: *mut u8,
        vary_rule_out_len: usize,
        nwritten_out: *mut usize,
    ) -> FastlyStatus {
        alloc_result!(vary_rule_out_ptr, vary_rule_out_len, nwritten_out, {
            host::get_vary_rule(handle, vary_rule_out_len.try_into().trapping_unwrap())
        })
    }
}
