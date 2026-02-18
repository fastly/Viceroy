use super::{
    convert_result, BodyHandle, CacheDurationNs, CacheHitCount, CacheLookupState,
    CacheObjectLength, FastlyStatus, RequestHandle, ResponseHandle,
};

use crate::{
    alloc_result, alloc_result_opt, with_buffer, write_bool_result, write_bool_result_opt,
    write_handle_result, write_result_opt, TrappingUnwrap,
};
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
    pub backend_name_ptr: *const u8,
    pub backend_name_len: usize,
}

bitflags::bitflags! {
    #[repr(transparent)]
    pub struct HttpCacheLookupOptionsMask: u32 {
        const _RESERVED = 1 << 0;
        const OVERRIDE_KEY = 1 << 1;
        const BACKEND_NAME = 1 << 2;
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
    use crate::bindings::fastly::compute::backend;
    use crate::bindings::fastly::compute::http_cache as host;
    use crate::bindings::fastly::compute::http_req as host_http_req;
    use crate::bindings::fastly::compute::http_resp as host_http_resp;

    fn cache_lookup_options(
        mask: HttpCacheLookupOptionsMask,
        options: *const HttpCacheLookupOptions,
    ) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>), FastlyStatus> {
        macro_rules! make_vec {
            ($ptr_field:ident, $len_field:ident) => {
                unsafe { crate::make_vec!(main_ptr!((*options).$ptr_field), (*options).$len_field) }
            };
        }

        let override_key = if mask.contains(HttpCacheLookupOptionsMask::OVERRIDE_KEY) {
            Some(ManuallyDrop::into_inner(make_vec!(
                override_key_ptr,
                override_key_len
            )))
        } else {
            None
        };
        let backend_name = if mask.contains(HttpCacheLookupOptionsMask::BACKEND_NAME) {
            Some(ManuallyDrop::into_inner(make_vec!(
                backend_name_ptr,
                backend_name_len
            )))
        } else {
            None
        };

        Ok((override_key, backend_name))
    }

    fn cache_write_options(
        mask: HttpCacheWriteOptionsMask,
        options: *const HttpCacheWriteOptions,
    ) -> Result<host::WriteOptions<'static>, FastlyStatus> {
        macro_rules! when_enabled {
            ($flag:ident, $value:expr) => {
                if mask.contains(HttpCacheWriteOptionsMask::$flag) {
                    #[allow(unused_unsafe)]
                    unsafe {
                        Some($value)
                    }
                } else {
                    None
                }
            };
        }

        macro_rules! make_string {
            ($ptr_field:ident, $len_field:ident) => {
                crate::make_string!(main_ptr!((*options).$ptr_field), (*options).$len_field)
            };
        }

        let vary_rule = when_enabled!(
            VARY_RULE,
            ManuallyDrop::into_inner(make_string!(vary_rule_ptr, vary_rule_len))
        );
        let surrogate_keys = when_enabled!(
            SURROGATE_KEYS,
            ManuallyDrop::into_inner(make_string!(surrogate_keys_ptr, surrogate_keys_len))
        );
        let options = host::WriteOptions {
            max_age_ns: unsafe { (*options).max_age_ns },
            vary_rule,
            initial_age_ns: when_enabled!(INITIAL_AGE_NS, (*options).initial_age_ns),
            stale_while_revalidate_ns: when_enabled!(
                STALE_WHILE_REVALIDATE_NS,
                (*options).stale_while_revalidate_ns
            ),
            stale_if_error_ns: None,
            surrogate_keys,
            length: when_enabled!(LENGTH, (*options).length),
            sensitive_data: mask.contains(HttpCacheWriteOptionsMask::SENSITIVE_DATA),
            extra: None,
        };

        Ok(options)
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
        let req_handle =
            ManuallyDrop::new(unsafe { host_http_req::Request::from_handle(req_handle) });
        let is_cacheable_out = unsafe_main_ptr!(is_cacheable_out);
        write_bool_result!(host::is_request_cacheable(&req_handle), is_cacheable_out)
    }

    #[export_name = "fastly_http_cache#get_suggested_cache_key"]
    pub fn get_suggested_cache_key(
        req_handle: RequestHandle,
        key_out_ptr: *mut u8,
        key_out_len: usize,
        nwritten_out: *mut usize,
    ) -> FastlyStatus {
        let req_handle =
            ManuallyDrop::new(unsafe { host_http_req::Request::from_handle(req_handle) });
        alloc_result!(
            unsafe_main_ptr!(key_out_ptr),
            key_out_len,
            main_ptr!(nwritten_out),
            {
                host::get_suggested_cache_key(&req_handle, key_out_len.try_into().trapping_unwrap())
            }
        )
    }

    #[export_name = "fastly_http_cache#lookup"]
    pub fn lookup(
        req_handle: RequestHandle,
        options_mask: HttpCacheLookupOptionsMask,
        options: *const HttpCacheLookupOptions,
        cache_handle_out: *mut HttpCacheHandle,
    ) -> FastlyStatus {
        let req_handle =
            ManuallyDrop::new(unsafe { host_http_req::Request::from_handle(req_handle) });
        let (override_key, backend_name) =
            match cache_lookup_options(options_mask, unsafe_main_ptr!(options)) {
                Ok(options) => options,
                Err(err) => return convert_result(Err(err)),
            };

        let backend = if let Some(backend_name) = backend_name {
            let res = backend::Backend::open(&backend_name);
            std::mem::forget(backend_name);
            let backend = match res {
                Ok(backend) => backend,
                Err(err) => {
                    std::mem::forget(override_key);
                    return convert_result(Err(err));
                }
            };
            Some(backend)
        } else {
            None
        };
        let options = host::LookupOptions {
            override_key,
            backend: backend.as_ref(),
            extra: None,
        };

        let res = host::Entry::transaction_lookup(&req_handle, &options);

        std::mem::forget(options);
        let cache_handle_out = unsafe_main_ptr!(cache_handle_out);
        write_handle_result!(res, cache_handle_out)
    }

    #[export_name = "fastly_http_cache#transaction_lookup"]
    pub fn transaction_lookup(
        req_handle: RequestHandle,
        options_mask: HttpCacheLookupOptionsMask,
        options: *const HttpCacheLookupOptions,
        cache_handle_out: *mut HttpCacheHandle,
    ) -> FastlyStatus {
        let req_handle =
            ManuallyDrop::new(unsafe { host_http_req::Request::from_handle(req_handle) });
        let (override_key, backend_name) =
            match cache_lookup_options(options_mask, unsafe_main_ptr!(options)) {
                Ok(options) => options,
                Err(err) => return convert_result(Err(err)),
            };

        let backend = if let Some(backend_name) = backend_name {
            let res = backend::Backend::open(&backend_name);
            std::mem::forget(backend_name);
            let backend = match res {
                Ok(backend) => backend,
                Err(err) => {
                    std::mem::forget(override_key);
                    return convert_result(Err(err));
                }
            };
            Some(backend)
        } else {
            None
        };
        let options = host::LookupOptions {
            override_key,
            backend: backend.as_ref(),
            extra: None,
        };

        let res = host::Entry::transaction_lookup(&req_handle, &options);

        std::mem::forget(options);
        let cache_handle_out = unsafe_main_ptr!(cache_handle_out);
        write_handle_result!(res, cache_handle_out)
    }

    #[export_name = "fastly_http_cache#transaction_choose_stale"]
    pub fn transaction_choose_stale(handle: HttpCacheHandle) -> FastlyStatus {
        let handle = ManuallyDrop::new(unsafe { host::Entry::from_handle(handle) });

        match handle.transaction_choose_stale() {
        Ok(()) => FastlyStatus::OK,
        Err(e) => e.into(),
    }
    }

    #[export_name = "fastly_http_cache#transaction_insert"]
    pub fn transaction_insert(
        handle: HttpCacheHandle,
        resp_handle: ResponseHandle,
        options_mask: HttpCacheWriteOptionsMask,
        options: *const HttpCacheWriteOptions,
        body_handle_out: *mut BodyHandle,
    ) -> FastlyStatus {
        let handle = ManuallyDrop::new(unsafe { host::Entry::from_handle(handle) });
        let resp_handle = unsafe { host_http_resp::Response::from_handle(resp_handle) };
        let options = match cache_write_options(options_mask, unsafe_main_ptr!(options)) {
            Ok(tuple) => tuple,
            Err(err) => return err,
        };

        let res = handle.transaction_insert(resp_handle, &options);

        std::mem::forget(options);
        let body_handle_out = unsafe_main_ptr!(body_handle_out);
        write_handle_result!(res, body_handle_out)
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
        let handle = ManuallyDrop::new(unsafe { host::Entry::from_handle(handle) });
        let resp_handle = unsafe { host_http_resp::Response::from_handle(resp_handle) };
        let options = match cache_write_options(options_mask, unsafe_main_ptr!(options)) {
            Ok(tuple) => tuple,
            Err(err) => return err,
        };

        let res = handle.transaction_insert_and_stream_back(resp_handle, &options);

        std::mem::forget(options);

        match res {
            Ok((body_handle, cache_handle)) => {
                unsafe {
                    *main_ptr!(body_handle_out) = body_handle.take_handle();
                    *main_ptr!(cache_handle_out) = cache_handle.take_handle();
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
        let handle = ManuallyDrop::new(unsafe { host::Entry::from_handle(handle) });
        let resp_handle = unsafe { host_http_resp::Response::from_handle(resp_handle) };
        let options = match cache_write_options(options_mask, unsafe_main_ptr!(options)) {
            Ok(tuple) => tuple,
            Err(err) => return err,
        };

        let res = handle.transaction_update(resp_handle, &options);

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
        let handle = ManuallyDrop::new(unsafe { host::Entry::from_handle(handle) });
        let resp_handle = unsafe { host_http_resp::Response::from_handle(resp_handle) };

        let options = match cache_write_options(options_mask, unsafe_main_ptr!(options)) {
            Ok(tuple) => tuple,
            Err(err) => return err,
        };

        let res = handle.transaction_update_and_return_fresh(resp_handle, &options);

        std::mem::forget(options);
        let cache_handle_out = unsafe_main_ptr!(cache_handle_out);
        write_handle_result!(res, cache_handle_out)
    }

    #[export_name = "fastly_http_cache#transaction_record_not_cacheable"]
    pub fn transaction_record_not_cacheable(
        handle: HttpCacheHandle,
        options_mask: HttpCacheWriteOptionsMask,
        options: *const HttpCacheWriteOptions,
    ) -> FastlyStatus {
        let handle = ManuallyDrop::new(unsafe { host::Entry::from_handle(handle) });
        let options = match cache_write_options(options_mask, unsafe_main_ptr!(options)) {
            Ok(tuple) => tuple,
            Err(err) => return err,
        };

        let res = handle.transaction_record_not_cacheable(&options);

        std::mem::forget(options);

        convert_result(res)
    }

    #[export_name = "fastly_http_cache#transaction_abandon"]
    pub fn transaction_abandon(handle: HttpCacheHandle) -> FastlyStatus {
        let handle = ManuallyDrop::new(unsafe { host::Entry::from_handle(handle) });
        convert_result(handle.transaction_abandon())
    }

    #[export_name = "fastly_http_cache#close"]
    pub fn close(handle: HttpCacheHandle) -> FastlyStatus {
        let handle = unsafe { host::Entry::from_handle(handle) };
        convert_result(host::close_entry(handle))
    }

    #[export_name = "fastly_http_cache#get_suggested_backend_request"]
    pub fn get_suggested_backend_request(
        handle: HttpCacheHandle,
        req_handle_out: *mut RequestHandle,
    ) -> FastlyStatus {
        let handle = ManuallyDrop::new(unsafe { host::Entry::from_handle(handle) });
        let req_handle_out = unsafe_main_ptr!(req_handle_out);
        write_handle_result!(handle.get_suggested_backend_request(), req_handle_out)
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
            match main_ptr!(options_mask_out).as_mut() {
                Some(mask) => mask,
                None => return FastlyStatus::INVALID_ARGUMENT,
            }
        };
        let handle = ManuallyDrop::new(unsafe { host::Entry::from_handle(handle) });
        let resp_handle =
            ManuallyDrop::new(unsafe { host_http_resp::Response::from_handle(resp_handle) });

        let res = match handle.get_suggested_write_options(&resp_handle) {
            Ok(res) => res,
            Err(e) => return e.into(),
        };

        let options = unsafe_main_ptr!(options);
        let options_out = unsafe_main_ptr!(options_out);
        // max_age_ns is not optional
        unsafe {
            (*options_out).max_age_ns = res.get_max_age_ns();
        }

        let mut buffer_len_error = false;

        if requested.contains(HttpCacheWriteOptionsMask::VARY_RULE) {
            options_mask_out.insert(HttpCacheWriteOptionsMask::VARY_RULE);

            let vary_len = unsafe { (*options).vary_rule_len };
            let vary_nwritten = unsafe { &mut (*options_out).vary_rule_len as *mut _ };

            with_buffer!(
                unsafe { main_ptr!((*options).vary_rule_ptr) as *mut _ },
                vary_len,
                { res.get_vary_rule(vary_len.try_into().trapping_unwrap()) },
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
                unsafe { main_ptr!((*options).surrogate_keys_ptr) as *mut _ },
                surrogate_keys_len,
                { res.get_surrogate_keys(surrogate_keys_len.try_into().trapping_unwrap()) },
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
                (*options_out).initial_age_ns = res.get_initial_age_ns();
            }
        }

        if requested.contains(HttpCacheWriteOptionsMask::STALE_WHILE_REVALIDATE_NS) {
            options_mask_out.insert(HttpCacheWriteOptionsMask::STALE_WHILE_REVALIDATE_NS);
            unsafe {
                (*options_out).stale_while_revalidate_ns = res.get_stale_while_revalidate_ns();
            }
        }

        if requested.contains(HttpCacheWriteOptionsMask::LENGTH) {
            if let Some(len) = res.get_length() {
                options_mask_out.insert(HttpCacheWriteOptionsMask::LENGTH);
                unsafe {
                    (*options_out).length = len;
                }
            }
        }

        if requested.contains(HttpCacheWriteOptionsMask::SENSITIVE_DATA) && res.get_sensitive_data()
        {
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
        let handle = ManuallyDrop::new(unsafe { host::Entry::from_handle(handle) });
        let resp_handle =
            ManuallyDrop::new(unsafe { host_http_resp::Response::from_handle(resp_handle) });
        match handle.prepare_response_for_storage(&resp_handle) {
            Ok((action, resp_handle)) => {
                unsafe {
                    *main_ptr!(http_storage_action_out) = action.into();
                    *main_ptr!(resp_handle_out) = resp_handle.take_handle();
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
        let handle = ManuallyDrop::new(unsafe { host::Entry::from_handle(handle) });
        match handle.get_found_response(transform_for_client) {
            Ok(Some((resp_handle, body_handle))) => {
                unsafe {
                    *main_ptr!(resp_handle_out) = resp_handle.take_handle();
                    *main_ptr!(body_handle_out) = body_handle.take_handle();
                }

                FastlyStatus::OK
            }

            Ok(None) => FastlyStatus::NONE,

            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_http_cache#get_state"]
    pub fn get_state(
        handle: HttpCacheHandle,
        cache_lookup_state_out: *mut CacheLookupState,
    ) -> FastlyStatus {
        let handle = ManuallyDrop::new(unsafe { host::Entry::from_handle(handle) });
        match handle.get_state() {
            Ok(res) => {
                unsafe {
                    *main_ptr!(cache_lookup_state_out) = res.into();
                }
                FastlyStatus::OK
            }

            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_http_cache#get_length"]
    pub fn get_length(handle: HttpCacheHandle, length_out: *mut CacheObjectLength) -> FastlyStatus {
        let handle = ManuallyDrop::new(unsafe { host::Entry::from_handle(handle) });
        let length_out = unsafe_main_ptr!(length_out);
        write_result_opt!(handle.get_length(), length_out)
    }

    #[export_name = "fastly_http_cache#get_max_age_ns"]
    pub fn get_max_age_ns(
        handle: HttpCacheHandle,
        duration_out: *mut CacheDurationNs,
    ) -> FastlyStatus {
        let handle = ManuallyDrop::new(unsafe { host::Entry::from_handle(handle) });
        let duration_out = unsafe_main_ptr!(duration_out);
        write_result_opt!(handle.get_max_age_ns(), duration_out)
    }

    #[export_name = "fastly_http_cache#get_stale_while_revalidate_ns"]
    pub fn get_stale_while_revalidate_ns(
        handle: HttpCacheHandle,
        duration_out: *mut CacheDurationNs,
    ) -> FastlyStatus {
        let handle = ManuallyDrop::new(unsafe { host::Entry::from_handle(handle) });
        let duration_out = unsafe_main_ptr!(duration_out);
        write_result_opt!(handle.get_stale_while_revalidate_ns(), duration_out)
    }

    #[export_name = "fastly_http_cache#get_stale_if_error_ns"]
    pub fn get_stale_if_error_ns(
        handle: HttpCacheHandle,
        duration_out: *mut CacheDurationNs,
    ) -> FastlyStatus {
        let handle = ManuallyDrop::new(unsafe { host::Entry::from_handle(handle) });
        let duration_out = unsafe_main_ptr!(duration_out);
        write_result_opt!(handle.get_stale_if_error_ns(), duration_out)
    }


    #[export_name = "fastly_http_cache#get_age_ns"]
    pub fn get_age_ns(handle: HttpCacheHandle, duration_out: *mut CacheDurationNs) -> FastlyStatus {
        let handle = ManuallyDrop::new(unsafe { host::Entry::from_handle(handle) });
        let duration_out = unsafe_main_ptr!(duration_out);
        write_result_opt!(handle.get_age_ns(), duration_out)
    }

    #[export_name = "fastly_http_cache#get_hits"]
    pub fn get_hits(handle: HttpCacheHandle, hits_out: *mut CacheHitCount) -> FastlyStatus {
        let handle = ManuallyDrop::new(unsafe { host::Entry::from_handle(handle) });
        let hits_out = unsafe_main_ptr!(hits_out);
        write_result_opt!(handle.get_hits(), hits_out)
    }

    #[export_name = "fastly_http_cache#get_sensitive_data"]
    pub fn get_sensitive_data(
        handle: HttpCacheHandle,
        sensitive_data_out: *mut IsSensitive,
    ) -> FastlyStatus {
        let handle = ManuallyDrop::new(unsafe { host::Entry::from_handle(handle) });
        let sensitive_data_out = unsafe_main_ptr!(sensitive_data_out);
        write_bool_result_opt!(handle.get_sensitive_data(), sensitive_data_out)
    }

    #[export_name = "fastly_http_cache#get_surrogate_keys"]
    pub fn get_surrogate_keys(
        handle: HttpCacheHandle,
        surrogate_keys_out_ptr: *mut u8,
        surrogate_keys_out_len: usize,
        nwritten_out: *mut usize,
    ) -> FastlyStatus {
        let handle = ManuallyDrop::new(unsafe { host::Entry::from_handle(handle) });
        alloc_result_opt!(
            unsafe_main_ptr!(surrogate_keys_out_ptr),
            surrogate_keys_out_len,
            main_ptr!(nwritten_out),
            { handle.get_surrogate_keys(surrogate_keys_out_len.try_into().trapping_unwrap(),) }
        )
    }

    #[export_name = "fastly_http_cache#get_vary_rule"]
    pub fn get_vary_rule(
        handle: HttpCacheHandle,
        vary_rule_out_ptr: *mut u8,
        vary_rule_out_len: usize,
        nwritten_out: *mut usize,
    ) -> FastlyStatus {
        let handle = ManuallyDrop::new(unsafe { host::Entry::from_handle(handle) });
        alloc_result_opt!(
            unsafe_main_ptr!(vary_rule_out_ptr),
            vary_rule_out_len,
            main_ptr!(nwritten_out),
            { handle.get_vary_rule(vary_rule_out_len.try_into().trapping_unwrap()) }
        )
    }
}
