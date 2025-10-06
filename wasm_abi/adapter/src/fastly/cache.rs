use super::{convert_result, BodyHandle, FastlyStatus, RequestHandle};
use crate::fastly::INVALID_HANDLE;
use crate::{alloc_result_opt, TrappingUnwrap};
use core::mem::ManuallyDrop;
use core::ops::Deref;

pub type CacheHandle = u32;
pub type CacheBusyHandle = u32;
pub type CacheReplaceHandle = u32;

pub type CacheObjectLength = u64;
pub type CacheDurationNs = u64;
pub type CacheHitCount = u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct CacheLookupOptions {
    pub request_headers: RequestHandle,
    pub service: *const u8,
    pub service_len: u32,
}

bitflags::bitflags! {
    #[repr(transparent)]
    #[derive(Copy, Clone)]
    pub struct CacheLookupOptionsMask: u32 {
        const _RESERVED = 1 << 0;
        const REQUEST_HEADERS = 1 << 1;
        const SERVICE = 1 << 2;
        const ALWAYS_USE_REQUESTED_RANGE = 1 << 3;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct CacheReplaceOptions {
    pub request_headers: RequestHandle,
    pub replace_strategy: u32,
    pub service: *const u8,
    pub service_len: u32,
}

bitflags::bitflags! {
    #[repr(transparent)]
    #[derive(Copy, Clone)]
    pub struct CacheReplaceOptionsMask: u32 {
        const _RESERVED = 1 << 0;
        const REQUEST_HEADERS = 1 << 1;
        const REPLACE_STRATEGY = 1 << 2;
        const SERVICE = 1 << 3;
        const ALWAYS_USE_REQUESTED_RANGE = 1 << 4;
    }
}

#[repr(u32)]
pub enum CacheReplaceStrategy {
    Immediate = 1,
    ImmediateForceMiss = 2,
    Wait = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct CacheWriteOptions {
    pub max_age_ns: u64,
    pub request_headers: RequestHandle,
    pub vary_rule_ptr: *const u8,
    pub vary_rule_len: usize,
    pub initial_age_ns: u64,
    pub stale_while_revalidate_ns: u64,
    pub surrogate_keys_ptr: *const u8,
    pub surrogate_keys_len: usize,
    pub length: CacheObjectLength,
    pub user_metadata_ptr: *const u8,
    pub user_metadata_len: usize,
    pub edge_max_age_ns: u64,
    pub service: *const u8,
    pub service_len: u32,
}

bitflags::bitflags! {
    #[repr(transparent)]
    #[derive(Copy, Clone)]
    pub struct CacheWriteOptionsMask: u32 {
        const _RESERVED = 1 << 0;
        const REQUEST_HEADERS = 1 << 1;
        const VARY_RULE = 1 << 2;
        const INITIAL_AGE_NS = 1 << 3;
        const STALE_WHILE_REVALIDATE_NS = 1 << 4;
        const SURROGATE_KEYS = 1 << 5;
        const LENGTH = 1 << 6;
        const USER_METADATA = 1 << 7;
        const SENSITIVE_DATA = 1 << 8;
        const EDGE_MAX_AGE_NS = 1 << 9;
        const SERVICE = 1 << 10;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct CacheGetBodyOptions {
    pub from: u64,
    pub to: u64,
}

bitflags::bitflags! {
    #[repr(transparent)]
    pub struct CacheGetBodyOptionsMask: u32 {
        const _RESERVED = 1 << 0;
        const FROM = 1 << 1;
        const TO = 1 << 2;
    }
}

bitflags::bitflags! {
    #[repr(transparent)]
    pub struct CacheLookupState: u32 {
        const FOUND = 1 << 0;
        const USABLE = 1 << 1;
        const STALE = 1 << 2;
        const MUST_INSERT_OR_UPDATE = 1 << 3;
    }
}

mod cache {
    use super::*;
    use crate::bindings::fastly::adapter::adapter_cache;
    use crate::bindings::fastly::compute::{cache, http_req};
    use core::slice;

    impl From<cache::LookupState> for CacheLookupState {
        fn from(value: cache::LookupState) -> Self {
            let mut flags = Self::empty();
            flags.set(Self::FOUND, value.contains(cache::LookupState::FOUND));
            flags.set(Self::USABLE, value.contains(cache::LookupState::USABLE));
            flags.set(Self::STALE, value.contains(cache::LookupState::STALE));
            flags.set(
                Self::MUST_INSERT_OR_UPDATE,
                value.contains(cache::LookupState::MUST_INSERT_OR_UPDATE),
            );
            flags
        }
    }

    impl TryFrom<u32> for cache::ReplaceStrategy {
        type Error = FastlyStatus;

        fn try_from(value: u32) -> Result<Self, Self::Error> {
            match value {
                1 => Ok(Self::Immediate),
                2 => Ok(Self::ImmediateForceMiss),
                3 => Ok(Self::Wait),
                _ => Err(FastlyStatus::INVALID_ARGUMENT),
            }
        }
    }

    /// Converts a witx `CacheLookupOptions` and `CacheLookupOptionsMask` into
    /// Wit types. This initializes the `request_headers` and `extra` fields to
    /// `None`; callers are expected to overwrite this with their own value.
    unsafe fn convert_lookup_options<'a>(
        options_mask: CacheLookupOptionsMask,
    ) -> Result<cache::LookupOptions<'a>, FastlyStatus> {
        let options = cache::LookupOptions {
            // This is expected to be filled in by the caller.
            request_headers: None,

            always_use_requested_range: options_mask
                .contains(CacheLookupOptionsMask::ALWAYS_USE_REQUESTED_RANGE),

            // This is expected to be filled in by the caller.
            extra: None,
        };

        Ok(options)
    }

    #[export_name = "fastly_cache#lookup"]
    pub fn lookup(
        cache_key_ptr: *const u8,
        cache_key_len: usize,
        options_mask: CacheLookupOptionsMask,
        options: *const CacheLookupOptions,
        cache_handle_out: *mut CacheHandle,
    ) -> FastlyStatus {
        let options = unsafe_main_ptr!(options);
        macro_rules! make_str {
            ($ptr_field:ident, $len_field:ident) => {
                unsafe { crate::make_str!(main_ptr!((*options).$ptr_field), (*options).$len_field) }
            };
        }

        let cache_key = unsafe { slice::from_raw_parts(main_ptr!(cache_key_ptr), cache_key_len) };

        let mut new_options = match unsafe { convert_lookup_options(options_mask) } {
            Ok(tuple) => tuple,
            Err(err) => return err,
        };

        let request_headers;
        if options_mask.contains(CacheLookupOptionsMask::REQUEST_HEADERS) {
            request_headers = match unsafe { (*options).request_headers } {
                INVALID_HANDLE => None,
                request_headers => Some(ManuallyDrop::new(unsafe {
                    http_req::Request::from_handle(request_headers)
                })),
            };
            new_options.request_headers = request_headers.as_deref();
        }

        let extra;
        if options_mask.contains(CacheLookupOptionsMask::SERVICE) {
            extra = cache::ExtraLookupOptions::new();
            match adapter_cache::set_lookup_service_id_deprecated(
                &extra,
                make_str!(service, service_len),
            ) {
                Ok(()) => {}
                Err(err) => {
                    std::mem::forget(new_options);
                    return err.into();
                }
            }
            new_options.extra = Some(&extra);
        }

        let options = new_options;

        let res = cache::Entry::lookup(cache_key, &options);

        std::mem::forget(options);

        match res {
            Ok(res) => {
                unsafe {
                    *main_ptr!(cache_handle_out) = res.take_handle();
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    /// In order to borrow the `request_headers` with the needed lifetime, we
    /// oblige the caller to pass it in. This initializes the `extra` field to
    /// `None`; callers are expected to overwrite this with their own value.
    unsafe fn write_options<'a>(
        mask: CacheWriteOptionsMask,
        options: *const CacheWriteOptions,
        request_headers: Option<&'a ManuallyDrop<http_req::Request>>,
    ) -> Result<cache::WriteOptions<'a>, FastlyStatus> {
        macro_rules! make_vec {
            ($ptr_field:ident, $len_field:ident) => {
                unsafe { crate::make_vec!(main_ptr!((*options).$ptr_field), (*options).$len_field) }
            };
        }
        macro_rules! make_string {
            ($ptr_field:ident, $len_field:ident) => {
                crate::make_string!(
                    unsafe_main_ptr!((*options).$ptr_field),
                    (*options).$len_field
                )
            };
        }

        let vary_rule = make_string!(vary_rule_ptr, vary_rule_len);
        let surrogate_keys = make_string!(surrogate_keys_ptr, surrogate_keys_len);
        let user_metadata = make_vec!(user_metadata_ptr, user_metadata_len);
        Ok(cache::WriteOptions {
            max_age_ns: (*options).max_age_ns,
            request_headers: request_headers.map(ManuallyDrop::deref),
            vary_rule: if mask.contains(CacheWriteOptionsMask::VARY_RULE) {
                Some(ManuallyDrop::into_inner(vary_rule))
            } else {
                None
            },
            initial_age_ns: if mask.contains(CacheWriteOptionsMask::INITIAL_AGE_NS) {
                Some((*options).initial_age_ns)
            } else {
                None
            },
            stale_while_revalidate_ns: if mask
                .contains(CacheWriteOptionsMask::STALE_WHILE_REVALIDATE_NS)
            {
                Some((*options).stale_while_revalidate_ns)
            } else {
                None
            },
            surrogate_keys: if mask.contains(CacheWriteOptionsMask::SURROGATE_KEYS) {
                Some(ManuallyDrop::into_inner(surrogate_keys))
            } else {
                None
            },
            length: if mask.contains(CacheWriteOptionsMask::LENGTH) {
                Some((*options).length)
            } else {
                None
            },
            user_metadata: if mask.contains(CacheWriteOptionsMask::USER_METADATA) {
                Some(ManuallyDrop::into_inner(user_metadata))
            } else {
                None
            },
            edge_max_age_ns: if mask.contains(CacheWriteOptionsMask::EDGE_MAX_AGE_NS) {
                Some((*options).edge_max_age_ns)
            } else {
                None
            },
            sensitive_data: mask.contains(CacheWriteOptionsMask::SENSITIVE_DATA),

            // This is expected to be filled in by the caller.
            extra: None,
        })
    }

    #[export_name = "fastly_cache#insert"]
    pub fn insert(
        cache_key_ptr: *const u8,
        cache_key_len: usize,
        options_mask: CacheWriteOptionsMask,
        options: *const CacheWriteOptions,
        body_handle_out: *mut BodyHandle,
    ) -> FastlyStatus {
        let options = unsafe_main_ptr!(options);
        macro_rules! make_str {
            ($ptr_field:ident, $len_field:ident) => {
                unsafe { crate::make_str!(main_ptr!((*options).$ptr_field), (*options).$len_field) }
            };
        }

        let cache_key = unsafe { slice::from_raw_parts(main_ptr!(cache_key_ptr), cache_key_len) };

        let request_headers = match unsafe { (*options).request_headers } {
            INVALID_HANDLE => None,
            request_headers => Some(ManuallyDrop::new(unsafe {
                http_req::Request::from_handle(request_headers)
            })),
        };
        let mut options =
            match unsafe { write_options(options_mask, options, request_headers.as_ref()) } {
                Ok(options) => options,
                Err(err) => return err,
            };

        let extra;
        if options_mask.contains(CacheWriteOptionsMask::SERVICE) {
            extra = cache::ExtraWriteOptions::new();
            match adapter_cache::set_write_service_id_deprecated(
                &extra,
                make_str!(service, service_len),
            ) {
                Ok(()) => {}
                Err(err) => {
                    std::mem::forget(options);
                    return err.into();
                }
            }
            options.extra = Some(&extra);
        }

        let res = cache::insert(cache_key, &options);

        std::mem::forget(options);

        match res {
            Ok(res) => {
                unsafe {
                    *main_ptr!(body_handle_out) = res.take_handle();
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_cache#transaction_lookup"]
    pub fn transaction_lookup(
        cache_key_ptr: *const u8,
        cache_key_len: usize,
        options_mask: CacheLookupOptionsMask,
        options: *const CacheLookupOptions,
        cache_handle_out: *mut CacheHandle,
    ) -> FastlyStatus {
        let options = unsafe_main_ptr!(options);
        macro_rules! make_str {
            ($ptr_field:ident, $len_field:ident) => {
                unsafe { crate::make_str!(main_ptr!((*options).$ptr_field), (*options).$len_field) }
            };
        }

        let cache_key = unsafe { slice::from_raw_parts(main_ptr!(cache_key_ptr), cache_key_len) };
        let mut new_options = match unsafe { convert_lookup_options(options_mask) } {
            Ok(tuple) => tuple,
            Err(err) => return err,
        };
        let request_headers;
        if options_mask.contains(CacheLookupOptionsMask::REQUEST_HEADERS) {
            request_headers = match unsafe { (*options).request_headers } {
                INVALID_HANDLE => None,
                request_headers => Some(ManuallyDrop::new(unsafe {
                    http_req::Request::from_handle(request_headers)
                })),
            };
            new_options.request_headers = request_headers.as_deref();
        }

        let extra;
        if options_mask.contains(CacheLookupOptionsMask::SERVICE) {
            extra = cache::ExtraLookupOptions::new();
            match adapter_cache::set_lookup_service_id_deprecated(
                &extra,
                make_str!(service, service_len),
            ) {
                Ok(()) => {}
                Err(err) => {
                    std::mem::forget(new_options);
                    return err.into();
                }
            }
            new_options.extra = Some(&extra);
        }

        let options = new_options;

        let res = cache::Entry::transaction_lookup(cache_key, &options);

        std::mem::forget(options);

        match res {
            Ok(res) => {
                unsafe {
                    *main_ptr!(cache_handle_out) = res.take_handle();
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_cache#transaction_lookup_async"]
    pub fn transaction_lookup_async(
        cache_key_ptr: *const u8,
        cache_key_len: usize,
        options_mask: CacheLookupOptionsMask,
        options: *const CacheLookupOptions,
        cache_handle_out: *mut CacheBusyHandle,
    ) -> FastlyStatus {
        let options = unsafe_main_ptr!(options);
        macro_rules! make_str {
            ($ptr_field:ident, $len_field:ident) => {
                unsafe { crate::make_str!(main_ptr!((*options).$ptr_field), (*options).$len_field) }
            };
        }

        let cache_key = unsafe { slice::from_raw_parts(main_ptr!(cache_key_ptr), cache_key_len) };
        let mut new_options = match unsafe { convert_lookup_options(options_mask) } {
            Ok(tuple) => tuple,
            Err(err) => return err,
        };
        let request_headers;
        if options_mask.contains(CacheLookupOptionsMask::REQUEST_HEADERS) {
            request_headers = match unsafe { (*options).request_headers } {
                INVALID_HANDLE => None,
                request_headers => Some(ManuallyDrop::new(unsafe {
                    http_req::Request::from_handle(request_headers)
                })),
            };
            new_options.request_headers = request_headers.as_deref();
        }

        let extra;
        if options_mask.contains(CacheLookupOptionsMask::SERVICE) {
            extra = cache::ExtraLookupOptions::new();
            match adapter_cache::set_lookup_service_id_deprecated(
                &extra,
                make_str!(service, service_len),
            ) {
                Ok(()) => {}
                Err(err) => {
                    std::mem::forget(new_options);
                    return err.into();
                }
            }
            new_options.extra = Some(&extra);
        }

        let options = new_options;

        let res = cache::Entry::transaction_lookup_async(cache_key, &options);

        std::mem::forget(options);

        match res {
            Ok(res) => {
                unsafe {
                    *main_ptr!(cache_handle_out) = res.take_handle();
                }

                // We just created a new `CacheBusyHandle` so forget the
                // recently consumed one.
                crate::State::with::<FastlyStatus>(|state| {
                    state
                        .recently_consumed_cache_busy_handle
                        .set(INVALID_HANDLE);
                    Ok(())
                });

                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_cache#cache_busy_handle_wait"]
    pub fn cache_busy_handle_wait(
        handle: CacheBusyHandle,
        cache_handle_out: *mut CacheHandle,
    ) -> FastlyStatus {
        let cache_busy_handle = unsafe { cache::PendingEntry::from_handle(handle) };
        match cache::await_entry(cache_busy_handle) {
            Ok(res) => {
                unsafe {
                    *main_ptr!(cache_handle_out) = res.take_handle();
                }

                // Remember that we just consumed `handle` so that if there's
                // a subsequent call to `close`, we can avoid double-closing it.
                crate::State::with::<FastlyStatus>(|state| {
                    state.recently_consumed_cache_busy_handle.set(handle);
                    Ok(())
                });

                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_cache#transaction_insert"]
    pub fn transaction_insert(
        handle: CacheHandle,
        options_mask: CacheWriteOptionsMask,
        options: *const CacheWriteOptions,
        body_handle_out: *mut BodyHandle,
    ) -> FastlyStatus {
        let options = unsafe_main_ptr!(options);
        macro_rules! make_str {
            ($ptr_field:ident, $len_field:ident) => {
                unsafe { crate::make_str!(main_ptr!((*options).$ptr_field), (*options).$len_field) }
            };
        }

        let handle = ManuallyDrop::new(unsafe { cache::Entry::from_handle(handle) });
        let request_headers = match unsafe { (*options).request_headers } {
            INVALID_HANDLE => None,
            request_headers => Some(ManuallyDrop::new(unsafe {
                http_req::Request::from_handle(request_headers)
            })),
        };
        let mut options =
            match unsafe { write_options(options_mask, options, request_headers.as_ref()) } {
                Ok(options) => options,
                Err(err) => return err,
            };

        let extra;
        if options_mask.contains(CacheWriteOptionsMask::SERVICE) {
            extra = cache::ExtraWriteOptions::new();
            match adapter_cache::set_write_service_id_deprecated(
                &extra,
                make_str!(service, service_len),
            ) {
                Ok(()) => {}
                Err(err) => {
                    std::mem::forget(options);
                    return err.into();
                }
            }
            options.extra = Some(&extra);
        }

        let res = handle.transaction_insert(&options);

        std::mem::forget(options);

        match res {
            Ok(res) => {
                unsafe {
                    *main_ptr!(body_handle_out) = res.take_handle();
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_cache#transaction_insert_and_stream_back"]
    pub fn transaction_insert_and_stream_back(
        handle: CacheHandle,
        options_mask: CacheWriteOptionsMask,
        options: *const CacheWriteOptions,
        body_handle_out: *mut BodyHandle,
        cache_handle_out: *mut CacheHandle,
    ) -> FastlyStatus {
        let options = unsafe_main_ptr!(options);
        macro_rules! make_str {
            ($ptr_field:ident, $len_field:ident) => {
                unsafe { crate::make_str!(main_ptr!((*options).$ptr_field), (*options).$len_field) }
            };
        }

        let handle = ManuallyDrop::new(unsafe { cache::Entry::from_handle(handle) });
        let request_headers = match unsafe { (*options).request_headers } {
            INVALID_HANDLE => None,
            request_headers => Some(ManuallyDrop::new(unsafe {
                http_req::Request::from_handle(request_headers)
            })),
        };
        let mut options =
            match unsafe { write_options(options_mask, options, request_headers.as_ref()) } {
                Ok(options) => options,
                Err(err) => return err,
            };

        let extra;
        if options_mask.contains(CacheWriteOptionsMask::SERVICE) {
            extra = cache::ExtraWriteOptions::new();
            match adapter_cache::set_write_service_id_deprecated(
                &extra,
                make_str!(service, service_len),
            ) {
                Ok(()) => {}
                Err(err) => {
                    std::mem::forget(options);
                    return err.into();
                }
            }
            options.extra = Some(&extra);
        }

        let res = handle.transaction_insert_and_stream_back(&options);

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

    #[export_name = "fastly_cache#transaction_update"]
    pub fn transaction_update(
        handle: CacheHandle,
        options_mask: CacheWriteOptionsMask,
        options: *const CacheWriteOptions,
    ) -> FastlyStatus {
        let options = unsafe_main_ptr!(options);
        macro_rules! make_str {
            ($ptr_field:ident, $len_field:ident) => {
                unsafe { crate::make_str!(main_ptr!((*options).$ptr_field), (*options).$len_field) }
            };
        }

        let handle = ManuallyDrop::new(unsafe { cache::Entry::from_handle(handle) });
        let request_headers = match unsafe { (*options).request_headers } {
            INVALID_HANDLE => None,
            request_headers => Some(ManuallyDrop::new(unsafe {
                http_req::Request::from_handle(request_headers)
            })),
        };
        let mut options =
            match unsafe { write_options(options_mask, options, request_headers.as_ref()) } {
                Ok(options) => options,
                Err(err) => return err,
            };

        let extra;
        if options_mask.contains(CacheWriteOptionsMask::SERVICE) {
            extra = cache::ExtraWriteOptions::new();
            match adapter_cache::set_write_service_id_deprecated(
                &extra,
                make_str!(service, service_len),
            ) {
                Ok(()) => {}
                Err(err) => {
                    std::mem::forget(options);
                    return err.into();
                }
            }
            options.extra = Some(&extra);
        }

        let res = handle.transaction_update(&options);

        std::mem::forget(options);

        convert_result(res)
    }

    #[export_name = "fastly_cache#transaction_cancel"]
    pub fn transaction_cancel(handle: CacheHandle) -> FastlyStatus {
        let handle = ManuallyDrop::new(unsafe { cache::Entry::from_handle(handle) });
        convert_result(handle.transaction_cancel())
    }

    #[export_name = "fastly_cache#close_busy"]
    pub fn close_busy(handle: CacheBusyHandle) -> FastlyStatus {
        // If `handle` is the handle that we recently consumed in
        // `cache_busy_handle_wait`, don't close it, as it's already closed.
        let status = crate::State::with::<FastlyStatus>(|state| {
            let old = state
                .recently_consumed_cache_busy_handle
                .replace(INVALID_HANDLE);
            if handle == old {
                Err(FastlyStatus::BADF)
            } else {
                Ok(())
            }
        });
        if status == FastlyStatus::BADF {
            return FastlyStatus::OK;
        }

        let handle = unsafe { cache::PendingEntry::from_handle(handle) };
        convert_result(cache::close_pending_entry(handle))
    }

    #[export_name = "fastly_cache#close"]
    pub fn close(handle: CacheHandle) -> FastlyStatus {
        // If `handle` is the handle that we recently consumed in
        // `replace_insert`, don't close it, as it's already closed.
        let status = crate::State::with::<FastlyStatus>(|state| {
            let old = state
                .recently_consumed_cache_replace_handle
                .replace(INVALID_HANDLE);
            if handle == old {
                Err(FastlyStatus::BADF)
            } else {
                Ok(())
            }
        });
        if status == FastlyStatus::BADF {
            return FastlyStatus::OK;
        }

        let handle = unsafe { cache::Entry::from_handle(handle) };
        convert_result(cache::close_entry(handle))
    }

    #[export_name = "fastly_cache#get_state"]
    pub fn get_state(
        handle: CacheHandle,
        cache_lookup_state_out: *mut CacheLookupState,
    ) -> FastlyStatus {
        let handle = ManuallyDrop::new(unsafe { cache::Entry::from_handle(handle) });
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

    #[export_name = "fastly_cache#get_user_metadata"]
    pub fn get_user_metadata(
        handle: CacheHandle,
        user_metadata_out_ptr: *mut u8,
        user_metadata_out_len: usize,
        nwritten_out: *mut usize,
    ) -> FastlyStatus {
        let handle = ManuallyDrop::new(unsafe { cache::Entry::from_handle(handle) });
        alloc_result_opt!(
            unsafe_main_ptr!(user_metadata_out_ptr),
            user_metadata_out_len,
            main_ptr!(nwritten_out),
            { handle.get_user_metadata(u64::try_from(user_metadata_out_len).trapping_unwrap(),) }
        )
    }

    impl From<(CacheGetBodyOptionsMask, CacheGetBodyOptions)> for cache::GetBodyOptions<'_> {
        fn from((mask, value): (CacheGetBodyOptionsMask, CacheGetBodyOptions)) -> Self {
            Self {
                from: mask
                    .contains(CacheGetBodyOptionsMask::FROM)
                    .then_some(value.from),
                to: mask
                    .contains(CacheGetBodyOptionsMask::TO)
                    .then_some(value.to),
                extra: None,
            }
        }
    }

    #[export_name = "fastly_cache#get_body"]
    pub fn get_body(
        handle: CacheHandle,
        options_mask: CacheGetBodyOptionsMask,
        options: *const CacheGetBodyOptions,
        body_handle_out: *mut BodyHandle,
    ) -> FastlyStatus {
        let handle = ManuallyDrop::new(unsafe { cache::Entry::from_handle(handle) });
        let options = unsafe { cache::GetBodyOptions::from((options_mask, *main_ptr!(options))) };

        let res = handle.get_body(&options);

        std::mem::forget(options);

        match res {
            Ok(res) => {
                unsafe {
                    *main_ptr!(body_handle_out) = res.take_handle();
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_cache#get_length"]
    pub fn get_length(handle: CacheHandle, length_out: *mut CacheObjectLength) -> FastlyStatus {
        let handle = ManuallyDrop::new(unsafe { cache::Entry::from_handle(handle) });
        match handle.get_length() {
            Ok(Some(res)) => {
                unsafe {
                    *main_ptr!(length_out) = res;
                }
                FastlyStatus::OK
            }
            Ok(None) => FastlyStatus::NONE,
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_cache#get_max_age_ns"]
    pub fn get_max_age_ns(handle: CacheHandle, duration_out: *mut CacheDurationNs) -> FastlyStatus {
        let handle = ManuallyDrop::new(unsafe { cache::Entry::from_handle(handle) });
        match handle.get_max_age_ns() {
            Ok(Some(res)) => {
                unsafe {
                    *main_ptr!(duration_out) = res;
                }
                FastlyStatus::OK
            }
            Ok(None) => FastlyStatus::NONE,
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_cache#get_stale_while_revalidate_ns"]
    pub fn get_stale_while_revalidate_ns(
        handle: CacheHandle,
        duration_out: *mut CacheDurationNs,
    ) -> FastlyStatus {
        let handle = ManuallyDrop::new(unsafe { cache::Entry::from_handle(handle) });
        match handle.get_stale_while_revalidate_ns() {
            Ok(Some(res)) => {
                unsafe {
                    *main_ptr!(duration_out) = res;
                }
                FastlyStatus::OK
            }
            Ok(None) => FastlyStatus::NONE,
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_cache#get_age_ns"]
    pub fn get_age_ns(handle: CacheHandle, duration_out: *mut CacheDurationNs) -> FastlyStatus {
        let handle = ManuallyDrop::new(unsafe { cache::Entry::from_handle(handle) });
        match handle.get_age_ns() {
            Ok(Some(res)) => {
                unsafe {
                    *main_ptr!(duration_out) = res;
                }
                FastlyStatus::OK
            }
            Ok(None) => FastlyStatus::NONE,
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_cache#get_hits"]
    pub fn get_hits(handle: CacheHandle, hits_out: *mut CacheHitCount) -> FastlyStatus {
        let handle = ManuallyDrop::new(unsafe { cache::Entry::from_handle(handle) });
        match handle.get_hits() {
            Ok(Some(res)) => {
                unsafe {
                    *main_ptr!(hits_out) = res;
                }
                FastlyStatus::OK
            }
            Ok(None) => FastlyStatus::NONE,
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_cache#replace"]
    pub fn replace(
        cache_key_ptr: *const u8,
        cache_key_len: usize,
        options_mask: CacheReplaceOptionsMask,
        options: *const CacheReplaceOptions,
        cache_handle_out: *mut CacheHandle,
    ) -> FastlyStatus {
        let options = unsafe_main_ptr!(options);
        let cache_key = unsafe { slice::from_raw_parts(main_ptr!(cache_key_ptr), cache_key_len) };

        let replace_strategy = if options_mask.contains(CacheReplaceOptionsMask::REPLACE_STRATEGY) {
            match cache::ReplaceStrategy::try_from(unsafe { (*options).replace_strategy }) {
                Ok(r) => Some(r),
                Err(e) => return e,
            }
        } else {
            None
        };

        macro_rules! make_str {
            ($ptr_field:ident, $len_field:ident) => {
                unsafe { crate::make_str!(main_ptr!((*options).$ptr_field), (*options).$len_field) }
            };
        }

        let extra = if options_mask.contains(CacheReplaceOptionsMask::SERVICE) {
            let extra_options = cache::ExtraReplaceOptions::new();
            match adapter_cache::set_replace_service_id_deprecated(
                &extra_options,
                make_str!(service, service_len),
            ) {
                Ok(()) => {}
                Err(err) => return err.into(),
            }
            Some(extra_options)
        } else {
            None
        };
        let request_headers = match unsafe { (*options).request_headers } {
            INVALID_HANDLE => None,
            request_headers => Some(ManuallyDrop::new(unsafe {
                http_req::Request::from_handle(request_headers)
            })),
        };
        let options = cache::ReplaceOptions {
            request_headers: request_headers.as_deref(),
            replace_strategy,
            always_use_requested_range: options_mask
                .contains(CacheReplaceOptionsMask::ALWAYS_USE_REQUESTED_RANGE),
            extra: extra.as_ref(),
        };

        let res = cache::replace(cache_key, &options);

        std::mem::forget(options);

        match res {
            Ok(res) => {
                unsafe {
                    *main_ptr!(cache_handle_out) = res.take_handle();
                }

                // We just created a new `CacheReplaceHandle` so forget the
                // recently consumed one.
                crate::State::with::<FastlyStatus>(|state| {
                    state
                        .recently_consumed_cache_replace_handle
                        .set(INVALID_HANDLE);
                    Ok(())
                });
                FastlyStatus::OK
            }

            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_cache#replace_insert"]
    pub fn replace_insert(
        handle: CacheReplaceHandle,
        options_mask: CacheWriteOptionsMask,
        options: *const CacheWriteOptions,
        body_handle_out: *mut BodyHandle,
    ) -> FastlyStatus {
        let options = unsafe_main_ptr!(options);
        macro_rules! make_str {
            ($ptr_field:ident, $len_field:ident) => {
                unsafe { crate::make_str!(main_ptr!((*options).$ptr_field), (*options).$len_field) }
            };
        }

        let replace_handle = ManuallyDrop::new(unsafe { cache::ReplaceEntry::from_handle(handle) });
        let request_headers = match unsafe { (*options).request_headers } {
            INVALID_HANDLE => None,
            request_headers => Some(ManuallyDrop::new(unsafe {
                http_req::Request::from_handle(request_headers)
            })),
        };
        let mut options =
            match unsafe { write_options(options_mask, options, request_headers.as_ref()) } {
                Ok(options) => options,
                Err(err) => return err,
            };

        let extra;
        if options_mask.contains(CacheWriteOptionsMask::SERVICE) {
            extra = cache::ExtraWriteOptions::new();
            match adapter_cache::set_write_service_id_deprecated(
                &extra,
                make_str!(service, service_len),
            ) {
                Ok(()) => {}
                Err(err) => {
                    std::mem::forget(options);
                    return err.into();
                }
            }
            options.extra = Some(&extra);
        }

        let res = cache::replace_insert(&replace_handle, &options);

        std::mem::forget(options);

        match res {
            Ok(res) => {
                unsafe {
                    *main_ptr!(body_handle_out) = res.take_handle();
                }

                // Remember that we just consumed `handle` so that if there's
                // a subsequent call to `close`, we can avoid double-closing it.
                crate::State::with::<FastlyStatus>(|state| {
                    state.recently_consumed_cache_replace_handle.set(handle);
                    Ok(())
                });

                FastlyStatus::OK
            }

            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_cache#replace_get_age_ns"]
    pub fn replace_get_age_ns(
        handle: CacheReplaceHandle,
        duration_out: *mut CacheDurationNs,
    ) -> FastlyStatus {
        let handle = ManuallyDrop::new(unsafe { cache::ReplaceEntry::from_handle(handle) });
        match cache::replace_get_age_ns(&handle) {
            Ok(Some(res)) => {
                unsafe {
                    *main_ptr!(duration_out) = res;
                }

                FastlyStatus::OK
            }
            Ok(None) => FastlyStatus::NONE,
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_cache#replace_get_body"]
    pub fn replace_get_body(
        handle: CacheReplaceHandle,
        options_mask: CacheGetBodyOptionsMask,
        options: *const CacheGetBodyOptions,
        body_handle_out: *mut BodyHandle,
    ) -> FastlyStatus {
        let handle = ManuallyDrop::new(unsafe { cache::ReplaceEntry::from_handle(handle) });
        let options = unsafe { cache::GetBodyOptions::from((options_mask, *main_ptr!(options))) };

        let res = cache::replace_get_body(&handle, &options);

        std::mem::forget(options);

        match res {
            Ok(Some(res)) => {
                unsafe {
                    *main_ptr!(body_handle_out) = res.take_handle();
                }

                FastlyStatus::OK
            }
            Ok(None) => FastlyStatus::NONE,
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_cache#replace_get_hits"]
    pub fn replace_get_hits(
        handle: CacheReplaceHandle,
        hits_out: *mut CacheHitCount,
    ) -> FastlyStatus {
        let handle = ManuallyDrop::new(unsafe { cache::ReplaceEntry::from_handle(handle) });
        match cache::replace_get_hits(&handle) {
            Ok(Some(res)) => {
                unsafe {
                    *main_ptr!(hits_out) = res;
                }

                FastlyStatus::OK
            }
            Ok(None) => FastlyStatus::NONE,
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_cache#replace_get_length"]
    pub fn replace_get_length(
        handle: CacheReplaceHandle,
        length_out: *mut CacheObjectLength,
    ) -> FastlyStatus {
        let handle = ManuallyDrop::new(unsafe { cache::ReplaceEntry::from_handle(handle) });
        match cache::replace_get_length(&handle) {
            Ok(Some(res)) => {
                unsafe {
                    *main_ptr!(length_out) = res;
                }

                FastlyStatus::OK
            }
            Ok(None) => FastlyStatus::NONE,
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_cache#replace_get_max_age_ns"]
    pub fn replace_get_max_age_ns(
        handle: CacheReplaceHandle,
        duration_out: *mut CacheDurationNs,
    ) -> FastlyStatus {
        let handle = ManuallyDrop::new(unsafe { cache::ReplaceEntry::from_handle(handle) });
        match cache::replace_get_max_age_ns(&handle) {
            Ok(Some(res)) => {
                unsafe {
                    *main_ptr!(duration_out) = res;
                }

                FastlyStatus::OK
            }
            Ok(None) => FastlyStatus::NONE,
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_cache#replace_get_stale_while_revalidate_ns"]
    pub fn replace_get_stale_while_revalidate_ns(
        handle: CacheReplaceHandle,
        duration_out: *mut CacheDurationNs,
    ) -> FastlyStatus {
        let handle = ManuallyDrop::new(unsafe { cache::ReplaceEntry::from_handle(handle) });
        match cache::replace_get_stale_while_revalidate_ns(&handle) {
            Ok(Some(res)) => {
                unsafe {
                    *main_ptr!(duration_out) = res;
                }

                FastlyStatus::OK
            }
            Ok(None) => FastlyStatus::NONE,
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_cache#replace_get_state"]
    pub fn replace_get_state(
        handle: CacheReplaceHandle,
        cache_lookup_state_out: *mut CacheLookupState,
    ) -> FastlyStatus {
        let handle = ManuallyDrop::new(unsafe { cache::ReplaceEntry::from_handle(handle) });
        match cache::replace_get_state(&handle) {
            Ok(Some(res)) => {
                unsafe {
                    *main_ptr!(cache_lookup_state_out) = res.into();
                }

                FastlyStatus::OK
            }
            Ok(None) => FastlyStatus::NONE,
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_cache#replace_get_user_metadata"]
    pub fn replace_get_user_metadata(
        handle: CacheReplaceHandle,
        user_metadata_out_ptr: *mut u8,
        user_metadata_out_len: usize,
        nwritten_out: *mut usize,
    ) -> FastlyStatus {
        let handle = ManuallyDrop::new(unsafe { cache::ReplaceEntry::from_handle(handle) });
        alloc_result_opt!(
            unsafe_main_ptr!(user_metadata_out_ptr),
            user_metadata_out_len,
            main_ptr!(nwritten_out),
            {
                cache::replace_get_user_metadata(
                    &handle,
                    u64::try_from(user_metadata_out_len).trapping_unwrap(),
                )
            }
        )
    }
}
