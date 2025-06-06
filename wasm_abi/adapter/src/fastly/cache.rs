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
    use crate::bindings::fastly::api::{cache, http_req};
    use core::slice;

    impl From<CacheLookupOptionsMask> for cache::LookupOptionsMask {
        fn from(value: CacheLookupOptionsMask) -> Self {
            let mut flags = Self::empty();
            flags.set(
                Self::RESERVED,
                value.contains(CacheLookupOptionsMask::_RESERVED),
            );
            flags.set(
                Self::REQUEST_HEADERS,
                value.contains(CacheLookupOptionsMask::REQUEST_HEADERS),
            );
            flags.set(
                Self::SERVICE_ID,
                value.contains(CacheLookupOptionsMask::SERVICE),
            );
            flags.set(
                Self::ALWAYS_USE_REQUESTED_RANGE,
                value.contains(CacheLookupOptionsMask::ALWAYS_USE_REQUESTED_RANGE),
            );
            flags
        }
    }

    impl From<CacheWriteOptionsMask> for cache::WriteOptionsMask {
        fn from(value: CacheWriteOptionsMask) -> Self {
            let mut flags = Self::empty();
            flags.set(
                Self::RESERVED,
                value.contains(CacheWriteOptionsMask::_RESERVED),
            );
            flags.set(
                Self::REQUEST_HEADERS,
                value.contains(CacheWriteOptionsMask::REQUEST_HEADERS),
            );
            flags.set(
                Self::VARY_RULE,
                value.contains(CacheWriteOptionsMask::VARY_RULE),
            );
            flags.set(
                Self::INITIAL_AGE_NS,
                value.contains(CacheWriteOptionsMask::INITIAL_AGE_NS),
            );
            flags.set(
                Self::STALE_WHILE_REVALIDATE_NS,
                value.contains(CacheWriteOptionsMask::STALE_WHILE_REVALIDATE_NS),
            );
            flags.set(
                Self::SURROGATE_KEYS,
                value.contains(CacheWriteOptionsMask::SURROGATE_KEYS),
            );
            flags.set(Self::LENGTH, value.contains(CacheWriteOptionsMask::LENGTH));
            flags.set(
                Self::USER_METADATA,
                value.contains(CacheWriteOptionsMask::USER_METADATA),
            );
            flags.set(
                Self::SENSITIVE_DATA,
                value.contains(CacheWriteOptionsMask::SENSITIVE_DATA),
            );
            flags.set(
                Self::EDGE_MAX_AGE_NS,
                value.contains(CacheWriteOptionsMask::EDGE_MAX_AGE_NS),
            );
            flags.set(
                Self::SERVICE_ID,
                value.contains(CacheWriteOptionsMask::SERVICE),
            );
            flags
        }
    }

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

    impl From<CacheReplaceOptionsMask> for cache::ReplaceOptionsMask {
        fn from(value: CacheReplaceOptionsMask) -> Self {
            let mut flags = Self::empty();

            flags.set(
                Self::RESERVED,
                value.contains(CacheReplaceOptionsMask::_RESERVED),
            );
            flags.set(
                Self::REQUEST_HEADERS,
                value.contains(CacheReplaceOptionsMask::REQUEST_HEADERS),
            );
            flags.set(
                Self::REPLACE_STRATEGY,
                value.contains(CacheReplaceOptionsMask::REPLACE_STRATEGY),
            );
            flags.set(
                Self::SERVICE_ID,
                value.contains(CacheReplaceOptionsMask::SERVICE),
            );
            flags.set(
                Self::ALWAYS_USE_REQUESTED_RANGE,
                value.contains(CacheReplaceOptionsMask::ALWAYS_USE_REQUESTED_RANGE),
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

    unsafe fn convert_lookup_options<'a>(
        options_mask: CacheLookupOptionsMask,
        options: *const CacheLookupOptions,
    ) -> Result<(cache::LookupOptionsMask, cache::LookupOptions<'a>), FastlyStatus> {
        let mask = cache::LookupOptionsMask::from(options_mask);

        let service_id = if mask.contains(cache::LookupOptionsMask::SERVICE_ID) {
            crate::make_string_result!((*options).service, (*options).service_len)
        } else {
            ManuallyDrop::new(Default::default())
        };
        let options = cache::LookupOptions {
            // This is filled in by the macro below.
            request_headers: None,

            service_id: ManuallyDrop::into_inner(service_id),
        };

        Ok((mask, options))
    }

    #[export_name = "fastly_cache#lookup"]
    pub fn lookup(
        cache_key_ptr: *const u8,
        cache_key_len: usize,
        options_mask: CacheLookupOptionsMask,
        options: *const CacheLookupOptions,
        cache_handle_out: *mut CacheHandle,
    ) -> FastlyStatus {
        let cache_key = unsafe { slice::from_raw_parts(cache_key_ptr, cache_key_len) };

        let (options_mask, mut new_options) =
            match unsafe { convert_lookup_options(options_mask, options) } {
                Ok(tuple) => tuple,
                Err(err) => return err,
            };

        let request_headers;
        if options_mask.contains(cache::LookupOptionsMask::REQUEST_HEADERS) {
            request_headers = match unsafe { (*options).request_headers } {
                INVALID_HANDLE => None,
                request_headers => Some(ManuallyDrop::new(unsafe {
                    http_req::RequestHandle::from_handle(request_headers)
                })),
            };
            new_options.request_headers = request_headers.as_deref();
        }

        let options = new_options;

        let res = cache::Handle::lookup(cache_key, options_mask, &options);

        std::mem::forget(options);

        match res {
            Ok(res) => {
                unsafe {
                    *cache_handle_out = res.take_handle();
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    /// In order to borrow the `request_headers` with the needed lifetime, we
    /// oblige the caller to pass it in.
    unsafe fn write_options<'a>(
        mask: cache::WriteOptionsMask,
        options: *const CacheWriteOptions,
        request_headers: Option<&'a ManuallyDrop<http_req::RequestHandle>>,
    ) -> Result<cache::WriteOptions<'a>, FastlyStatus> {
        // NOTE: this is only really safe because we never mutate the vectors -- we only need
        // vectors to satisfy the interface produced by the DynamicBackendConfig record,
        // `register_dynamic_backend` will never mutate the vectors it's given.
        macro_rules! make_vec {
            ($ptr_field:ident, $len_field:ident) => {
                unsafe { crate::make_vec!((*options).$ptr_field, (*options).$len_field) }
            };
        }
        macro_rules! make_string {
            ($ptr_field:ident, $len_field:ident) => {
                crate::make_string_result!((*options).$ptr_field, (*options).$len_field)
            };
        }

        let vary_rule = make_string!(vary_rule_ptr, vary_rule_len);
        let surrogate_keys = make_string!(surrogate_keys_ptr, surrogate_keys_len);
        let user_metadata = make_vec!(user_metadata_ptr, user_metadata_len);
        let service_id = if mask.contains(cache::WriteOptionsMask::SERVICE_ID) {
            make_string!(service, service_len)
        } else {
            ManuallyDrop::new(Default::default())
        };
        Ok(cache::WriteOptions {
            max_age_ns: (*options).max_age_ns,
            request_headers: request_headers.map(ManuallyDrop::deref),
            vary_rule: ManuallyDrop::into_inner(vary_rule),
            initial_age_ns: (*options).initial_age_ns,
            stale_while_revalidate_ns: (*options).stale_while_revalidate_ns,
            surrogate_keys: ManuallyDrop::into_inner(surrogate_keys),
            length: (*options).length,
            user_metadata: ManuallyDrop::into_inner(user_metadata),
            edge_max_age_ns: if mask.contains(cache::WriteOptionsMask::EDGE_MAX_AGE_NS) {
                (*options).edge_max_age_ns
            } else {
                0
            },
            service_id: ManuallyDrop::into_inner(service_id),
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
        let cache_key = unsafe { slice::from_raw_parts(cache_key_ptr, cache_key_len) };
        let options_mask = cache::WriteOptionsMask::from(options_mask);

        let request_headers = match unsafe { (*options).request_headers } {
            INVALID_HANDLE => None,
            request_headers => Some(ManuallyDrop::new(unsafe {
                http_req::RequestHandle::from_handle(request_headers)
            })),
        };
        let options =
            match unsafe { write_options(options_mask, options, request_headers.as_ref()) } {
                Ok(options) => options,
                Err(err) => return err,
            };

        let res = cache::insert(cache_key, options_mask, &options);

        std::mem::forget(options);

        match res {
            Ok(res) => {
                unsafe {
                    *body_handle_out = res.take_handle();
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
        let cache_key = unsafe { slice::from_raw_parts(cache_key_ptr, cache_key_len) };
        let (options_mask, mut new_options) =
            match unsafe { convert_lookup_options(options_mask, options) } {
                Ok(tuple) => tuple,
                Err(err) => return err,
            };
        let request_headers;
        if options_mask.contains(cache::LookupOptionsMask::REQUEST_HEADERS) {
            request_headers = match unsafe { (*options).request_headers } {
                INVALID_HANDLE => None,
                request_headers => Some(ManuallyDrop::new(unsafe {
                    http_req::RequestHandle::from_handle(request_headers)
                })),
            };
            new_options.request_headers = request_headers.as_deref();
        }

        let options = new_options;
        let res = cache::Handle::transaction_lookup(cache_key, options_mask, &options);
        std::mem::forget(options);
        match res {
            Ok(res) => {
                unsafe {
                    *cache_handle_out = res.take_handle();
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
        let cache_key = unsafe { slice::from_raw_parts(cache_key_ptr, cache_key_len) };
        let (options_mask, mut new_options) =
            match unsafe { convert_lookup_options(options_mask, options) } {
                Ok(tuple) => tuple,
                Err(err) => return err,
            };
        let request_headers;
        if options_mask.contains(cache::LookupOptionsMask::REQUEST_HEADERS) {
            request_headers = match unsafe { (*options).request_headers } {
                INVALID_HANDLE => None,
                request_headers => Some(ManuallyDrop::new(unsafe {
                    http_req::RequestHandle::from_handle(request_headers)
                })),
            };
            new_options.request_headers = request_headers.as_deref();
        }

        let options = new_options;
        let res = cache::Handle::transaction_lookup_async(cache_key, options_mask, &options);
        std::mem::forget(options);
        match res {
            Ok(res) => {
                unsafe {
                    *cache_handle_out = res.take_handle();
                }
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
        let handle = ManuallyDrop::new(unsafe { cache::BusyHandle::from_handle(handle) });
        match cache::cache_busy_handle_wait(&handle) {
            Ok(res) => {
                unsafe {
                    *cache_handle_out = res.take_handle();
                }

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
        let handle = ManuallyDrop::new(unsafe { cache::Handle::from_handle(handle) });
        let options_mask = cache::WriteOptionsMask::from(options_mask);
        let request_headers = match unsafe { (*options).request_headers } {
            INVALID_HANDLE => None,
            request_headers => Some(ManuallyDrop::new(unsafe {
                http_req::RequestHandle::from_handle(request_headers)
            })),
        };
        let options =
            match unsafe { write_options(options_mask, options, request_headers.as_ref()) } {
                Ok(options) => options,
                Err(err) => return err,
            };
        let res = handle.transaction_insert(options_mask, &options);

        std::mem::forget(options);

        match res {
            Ok(res) => {
                unsafe {
                    *body_handle_out = res.take_handle();
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
        let handle = ManuallyDrop::new(unsafe { cache::Handle::from_handle(handle) });
        let options_mask = cache::WriteOptionsMask::from(options_mask);
        let request_headers = match unsafe { (*options).request_headers } {
            INVALID_HANDLE => None,
            request_headers => Some(ManuallyDrop::new(unsafe {
                http_req::RequestHandle::from_handle(request_headers)
            })),
        };
        let options =
            match unsafe { write_options(options_mask, options, request_headers.as_ref()) } {
                Ok(options) => options,
                Err(err) => return err,
            };
        let res = handle.transaction_insert_and_stream_back(options_mask, &options);
        std::mem::forget(options);
        match res {
            Ok((body_handle, cache_handle)) => {
                unsafe {
                    *body_handle_out = body_handle.take_handle();
                    *cache_handle_out = cache_handle.take_handle();
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
        let handle = ManuallyDrop::new(unsafe { cache::Handle::from_handle(handle) });
        let options_mask = cache::WriteOptionsMask::from(options_mask);
        let request_headers = match unsafe { (*options).request_headers } {
            INVALID_HANDLE => None,
            request_headers => Some(ManuallyDrop::new(unsafe {
                http_req::RequestHandle::from_handle(request_headers)
            })),
        };
        let options =
            match unsafe { write_options(options_mask, options, request_headers.as_ref()) } {
                Ok(options) => options,
                Err(err) => return err,
            };
        let res = handle.transaction_update(options_mask, &options);
        std::mem::forget(options);
        convert_result(res)
    }

    #[export_name = "fastly_cache#transaction_cancel"]
    pub fn transaction_cancel(handle: CacheHandle) -> FastlyStatus {
        let handle = ManuallyDrop::new(unsafe { cache::Handle::from_handle(handle) });
        convert_result(handle.transaction_cancel())
    }

    #[export_name = "fastly_cache#close_busy"]
    pub fn close_busy(handle: CacheBusyHandle) -> FastlyStatus {
        let handle = unsafe { cache::BusyHandle::from_handle(handle) };
        convert_result(cache::close_busy(handle))
    }

    #[export_name = "fastly_cache#close"]
    pub fn close(handle: CacheHandle) -> FastlyStatus {
        let handle = unsafe { cache::Handle::from_handle(handle) };
        convert_result(cache::close(handle))
    }

    #[export_name = "fastly_cache#get_state"]
    pub fn get_state(
        handle: CacheHandle,
        cache_lookup_state_out: *mut CacheLookupState,
    ) -> FastlyStatus {
        let handle = ManuallyDrop::new(unsafe { cache::Handle::from_handle(handle) });
        match handle.get_state() {
            Ok(res) => {
                unsafe {
                    *cache_lookup_state_out = res.into();
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
        let handle = ManuallyDrop::new(unsafe { cache::Handle::from_handle(handle) });
        alloc_result_opt!(
            user_metadata_out_ptr,
            user_metadata_out_len,
            nwritten_out,
            { handle.get_user_metadata(u64::try_from(user_metadata_out_len).trapping_unwrap(),) }
        )
    }

    impl From<CacheGetBodyOptionsMask> for cache::GetBodyOptionsMask {
        fn from(value: CacheGetBodyOptionsMask) -> Self {
            let mut flags = Self::empty();
            flags.set(
                Self::RESERVED,
                value.contains(CacheGetBodyOptionsMask::_RESERVED),
            );
            flags.set(Self::FROM, value.contains(CacheGetBodyOptionsMask::FROM));
            flags.set(Self::TO, value.contains(CacheGetBodyOptionsMask::TO));
            flags
        }
    }

    impl From<CacheGetBodyOptions> for cache::GetBodyOptions {
        fn from(value: CacheGetBodyOptions) -> Self {
            Self {
                from: value.from,
                to: value.to,
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
        let handle = ManuallyDrop::new(unsafe { cache::Handle::from_handle(handle) });
        let options_mask = cache::GetBodyOptionsMask::from(options_mask);
        let options = unsafe { cache::GetBodyOptions::from(*options) };
        match handle.get_body(options_mask, options) {
            Ok(res) => {
                unsafe {
                    *body_handle_out = res.take_handle();
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_cache#get_length"]
    pub fn get_length(handle: CacheHandle, length_out: *mut CacheObjectLength) -> FastlyStatus {
        let handle = ManuallyDrop::new(unsafe { cache::Handle::from_handle(handle) });
        match handle.get_length() {
            Ok(res) => {
                unsafe {
                    *length_out = res;
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_cache#get_max_age_ns"]
    pub fn get_max_age_ns(handle: CacheHandle, duration_out: *mut CacheDurationNs) -> FastlyStatus {
        let handle = ManuallyDrop::new(unsafe { cache::Handle::from_handle(handle) });
        match handle.get_max_age_ns() {
            Ok(res) => {
                unsafe {
                    *duration_out = res;
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_cache#get_stale_while_revalidate_ns"]
    pub fn get_stale_while_revalidate_ns(
        handle: CacheHandle,
        duration_out: *mut CacheDurationNs,
    ) -> FastlyStatus {
        let handle = ManuallyDrop::new(unsafe { cache::Handle::from_handle(handle) });
        match handle.get_stale_while_revalidate_ns() {
            Ok(res) => {
                unsafe {
                    *duration_out = res;
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_cache#get_age_ns"]
    pub fn get_age_ns(handle: CacheHandle, duration_out: *mut CacheDurationNs) -> FastlyStatus {
        let handle = ManuallyDrop::new(unsafe { cache::Handle::from_handle(handle) });
        match handle.get_age_ns() {
            Ok(res) => {
                unsafe {
                    *duration_out = res;
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_cache#get_hits"]
    pub fn get_hits(handle: CacheHandle, hits_out: *mut CacheHitCount) -> FastlyStatus {
        let handle = ManuallyDrop::new(unsafe { cache::Handle::from_handle(handle) });
        match handle.get_hits() {
            Ok(res) => {
                unsafe {
                    *hits_out = res;
                }
                FastlyStatus::OK
            }
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
        let cache_key = unsafe { slice::from_raw_parts(cache_key_ptr, cache_key_len) };
        let options_mask = cache::ReplaceOptionsMask::from(options_mask);

        let replace_strategy =
            match cache::ReplaceStrategy::try_from(unsafe { (*options).replace_strategy }) {
                Ok(r) => r,
                Err(e) => return e,
            };

        // NOTE: this is only really safe because we never mutate the vectors -- we only need
        // vectors to satisfy the interface produced by the DynamicBackendConfig record,
        // `register_dynamic_backend` will never mutate the vectors it's given.
        macro_rules! make_string {
            ($ptr_field:ident, $len_field:ident) => {
                unsafe { crate::make_string!((*options).$ptr_field, (*options).$len_field) }
            };
        }

        let service_id = if options_mask.contains(cache::ReplaceOptionsMask::SERVICE_ID) {
            make_string!(service, service_len)
        } else {
            ManuallyDrop::new(Default::default())
        };
        let request_headers = match unsafe { (*options).request_headers } {
            INVALID_HANDLE => None,
            request_headers => Some(ManuallyDrop::new(unsafe {
                http_req::RequestHandle::from_handle(request_headers)
            })),
        };
        let options = cache::ReplaceOptions {
            request_headers: request_headers.as_deref(),
            replace_strategy,
            service_id: ManuallyDrop::into_inner(service_id),
        };

        let res = cache::replace(cache_key, options_mask, &options);

        std::mem::forget(options);

        match res {
            Ok(res) => {
                unsafe {
                    *cache_handle_out = res.take_handle();
                }

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
        let handle = ManuallyDrop::new(unsafe { cache::CacheReplaceHandle::from_handle(handle) });
        let options_mask = cache::WriteOptionsMask::from(options_mask);
        let request_headers = match unsafe { (*options).request_headers } {
            INVALID_HANDLE => None,
            request_headers => Some(ManuallyDrop::new(unsafe {
                http_req::RequestHandle::from_handle(request_headers)
            })),
        };
        let options =
            match unsafe { write_options(options_mask, options, request_headers.as_ref()) } {
                Ok(options) => options,
                Err(err) => return err,
            };
        let res = cache::replace_insert(&handle, options_mask, &options);

        std::mem::forget(options);

        match res {
            Ok(res) => {
                unsafe {
                    *body_handle_out = res.take_handle();
                }

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
        let handle = ManuallyDrop::new(unsafe { cache::CacheReplaceHandle::from_handle(handle) });
        match cache::replace_get_age_ns(&handle) {
            Ok(Some(res)) => {
                unsafe {
                    *duration_out = res;
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
        let handle = ManuallyDrop::new(unsafe { cache::CacheReplaceHandle::from_handle(handle) });
        let options_mask = cache::GetBodyOptionsMask::from(options_mask);
        let options = unsafe { cache::GetBodyOptions::from(*options) };
        match cache::replace_get_body(&handle, options_mask, options) {
            Ok(Some(res)) => {
                unsafe {
                    *body_handle_out = res.take_handle();
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
        let handle = ManuallyDrop::new(unsafe { cache::CacheReplaceHandle::from_handle(handle) });
        match cache::replace_get_hits(&handle) {
            Ok(Some(res)) => {
                unsafe {
                    *hits_out = res;
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
        let handle = ManuallyDrop::new(unsafe { cache::CacheReplaceHandle::from_handle(handle) });
        match cache::replace_get_length(&handle) {
            Ok(Some(res)) => {
                unsafe {
                    *length_out = res;
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
        let handle = ManuallyDrop::new(unsafe { cache::CacheReplaceHandle::from_handle(handle) });
        match cache::replace_get_max_age_ns(&handle) {
            Ok(Some(res)) => {
                unsafe {
                    *duration_out = res;
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
        let handle = ManuallyDrop::new(unsafe { cache::CacheReplaceHandle::from_handle(handle) });
        match cache::replace_get_stale_while_revalidate_ns(&handle) {
            Ok(Some(res)) => {
                unsafe {
                    *duration_out = res;
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
        let handle = ManuallyDrop::new(unsafe { cache::CacheReplaceHandle::from_handle(handle) });
        match cache::replace_get_state(&handle) {
            Ok(Some(res)) => {
                unsafe {
                    *cache_lookup_state_out = res.into();
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
        let handle = ManuallyDrop::new(unsafe { cache::CacheReplaceHandle::from_handle(handle) });
        alloc_result_opt!(
            user_metadata_out_ptr,
            user_metadata_out_len,
            nwritten_out,
            {
                cache::replace_get_user_metadata(
                    &handle,
                    u64::try_from(user_metadata_out_len).trapping_unwrap(),
                )
            }
        )
    }
}
