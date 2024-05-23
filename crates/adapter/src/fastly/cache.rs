use super::{convert_result, BodyHandle, FastlyStatus, RequestHandle};
use crate::{alloc_result, with_buffer, TrappingUnwrap};

pub type CacheHandle = u32;

pub type CacheObjectLength = u64;
pub type CacheDurationNs = u64;
pub type CacheHitCount = u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct CacheLookupOptions {
    pub request_headers: RequestHandle,
}

bitflags::bitflags! {
    #[repr(transparent)]
    pub struct CacheLookupOptionsMask: u32 {
        const _RESERVED = 1 << 0;
        const REQUEST_HEADERS = 1 << 1;
    }
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
    use crate::bindings::fastly::api::cache;
    use core::slice;

    impl From<CacheLookupOptionsMask> for cache::LookupOptionsMask {
        fn from(value: CacheLookupOptionsMask) -> Self {
            let mut flags = Self::empty();
            flags.set(
                Self::REQUEST_HEADERS,
                value.contains(CacheLookupOptionsMask::REQUEST_HEADERS),
            );
            flags
        }
    }

    impl From<CacheLookupOptions> for cache::LookupOptions {
        fn from(value: CacheLookupOptions) -> Self {
            Self {
                request_headers: value.request_headers,
            }
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

    #[export_name = "fastly_cache#lookup"]
    pub fn lookup(
        cache_key_ptr: *const u8,
        cache_key_len: usize,
        options_mask: CacheLookupOptionsMask,
        options: *const CacheLookupOptions,
        cache_handle_out: *mut CacheHandle,
    ) -> FastlyStatus {
        let cache_key = unsafe { slice::from_raw_parts(cache_key_ptr, cache_key_len) };
        let options_mask = cache::LookupOptionsMask::from(options_mask);
        let options = unsafe { cache::LookupOptions::from(*options) };
        match cache::lookup(cache_key, options_mask, options) {
            Ok(res) => {
                unsafe {
                    *cache_handle_out = res;
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    unsafe fn write_options(options: *const CacheWriteOptions) -> cache::WriteOptions {
        // NOTE: this is only really safe because we never mutate the vectors -- we only need
        // vectors to satisfy the interface produced by the DynamicBackendConfig record,
        // `register_dynamic_backend` will never mutate the vectors it's given.
        macro_rules! make_vec {
            ($ptr_field:ident, $len_field:ident) => {{
                let len = usize::try_from((*options).$len_field).trapping_unwrap();
                Vec::from_raw_parts((*options).$ptr_field as *mut _, len, len)
            }};
        }

        cache::WriteOptions {
            max_age_ns: (*options).max_age_ns,
            request_headers: (*options).request_headers,
            vary_rule: make_vec!(vary_rule_ptr, vary_rule_len),
            initial_age_ns: (*options).initial_age_ns,
            stale_while_revalidate_ns: (*options).stale_while_revalidate_ns,
            surrogate_keys: make_vec!(surrogate_keys_ptr, surrogate_keys_len),
            length: (*options).length,
            user_metadata: make_vec!(user_metadata_ptr, user_metadata_len),
        }
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

        let options = unsafe { write_options(options) };

        let res = cache::insert(cache_key, options_mask, &options);

        std::mem::forget(options);

        match res {
            Ok(res) => {
                unsafe {
                    *body_handle_out = res;
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
        let options_mask = cache::LookupOptionsMask::from(options_mask);
        let options = unsafe { cache::LookupOptions::from(*options) };
        match cache::transaction_lookup(cache_key, options_mask, options) {
            Ok(res) => {
                unsafe {
                    *cache_handle_out = res;
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
        let options_mask = cache::WriteOptionsMask::from(options_mask);
        let options = unsafe { write_options(options) };
        let res = cache::transaction_insert(handle, options_mask, &options);

        std::mem::forget(options);

        match res {
            Ok(res) => {
                unsafe {
                    *body_handle_out = res;
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
        let options_mask = cache::WriteOptionsMask::from(options_mask);
        let options = unsafe { write_options(options) };
        let res = cache::transaction_insert_and_stream_back(handle, options_mask, &options);
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

    #[export_name = "fastly_cache#transaction_update"]
    pub fn transaction_update(
        handle: CacheHandle,
        options_mask: CacheWriteOptionsMask,
        options: *const CacheWriteOptions,
    ) -> FastlyStatus {
        let options_mask = cache::WriteOptionsMask::from(options_mask);
        let options = unsafe { write_options(options) };
        let res = cache::transaction_update(handle, options_mask, &options);
        std::mem::forget(options);
        convert_result(res)
    }

    #[export_name = "fastly_cache#transaction_cancel"]
    pub fn transaction_cancel(handle: CacheHandle) -> FastlyStatus {
        convert_result(cache::transaction_cancel(handle))
    }

    #[export_name = "fastly_cache#close"]
    pub fn close(handle: CacheHandle) -> FastlyStatus {
        convert_result(cache::close(handle))
    }

    #[export_name = "fastly_cache#get_state"]
    pub fn get_state(
        handle: CacheHandle,
        cache_lookup_state_out: *mut CacheLookupState,
    ) -> FastlyStatus {
        match cache::get_state(handle) {
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
        alloc_result!(
            user_metadata_out_ptr,
            user_metadata_out_len,
            nwritten_out,
            { cache::get_user_metadata(handle) }
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
        let options_mask = cache::GetBodyOptionsMask::from(options_mask);
        let options = unsafe { cache::GetBodyOptions::from(*options) };
        match cache::get_body(handle, options_mask, options) {
            Ok(res) => {
                unsafe {
                    *body_handle_out = res;
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }

    #[export_name = "fastly_cache#get_length"]
    pub fn get_length(handle: CacheHandle, length_out: *mut CacheObjectLength) -> FastlyStatus {
        match cache::get_length(handle) {
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
        match cache::get_max_age_ns(handle) {
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
        match cache::get_stale_while_revalidate_ns(handle) {
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
        match cache::get_age_ns(handle) {
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
        match cache::get_hits(handle) {
            Ok(res) => {
                unsafe {
                    *hits_out = res;
                }
                FastlyStatus::OK
            }
            Err(e) => e.into(),
        }
    }
}
