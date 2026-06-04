//! Limited dynamic typing for handle values.
//!
//! In order to emulate the behavior of the original WITX hostcalls, where
//! handles were just a plain `u32` and some hostcalls could work with
//! multiple types of resources, we use the unused high bits of the `u32`
//! values to encode a dynamic type ID in the adapter, so that we can detect
//! handles of different types and emulate the needed behavior.

use crate::fastly::AsyncItemHandle;

/// Reserve bits used to encode extra information in handle "index" values.
///
/// The Rust SDK uses u32::MAX or, in one case, u32::MAX - 1, as an "invalid handle" signal.
/// We treat all "negative" values as invalid values, preserving without modification.
///
/// The Canonical ABI doesn't use the high four bits.
/// We mask all four high bits, but use only bits {30, 29, 28} in our values, so we consider all
/// negative values "invalid".
const DYNAMIC_TYPE_MASK: u32 = 0xF000_0000;
const INVALID_HANDLE_MASK: u32 = 0x8000_0000;

/// All resources that don't need special handling.
const OTHER_TYPE: u32 = 0x0000_0000;
/// `cache.entry`
const CACHE_ENTRY_TYPE: u32 = 0x1000_0000;
/// `cache.replace-entry`
const CACHE_REPLACE_ENTRY_TYPE: u32 = 0x2000_0000;
/// `http-cache.entry`
const HTTP_CACHE_ENTRY_TYPE: u32 = 0x3000_0000;

/// An `enum` of the different types we need dynamic typing for.
#[derive(Copy, Clone)]
pub enum DynamicType {
    Other,
    CacheEntry,
    CacheReplaceEntry,
    HttpCacheEntry,
}

/// Returns true if this is an "invalid"-flagged handle.
#[inline]
pub const fn is_invalid(handle: AsyncItemHandle) -> bool {
    (handle & INVALID_HANDLE_MASK) == INVALID_HANDLE_MASK
}

/// Test whether the dynamic type encoding in `handle`'s bits is `ty`.
pub fn is_type(handle: AsyncItemHandle, ty: DynamicType) -> bool {
    // We consider invalid handles as inhabitants of every type.
    is_invalid(handle)
        || matches!(
            ((handle & DYNAMIC_TYPE_MASK), ty),
            (OTHER_TYPE, DynamicType::Other)
                | (CACHE_ENTRY_TYPE, DynamicType::CacheEntry)
                | (CACHE_REPLACE_ENTRY_TYPE, DynamicType::CacheReplaceEntry)
                | (HTTP_CACHE_ENTRY_TYPE, DynamicType::HttpCacheEntry)
        )
}

/// Test whether the type of `handle` is `DynamicType::Other`.
pub fn is_other(handle: AsyncItemHandle) -> bool {
    is_type(handle, DynamicType::Other)
}

/// Return the dynamic type and the raw handle value.
pub fn parts(handle: AsyncItemHandle) -> (DynamicType, AsyncItemHandle) {
    let ty = match handle & DYNAMIC_TYPE_MASK {
        OTHER_TYPE => DynamicType::Other,
        CACHE_ENTRY_TYPE => DynamicType::CacheEntry,
        CACHE_REPLACE_ENTRY_TYPE => DynamicType::CacheReplaceEntry,
        HTTP_CACHE_ENTRY_TYPE => DynamicType::HttpCacheEntry,
        // Categorize all invalid handles as "other": we don't know how they came about.
        _ if is_invalid(handle) => DynamicType::Other,
        // All negative handles are invalid, so we've covered all cases that we actually produce.
        _ => unreachable!("invalid handle for parts()"),
    };
    let raw = if is_invalid(handle) {
        handle
    } else {
        raw_handle_unchecked(handle)
    };
    (ty, raw)
}

/// Return the raw handle value.
pub fn raw_handle(handle: AsyncItemHandle, ty: DynamicType) -> AsyncItemHandle {
    if is_invalid(handle) {
        handle
    } else {
        assert!(is_type(handle, ty));
        raw_handle_unchecked(handle)
    }
}

/// Return the raw handle value, without asserting the type.
fn raw_handle_unchecked(handle: AsyncItemHandle) -> AsyncItemHandle {
    handle & !DYNAMIC_TYPE_MASK
}

/// Return a handle value with the dynamic type bits set.
pub fn set_type(handle: AsyncItemHandle, ty: DynamicType) -> AsyncItemHandle {
    if is_invalid(handle) {
        // Preserve invalid handles verbatim.
        return handle;
    }
    assert!(is_type(handle, DynamicType::Other));
    handle
        | match ty {
            DynamicType::Other => OTHER_TYPE,
            DynamicType::CacheEntry => CACHE_ENTRY_TYPE,
            DynamicType::CacheReplaceEntry => CACHE_REPLACE_ENTRY_TYPE,
            DynamicType::HttpCacheEntry => HTTP_CACHE_ENTRY_TYPE,
        }
}
