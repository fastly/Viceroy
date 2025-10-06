use super::FastlyStatus;
use crate::{alloc_result_opt, bindings::fastly::compute::config_store, TrappingUnwrap};
use core::mem::ManuallyDrop;

pub type ConfigStoreHandle = u32;

#[export_name = "fastly_config_store#open"]
pub fn open(
    name: *const u8,
    name_len: usize,
    store_handle_out: *mut ConfigStoreHandle,
) -> FastlyStatus {
    let name = crate::make_str!(unsafe_main_ptr!(name), name_len);
    match config_store::Store::open(name) {
        Ok(res) => {
            unsafe {
                *main_ptr!(store_handle_out) = res.take_handle();
            }
            FastlyStatus::OK
        }
        // As a special case, `fastly_config_store#open` uses `BADF` to indicate not found.
        Err(config_store::OpenError::NotFound) => FastlyStatus::BADF,
        // As a special case, `fastly_config_store#open` uses `NONE` to indicate an empty name.
        Err(config_store::OpenError::InvalidSyntax) if name_len == 0 => FastlyStatus::NONE,
        // As a special case, `fastly_config_store#open` uses `UNSUPPORTED` to indicate an empty name.
        Err(config_store::OpenError::NameTooLong) => FastlyStatus::UNSUPPORTED,
        Err(e) => e.into(),
    }
}

#[export_name = "fastly_config_store#get"]
pub fn get(
    store_handle: ConfigStoreHandle,
    key: *const u8,
    key_len: usize,
    value: *mut u8,
    value_max_len: usize,
    nwritten: *mut usize,
) -> FastlyStatus {
    let key = crate::make_str!(unsafe_main_ptr!(key), key_len);
    let store_handle = ManuallyDrop::new(unsafe { config_store::Store::from_handle(store_handle) });
    alloc_result_opt!(
        unsafe_main_ptr!(value),
        value_max_len,
        main_ptr!(nwritten),
        { store_handle.get(key, u64::try_from(value_max_len).trapping_unwrap()) }
    )
}
