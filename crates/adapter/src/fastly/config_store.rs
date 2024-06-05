use super::FastlyStatus;
use crate::{bindings::fastly::api::config_store, with_buffer, TrappingUnwrap};
use core::slice;

pub type ConfigStoreHandle = u32;

#[export_name = "fastly_config_store#open"]
pub fn open(
    name: *const u8,
    name_len: usize,
    store_handle_out: *mut ConfigStoreHandle,
) -> FastlyStatus {
    let name = unsafe { slice::from_raw_parts(name, name_len) };
    match config_store::open(name) {
        Ok(res) => {
            unsafe {
                *store_handle_out = res;
            }
            FastlyStatus::OK
        }
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
    let key = unsafe { slice::from_raw_parts(key, key_len) };
    with_buffer!(
        value,
        value_max_len,
        {
            config_store::get(
                store_handle,
                key,
                u64::try_from(value_max_len).trapping_unwrap(),
            )
        },
        |res| {
            let res = res.ok_or(FastlyStatus::NONE)?;
            unsafe {
                *nwritten = res.len();
            }
            std::mem::forget(res)
        }
    )
}
