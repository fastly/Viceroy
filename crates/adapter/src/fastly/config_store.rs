use super::fastly_dictionary;
use super::FastlyStatus;

pub type ConfigStoreHandle = u32;

#[export_name = "fastly_config_store#open"]
pub fn open(
    name: *const u8,
    name_len: usize,
    store_handle_out: *mut ConfigStoreHandle,
) -> FastlyStatus {
    fastly_dictionary::open(name, name_len, store_handle_out)
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
    fastly_dictionary::get(store_handle, key, key_len, value, value_max_len, nwritten)
}
