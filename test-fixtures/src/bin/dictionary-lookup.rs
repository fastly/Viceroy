//! A guest program to test that dictionary lookups work properly.

use fastly_shared::FastlyStatus;

fn main() {
    let animals = unsafe {
        let mut dict_handle = fastly_shared::INVALID_DICTIONARY_HANDLE;
        let res = fastly_sys::fastly_dictionary::open(
            "animals".as_ptr(),
            "animals".len(),
            &mut dict_handle as *mut _,
        );
        assert_eq!(res, FastlyStatus::OK, "Failed to open dictionary");
        dict_handle
    };

    let get = |key: &str, buf_len: usize| unsafe {
        let mut value = Vec::with_capacity(buf_len);
        let mut nwritten = 0;
        let res = fastly_sys::fastly_dictionary::get(
            animals,
            key.as_ptr(),
            key.len(),
            value.as_mut_ptr(),
            buf_len,
            &mut nwritten as *mut _,
        );

        if res != FastlyStatus::OK {
            if res == FastlyStatus::NONE {
                return Ok(None);
            }

            return Err(res);
        }

        value.set_len(nwritten);
        value.shrink_to(nwritten);
        Ok(Some(String::from_utf8(value).unwrap()))
    };

    assert_eq!(get("dog", 4).unwrap().unwrap(), "woof");
    assert_eq!(get("cat", 4).unwrap().unwrap(), "meow");
    assert_eq!(get("lamp", 4), Ok(None));
}
