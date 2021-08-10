//! fastly_dictionary` hostcall implementations.

use std::convert::TryFrom;
use std::convert::TryInto;
use std::fs;
use {
    crate::{
        error::Error,
        session::Session,
        wiggle_abi::{fastly_dictionary::FastlyDictionary, types::DictionaryHandle},
    },
    wiggle::GuestPtr,
};

use memoize::memoize;

#[memoize]
fn read_json_file(file: String) -> serde_json::Map<String, serde_json::Value> {
    let data = fs::read_to_string(file).expect("Unable to read file");
    let json: serde_json::Value = serde_json::from_str(&data).expect("JSON was not well-formatted");
    let obj = json.as_object().expect("Expected the JSON to be an Object");
    obj.clone()
}

impl FastlyDictionary for Session {
    fn open(&mut self, name: &GuestPtr<str>) -> Result<DictionaryHandle, Error> {
        let name = name.as_str()?.to_owned();
        self.dictionary_handle(&name)
    }

    fn get(
        &mut self,
        dictionary: DictionaryHandle,
        key: &GuestPtr<str>,
        buf: &GuestPtr<u8>,
        buf_len: u32,
    ) -> Result<u32, Error> {
        let key = key.as_str()?.to_owned();
        let dict = self.dictionary(dictionary)?;
        let file = dict.file.clone();
        let obj = read_json_file(file);
        if !obj.contains_key(&key) {
            return Err(Error::UnknownDictionaryItem(key));
        }
        let item = obj.get(&key).unwrap(); // Safe to do due to `!obj.contains_key(&key)` above
        let item = serde_json::to_string(item).unwrap();
        let item_bytes = item.as_bytes();

        if item_bytes.len() > buf_len as usize {
            // Write out the number of bytes necessary to fit this dictionary_item, or zero on overflow to
            // signal an error condition.
            buf.write(item_bytes.len().try_into().unwrap_or(0))?;
            return Err(Error::BufferLengthError {
                buf: "dictionary_item",
                len: "dictionary_item_max_len",
            });
        }
        let item_len = u32::try_from(item_bytes.len())
            .expect("smaller than dictionary_item_max_len means it must fit");

        let mut buf_slice = buf.as_array(item_len).as_slice_mut()?;
        buf_slice.copy_from_slice(item_bytes);
        Ok(item_len)
    }
}
