//! fastly_dictionary` hostcall implementations.

use {
    crate::{
        error::Error,
        session::Session,
        wiggle_abi::{
            fastly_dictionary::FastlyDictionary,
            types::{DictionaryHandle, FastlyStatus},
        },
    },
    std::{convert::TryFrom, fs, path::Path},
    wiggle::GuestPtr,
};

#[derive(Debug, thiserror::Error)]
pub enum DictionaryError {
    /// A dictionary item with the given key was not found.
    #[error("Unknown dictionary item")]
    UnknownDictionaryItem,
}

impl DictionaryError {
    /// Convert to an error code representation suitable for passing across the ABI boundary.
    pub fn to_fastly_status(&self) -> FastlyStatus {
        use DictionaryError::*;
        match self {
            UnknownDictionaryItem => FastlyStatus::None,
        }
    }
}

fn read_json_file<P: AsRef<Path>>(file: P) -> serde_json::Map<String, serde_json::Value> {
    let data = fs::read_to_string(file).expect("Unable to read file");
    let json: serde_json::Value = serde_json::from_str(&data).expect("JSON was not well-formatted");
    let obj = json.as_object().expect("Expected the JSON to be an Object");
    obj.clone()
}

impl FastlyDictionary for Session {
    fn open(&mut self, name: &GuestPtr<str>) -> Result<DictionaryHandle, Error> {
        self.dictionary_handle(&name.as_str()?)
    }

    fn get(
        &mut self,
        dictionary: DictionaryHandle,
        key: &GuestPtr<str>,
        buf: &GuestPtr<u8>,
        buf_len: u32,
    ) -> Result<u32, Error> {
        let key: &str = &key.as_str()?;
        let dict = self.dictionary(dictionary)?;
        let file = dict.file.clone();
        let obj = read_json_file(file);
        let item = obj.get(key).ok_or(DictionaryError::UnknownDictionaryItem)?;
        let item = item.as_str().unwrap();
        let item_bytes = item.as_bytes();

        if item_bytes.len() > buf_len as usize {
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
