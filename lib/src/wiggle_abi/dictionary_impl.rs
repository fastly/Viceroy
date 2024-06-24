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
    wiggle::GuestPtr,
};

#[derive(Debug, thiserror::Error)]
pub enum DictionaryError {
    /// A dictionary item with the given key was not found.
    #[error("Unknown dictionary item: {0}")]
    UnknownDictionaryItem(String),
    /// A dictionary with the given name was not found.
    #[error("Unknown dictionary: {0}")]
    UnknownDictionary(String),
}

impl DictionaryError {
    /// Convert to an error code representation suitable for passing across the ABI boundary.
    pub fn to_fastly_status(&self) -> FastlyStatus {
        use DictionaryError::*;
        match self {
            UnknownDictionaryItem(_) => FastlyStatus::None,
            UnknownDictionary(_) => FastlyStatus::Badf,
        }
    }
}

impl FastlyDictionary for Session {
    fn open(&mut self, name: &GuestPtr<str>) -> Result<DictionaryHandle, Error> {
        self.dictionary_handle(&name.as_str()?.ok_or(Error::SharedMemory)?)
    }

    fn get(
        &mut self,
        dictionary: DictionaryHandle,
        key: &GuestPtr<str>,
        buf: &GuestPtr<u8>,
        buf_len: u32,
        nwritten_out: &GuestPtr<u32>,
    ) -> Result<(), Error> {
        let dict = &self.dictionary(dictionary)?.contents;

        let item_bytes = {
            let key: &str = &key.as_str()?.ok_or(Error::SharedMemory)?;
            dict.get(key)
                .ok_or_else(|| DictionaryError::UnknownDictionaryItem(key.to_owned()))?
                .as_bytes()
        };

        if item_bytes.len() > usize::try_from(buf_len).expect("buf_len must fit in usize") {
            // Write out the number of bytes necessary to fit this item, or zero on overflow to
            // signal an error condition. This is probably unnecessary, as config store entries
            // may be at most 8000 utf-8 characters large.
            nwritten_out.write(u32::try_from(item_bytes.len()).unwrap_or(0))?;
            return Err(Error::BufferLengthError {
                buf: "dictionary_item",
                len: "dictionary_item_max_len",
            });
        }

        // We know the conversion of item_bytes.len() to u32 will succeed, as it's <= buf_len.
        let item_len = u32::try_from(item_bytes.len()).unwrap();

        nwritten_out.write(item_len)?;
        buf.as_array(item_len).copy_from_slice(item_bytes)?;

        Ok(())
    }
}
