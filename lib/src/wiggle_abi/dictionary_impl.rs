//! fastly_dictionary` hostcall implementations.

use {
    crate::{
        error::Error,
        session::Session,
        wiggle_abi::{fastly_dictionary::FastlyDictionary, types::DictionaryHandle},
    },
    wiggle::GuestPtr,
};

impl FastlyDictionary for Session {
    #[allow(unused_variables)] // FIXME: Remove this directive once implemented.
    fn open(&mut self, name: &GuestPtr<str>) -> Result<DictionaryHandle, Error> {
        Err(Error::NotAvailable("Dictionary lookup"))
    }

    #[allow(unused_variables)] // FIXME: Remove this directive once implemented.
    fn get(
        &mut self,
        dictionary: DictionaryHandle,
        key: &GuestPtr<str>,
        buf: &GuestPtr<u8>,
        buf_len: u32,
    ) -> Result<u32, Error> {
        Err(Error::NotAvailable("Dictionary lookup"))
    }
}
