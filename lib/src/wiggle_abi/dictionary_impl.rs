//! fastly_dictionary` hostcall implementations.

use cranelift_entity::PrimaryMap;

use crate::config::{Dictionary, FastlyConfig};

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
        let dicts = self.dictionaries.as_ref();
        let n = name.as_str().unwrap().to_owned();
        match dicts.get(&n) {
            Some(dict) => {
                Ok(
                    DictionaryHandle::from(dict.id)
                )
            },
            None => Err(Error::UnknownDictionary(n.clone())),
        }
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
