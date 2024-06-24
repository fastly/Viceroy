use super::{
    fastly_config_store::FastlyConfigStore,
    fastly_dictionary::FastlyDictionary,
    types::{ConfigStoreHandle, DictionaryHandle},
};
use crate::{session::Session, Error};
use wiggle::GuestPtr;

impl FastlyConfigStore for Session {
    fn open(&mut self, name: &GuestPtr<str>) -> Result<ConfigStoreHandle, Error> {
        let dict_answer = <Self as FastlyDictionary>::open(self, name)?;
        Ok(ConfigStoreHandle::from(unsafe { dict_answer.inner() }))
    }

    fn get(
        &mut self,
        config_store: ConfigStoreHandle,
        key: &GuestPtr<str>,
        buf: &GuestPtr<u8>,
        buf_len: u32,
        nwritten_out: &GuestPtr<u32>,
    ) -> Result<(), Error> {
        let dict_handle = DictionaryHandle::from(unsafe { config_store.inner() });
        <Self as FastlyDictionary>::get(self, dict_handle, key, buf, buf_len, nwritten_out)
    }
}
