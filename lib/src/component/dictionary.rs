use {
    super::fastly::api::{dictionary, types},
    super::FastlyError,
    crate::{error, session::Session},
};

#[async_trait::async_trait]
impl dictionary::Host for Session {
    async fn open(&mut self, name: String) -> Result<dictionary::Handle, FastlyError> {
        let handle = self.dictionary_handle(name.as_str())?;
        Ok(handle.into())
    }

    async fn get(
        &mut self,
        h: dictionary::Handle,
        key: String,
        max_len: u64,
    ) -> Result<Option<String>, FastlyError> {
        let dict = self
            .dictionary(h.into())?
            .contents()
            .map_err(|err| error::Error::Other(err.into()))?;

        let key = key.as_str();
        let item = dict
            .get(key)
            .ok_or_else(|| FastlyError::from(types::Error::OptionalNone))?;

        if item.len() > usize::try_from(max_len).unwrap() {
            return Err(error::Error::BufferLengthError {
                buf: "item_out",
                len: "item_max_len",
            }
            .into());
        }

        Ok(Some(item.clone()))
    }
}
