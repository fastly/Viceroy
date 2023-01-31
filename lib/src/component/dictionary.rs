use {
    super::fastly::compute_at_edge::{dictionary, types},
    crate::{error, session::Session},
};

#[async_trait::async_trait]
impl dictionary::Host for Session {
    async fn open(&mut self, name: String) -> Result<dictionary::Handle, types::FastlyError> {
        let handle = self.dictionary_handle(name.as_str())?;
        Ok(handle.into())
    }

    async fn get(
        &mut self,
        h: dictionary::Handle,
        key: String,
    ) -> Result<Option<String>, types::FastlyError> {
        let dict = self
            .dictionary(h.into())?
            .contents()
            .map_err(|err| error::Error::Other(err.into()))?;

        let key = key.as_str();
        let item = dict
            .get(key)
            .ok_or_else(|| types::FastlyError::from(types::Error::OptionalNone))?;

        Ok(Some(item.clone()))
    }
}
