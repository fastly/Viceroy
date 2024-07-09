use {
    super::fastly::api::{config_store, types},
    crate::session::Session,
};

#[async_trait::async_trait]
impl config_store::Host for Session {
    async fn open(&mut self, name: String) -> Result<config_store::Handle, types::Error> {
        let handle = self.dictionary_handle(name.as_str())?;
        Ok(handle.into())
    }

    async fn get(
        &mut self,
        store: config_store::Handle,
        name: String,
        max_len: u64,
    ) -> Result<Option<String>, types::Error> {
        let dict = &self.dictionary(store.into())?.contents;

        let item = if let Some(item) = dict.get(&name) {
            item
        } else {
            return Ok(None);
        };

        if item.len() > usize::try_from(max_len).unwrap() {
            return Err(types::Error::BufferLen(u64::try_from(item.len()).unwrap()));
        }

        Ok(Some(item.clone()))
    }
}
