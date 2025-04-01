use {
    super::fastly::api::{dictionary, types},
    crate::linking::ComponentCtx,
};

#[async_trait::async_trait]
impl dictionary::Host for ComponentCtx {
    async fn open(&mut self, name: String) -> Result<dictionary::Handle, types::Error> {
        let handle = self.session.dictionary_handle(name.as_str())?;
        Ok(handle.into())
    }

    async fn get(
        &mut self,
        h: dictionary::Handle,
        key: String,
        max_len: u64,
    ) -> Result<Option<Vec<u8>>, types::Error> {
        let dict = &self.session.dictionary(h.into())?.contents;

        let item = if let Some(item) = dict.get(&key) {
            item
        } else {
            return Ok(None);
        };

        if item.len() > usize::try_from(max_len).unwrap() {
            return Err(types::Error::BufferLen(u64::try_from(item.len()).unwrap()));
        }

        Ok(Some(item.as_bytes().to_owned()))
    }
}
