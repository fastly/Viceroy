use {
    super::fastly::api::{dictionary, types},
    crate::component::component::Resource,
    crate::linking::ComponentCtx,
};

#[async_trait::async_trait]
impl dictionary::HostHandle for ComponentCtx {
    async fn open(&mut self, name: String) -> Result<Resource<dictionary::Handle>, types::Error> {
        let handle = self.session.dictionary_handle(name.as_str())?;
        Ok(handle.into())
    }

    async fn get(
        &mut self,
        h: Resource<dictionary::Handle>,
        key: String,
        max_len: u64,
    ) -> Result<Option<String>, types::Error> {
        let dict = &self.session.dictionary(h.into())?.contents;

        let item = if let Some(item) = dict.get(&key) {
            item
        } else {
            return Ok(None);
        };

        if item.len() > usize::try_from(max_len).unwrap() {
            return Err(types::Error::BufferLen(u64::try_from(item.len()).unwrap()));
        }

        Ok(Some(item.to_owned()))
    }

    async fn drop(&mut self, _h: Resource<dictionary::Handle>) -> anyhow::Result<()> {
        Ok(())
    }
}

#[async_trait::async_trait]
impl dictionary::Host for ComponentCtx {}
