use {
    super::fastly::api::{config_store, types},
    crate::component::component::Resource,
    crate::linking::ComponentCtx,
    crate::wiggle_abi::types::ConfigStoreHandle,
};

#[async_trait::async_trait]
impl config_store::HostHandle for ComponentCtx {
    async fn open(&mut self, name: String) -> Result<Resource<config_store::Handle>, types::Error> {
        let handle = self.session.dictionary_handle(name.as_str())?;
        Ok(ConfigStoreHandle::from(handle).into())
    }

    async fn get(
        &mut self,
        store: Resource<config_store::Handle>,
        name: String,
        max_len: u64,
    ) -> Result<Option<String>, types::Error> {
        let store = ConfigStoreHandle::from(store);
        let dict = &self.session.dictionary(store.into())?.contents;

        let item = if let Some(item) = dict.get(&name) {
            item
        } else {
            return Ok(None);
        };

        if item.len() > usize::try_from(max_len).unwrap() {
            return Err(types::Error::BufferLen(u64::try_from(item.len()).unwrap()));
        }

        Ok(Some(item.to_owned()))
    }

    async fn drop(&mut self, _store: Resource<config_store::Handle>) -> anyhow::Result<()> {
        Ok(())
    }
}

#[async_trait::async_trait]
impl config_store::Host for ComponentCtx {}
