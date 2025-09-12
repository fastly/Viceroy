use {
    crate::component::bindings::fastly::compute::{config_store, types},
    crate::linking::{ComponentCtx, SessionView},
    crate::wiggle_abi::types::{ConfigStoreHandle, DictionaryHandle},
    wasmtime::component::Resource,
};

impl config_store::HostStore for ComponentCtx {
    fn open(&mut self, name: String) -> Result<Resource<config_store::Store>, types::Error> {
        let handle = self.session_mut().dictionary_handle(name.as_str())?;
        let handle = ConfigStoreHandle::from(u32::from(handle));
        Ok(handle.into())
    }

    fn get(
        &mut self,
        store: Resource<config_store::Store>,
        name: String,
        max_len: u64,
    ) -> Result<Option<String>, types::Error> {
        let handle = DictionaryHandle::from(store.rep());
        let dict = &self.session().dictionary(handle)?.contents;

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

    fn drop(&mut self, _store: Resource<config_store::Store>) -> wasmtime::Result<()> {
        Ok(())
    }
}

impl config_store::Host for ComponentCtx {}
