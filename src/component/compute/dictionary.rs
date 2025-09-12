use {
    crate::component::bindings::fastly::compute::{dictionary, types},
    crate::linking::{ComponentCtx, SessionView},
    wasmtime::component::Resource,
};

impl dictionary::HostDictionary for ComponentCtx {
    fn open(&mut self, name: String) -> Result<Resource<dictionary::Dictionary>, types::Error> {
        let handle = self.session_mut().dictionary_handle(name.as_str())?;
        Ok(handle.into())
    }

    fn lookup(
        &mut self,
        h: Resource<dictionary::Dictionary>,
        key: String,
        max_len: u64,
    ) -> Result<Option<String>, types::Error> {
        let dict = &self.session().dictionary(h.into())?.contents;

        let item = if let Some(item) = dict.get(&key) {
            item
        } else {
            return Ok(None);
        };

        if item.len() > usize::try_from(max_len).unwrap() {
            return Err(types::Error::BufferLen(u64::try_from(item.len()).unwrap()));
        }

        Ok(Some(item.as_str().to_owned()))
    }

    fn drop(&mut self, _dictionary: Resource<dictionary::Dictionary>) -> wasmtime::Result<()> {
        Ok(())
    }
}

impl dictionary::Host for ComponentCtx {}
