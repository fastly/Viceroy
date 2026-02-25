use {
    crate::Error,
    crate::component::bindings::fastly::compute::{purge, types},
    crate::linking::ComponentCtx,
    wasmtime::component::Resource,
};

impl purge::Host for ComponentCtx {
    fn purge_surrogate_key(
        &mut self,
        surrogate_key: String,
        options: purge::PurgeOptions,
    ) -> Result<(), types::Error> {
        let soft_purge = options.soft_purge;
        let surrogate_key = surrogate_key.parse()?;
        let purged = self.session().cache().purge(surrogate_key, soft_purge);
        tracing::debug!("{purged} variants purged");
        Ok(())
    }

    fn purge_surrogate_key_verbose(
        &mut self,
        _surrogate_key: String,
        _options: purge::PurgeOptions,
        _max_len: u64,
    ) -> Result<String, types::Error> {
        Err(Error::Unsupported {
            msg: "purge.purge-surrogate-key-verbose is not supported in Viceroy",
        }
        .into())
    }
}

impl purge::HostExtraPurgeOptions for ComponentCtx {
    fn drop(&mut self, _options: Resource<purge::ExtraPurgeOptions>) -> wasmtime::Result<()> {
        Ok(())
    }
}
