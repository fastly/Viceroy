use {
    super::fastly::api::{purge, types},
    crate::{error::Error, linking::ComponentCtx},
};

#[async_trait::async_trait]
impl purge::Host for ComponentCtx {
    async fn purge_surrogate_key(
        &mut self,
        surrogate_key: String,
        options: purge::PurgeOptionsMask,
        _max_len: u64,
    ) -> Result<Option<String>, types::Error> {
        if options.contains(purge::PurgeOptionsMask::SOFT_PURGE) {
            return Err(Error::NotAvailable("soft purge").into());
        }
        if options.contains(purge::PurgeOptionsMask::RET_BUF) {
            return Err(Error::NotAvailable("purge response").into());
        }

        let surrogate_key = surrogate_key.parse()?;
        let purged = self.session.cache().purge(surrogate_key);
        tracing::debug!("{purged} variants purged");
        Ok(None)
    }
}
