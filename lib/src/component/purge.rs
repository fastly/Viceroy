use {
    super::fastly::api::{purge, types},
    crate::{error::Error, linking::ComponentCtx},
};

impl purge::Host for ComponentCtx {
    async fn purge_surrogate_key(
        &mut self,
        _surrogate_key: String,
        _options: purge::PurgeOptionsMask,
        _max_len: u64,
    ) -> Result<Option<String>, types::Error> {
        Err(Error::NotAvailable("FastlyPurge").into())
    }
}
