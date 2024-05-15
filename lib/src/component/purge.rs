use {
    super::fastly::api::purge,
    super::FastlyError,
    crate::{error::Error, session::Session},
};

#[async_trait::async_trait]
impl purge::Host for Session {
    async fn purge_surrogate_key(
        &mut self,
        _surrogate_key: String,
        _options: purge::PurgeOptionsMask,
        _max_len: u64,
    ) -> Result<Option<String>, FastlyError> {
        Err(Error::NotAvailable("FastlyPurge").into())
    }
}
