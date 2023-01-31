use {
    super::fastly::compute_at_edge::{purge, types},
    crate::{error::Error, session::Session},
};

#[async_trait::async_trait]
impl purge::Host for Session {
    async fn surrogate_key(
        &mut self,
        _surrogate_key: String,
        _options: purge::OptionsMask,
    ) -> Result<Option<String>, types::FastlyError> {
        Err(Error::NotAvailable("FastlyPurge").into())
    }
}
