use {
    super::fastly::compute_at_edge::{types, uap},
    crate::session::Session,
};

#[async_trait::async_trait]
impl uap::Host for Session {
    async fn parse(&mut self, _user_agent: String) -> Result<uap::UserAgent, types::FastlyError> {
        // not available
        Err(types::Error::GenericError.into())
    }
}
