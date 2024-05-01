use {
    super::fastly::api::{types, uap},
    super::FastlyError,
    crate::session::Session,
};

#[async_trait::async_trait]
impl uap::Host for Session {
    async fn parse(&mut self, _user_agent: String) -> Result<uap::UserAgent, FastlyError> {
        // not available
        Err(types::Error::GenericError.into())
    }
}
