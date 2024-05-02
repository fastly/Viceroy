use {
    super::fastly::api::uap,
    super::FastlyError,
    crate::{error::Error, session::Session},
    wasmtime::component::Resource,
};

#[derive(Debug)]
pub struct UserAgent;

#[async_trait::async_trait]
impl uap::HostUserAgent for Session {
    async fn family(
        &mut self,
        _agent: Resource<UserAgent>,
        _max_len: u64,
    ) -> wasmtime::Result<String> {
        anyhow::bail!("UserAgent resource is unimplemented")
    }

    async fn major(
        &mut self,
        _agent: Resource<UserAgent>,
        _max_len: u64,
    ) -> wasmtime::Result<String> {
        anyhow::bail!("UserAgent resource is unimplemented")
    }

    async fn minor(
        &mut self,
        _agent: Resource<UserAgent>,
        _max_len: u64,
    ) -> wasmtime::Result<String> {
        anyhow::bail!("UserAgent resource is unimplemented")
    }

    async fn patch(
        &mut self,
        _agent: Resource<UserAgent>,
        _max_len: u64,
    ) -> wasmtime::Result<String> {
        anyhow::bail!("UserAgent resource is unimplemented")
    }

    fn drop(&mut self, _agent: Resource<UserAgent>) -> wasmtime::Result<()> {
        anyhow::bail!("UserAgent resource is unimplemented")
    }
}

#[async_trait::async_trait]
impl uap::Host for Session {
    async fn parse(&mut self, _user_agent: String) -> Result<Resource<UserAgent>, FastlyError> {
        // not available
        Err(Error::NotAvailable("User-agent parsing is not available").into())
    }
}
