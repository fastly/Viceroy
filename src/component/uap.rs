use {
    super::fastly::api::{types, uap},
    crate::{error::Error, linking::ComponentCtx},
    wasmtime::component::Resource,
};

#[derive(Debug)]
pub struct UserAgent {}

#[async_trait::async_trait]
impl uap::HostUserAgent for ComponentCtx {
    async fn family(
        &mut self,
        _agent: Resource<UserAgent>,
        _max_len: u64,
    ) -> Result<String, types::Error> {
        Err(Error::NotAvailable("User-agent parsing is not available").into())
    }

    async fn major(
        &mut self,
        _agent: Resource<UserAgent>,
        _max_len: u64,
    ) -> Result<String, types::Error> {
        Err(Error::NotAvailable("User-agent parsing is not available").into())
    }

    async fn minor(
        &mut self,
        _agent: Resource<UserAgent>,
        _max_len: u64,
    ) -> Result<String, types::Error> {
        Err(Error::NotAvailable("User-agent parsing is not available").into())
    }

    async fn patch(
        &mut self,
        _agent: Resource<UserAgent>,
        _max_len: u64,
    ) -> Result<String, types::Error> {
        Err(Error::NotAvailable("User-agent parsing is not available").into())
    }

    async fn drop(&mut self, _agent: Resource<UserAgent>) -> wasmtime::Result<()> {
        Err(Error::NotAvailable("User-agent parsing is not available").into())
    }
}

#[async_trait::async_trait]
impl uap::Host for ComponentCtx {
    async fn parse(&mut self, _user_agent: Vec<u8>) -> Result<Resource<UserAgent>, types::Error> {
        // not available
        Err(Error::NotAvailable("User-agent parsing is not available").into())
    }
}
