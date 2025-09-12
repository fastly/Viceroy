use {
    crate::component::bindings::fastly::adapter::adapter_uap,
    crate::component::bindings::fastly::compute::types,
    crate::{error::Error, linking::ComponentCtx},
    wasmtime::component::Resource,
};

#[derive(Debug)]
pub struct UserAgent {}

impl adapter_uap::HostUserAgent for ComponentCtx {
    fn family(
        &mut self,
        _agent: Resource<UserAgent>,
        _max_len: u64,
    ) -> Result<String, types::Error> {
        Err(Error::NotAvailable("User-agent parsing is not available").into())
    }

    fn major(
        &mut self,
        _agent: Resource<UserAgent>,
        _max_len: u64,
    ) -> Result<String, types::Error> {
        Err(Error::NotAvailable("User-agent parsing is not available").into())
    }

    fn minor(
        &mut self,
        _agent: Resource<UserAgent>,
        _max_len: u64,
    ) -> Result<String, types::Error> {
        Err(Error::NotAvailable("User-agent parsing is not available").into())
    }

    fn patch(
        &mut self,
        _agent: Resource<UserAgent>,
        _max_len: u64,
    ) -> Result<String, types::Error> {
        Err(Error::NotAvailable("User-agent parsing is not available").into())
    }

    fn drop(&mut self, _agent: Resource<UserAgent>) -> wasmtime::Result<()> {
        Err(Error::NotAvailable("User-agent parsing is not available").into())
    }
}

impl adapter_uap::Host for ComponentCtx {
    fn parse(&mut self, _user_agent: Vec<u8>) -> Result<Resource<UserAgent>, types::Error> {
        // not available
        Err(Error::NotAvailable("User-agent parsing is not available").into())
    }
}
