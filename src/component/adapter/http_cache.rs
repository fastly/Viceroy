use {
    crate::component::bindings::{
        fastly::adapter::adapter_http_cache,
        fastly::compute::{http_cache, types},
    },
    crate::{error::Error, linking::ComponentCtx},
    wasmtime::component::Resource,
};

impl adapter_http_cache::Host for ComponentCtx {
    fn lookup(
        &mut self,
        _req_handle: Resource<http_cache::Request>,
        _options: http_cache::LookupOptions,
    ) -> Result<Resource<http_cache::Entry>, types::Error> {
        Err(Error::Unsupported {
            msg: "HTTP Cache API primitives not yet supported",
        }
        .into())
    }
}
