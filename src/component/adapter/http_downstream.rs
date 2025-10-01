use {
    crate::component::{
        bindings::fastly::adapter::adapter_http_downstream,
        bindings::fastly::compute::{http_req, types},
        compute::http_downstream::MetadataView,
    },
    crate::linking::ComponentCtx,
    wasmtime::component::Resource,
};

impl adapter_http_downstream::Host for ComponentCtx {
    fn downstream_tls_raw_client_certificate_deprecated(
        &mut self,
        h: Resource<http_req::Request>,
        _max_len: u64,
    ) -> Result<Option<Vec<u8>>, types::Error> {
        Ok(self.session().absent_metadata_value(h)?)
    }
}
