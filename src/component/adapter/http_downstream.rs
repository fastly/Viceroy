use {
    crate::component::{
        fastly::adapter::adapter_http_downstream,
        fastly::compute::{http_req, types},
    },
    crate::linking::{ComponentCtx, SessionView},
    wasmtime::component::Resource,
};

impl adapter_http_downstream::Host for ComponentCtx {
    async fn downstream_tls_raw_client_certificate_deprecated(
        &mut self,
        h: Resource<http_req::Request>,
        _max_len: u64,
    ) -> Result<Vec<u8>, types::Error> {
        self.session()
            .absent_metadata_value(h.into())
            .map_err(Into::into)
    }
}
