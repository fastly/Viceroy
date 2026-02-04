use {
    crate::component::bindings::{
        fastly::adapter::adapter_http_req,
        fastly::compute::http_downstream::Host as HttpDownstream,
        fastly::compute::{http_body, http_req, http_resp, types},
    },
    crate::{
        error::Error,
        linking::{ComponentCtx, SessionView},
    },
    wasmtime::component::Resource,
};

/// Extension trait to add a `.ds_req_handle()` for `CompontentCtx` so to help
/// `http_req` implementations forward to `http_downstream` implementations.
trait DsView {
    fn ds_req_handle(&self) -> Resource<http_req::Request>;
}
impl DsView for ComponentCtx {
    fn ds_req_handle(&self) -> Resource<http_req::Request> {
        self.session().downstream_request().into()
    }
}

impl adapter_http_req::Host for ComponentCtx {
    fn get_original_header_names(
        &mut self,
        max_len: u64,
        cursor: u32,
    ) -> Result<(String, Option<u32>), types::Error> {
        HttpDownstream::downstream_original_header_names(
            self,
            self.ds_req_handle(),
            max_len,
            cursor,
        )
    }

    fn original_header_count(&mut self) -> Result<u32, types::Error> {
        let h = self.ds_req_handle();
        HttpDownstream::downstream_original_header_count(self, h)
    }

    fn downstream_tls_cipher_openssl_name(
        &mut self,
        max_len: u64,
    ) -> Result<Option<Vec<u8>>, types::Error> {
        let h = self.ds_req_handle();
        HttpDownstream::downstream_tls_cipher_openssl_name(self, h, max_len)
    }

    fn downstream_tls_protocol(&mut self, max_len: u64) -> Result<Option<Vec<u8>>, types::Error> {
        let h = self.ds_req_handle();
        HttpDownstream::downstream_tls_protocol(self, h, max_len)
    }

    fn downstream_tls_raw_client_certificate_deprecated(
        &mut self,
        max_len: u64,
    ) -> Result<Option<Vec<u8>>, types::Error> {
        let h = self.ds_req_handle();
        HttpDownstream::downstream_tls_raw_client_certificate(self, h, max_len)
    }
}
