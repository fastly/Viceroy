use {
    crate::component::bindings::{
        fastly::adapter::adapter_http_req,
        fastly::compute::http_downstream::Host as HttpDownstream,
        fastly::compute::{http_req, types},
    },
    crate::{
        error::Error,
        linking::{ComponentCtx, SessionView},
        pushpin::PushpinRedirectInfo,
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
    fn fastly_key_is_valid(&mut self) -> Result<bool, types::Error> {
        HttpDownstream::fastly_key_is_valid(self, self.ds_req_handle())
    }

    fn redirect_to_websocket_proxy_deprecated(
        &mut self,
        _backend: String,
    ) -> Result<(), types::Error> {
        Err(Error::NotAvailable("Redirect to WebSocket proxy").into())
    }

    fn redirect_to_grip_proxy_deprecated(
        &mut self,
        backend_name: String,
    ) -> Result<(), types::Error> {
        let redirect_info = PushpinRedirectInfo {
            backend_name,
            request_info: None,
        };

        self.session_mut()
            .redirect_downstream_to_pushpin(redirect_info)?;
        Ok(())
    }

    fn downstream_client_request_id(&mut self, max_len: u64) -> Result<String, types::Error> {
        HttpDownstream::downstream_client_request_id(self, self.ds_req_handle(), max_len)
    }

    fn downstream_client_h2_fingerprint(&mut self, max_len: u64) -> Result<String, types::Error> {
        HttpDownstream::downstream_client_h2_fingerprint(self, self.ds_req_handle(), max_len)
    }

    fn downstream_client_oh_fingerprint(&mut self, max_len: u64) -> Result<String, types::Error> {
        let h = self.ds_req_handle();
        HttpDownstream::downstream_client_oh_fingerprint(self, h, max_len)
    }

    fn downstream_tls_ja4(&mut self, max_len: u64) -> Result<Option<String>, types::Error> {
        HttpDownstream::downstream_tls_ja4(self, self.ds_req_handle(), max_len)
    }

    fn downstream_compliance_region(
        &mut self,
        region_max_len: u64,
    ) -> Result<Option<String>, types::Error> {
        HttpDownstream::downstream_compliance_region(self, self.ds_req_handle(), region_max_len)
    }

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

    fn downstream_client_ip_addr(&mut self) -> Option<types::IpAddress> {
        let h = self.ds_req_handle();
        HttpDownstream::downstream_client_ip_addr(self, h)
    }

    fn downstream_server_ip_addr(&mut self) -> Option<types::IpAddress> {
        let h = self.ds_req_handle();
        HttpDownstream::downstream_server_ip_addr(self, h)
    }

    fn downstream_client_ddos_detected(&mut self) -> Result<bool, types::Error> {
        let h = self.ds_req_handle();
        HttpDownstream::downstream_client_ddos_detected(self, h)
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

    fn downstream_tls_client_hello(
        &mut self,
        max_len: u64,
    ) -> Result<Option<Vec<u8>>, types::Error> {
        let h = self.ds_req_handle();
        HttpDownstream::downstream_tls_client_hello(self, h, max_len)
    }

    fn downstream_tls_raw_client_certificate_deprecated(
        &mut self,
        max_len: u64,
    ) -> Result<Option<Vec<u8>>, types::Error> {
        let h = self.ds_req_handle();
        HttpDownstream::downstream_tls_raw_client_certificate(self, h, max_len)
    }

    fn downstream_tls_client_cert_verify_result(
        &mut self,
    ) -> Result<Option<http_req::ClientCertVerifyResult>, types::Error> {
        HttpDownstream::downstream_tls_client_cert_verify_result(self, self.ds_req_handle())
    }

    fn downstream_tls_ja3_md5(&mut self) -> Result<Option<Vec<u8>>, types::Error> {
        HttpDownstream::downstream_tls_ja3_md5(self, self.ds_req_handle())
    }
}
