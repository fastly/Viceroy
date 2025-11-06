use crate::component::{
    bindings::fastly::adapter::adapter_backend,
    bindings::fastly::compute::{http_types, types},
};
use crate::linking::ComponentCtx;
use wasmtime::component::Resource;

impl adapter_backend::Host for ComponentCtx {
    async fn register_dynamic_backend(
        &mut self,
        name: String,
        origin: String,
        config_handle: Resource<adapter_backend::DynamicBackendOptions>,
    ) -> Result<(), types::Error> {
        // Discard the handle for this API, as we register the backend
        // in a namespace that other adapter APIs access by name.
        crate::component::backend::register_dynamic_backend(
            &mut self.session,
            &mut self.wasi_table,
            name,
            origin,
            config_handle,
        )
        .await
        .map(|_| ())
    }

    fn exists(&mut self, name: String) -> Result<bool, types::Error> {
        Ok(crate::component::backend::exists(&mut self.session, &name))
    }

    fn is_healthy(&mut self, name: String) -> Result<adapter_backend::BackendHealth, types::Error> {
        crate::component::backend::is_healthy(&mut self.session, &name)
    }

    fn is_dynamic(&mut self, name: String) -> Result<bool, types::Error> {
        crate::component::backend::is_dynamic(&mut self.session, &name)
    }

    fn get_host(&mut self, name: String, max_len: u64) -> Result<String, types::Error> {
        crate::component::backend::get_host(&mut self.session, &name, max_len)
    }

    fn get_override_host(
        &mut self,
        name: String,
        max_len: u64,
    ) -> Result<Option<Vec<u8>>, types::Error> {
        crate::component::backend::get_override_host(&mut self.session, &name, max_len)
    }

    fn get_port(&mut self, backend: String) -> Result<u16, types::Error> {
        crate::component::backend::get_port(&mut self.session, &backend)
    }

    fn get_connect_timeout_ms(&mut self, backend: String) -> Result<u32, types::Error> {
        crate::component::backend::get_connect_timeout_ms(&mut self.session, &backend)
    }

    fn get_first_byte_timeout_ms(&mut self, backend: String) -> Result<u32, types::Error> {
        crate::component::backend::get_first_byte_timeout_ms(&mut self.session, &backend)
    }

    fn get_between_bytes_timeout_ms(&mut self, backend: String) -> Result<u32, types::Error> {
        crate::component::backend::get_between_bytes_timeout_ms(&mut self.session, &backend)
    }

    fn get_http_keepalive_time(
        &mut self,
        backend: String,
    ) -> Result<adapter_backend::TimeoutMs, types::Error> {
        crate::component::backend::get_http_keepalive_time(&mut self.session, &backend)
    }

    fn get_tcp_keepalive_enable(&mut self, backend: String) -> Result<bool, types::Error> {
        crate::component::backend::get_tcp_keepalive_enable(&mut self.session, &backend)
    }

    fn get_tcp_keepalive_interval(
        &mut self,
        backend: String,
    ) -> Result<adapter_backend::TimeoutSecs, types::Error> {
        crate::component::backend::get_tcp_keepalive_interval(&mut self.session, &backend)
    }

    fn get_tcp_keepalive_probes(
        &mut self,
        backend: String,
    ) -> Result<adapter_backend::ProbeCount, types::Error> {
        crate::component::backend::get_tcp_keepalive_probes(&mut self.session, &backend)
    }

    fn get_tcp_keepalive_time(
        &mut self,
        backend: String,
    ) -> Result<adapter_backend::TimeoutSecs, types::Error> {
        crate::component::backend::get_tcp_keepalive_time(&mut self.session, &backend)
    }

    fn is_tls(&mut self, backend: String) -> Result<bool, types::Error> {
        crate::component::backend::is_tls(&mut self.session, &backend)
    }

    fn get_tls_min_version(
        &mut self,
        backend: String,
    ) -> Result<Option<http_types::TlsVersion>, types::Error> {
        crate::component::backend::get_tls_min_version(&mut self.session, &backend)
    }

    fn get_tls_max_version(
        &mut self,
        backend: String,
    ) -> Result<Option<http_types::TlsVersion>, types::Error> {
        crate::component::backend::get_tls_max_version(&mut self.session, &backend)
    }
}
