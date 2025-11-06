use std::num::NonZeroUsize;
use std::time::Duration;

use {
    crate::component::bindings::fastly::compute::{backend, http_types, types},
    crate::linking::ComponentCtx,
    crate::wiggle_abi::types::SecretHandle,
    wasmtime::component::Resource,
    wasmtime_wasi_io::IoView,
};

impl backend::Host for ComponentCtx {
    async fn register_dynamic_backend(
        &mut self,
        prefix: String,
        target: String,
        options: Resource<backend::DynamicBackendOptions>,
    ) -> Result<Resource<String>, types::Error> {
        crate::component::backend::register_dynamic_backend(
            &mut self.session,
            &mut self.wasi_table,
            prefix,
            target,
            options,
        )
        .await
    }
}

impl backend::HostBackend for ComponentCtx {
    fn open(&mut self, name: String) -> Result<Resource<String>, backend::OpenError> {
        if !crate::component::backend::exists(&mut self.session, &name) {
            return Err(backend::OpenError::NotFound);
        }

        let res = self.table().push(name).unwrap();

        Ok(res)
    }

    fn get_name(&mut self, name: Resource<String>) -> String {
        self.wasi_table.get(&name).unwrap().to_owned()
    }

    fn is_healthy(
        &mut self,
        name: Resource<String>,
    ) -> Result<backend::BackendHealth, types::Error> {
        let name = self.wasi_table.get(&name).unwrap();
        crate::component::backend::is_healthy(&mut self.session, name)
    }

    fn is_dynamic(&mut self, name: Resource<String>) -> Result<bool, types::Error> {
        let name = self.wasi_table.get(&name).unwrap();
        crate::component::backend::is_dynamic(&mut self.session, name)
    }

    fn get_host(&mut self, name: Resource<String>, max_len: u64) -> Result<String, types::Error> {
        let name = self.wasi_table.get(&name).unwrap();
        crate::component::backend::get_host(&mut self.session, name, max_len)
    }

    fn get_override_host(
        &mut self,
        name: Resource<String>,
        max_len: u64,
    ) -> Result<Option<Vec<u8>>, types::Error> {
        let name = self.wasi_table.get(&name).unwrap();
        crate::component::backend::get_override_host(&mut self.session, name, max_len)
    }

    fn get_port(&mut self, backend: Resource<String>) -> Result<u16, types::Error> {
        let backend = self.wasi_table.get(&backend).unwrap();
        crate::component::backend::get_port(&mut self.session, backend)
    }

    fn get_connect_timeout_ms(&mut self, backend: Resource<String>) -> Result<u32, types::Error> {
        let backend = self.wasi_table.get(&backend).unwrap();
        crate::component::backend::get_connect_timeout_ms(&mut self.session, backend)
    }

    fn get_first_byte_timeout_ms(
        &mut self,
        backend: Resource<String>,
    ) -> Result<u32, types::Error> {
        let backend = self.wasi_table.get(&backend).unwrap();
        crate::component::backend::get_first_byte_timeout_ms(&mut self.session, backend)
    }

    fn get_between_bytes_timeout_ms(
        &mut self,
        backend: Resource<String>,
    ) -> Result<u32, types::Error> {
        let backend = self.wasi_table.get(&backend).unwrap();
        crate::component::backend::get_between_bytes_timeout_ms(&mut self.session, backend)
    }

    fn get_http_keepalive_time(
        &mut self,
        backend: Resource<String>,
    ) -> Result<backend::TimeoutMs, types::Error> {
        let backend = self.wasi_table.get(&backend).unwrap();
        crate::component::backend::get_http_keepalive_time(&mut self.session, backend)
    }

    fn get_tcp_keepalive_enable(
        &mut self,
        backend: Resource<String>,
    ) -> Result<bool, types::Error> {
        let backend = self.wasi_table.get(&backend).unwrap();
        crate::component::backend::get_tcp_keepalive_enable(&mut self.session, backend)
    }

    fn get_tcp_keepalive_interval(
        &mut self,
        backend: Resource<String>,
    ) -> Result<backend::TimeoutSecs, types::Error> {
        let backend = self.wasi_table.get(&backend).unwrap();
        crate::component::backend::get_tcp_keepalive_interval(&mut self.session, backend)
    }

    fn get_tcp_keepalive_probes(
        &mut self,
        backend: Resource<String>,
    ) -> Result<backend::ProbeCount, types::Error> {
        let backend = self.wasi_table.get(&backend).unwrap();
        crate::component::backend::get_tcp_keepalive_probes(&mut self.session, backend)
    }

    fn get_tcp_keepalive_time(
        &mut self,
        backend: Resource<String>,
    ) -> Result<backend::TimeoutSecs, types::Error> {
        let backend = self.wasi_table.get(&backend).unwrap();
        crate::component::backend::get_tcp_keepalive_time(&mut self.session, backend)
    }

    fn is_tls(&mut self, backend: Resource<String>) -> Result<bool, types::Error> {
        let backend = self.wasi_table.get(&backend).unwrap();
        crate::component::backend::is_tls(&mut self.session, backend)
    }

    fn get_tls_min_version(
        &mut self,
        backend: Resource<String>,
    ) -> Result<Option<http_types::TlsVersion>, types::Error> {
        let backend = self.wasi_table.get(&backend).unwrap();
        crate::component::backend::get_tls_min_version(&mut self.session, backend)
    }

    fn get_tls_max_version(
        &mut self,
        backend: Resource<String>,
    ) -> Result<Option<http_types::TlsVersion>, types::Error> {
        let backend = self.wasi_table.get(&backend).unwrap();
        crate::component::backend::get_tls_max_version(&mut self.session, backend)
    }

    fn drop(&mut self, backend: Resource<String>) -> wasmtime::Result<()> {
        self.table().delete(backend)?;
        Ok(())
    }
}

/// Implementation of the `DynamicBackendOptions` resource.
#[derive(Debug)]
pub struct BackendBuilder {
    pub(crate) host_override: Option<String>,
    pub(crate) connect_timeout: u32,
    pub(crate) first_byte_timeout: u32,
    pub(crate) between_bytes_timeout: u32,
    pub(crate) use_tls: bool,
    pub(crate) tls_min_version: Option<backend::TlsVersion>,
    pub(crate) tls_max_version: Option<backend::TlsVersion>,
    pub(crate) cert_hostname: Option<String>,
    pub(crate) ca_cert: Option<String>,
    pub(crate) ciphers: Option<String>,
    pub(crate) sni_hostname: Option<String>,
    pub(crate) client_cert: Option<(String, SecretHandle)>,
    pub(crate) keepalive: bool,
    pub(crate) http_keepalive_time_ms: u32,
    pub(crate) tcp_keepalive_enable: u32,
    pub(crate) tcp_keepalive_interval_secs: u32,
    pub(crate) tcp_keepalive_probes: u32,
    pub(crate) tcp_keepalive_time_secs: u32,
    pub(crate) max_connections: u32,
    pub(crate) max_use: Option<NonZeroUsize>,
    pub(crate) max_lifetime: Duration,
    pub(crate) prefer_ipv6: bool,
    pub(crate) grpc: bool,
    pub(crate) pooling: bool,
}

impl Default for BackendBuilder {
    fn default() -> Self {
        BackendBuilder {
            host_override: None,
            connect_timeout: 1_000,
            first_byte_timeout: 15_000,
            between_bytes_timeout: 10_000,
            use_tls: false,
            tls_min_version: None,
            tls_max_version: None,
            cert_hostname: None,
            ca_cert: None,
            ciphers: None,
            sni_hostname: None,
            client_cert: None,
            keepalive: false,
            http_keepalive_time_ms: 0,
            tcp_keepalive_enable: 0,
            tcp_keepalive_interval_secs: 0,
            tcp_keepalive_probes: 0,
            tcp_keepalive_time_secs: 0,
            max_connections: 0,
            max_use: None,
            max_lifetime: Duration::ZERO,
            grpc: false,
            pooling: true,
            prefer_ipv6: true,
        }
    }
}

impl backend::HostDynamicBackendOptions for ComponentCtx {
    fn new(&mut self) -> wasmtime::Result<Resource<backend::DynamicBackendOptions>> {
        let builder = BackendBuilder::default();

        Ok(self.table().push(builder)?)
    }

    fn override_host(&mut self, config: Resource<backend::DynamicBackendOptions>, value: String) {
        self.table().get_mut(&config).unwrap().host_override = Some(value);
    }

    fn connect_timeout(&mut self, config: Resource<backend::DynamicBackendOptions>, value: u32) {
        self.table().get_mut(&config).unwrap().connect_timeout = value;
    }

    fn first_byte_timeout(&mut self, config: Resource<backend::DynamicBackendOptions>, value: u32) {
        self.table().get_mut(&config).unwrap().first_byte_timeout = value;
    }

    fn between_bytes_timeout(
        &mut self,
        config: Resource<backend::DynamicBackendOptions>,
        value: u32,
    ) {
        self.table().get_mut(&config).unwrap().between_bytes_timeout = value;
    }

    fn use_tls(&mut self, config: Resource<backend::DynamicBackendOptions>, value: bool) {
        self.table().get_mut(&config).unwrap().use_tls = value;
    }

    fn tls_min_version(
        &mut self,
        config: Resource<backend::DynamicBackendOptions>,
        value: backend::TlsVersion,
    ) {
        self.table().get_mut(&config).unwrap().tls_min_version = Some(value);
    }

    fn tls_max_version(
        &mut self,
        config: Resource<backend::DynamicBackendOptions>,
        value: backend::TlsVersion,
    ) {
        self.table().get_mut(&config).unwrap().tls_max_version = Some(value);
    }

    fn cert_hostname(&mut self, config: Resource<backend::DynamicBackendOptions>, value: String) {
        self.table().get_mut(&config).unwrap().cert_hostname = Some(value);
    }

    fn ca_certificate(&mut self, config: Resource<backend::DynamicBackendOptions>, value: String) {
        self.table().get_mut(&config).unwrap().ca_cert = Some(value);
    }

    fn tls_ciphers(&mut self, config: Resource<backend::DynamicBackendOptions>, value: String) {
        self.table().get_mut(&config).unwrap().ciphers = Some(value);
    }

    fn sni_hostname(&mut self, config: Resource<backend::DynamicBackendOptions>, value: String) {
        self.table().get_mut(&config).unwrap().sni_hostname = Some(value);
    }

    fn client_cert(
        &mut self,
        config: Resource<backend::DynamicBackendOptions>,
        client_cert: String,
        client_key: Resource<backend::Secret>,
    ) {
        let client_key = SecretHandle::from(client_key);
        self.table().get_mut(&config).unwrap().client_cert = Some((client_cert, client_key));
    }

    fn http_keepalive_time_ms(
        &mut self,
        config: Resource<backend::DynamicBackendOptions>,
        value: u32,
    ) {
        let config = self.table().get_mut(&config).unwrap();
        config.keepalive = true;
        config.http_keepalive_time_ms = value;
    }

    fn tcp_keepalive_enable(
        &mut self,
        config: Resource<backend::DynamicBackendOptions>,
        value: u32,
    ) {
        let config = self.table().get_mut(&config).unwrap();
        config.keepalive = true;
        config.tcp_keepalive_enable = value;
    }

    fn tcp_keepalive_interval_secs(
        &mut self,
        config: Resource<backend::DynamicBackendOptions>,
        value: u32,
    ) {
        let config = self.table().get_mut(&config).unwrap();
        config.keepalive = true;
        config.tcp_keepalive_interval_secs = value;
    }

    fn tcp_keepalive_probes(
        &mut self,
        config: Resource<backend::DynamicBackendOptions>,
        value: u32,
    ) {
        let config = self.table().get_mut(&config).unwrap();
        config.keepalive = true;
        config.tcp_keepalive_probes = value;
    }

    fn tcp_keepalive_time_secs(
        &mut self,
        config: Resource<backend::DynamicBackendOptions>,
        value: u32,
    ) {
        let config = self.table().get_mut(&config).unwrap();
        config.keepalive = true;
        config.tcp_keepalive_time_secs = value;
    }

    fn max_connections(&mut self, config: Resource<backend::DynamicBackendOptions>, value: u32) {
        self.table().get_mut(&config).unwrap().max_connections = value;
    }

    fn max_use(&mut self, config: Resource<backend::DynamicBackendOptions>, value: u32) {
        self.table().get_mut(&config).unwrap().max_use = NonZeroUsize::new(value as _);
    }

    fn max_lifetime_ms(&mut self, config: Resource<backend::DynamicBackendOptions>, value: u32) {
        self.table().get_mut(&config).unwrap().max_lifetime = Duration::from_millis(value as _);
    }

    fn grpc(&mut self, config: Resource<backend::DynamicBackendOptions>, value: bool) {
        self.table().get_mut(&config).unwrap().grpc = value;
    }

    fn pooling(&mut self, config: Resource<backend::DynamicBackendOptions>, value: bool) {
        self.table().get_mut(&config).unwrap().pooling = value;
    }

    fn prefer_ipv6(&mut self, config: Resource<backend::DynamicBackendOptions>, value: bool) {
        self.table().get_mut(&config).unwrap().prefer_ipv6 = value;
    }

    fn drop(&mut self, options: Resource<backend::DynamicBackendOptions>) -> wasmtime::Result<()> {
        self.table().delete(options)?;
        Ok(())
    }
}
