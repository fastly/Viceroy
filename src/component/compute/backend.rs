use std::mem::take;
use std::num::NonZeroUsize;
use std::time::Duration;

use {
    crate::component::bindings::fastly::compute::{backend, http_types, types},
    crate::config::{Backend, ClientCertInfo},
    crate::secret_store::SecretLookup,
    crate::wiggle_abi::types::SecretHandle,
    crate::wiggle_abi::SecretStoreError,
    crate::{
        error::Error,
        linking::{ComponentCtx, SessionView},
    },
    http::HeaderValue,
    http::Uri,
    wasmtime::component::Resource,
    wasmtime_wasi_io::IoView,
};

impl backend::Host for ComponentCtx {
    async fn register_dynamic_backend(
        &mut self,
        prefix: String,
        target: String,
        options: Resource<backend::DynamicBackendOptions>,
    ) -> Result<(), types::Error> {
        let options = take(self.table().get_mut(&options)?);

        let name = prefix.as_str();
        let origin_name = target.as_str();

        let override_host = if let Some(host_override) = options.host_override {
            if host_override.is_empty() {
                return Err(types::Error::InvalidArgument);
            }

            if host_override.len() > 1024 {
                return Err(types::Error::InvalidArgument);
            }

            Some(HeaderValue::from_bytes(host_override.as_bytes())?)
        } else {
            None
        };

        let use_tls = options.use_tls;
        let scheme = if use_tls { "https" } else { "http" };

        let ca_certs = if use_tls {
            if let Some(ca_cert) = options.ca_cert {
                if ca_cert.is_empty() {
                    return Err(types::Error::InvalidArgument);
                }

                if ca_cert.len() > (64 * 1024) {
                    return Err(types::Error::InvalidArgument);
                }

                let mut byte_cursor = std::io::Cursor::new(ca_cert.as_bytes());
                rustls_pemfile::certs(&mut byte_cursor)?
                    .drain(..)
                    .map(rustls::Certificate)
                    .collect()
            } else {
                vec![]
            }
        } else {
            vec![]
        };

        let mut cert_host = if let Some(cert_hostname) = options.cert_hostname {
            if cert_hostname.is_empty() {
                return Err(types::Error::InvalidArgument);
            }

            if cert_hostname.len() > 1024 {
                return Err(types::Error::InvalidArgument);
            }

            Some(cert_hostname)
        } else {
            None
        };

        let use_sni = if let Some(sni_hostname) = options.sni_hostname {
            if sni_hostname.is_empty() {
                false
            } else if sni_hostname.len() > 1024 {
                return Err(types::Error::InvalidArgument);
            } else {
                if let Some(cert_host) = &cert_host {
                    if cert_host != &sni_hostname {
                        // because we're using rustls, we cannot support distinct SNI and cert hostnames
                        return Err(types::Error::InvalidArgument);
                    }
                } else {
                    cert_host = Some(sni_hostname);
                }

                true
            }
        } else {
            true
        };

        let client_cert = if let Some((client_cert, client_key)) = options.client_cert {
            let key_lookup =
                self.session()
                    .secret_lookup(client_key)
                    .ok_or(Error::SecretStoreError(
                        SecretStoreError::InvalidSecretHandle(client_key),
                    ))?;
            let key = match &key_lookup {
                SecretLookup::Standard {
                    store_name,
                    secret_name,
                } => self
                    .session()
                    .secret_stores()
                    .get_store(store_name)
                    .ok_or(Error::SecretStoreError(
                        SecretStoreError::InvalidSecretHandle(client_key),
                    ))?
                    .get_secret(secret_name)
                    .ok_or(Error::SecretStoreError(
                        SecretStoreError::InvalidSecretHandle(client_key),
                    ))?
                    .plaintext(),

                SecretLookup::Injected { plaintext } => plaintext,
            };

            Some(ClientCertInfo::new(client_cert.as_bytes(), key)?)
        } else {
            None
        };

        let grpc = options.grpc;

        let uri = Uri::builder()
            .scheme(scheme)
            .authority(origin_name)
            .path_and_query("/")
            .build()
            .map_err(|_e| types::Error::InvalidArgument)?;

        let new_backend = Backend {
            uri,
            override_host,
            cert_host,
            use_sni,
            grpc,
            client_cert,
            ca_certs,
        };

        if !self.session_mut().add_backend(name, new_backend) {
            return Err(Error::BackendNameRegistryError(name.to_string()).into());
        }

        Ok(())
    }

    fn exists(&mut self, backend: String) -> Result<bool, types::Error> {
        Ok(self.session().backend(&backend).is_some())
    }

    fn is_healthy(&mut self, backend: String) -> Result<backend::BackendHealth, types::Error> {
        // just doing this to get a different error if the backend doesn't exist
        let _ = self
            .session()
            .backend(&backend)
            .ok_or(Error::InvalidArgument)?;
        Ok(backend::BackendHealth::Unknown)
    }

    fn is_dynamic(&mut self, backend: String) -> Result<bool, types::Error> {
        if self.session().dynamic_backend(&backend).is_some() {
            Ok(true)
        } else if self.session().backend(&backend).is_some() {
            Ok(false)
        } else {
            Err(Error::InvalidArgument.into())
        }
    }

    fn get_host(&mut self, backend: String, _max_len: u64) -> Result<String, types::Error> {
        // just doing this to get a different error if the backend doesn't exist
        let _ = self
            .session()
            .backend(&backend)
            .ok_or(Error::InvalidArgument)?;
        Err(Error::Unsupported {
            msg: "`get-host` is not actually supported in Viceroy",
        }
        .into())
    }

    fn get_override_host(
        &mut self,
        backend: String,
        max_len: u64,
    ) -> Result<Option<Vec<u8>>, types::Error> {
        let backend = self
            .session()
            .backend(&backend)
            .ok_or(Error::InvalidArgument)?;
        if let Some(host) = backend.override_host.as_ref() {
            let host = host.to_str()?;

            if host.len() > usize::try_from(max_len).unwrap() {
                return Err(Error::BufferLengthError {
                    buf: "host_out",
                    len: "host_max_len",
                }
                .into());
            }

            Ok(Some(host.as_bytes().to_owned()))
        } else {
            Ok(None)
        }
    }

    fn get_port(&mut self, backend: String) -> Result<u16, types::Error> {
        let backend = self
            .session()
            .backend(&backend)
            .ok_or(Error::InvalidArgument)?;
        match backend.uri.port_u16() {
            Some(port) => Ok(port),
            None => {
                if backend.uri.scheme() == Some(&http::uri::Scheme::HTTPS) {
                    Ok(443)
                } else {
                    Ok(80)
                }
            }
        }
    }

    fn get_connect_timeout_ms(&mut self, backend: String) -> Result<u32, types::Error> {
        // just doing this to get a different error if the backend doesn't exist
        let _ = self
            .session()
            .backend(&backend)
            .ok_or(Error::InvalidArgument)?;
        Err(Error::Unsupported {
            msg: "connection timing is not actually supported in Viceroy",
        }
        .into())
    }

    fn get_first_byte_timeout_ms(&mut self, backend: String) -> Result<u32, types::Error> {
        // just doing this to get a different error if the backend doesn't exist
        let _ = self
            .session()
            .backend(&backend)
            .ok_or(Error::InvalidArgument)?;
        Err(Error::Unsupported {
            msg: "connection timing is not actually supported in Viceroy",
        }
        .into())
    }

    fn get_between_bytes_timeout_ms(&mut self, backend: String) -> Result<u32, types::Error> {
        // just doing this to get a different error if the backend doesn't exist
        let _ = self
            .session()
            .backend(&backend)
            .ok_or(Error::InvalidArgument)?;
        Err(Error::Unsupported {
            msg: "connection timing is not actually supported in Viceroy",
        }
        .into())
    }

    fn is_tls(&mut self, backend: String) -> Result<bool, types::Error> {
        let backend = self
            .session()
            .backend(&backend)
            .ok_or(Error::InvalidArgument)?;
        Ok(backend.uri.scheme() == Some(&http::uri::Scheme::HTTPS))
    }

    fn get_tls_min_version(
        &mut self,
        backend: String,
    ) -> Result<Option<http_types::TlsVersion>, types::Error> {
        // just doing this to get a different error if the backend doesn't exist
        let _ = self
            .session()
            .backend(&backend)
            .ok_or(Error::InvalidArgument)?;
        // health checks are not enabled in Viceroy :(
        Err(Error::Unsupported {
            msg: "tls version flags are not supported in Viceroy",
        }
        .into())
    }

    fn get_tls_max_version(
        &mut self,
        backend: String,
    ) -> Result<Option<http_types::TlsVersion>, types::Error> {
        // just doing this to get a different error if the backend doesn't exist
        let _ = self
            .session()
            .backend(&backend)
            .ok_or(Error::InvalidArgument)?;
        // health checks are not enabled in Viceroy :(
        Err(Error::Unsupported {
            msg: "tls version flags are not supported in Viceroy",
        }
        .into())
    }

    fn get_http_keepalive_time(
        &mut self,
        _backend: String,
    ) -> Result<backend::TimeoutMs, types::Error> {
        Err(Error::Unsupported {
            msg: "backend.get-http-keepalive-time is not supported in Viceroy",
        }
        .into())
    }

    fn get_tcp_keepalive_enable(&mut self, _backend: String) -> Result<bool, types::Error> {
        Err(Error::Unsupported {
            msg: "backend.get-tcp-keepalive-enable is not supported in Viceroy",
        }
        .into())
    }

    fn get_tcp_keepalive_interval(
        &mut self,
        _backend: String,
    ) -> Result<backend::TimeoutSecs, types::Error> {
        Err(Error::Unsupported {
            msg: "backend.get-tcp-keepalive-interval is not supported in Viceroy",
        }
        .into())
    }

    fn get_tcp_keepalive_probes(
        &mut self,
        _backend: String,
    ) -> Result<backend::ProbeCount, types::Error> {
        Err(Error::Unsupported {
            msg: "backend.get-tcp-keepalive-probes is not supported in Viceroy",
        }
        .into())
    }

    fn get_tcp_keepalive_time(
        &mut self,
        _backend: String,
    ) -> Result<backend::TimeoutSecs, types::Error> {
        Err(Error::Unsupported {
            msg: "backend.get_tcp_keepalive_time not supported in Viceroy",
        }
        .into())
    }
}

/// Implementation of the `DynamicBackendOptions` resource.
#[derive(Debug)]
pub struct BackendBuilder {
    host_override: Option<String>,
    connect_timeout: u32,
    first_byte_timeout: u32,
    between_bytes_timeout: u32,
    use_tls: bool,
    tls_min_version: Option<backend::TlsVersion>,
    tls_max_version: Option<backend::TlsVersion>,
    cert_hostname: Option<String>,
    ca_cert: Option<String>,
    ciphers: Option<String>,
    sni_hostname: Option<String>,
    client_cert: Option<(String, SecretHandle)>,
    keepalive: bool,
    http_keepalive_time_ms: u32,
    tcp_keepalive_enable: u32,
    tcp_keepalive_interval_secs: u32,
    tcp_keepalive_probes: u32,
    tcp_keepalive_time_secs: u32,
    max_connections: u32,
    max_use: Option<NonZeroUsize>,
    max_lifetime: Duration,
    prefer_ipv6: bool,
    grpc: bool,
    pooling: bool,
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
