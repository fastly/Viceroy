use {
    super::fastly::api::{backend, http_types, types},
    crate::{error::Error, linking::ComponentCtx},
};

#[async_trait::async_trait]
impl backend::Host for ComponentCtx {
    async fn exists(&mut self, backend: String) -> Result<bool, types::Error> {
        Ok(self.session.backend(&backend).is_some())
    }

    async fn is_healthy(
        &mut self,
        backend: String,
    ) -> Result<backend::BackendHealth, types::Error> {
        // just doing this to get a different error if the backend doesn't exist
        let _ = self
            .session
            .backend(&backend)
            .ok_or(Error::InvalidArgument)?;
        Ok(backend::BackendHealth::Unknown)
    }

    async fn is_dynamic(&mut self, backend: String) -> Result<bool, types::Error> {
        if self.session.dynamic_backend(&backend).is_some() {
            Ok(true)
        } else if self.session.backend(&backend).is_some() {
            Ok(false)
        } else {
            Err(Error::InvalidArgument.into())
        }
    }

    async fn get_host(&mut self, backend: String, max_len: u64) -> Result<String, types::Error> {
        let backend = self
            .session
            .backend(&backend)
            .ok_or(Error::InvalidArgument)?;

        let host = backend.uri.host().expect("backend uri has host");

        if host.len() > usize::try_from(max_len).unwrap() {
            return Err(Error::BufferLengthError {
                buf: "host_out",
                len: "host_max_len",
            }
            .into());
        }

        Ok(String::from(host))
    }

    async fn get_override_host(
        &mut self,
        backend: String,
        max_len: u64,
    ) -> Result<Option<Vec<u8>>, types::Error> {
        let backend = self
            .session
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

    async fn get_port(&mut self, backend: String) -> Result<u16, types::Error> {
        let backend = self
            .session
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

    async fn get_connect_timeout_ms(&mut self, backend: String) -> Result<u32, types::Error> {
        // just doing this to get a different error if the backend doesn't exist
        let _ = self
            .session
            .backend(&backend)
            .ok_or(Error::InvalidArgument)?;
        Err(Error::Unsupported {
            msg: "connection timing is not actually supported in Viceroy",
        }
        .into())
    }

    async fn get_first_byte_timeout_ms(&mut self, backend: String) -> Result<u32, types::Error> {
        // just doing this to get a different error if the backend doesn't exist
        let _ = self
            .session
            .backend(&backend)
            .ok_or(Error::InvalidArgument)?;
        Err(Error::Unsupported {
            msg: "connection timing is not actually supported in Viceroy",
        }
        .into())
    }

    async fn get_between_bytes_timeout_ms(&mut self, backend: String) -> Result<u32, types::Error> {
        // just doing this to get a different error if the backend doesn't exist
        let _ = self
            .session
            .backend(&backend)
            .ok_or(Error::InvalidArgument)?;
        Err(Error::Unsupported {
            msg: "connection timing is not actually supported in Viceroy",
        }
        .into())
    }

    async fn is_tls(&mut self, backend: String) -> Result<bool, types::Error> {
        let backend = self
            .session
            .backend(&backend)
            .ok_or(Error::InvalidArgument)?;
        Ok(backend.uri.scheme() == Some(&http::uri::Scheme::HTTPS))
    }

    async fn get_tls_min_version(
        &mut self,
        backend: String,
    ) -> Result<Option<http_types::TlsVersion>, types::Error> {
        // just doing this to get a different error if the backend doesn't exist
        let _ = self
            .session
            .backend(&backend)
            .ok_or(Error::InvalidArgument)?;
        // health checks are not enabled in Viceroy :(
        Err(Error::Unsupported {
            msg: "ssl version flags are not supported in Viceroy",
        }
        .into())
    }

    async fn get_tls_max_version(
        &mut self,
        backend: String,
    ) -> Result<Option<http_types::TlsVersion>, types::Error> {
        // just doing this to get a different error if the backend doesn't exist
        let _ = self
            .session
            .backend(&backend)
            .ok_or(Error::InvalidArgument)?;
        // health checks are not enabled in Viceroy :(
        Err(Error::Unsupported {
            msg: "ssl version flags are not supported in Viceroy",
        }
        .into())
    }

    async fn get_http_keepalive_time(&mut self, _backend: String) -> Result<u32, types::Error> {
        Err(Error::Unsupported {
            msg: "`get_http_keepalive_time` is not supported in Viceroy",
        }
        .into())
    }

    async fn get_tcp_keepalive_enable(&mut self, _backend: String) -> Result<bool, types::Error> {
        Err(Error::Unsupported {
            msg: "`get_tcp_keepalive_enable` is not supported in Viceroy",
        }
        .into())
    }

    async fn get_tcp_keepalive_interval(&mut self, _backend: String) -> Result<u32, types::Error> {
        Err(Error::Unsupported {
            msg: "`get_tcp_keepalive_interval` is not supported in Viceroy",
        }
        .into())
    }

    async fn get_tcp_keepalive_probes(&mut self, _backend: String) -> Result<u32, types::Error> {
        Err(Error::Unsupported {
            msg: "`get_tcp_keepalive_probes` is not supported in Viceroy",
        }
        .into())
    }

    async fn get_tcp_keepalive_time(&mut self, _backend: String) -> Result<u32, types::Error> {
        Err(Error::Unsupported {
            msg: "`get_tcp_keepalive_time` is not supported in Viceroy",
        }
        .into())
    }
}
