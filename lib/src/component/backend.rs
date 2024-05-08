use {
    super::fastly::compute_at_edge::{backend, http_types, types},
    crate::{error::Error, session::Session},
};

#[async_trait::async_trait]
impl backend::Host for Session {
    async fn exists(&mut self, backend: String) -> Result<bool, types::FastlyError> {
        Ok(self.backend(&backend).is_some())
    }

    async fn is_healthy(
        &mut self,
        backend: String,
    ) -> Result<backend::BackendHealth, types::FastlyError> {
        // just doing this to get a different error if the backend doesn't exist
        let _ = self.backend(&backend).ok_or(Error::InvalidArgument)?;
        Ok(backend::BackendHealth::Unknown)
    }

    async fn is_dynamic(&mut self, backend: String) -> Result<bool, types::FastlyError> {
        if self.dynamic_backend(&backend).is_some() {
            Ok(true)
        } else if self.backend(&backend).is_some() {
            Ok(false)
        } else {
            Err(Error::InvalidArgument.into())
        }
    }

    async fn get_host(&mut self, backend: String) -> Result<String, types::FastlyError> {
        let backend = self.backend(&backend).ok_or(Error::InvalidArgument)?;
        Ok(String::from(
            backend.uri.host().expect("backend uri has host"),
        ))
    }

    async fn get_override_host(
        &mut self,
        backend: String,
    ) -> Result<Option<String>, types::FastlyError> {
        let backend = self.backend(&backend).ok_or(Error::InvalidArgument)?;
        if let Some(host) = backend.override_host.as_ref() {
            let host = host.to_str()?;
            Ok(Some(String::from(host)))
        } else {
            Ok(None)
        }
    }

    async fn get_port(&mut self, backend: String) -> Result<u16, types::FastlyError> {
        let backend = self.backend(&backend).ok_or(Error::InvalidArgument)?;
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

    async fn get_connect_timeout_ms(&mut self, backend: String) -> Result<u32, types::FastlyError> {
        // just doing this to get a different error if the backend doesn't exist
        let _ = self.backend(&backend).ok_or(Error::InvalidArgument)?;
        Err(Error::Unsupported {
            msg: "connection timing is not actually supported in Viceroy",
        }
        .into())
    }

    async fn get_first_byte_timeout_ms(
        &mut self,
        backend: String,
    ) -> Result<u32, types::FastlyError> {
        // just doing this to get a different error if the backend doesn't exist
        let _ = self.backend(&backend).ok_or(Error::InvalidArgument)?;
        Err(Error::Unsupported {
            msg: "connection timing is not actually supported in Viceroy",
        }
        .into())
    }

    async fn get_between_bytes_timeout_ms(
        &mut self,
        backend: String,
    ) -> Result<u32, types::FastlyError> {
        // just doing this to get a different error if the backend doesn't exist
        let _ = self.backend(&backend).ok_or(Error::InvalidArgument)?;
        Err(Error::Unsupported {
            msg: "connection timing is not actually supported in Viceroy",
        }
        .into())
    }

    async fn is_ssl(&mut self, backend: String) -> Result<bool, types::FastlyError> {
        let backend = self.backend(&backend).ok_or(Error::InvalidArgument)?;
        Ok(backend.uri.scheme() == Some(&http::uri::Scheme::HTTPS))
    }

    async fn get_ssl_min_version(
        &mut self,
        backend: String,
    ) -> Result<http_types::TlsVersion, types::FastlyError> {
        // just doing this to get a different error if the backend doesn't exist
        let _ = self.backend(&backend).ok_or(Error::InvalidArgument)?;
        // health checks are not enabled in Viceroy :(
        Err(Error::Unsupported {
            msg: "ssl version flags are not supported in Viceroy",
        }
        .into())
    }

    async fn get_ssl_max_version(
        &mut self,
        backend: String,
    ) -> Result<http_types::TlsVersion, types::FastlyError> {
        // just doing this to get a different error if the backend doesn't exist
        let _ = self.backend(&backend).ok_or(Error::InvalidArgument)?;
        // health checks are not enabled in Viceroy :(
        Err(Error::Unsupported {
            msg: "ssl version flags are not supported in Viceroy",
        }
        .into())
    }
}
