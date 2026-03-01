use {
    crate::component::bindings::fastly::compute::{backend, http_types, types},
    crate::config::{Backend, ClientCertInfo},
    crate::error::Error,
    crate::secret_store::SecretLookup,
    crate::session::Session,
    crate::wiggle_abi::SecretStoreError,
    http::HeaderValue,
    http::Uri,
    std::mem::take,
    wasmtime::component::{Resource, ResourceTable},
};

pub(crate) async fn register_dynamic_backend(
    session: &mut Session,
    table: &mut ResourceTable,
    prefix: String,
    target: String,
    options: Resource<backend::DynamicBackendOptions>,
) -> Result<Resource<String>, types::Error> {
    let options = take(table.get_mut(&options)?);

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
        let key_lookup = session
            .secret_lookup(client_key)
            .ok_or(Error::SecretStoreError(
                SecretStoreError::InvalidSecretHandle(client_key),
            ))?;
        let key = match &key_lookup {
            SecretLookup::Standard {
                store_name,
                secret_name,
            } => session
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
        handler: None,
    };

    if !session.add_backend(name, new_backend) {
        return Err(Error::BackendNameRegistryError(name.to_string()).into());
    }

    let res = table.push(prefix)?;

    Ok(res)
}

pub(crate) fn exists(session: &mut Session, backend: &str) -> bool {
    session.backend(backend).is_some()
}

pub(crate) fn is_healthy(
    session: &mut Session,
    backend: &str,
) -> Result<backend::BackendHealth, types::Error> {
    // just doing this to get a different error if the backend doesn't exist
    let _ = session.backend(backend).ok_or(Error::InvalidArgument)?;
    Ok(backend::BackendHealth::Unknown)
}

pub(crate) fn is_dynamic(session: &mut Session, backend: &str) -> Result<bool, types::Error> {
    if session.dynamic_backend(backend).is_some() {
        Ok(true)
    } else if session.backend(backend).is_some() {
        Ok(false)
    } else {
        Err(Error::InvalidArgument.into())
    }
}

pub(crate) fn get_host(
    session: &mut Session,
    backend: &str,
    _max_len: u64,
) -> Result<String, types::Error> {
    // just doing this to get a different error if the backend doesn't exist
    let _ = session.backend(backend).ok_or(Error::InvalidArgument)?;
    Err(Error::Unsupported {
        msg: "`get-host` is not actually supported in Viceroy",
    }
    .into())
}

pub(crate) fn get_override_host(
    session: &mut Session,
    backend: &str,
    max_len: u64,
) -> Result<Option<Vec<u8>>, types::Error> {
    let backend = session.backend(backend).ok_or(Error::InvalidArgument)?;
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

pub(crate) fn get_port(session: &mut Session, backend: &str) -> Result<u16, types::Error> {
    let backend = session.backend(backend).ok_or(Error::InvalidArgument)?;
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

pub(crate) fn get_connect_timeout_ms(
    session: &mut Session,
    backend: &str,
) -> Result<u32, types::Error> {
    // just doing this to get a different error if the backend doesn't exist
    let _ = session.backend(backend).ok_or(Error::InvalidArgument)?;
    Err(Error::Unsupported {
        msg: "connection timing is not actually supported in Viceroy",
    }
    .into())
}

pub(crate) fn get_first_byte_timeout_ms(
    session: &mut Session,
    backend: &str,
) -> Result<u32, types::Error> {
    // just doing this to get a different error if the backend doesn't exist
    let _ = session.backend(backend).ok_or(Error::InvalidArgument)?;
    Err(Error::Unsupported {
        msg: "connection timing is not actually supported in Viceroy",
    }
    .into())
}

pub(crate) fn get_between_bytes_timeout_ms(
    session: &mut Session,
    backend: &str,
) -> Result<u32, types::Error> {
    // just doing this to get a different error if the backend doesn't exist
    let _ = session.backend(backend).ok_or(Error::InvalidArgument)?;
    Err(Error::Unsupported {
        msg: "connection timing is not actually supported in Viceroy",
    }
    .into())
}

pub(crate) fn is_tls(session: &mut Session, backend: &str) -> Result<bool, types::Error> {
    let backend = session.backend(backend).ok_or(Error::InvalidArgument)?;
    Ok(backend.uri.scheme() == Some(&http::uri::Scheme::HTTPS))
}

pub(crate) fn get_tls_min_version(
    session: &mut Session,
    backend: &str,
) -> Result<Option<http_types::TlsVersion>, types::Error> {
    // just doing this to get a different error if the backend doesn't exist
    let _ = session.backend(backend).ok_or(Error::InvalidArgument)?;
    // health checks are not enabled in Viceroy :(
    Err(Error::Unsupported {
        msg: "tls version flags are not supported in Viceroy",
    }
    .into())
}

pub(crate) fn get_tls_max_version(
    session: &mut Session,
    backend: &str,
) -> Result<Option<http_types::TlsVersion>, types::Error> {
    // just doing this to get a different error if the backend doesn't exist
    let _ = session.backend(backend).ok_or(Error::InvalidArgument)?;
    // health checks are not enabled in Viceroy :(
    Err(Error::Unsupported {
        msg: "tls version flags are not supported in Viceroy",
    }
    .into())
}

pub(crate) fn get_http_keepalive_time(
    _session: &mut Session,
    _backend: &str,
) -> Result<backend::TimeoutMs, types::Error> {
    Err(Error::Unsupported {
        msg: "backend.get-http-keepalive-time is not supported in Viceroy",
    }
    .into())
}

pub(crate) fn get_tcp_keepalive_enable(
    _session: &mut Session,
    _backend: &str,
) -> Result<bool, types::Error> {
    Err(Error::Unsupported {
        msg: "backend.get-tcp-keepalive-enable is not supported in Viceroy",
    }
    .into())
}

pub(crate) fn get_tcp_keepalive_interval(
    _session: &mut Session,
    _backend: &str,
) -> Result<backend::TimeoutSecs, types::Error> {
    Err(Error::Unsupported {
        msg: "backend.get-tcp-keepalive-interval is not supported in Viceroy",
    }
    .into())
}

pub(crate) fn get_tcp_keepalive_probes(
    _session: &mut Session,
    _backend: &str,
) -> Result<backend::ProbeCount, types::Error> {
    Err(Error::Unsupported {
        msg: "backend.get-tcp-keepalive-probes is not supported in Viceroy",
    }
    .into())
}

pub(crate) fn get_tcp_keepalive_time(
    _session: &mut Session,
    _backend: &str,
) -> Result<backend::TimeoutSecs, types::Error> {
    Err(Error::Unsupported {
        msg: "backend.get_tcp_keepalive_time not supported in Viceroy",
    }
    .into())
}
