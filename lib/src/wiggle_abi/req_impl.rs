//! fastly_req` hostcall implementations.

use super::types::SendErrorDetail;
use super::SecretStoreError;
use crate::config::ClientCertInfo;
use crate::secret_store::SecretLookup;

use {
    crate::{
        config::Backend,
        error::Error,
        session::{AsyncItem, PeekableTask, Session, ViceroyRequestMetadata},
        upstream,
        wiggle_abi::{
            fastly_http_req::FastlyHttpReq,
            headers::HttpHeaders,
            types::{
                BackendConfigOptions, BodyHandle, CacheOverrideTag, ClientCertVerifyResult,
                ContentEncodings, DynamicBackendConfig, FramingHeadersMode, HttpVersion,
                MultiValueCursor, MultiValueCursorResult, PendingRequestHandle, RequestHandle,
                ResponseHandle,
            },
        },
    },
    fastly_shared::{INVALID_BODY_HANDLE, INVALID_REQUEST_HANDLE, INVALID_RESPONSE_HANDLE},
    http::{HeaderValue, Method, Uri},
    hyper::http::request::Request,
    std::net::IpAddr,
    wiggle::{GuestMemory, GuestPtr},
};

#[wiggle::async_trait]
impl FastlyHttpReq for Session {
    fn body_downstream_get(
        &mut self,
        _memory: &mut GuestMemory<'_>,
    ) -> Result<(RequestHandle, BodyHandle), Error> {
        let req_handle = self.downstream_request();
        let body_handle = self.downstream_request_body();
        Ok((req_handle, body_handle))
    }

    #[allow(unused_variables)] // FIXME KTM 2020-06-25: Remove this directive once implemented.
    fn cache_override_set(
        &mut self,
        memory: &mut GuestMemory<'_>,
        req_handle: RequestHandle,
        tag: CacheOverrideTag,
        ttl: u32,
        stale_while_revalidate: u32,
    ) -> Result<(), Error> {
        // For now, we ignore caching directives because we never cache anything
        Ok(())
    }

    #[allow(unused_variables)] // FIXME KTM 2020-06-25: Remove this directive once implemented.
    fn cache_override_v2_set(
        &mut self,
        memory: &mut GuestMemory<'_>,
        req_handle: RequestHandle,
        tag: CacheOverrideTag,
        ttl: u32,
        stale_while_revalidate: u32,
        sk: GuestPtr<[u8]>,
    ) -> Result<(), Error> {
        // For now, we ignore caching directives because we never cache anything
        Ok(())
    }

    fn downstream_server_ip_addr(
        &mut self,
        memory: &mut GuestMemory<'_>,
        // Must be a 16-byte array:
        addr_octets_ptr: GuestPtr<u8>,
    ) -> Result<u32, Error> {
        match self.downstream_server_ip() {
            IpAddr::V4(addr) => {
                let octets = addr.octets();
                let octets_bytes = octets.len() as u32;
                debug_assert_eq!(octets_bytes, 4);
                memory.copy_from_slice(&octets, addr_octets_ptr.as_array(octets_bytes))?;
                Ok(octets_bytes)
            }
            IpAddr::V6(addr) => {
                let octets = addr.octets();
                let octets_bytes = octets.len() as u32;
                debug_assert_eq!(octets_bytes, 16);
                memory.copy_from_slice(&octets, addr_octets_ptr.as_array(octets_bytes))?;
                Ok(octets_bytes)
            }
        }
    }

    fn downstream_client_ip_addr(
        &mut self,
        memory: &mut GuestMemory<'_>,
        // Must be a 16-byte array:
        addr_octets_ptr: GuestPtr<u8>,
    ) -> Result<u32, Error> {
        match self.downstream_client_ip() {
            IpAddr::V4(addr) => {
                let octets = addr.octets();
                let octets_bytes = octets.len() as u32;
                debug_assert_eq!(octets_bytes, 4);
                memory.copy_from_slice(&octets, addr_octets_ptr.as_array(octets_bytes))?;
                Ok(octets_bytes)
            }
            IpAddr::V6(addr) => {
                let octets = addr.octets();
                let octets_bytes = octets.len() as u32;
                debug_assert_eq!(octets_bytes, 16);
                memory.copy_from_slice(&octets, addr_octets_ptr.as_array(octets_bytes))?;
                Ok(octets_bytes)
            }
        }
    }

    #[allow(unused_variables)] // FIXME JDC 2023-06-18: Remove this directive once implemented.
    fn downstream_client_h2_fingerprint(
        &mut self,
        memory: &mut GuestMemory<'_>,
        h2fp_out: GuestPtr<u8>,
        h2fp_max_len: u32,
        nwritten_out: GuestPtr<u32>,
    ) -> Result<(), Error> {
        Err(Error::NotAvailable("Client H2 fingerprint"))
    }

    fn downstream_client_request_id(
        &mut self,
        memory: &mut GuestMemory<'_>,
        reqid_out: GuestPtr<u8>,
        reqid_max_len: u32,
        nwritten_out: GuestPtr<u32>,
    ) -> Result<(), Error> {
        let reqid_bytes = format!("{:032x}", self.req_id()).into_bytes();

        if reqid_bytes.len() > reqid_max_len as usize {
            // Write out the number of bytes necessary to fit the value, or zero on overflow to
            // signal an error condition.
            memory.write(nwritten_out, reqid_bytes.len().try_into().unwrap_or(0))?;
            return Err(Error::BufferLengthError {
                buf: "reqid_out",
                len: "reqid_max_len",
            });
        }

        let reqid_len =
            u32::try_from(reqid_bytes.len()).expect("smaller u32::MAX means it must fit");

        memory.copy_from_slice(&reqid_bytes, reqid_out.as_array(reqid_len))?;
        memory.write(nwritten_out, reqid_len)?;
        Ok(())
    }

    fn downstream_client_oh_fingerprint(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        _ohfp_out: GuestPtr<u8>,
        _ohfp_max_len: u32,
        _nwritten_out: GuestPtr<u32>,
    ) -> Result<(), Error> {
        Err(Error::NotAvailable("Client original header fingerprint"))
    }

    fn downstream_tls_cipher_openssl_name(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        _cipher_out: GuestPtr<u8>,
        _cipher_max_len: u32,
        _nwritten_out: GuestPtr<u32>,
    ) -> Result<(), Error> {
        // FIXME JDC 2023-09-27: For now, we don't support incoming TLS connections, this function currently only implements the solution for non-tls connections.
        Err(Error::ValueAbsent)
    }

    #[allow(unused_variables)] // FIXME ACF 2022-05-03: Remove this directive once implemented.
    fn upgrade_websocket(
        &mut self,
        memory: &mut GuestMemory<'_>,
        backend_name: GuestPtr<str>,
    ) -> Result<(), Error> {
        Err(Error::NotAvailable("WebSocket upgrade"))
    }

    #[allow(unused_variables)] // FIXME ACF 2022-10-03: Remove this directive once implemented.
    fn redirect_to_websocket_proxy(
        &mut self,
        memory: &mut GuestMemory<'_>,
        backend_name: GuestPtr<str>,
    ) -> Result<(), Error> {
        Err(Error::NotAvailable("Redirect to WebSocket proxy"))
    }

    #[allow(unused_variables)] // FIXME ACF 2022-10-03: Remove this directive once implemented.
    fn redirect_to_grip_proxy(
        &mut self,
        memory: &mut GuestMemory<'_>,
        backend_name: GuestPtr<str>,
    ) -> Result<(), Error> {
        Err(Error::NotAvailable("Redirect to Fanout/GRIP proxy"))
    }

    fn redirect_to_websocket_proxy_v2(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        _req_handle: RequestHandle,
        _backend: GuestPtr<str>,
    ) -> Result<(), Error> {
        Err(Error::NotAvailable("Redirect to WebSocket proxy"))
    }

    fn redirect_to_grip_proxy_v2(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        _req_handle: RequestHandle,
        _backend: GuestPtr<str>,
    ) -> Result<(), Error> {
        Err(Error::NotAvailable("Redirect to Fanout/GRIP proxy"))
    }

    fn downstream_tls_protocol(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        _protocol_out: GuestPtr<u8>,
        _protocol_max_len: u32,
        _nwritten_out: GuestPtr<u32>,
    ) -> Result<(), Error> {
        // FIXME JDC 2023-09-27: For now, we don't support incoming TLS connections, this function currently only implements the solution for non-tls connections.
        Err(Error::ValueAbsent)
    }

    #[allow(unused_variables)] // FIXME KTM 2020-06-25: Remove this directive once implemented.
    fn downstream_tls_client_hello(
        &mut self,
        memory: &mut GuestMemory<'_>,
        chello_out: GuestPtr<u8>,
        chello_max_len: u32,
        nwritten_out: GuestPtr<u32>,
    ) -> Result<(), Error> {
        // FIXME JDC 2023-09-27: For now, we don't support incoming TLS connections, this function currently only implements the solution for non-tls connections.
        Err(Error::ValueAbsent)
    }

    fn downstream_tls_raw_client_certificate(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        _tokio_rustlsraw_client_cert_out: GuestPtr<u8>,
        _raw_client_cert_max_len: u32,
        _nwritten_out: GuestPtr<u32>,
    ) -> Result<(), Error> {
        // FIXME JDC 2023-09-27: For now, we don't support incoming TLS connections, this function currently only implements the solution for non-tls connections.
        Err(Error::ValueAbsent)
    }

    fn downstream_tls_client_cert_verify_result(
        &mut self,
        _memory: &mut GuestMemory<'_>,
    ) -> Result<ClientCertVerifyResult, Error> {
        // FIXME JDC 2023-09-27: For now, we don't support incoming TLS connections, this function currently only implements the solution for non-tls connections.
        Err(Error::ValueAbsent)
    }

    fn downstream_tls_ja3_md5(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        _ja3_md5_out: GuestPtr<u8>,
    ) -> Result<u32, Error> {
        // FIXME JDC 2023-09-27: For now, we don't support incoming TLS connections, this function currently only implements the solution for non-tls connections.
        Err(Error::ValueAbsent)
    }

    #[allow(unused_variables)] // FIXME UFSM 2024-02-19: Remove this directive once implemented.
    fn downstream_tls_ja4(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        ja4_out: GuestPtr<u8>,
        ja4_max_len: u32,
        nwritten_out: GuestPtr<u32>,
    ) -> Result<(), Error> {
        Err(Error::NotAvailable("Client TLS JA4 hash"))
    }

    fn framing_headers_mode_set(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        _h: RequestHandle,
        mode: FramingHeadersMode,
    ) -> Result<(), Error> {
        match mode {
            FramingHeadersMode::ManuallyFromHeaders => {
                Err(Error::NotAvailable("Manual framing headers"))
            }
            FramingHeadersMode::Automatic => Ok(()),
        }
    }

    fn register_dynamic_backend(
        &mut self,
        memory: &mut GuestMemory<'_>,
        name: GuestPtr<str>,
        upstream_dynamic: GuestPtr<str>,
        backend_info_mask: BackendConfigOptions,
        backend_info: GuestPtr<DynamicBackendConfig>,
    ) -> Result<(), Error> {
        let name = {
            let name_slice = memory.to_vec(name.as_bytes())?;
            String::from_utf8(name_slice).map_err(|_| Error::InvalidArgument)?
        };
        let origin_name = {
            let origin_name_slice = memory.to_vec(upstream_dynamic.as_bytes())?;
            String::from_utf8(origin_name_slice).map_err(|_| Error::InvalidArgument)?
        };
        let config = memory.read(backend_info)?;

        // If someone set our reserved bit, error. We might need it, and we don't
        // want anyone it early.
        if backend_info_mask.contains(BackendConfigOptions::RESERVED) {
            return Err(Error::InvalidArgument);
        }

        // If someone has set any bits we don't know about, let's also return false,
        // as there's either bad data or an API compatibility problem.
        if backend_info_mask != BackendConfigOptions::from_bits_truncate(backend_info_mask.bits()) {
            return Err(Error::InvalidArgument);
        }

        let override_host = if backend_info_mask.contains(BackendConfigOptions::HOST_OVERRIDE) {
            if config.host_override_len == 0 {
                return Err(Error::InvalidArgument);
            }

            if config.host_override_len > 1024 {
                return Err(Error::InvalidArgument);
            }

            let byte_slice =
                memory.to_vec(config.host_override.as_array(config.host_override_len))?;

            let string = String::from_utf8(byte_slice).map_err(|_| Error::InvalidArgument)?;

            Some(HeaderValue::from_str(&string)?)
        } else {
            None
        };

        let scheme = if backend_info_mask.contains(BackendConfigOptions::USE_SSL) {
            "https"
        } else {
            "http"
        };

        let ca_certs =
            if (scheme == "https") && backend_info_mask.contains(BackendConfigOptions::CA_CERT) {
                if config.ca_cert_len == 0 {
                    return Err(Error::InvalidArgument);
                }

                if config.ca_cert_len > (64 * 1024) {
                    return Err(Error::InvalidArgument);
                }

                let byte_slice = memory
                    .as_slice(config.ca_cert.as_array(config.ca_cert_len))?
                    .ok_or(Error::SharedMemory)?;
                let mut byte_cursor = std::io::Cursor::new(&byte_slice[..]);
                rustls_pemfile::certs(&mut byte_cursor)?
                    .drain(..)
                    .map(rustls::Certificate)
                    .collect()
            } else {
                vec![]
            };

        let mut cert_host = if backend_info_mask.contains(BackendConfigOptions::CERT_HOSTNAME) {
            if config.cert_hostname_len == 0 {
                return Err(Error::InvalidArgument);
            }

            if config.cert_hostname_len > 1024 {
                return Err(Error::InvalidArgument);
            }

            let byte_slice = memory
                .as_slice(config.cert_hostname.as_array(config.cert_hostname_len))?
                .ok_or(Error::SharedMemory)?;

            Some(std::str::from_utf8(&byte_slice)?.to_owned())
        } else {
            None
        };

        let use_sni = if backend_info_mask.contains(BackendConfigOptions::SNI_HOSTNAME) {
            if config.sni_hostname_len == 0 {
                false
            } else if config.sni_hostname_len > 1024 {
                return Err(Error::InvalidArgument);
            } else {
                let byte_slice = memory
                    .as_slice(config.sni_hostname.as_array(config.sni_hostname_len))?
                    .ok_or(Error::SharedMemory)?;
                let sni_hostname = std::str::from_utf8(&byte_slice)?;
                if let Some(cert_host) = &cert_host {
                    if cert_host != sni_hostname {
                        // because we're using rustls, we cannot support distinct SNI and cert hostnames
                        return Err(Error::InvalidArgument);
                    }
                } else {
                    cert_host = Some(sni_hostname.to_owned())
                }

                true
            }
        } else {
            true
        };

        let client_cert = if backend_info_mask.contains(BackendConfigOptions::CLIENT_CERT) {
            let cert_slice = memory
                .as_slice(
                    config
                        .client_certificate
                        .as_array(config.client_certificate_len),
                )?
                .ok_or(Error::SharedMemory)?;
            let key_lookup =
                self.secret_lookup(config.client_key)
                    .ok_or(Error::SecretStoreError(
                        SecretStoreError::InvalidSecretHandle(config.client_key),
                    ))?;
            let key = match &key_lookup {
                SecretLookup::Standard {
                    store_name,
                    secret_name,
                } => self
                    .secret_stores()
                    .get_store(store_name)
                    .ok_or(Error::SecretStoreError(
                        SecretStoreError::InvalidSecretHandle(config.client_key),
                    ))?
                    .get_secret(secret_name)
                    .ok_or(Error::SecretStoreError(
                        SecretStoreError::InvalidSecretHandle(config.client_key),
                    ))?
                    .plaintext(),

                SecretLookup::Injected { plaintext } => plaintext,
            };

            Some(ClientCertInfo::new(&cert_slice, key)?)
        } else {
            None
        };

        let grpc = backend_info_mask.contains(BackendConfigOptions::GRPC);

        let new_backend = Backend {
            uri: Uri::builder()
                .scheme(scheme)
                .authority(origin_name)
                .path_and_query("/")
                .build()?,
            override_host,
            cert_host,
            use_sni,
            grpc,
            client_cert,
            ca_certs,
        };

        if !self.add_backend(&name, new_backend) {
            return Err(Error::BackendNameRegistryError(name));
        }

        Ok(())
    }

    fn new(&mut self, _memory: &mut GuestMemory<'_>) -> Result<RequestHandle, Error> {
        let (parts, _) = Request::new(()).into_parts();
        Ok(self.insert_request_parts(parts))
    }

    fn header_names_get(
        &mut self,
        memory: &mut GuestMemory<'_>,
        req_handle: RequestHandle,
        buf: GuestPtr<u8>,
        buf_len: u32,
        cursor: MultiValueCursor,
        ending_cursor_out: GuestPtr<MultiValueCursorResult>,
        nwritten_out: GuestPtr<u32>,
    ) -> Result<(), Error> {
        let headers = &self.request_parts(req_handle)?.headers;
        multi_value_result!(
            memory,
            headers.names_get(memory, buf, buf_len, cursor, nwritten_out),
            ending_cursor_out
        )
    }

    fn original_header_names_get(
        &mut self,
        memory: &mut GuestMemory<'_>,
        buf: GuestPtr<u8>,
        buf_len: u32,
        cursor: MultiValueCursor,
        ending_cursor_out: GuestPtr<MultiValueCursorResult>,
        nwritten_out: GuestPtr<u32>,
    ) -> Result<(), Error> {
        let headers = self.downstream_original_headers();
        multi_value_result!(
            memory,
            headers.names_get(memory, buf, buf_len, cursor, nwritten_out),
            ending_cursor_out
        )
    }

    fn original_header_count(&mut self, _memory: &mut GuestMemory<'_>) -> Result<u32, Error> {
        let headers = self.downstream_original_headers();
        Ok(headers
            .len()
            .try_into()
            .expect("More than u32::MAX headers"))
    }

    fn header_value_get(
        &mut self,
        memory: &mut GuestMemory<'_>,
        req_handle: RequestHandle,
        name: GuestPtr<[u8]>,
        value: GuestPtr<u8>,
        value_max_len: u32,
        nwritten_out: GuestPtr<u32>,
    ) -> Result<(), Error> {
        let headers = &self.request_parts(req_handle)?.headers;
        headers.value_get(memory, name, value, value_max_len, nwritten_out)
    }

    fn header_values_get(
        &mut self,
        memory: &mut GuestMemory<'_>,
        req_handle: RequestHandle,
        name: GuestPtr<[u8]>,
        buf: GuestPtr<u8>,
        buf_len: u32,
        cursor: MultiValueCursor,
        ending_cursor_out: GuestPtr<MultiValueCursorResult>,
        nwritten_out: GuestPtr<u32>,
    ) -> Result<(), Error> {
        let headers = &self.request_parts(req_handle)?.headers;
        multi_value_result!(
            memory,
            headers.values_get(memory, name, buf, buf_len, cursor, nwritten_out),
            ending_cursor_out
        )
    }

    fn header_values_set(
        &mut self,
        memory: &mut GuestMemory<'_>,
        req_handle: RequestHandle,
        name: GuestPtr<[u8]>,
        values: GuestPtr<[u8]>,
    ) -> Result<(), Error> {
        let headers = &mut self.request_parts_mut(req_handle)?.headers;
        headers.values_set(memory, name, values)
    }

    fn header_insert(
        &mut self,
        memory: &mut GuestMemory<'_>,
        req_handle: RequestHandle,
        name: GuestPtr<[u8]>,
        value: GuestPtr<[u8]>,
    ) -> Result<(), Error> {
        let headers = &mut self.request_parts_mut(req_handle)?.headers;
        HttpHeaders::insert(headers, memory, name, value)
    }

    fn header_append(
        &mut self,
        memory: &mut GuestMemory<'_>,
        req_handle: RequestHandle,
        name: GuestPtr<[u8]>,
        value: GuestPtr<[u8]>,
    ) -> Result<(), Error> {
        let headers = &mut self.request_parts_mut(req_handle)?.headers;
        HttpHeaders::append(headers, memory, name, value)
    }

    fn header_remove(
        &mut self,
        memory: &mut GuestMemory<'_>,
        req_handle: RequestHandle,
        name: GuestPtr<[u8]>,
    ) -> Result<(), Error> {
        let headers = &mut self.request_parts_mut(req_handle)?.headers;
        HttpHeaders::remove(headers, memory, name)
    }

    fn method_get(
        &mut self,
        memory: &mut GuestMemory<'_>,
        req_handle: RequestHandle,
        buf: GuestPtr<u8>,
        buf_len: u32,
        nwritten_out: GuestPtr<u32>,
    ) -> Result<(), Error> {
        let req = self.request_parts(req_handle)?;
        let req_method = &req.method;
        let req_method_bytes = req_method.to_string().into_bytes();

        if req_method_bytes.len() > buf_len as usize {
            // Write out the number of bytes necessary to fit this method, or zero on overflow to
            // signal an error condition.
            memory.write(nwritten_out, req_method_bytes.len().try_into().unwrap_or(0))?;
            return Err(Error::BufferLengthError {
                buf: "method",
                len: "method_max_len",
            });
        }

        let req_method_len = u32::try_from(req_method_bytes.len())
            .expect("smaller than method_max_len means it must fit");

        memory.copy_from_slice(&req_method_bytes, buf.as_array(req_method_len))?;
        memory.write(nwritten_out, req_method_len)?;

        Ok(())
    }

    fn method_set(
        &mut self,
        memory: &mut GuestMemory<'_>,
        req_handle: RequestHandle,
        method: GuestPtr<str>,
    ) -> Result<(), Error> {
        let method_ref = &mut self.request_parts_mut(req_handle)?.method;
        let method_slice = memory
            .as_slice(method.as_bytes())?
            .ok_or(Error::SharedMemory)?;
        *method_ref = Method::from_bytes(method_slice)?;

        Ok(())
    }

    fn uri_get(
        &mut self,
        memory: &mut GuestMemory<'_>,
        req_handle: RequestHandle,
        buf: GuestPtr<u8>,
        buf_len: u32,
        nwritten_out: GuestPtr<u32>,
    ) -> Result<(), Error> {
        let req = self.request_parts(req_handle)?;
        let req_uri_bytes = req.uri.to_string().into_bytes();

        if req_uri_bytes.len() > buf_len as usize {
            // Write out the number of bytes necessary to fit this method, or zero on overflow to
            // signal an error condition.
            memory.write(nwritten_out, req_uri_bytes.len().try_into().unwrap_or(0))?;
            return Err(Error::BufferLengthError {
                buf: "uri",
                len: "uri_max_len",
            });
        }
        let req_uri_len =
            u32::try_from(req_uri_bytes.len()).expect("smaller than uri_max_len means it must fit");

        memory.copy_from_slice(&req_uri_bytes, buf.as_array(req_uri_len))?;
        memory.write(nwritten_out, req_uri_len)?;

        Ok(())
    }

    fn uri_set(
        &mut self,
        memory: &mut GuestMemory<'_>,
        req_handle: RequestHandle,
        uri: GuestPtr<str>,
    ) -> Result<(), Error> {
        let uri_ref = &mut self.request_parts_mut(req_handle)?.uri;
        let req_uri_bytes = memory
            .as_slice(uri.as_bytes())?
            .ok_or(Error::SharedMemory)?;

        *uri_ref = Uri::try_from(req_uri_bytes)?;
        Ok(())
    }

    fn version_get(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        req_handle: RequestHandle,
    ) -> Result<HttpVersion, Error> {
        let req = self.request_parts(req_handle)?;
        HttpVersion::try_from(req.version).map_err(|msg| Error::Unsupported { msg })
    }

    fn version_set(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        req_handle: RequestHandle,
        version: HttpVersion,
    ) -> Result<(), Error> {
        let req = self.request_parts_mut(req_handle)?;

        let version = hyper::Version::try_from(version)?;
        req.version = version;
        Ok(())
    }

    async fn send(
        &mut self,
        memory: &mut GuestMemory<'_>,
        req_handle: RequestHandle,
        body_handle: BodyHandle,
        backend_bytes: GuestPtr<str>,
    ) -> Result<(ResponseHandle, BodyHandle), Error> {
        let backend_bytes_slice = memory
            .as_slice(backend_bytes.as_bytes())?
            .ok_or(Error::SharedMemory)?;
        let backend_name = std::str::from_utf8(&backend_bytes_slice)?;

        // prepare the request
        let req_parts = self.take_request_parts(req_handle)?;
        let req_body = self.take_body(body_handle)?;
        let req = Request::from_parts(req_parts, req_body);
        let backend = self
            .backend(backend_name)
            .ok_or_else(|| Error::UnknownBackend(backend_name.to_owned()))?;

        // synchronously send the request
        let resp = upstream::send_request(req, backend, self.tls_config()).await?;
        Ok(self.insert_response(resp))
    }

    async fn send_v2(
        &mut self,
        memory: &mut GuestMemory<'_>,
        req_handle: RequestHandle,
        body_handle: BodyHandle,
        backend_bytes: GuestPtr<str>,
        _error_detail: GuestPtr<SendErrorDetail>,
    ) -> Result<(ResponseHandle, BodyHandle), Error> {
        // This initial implementation ignores the error detail field
        self.send(memory, req_handle, body_handle, backend_bytes)
            .await
    }

    async fn send_async(
        &mut self,
        memory: &mut GuestMemory<'_>,
        req_handle: RequestHandle,
        body_handle: BodyHandle,
        backend_bytes: GuestPtr<str>,
    ) -> Result<PendingRequestHandle, Error> {
        let backend_bytes_slice = memory
            .as_slice(backend_bytes.as_bytes())?
            .ok_or(Error::SharedMemory)?;
        let backend_name = std::str::from_utf8(&backend_bytes_slice)?;

        // prepare the request
        let req_parts = self.take_request_parts(req_handle)?;
        let req_body = self.take_body(body_handle)?;
        let req = Request::from_parts(req_parts, req_body);
        let backend = self
            .backend(backend_name)
            .ok_or_else(|| Error::UnknownBackend(backend_name.to_owned()))?;

        // asynchronously send the request
        let task =
            PeekableTask::spawn(upstream::send_request(req, backend, self.tls_config())).await;

        // return a handle to the pending task
        Ok(self.insert_pending_request(task))
    }

    async fn send_async_streaming(
        &mut self,
        memory: &mut GuestMemory<'_>,
        req_handle: RequestHandle,
        body_handle: BodyHandle,
        backend_bytes: GuestPtr<str>,
    ) -> Result<PendingRequestHandle, Error> {
        let backend_bytes_slice = memory
            .as_slice(backend_bytes.as_bytes())?
            .ok_or(Error::SharedMemory)?;
        let backend_name = std::str::from_utf8(backend_bytes_slice)?;

        // prepare the request
        let req_parts = self.take_request_parts(req_handle)?;
        let req_body = self.begin_streaming(body_handle)?;
        let req = Request::from_parts(req_parts, req_body);
        let backend = self
            .backend(backend_name)
            .ok_or_else(|| Error::UnknownBackend(backend_name.to_owned()))?;

        // asynchronously send the request
        let task =
            PeekableTask::spawn(upstream::send_request(req, backend, self.tls_config())).await;

        // return a handle to the pending task
        Ok(self.insert_pending_request(task))
    }

    // note: The first value in the return tuple represents whether the request is done: 0 when not
    // done, 1 when done.
    async fn pending_req_poll(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        pending_req_handle: PendingRequestHandle,
    ) -> Result<(u32, ResponseHandle, BodyHandle), Error> {
        if self.async_item_mut(pending_req_handle.into())?.is_ready() {
            let resp = self
                .take_pending_request(pending_req_handle)?
                .recv()
                .await?;
            let (resp_handle, resp_body_handle) = self.insert_response(resp);
            Ok((1, resp_handle, resp_body_handle))
        } else {
            Ok((0, INVALID_REQUEST_HANDLE.into(), INVALID_BODY_HANDLE.into()))
        }
    }

    async fn pending_req_poll_v2(
        &mut self,
        memory: &mut GuestMemory<'_>,
        pending_req_handle: PendingRequestHandle,
        _error_detail: GuestPtr<SendErrorDetail>,
    ) -> Result<(u32, ResponseHandle, BodyHandle), Error> {
        // This initial implementation ignores the error detail field
        self.pending_req_poll(memory, pending_req_handle).await
    }

    async fn pending_req_wait(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        pending_req_handle: PendingRequestHandle,
    ) -> Result<(ResponseHandle, BodyHandle), Error> {
        let pending_req = self
            .take_pending_request(pending_req_handle)?
            .recv()
            .await?;
        Ok(self.insert_response(pending_req))
    }

    async fn pending_req_wait_v2(
        &mut self,
        memory: &mut GuestMemory<'_>,
        pending_req_handle: PendingRequestHandle,
        _error_detail: GuestPtr<SendErrorDetail>,
    ) -> Result<(ResponseHandle, BodyHandle), Error> {
        // This initial implementation ignores the error detail field
        self.pending_req_wait(memory, pending_req_handle).await
    }

    // First element of return tuple is the "done index"
    async fn pending_req_select(
        &mut self,
        memory: &mut GuestMemory<'_>,
        pending_req_handles: GuestPtr<[PendingRequestHandle]>,
    ) -> Result<(u32, ResponseHandle, BodyHandle), Error> {
        if pending_req_handles.len() == 0 {
            return Err(Error::InvalidArgument);
        }
        let pending_req_handles = pending_req_handles.cast::<[u32]>();

        // perform the select operation
        let done_index = self
            .select_impl(
                memory
                    // TODO: `GuestMemory::as_slice` only supports guest pointers to u8 slices in
                    // wiggle 22.0.0, but `GuestMemory::to_vec` supports guest pointers to slices
                    // of arbitrary types. As `GuestMemory::to_vec` will copy the contents of the
                    // slice out of guest memory, we should switch this to `GuestMemory::as_slice`
                    // once it is polymorphic in the element type of the slice.
                    .to_vec(pending_req_handles)?
                    .into_iter()
                    .map(|handle| PendingRequestHandle::from(handle).into()),
            )
            .await? as u32;

        let item = self.take_async_item(
            PendingRequestHandle::from(memory.read(pending_req_handles.get(done_index).unwrap())?)
                .into(),
        )?;

        let outcome = match item {
            AsyncItem::PendingReq(task) => match task {
                PeekableTask::Complete(res) => match res {
                    Ok(res) => {
                        let (resp_handle, body_handle) = self.insert_response(res);
                        (done_index, resp_handle, body_handle)
                    }
                    Err(_) => (
                        done_index,
                        INVALID_RESPONSE_HANDLE.into(),
                        INVALID_BODY_HANDLE.into(),
                    ),
                },
                _ => panic!("Pending request was not completed"),
            },
            _ => panic!("AsyncItem was not a pending request"),
        };

        Ok(outcome)
    }

    async fn pending_req_select_v2(
        &mut self,
        memory: &mut GuestMemory<'_>,
        pending_req_handles: GuestPtr<[PendingRequestHandle]>,
        _error_detail: GuestPtr<SendErrorDetail>,
    ) -> Result<(u32, ResponseHandle, BodyHandle), Error> {
        // This initial implementation ignores the error detail field
        self.pending_req_select(memory, pending_req_handles).await
    }

    fn fastly_key_is_valid(&mut self, _memory: &mut GuestMemory<'_>) -> Result<u32, Error> {
        Err(Error::NotAvailable("FASTLY_KEY is valid"))
    }

    fn close(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        req_handle: RequestHandle,
    ) -> Result<(), Error> {
        // We don't do anything with the parts, but we do pass the error up if
        // the handle given doesn't exist
        self.take_request_parts(req_handle)?;
        Ok(())
    }

    fn auto_decompress_response_set(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        req_handle: RequestHandle,
        encodings: ContentEncodings,
    ) -> Result<(), Error> {
        // NOTE: We're going to hide this flag in the extensions of the request in order to decrease
        // the book-keeping burden inside Session. The flag will get picked up later, in `send_request`.
        let extensions = &mut self.request_parts_mut(req_handle)?.extensions;

        match extensions.get_mut::<ViceroyRequestMetadata>() {
            None => {
                extensions.insert(ViceroyRequestMetadata {
                    auto_decompress_encodings: encodings,
                    // future note: at time of writing, this is the only field of
                    // this structure, but there is an intention to add more fields.
                    // When we do, and if/when an error appears, what you're looking
                    // for is:
                    // ..Default::default()
                });
            }
            Some(vrm) => {
                vrm.auto_decompress_encodings = encodings;
            }
        }

        Ok(())
    }
}
