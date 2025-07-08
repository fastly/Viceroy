//! fastly_req` hostcall implementations.

use super::types::SendErrorDetail;
use super::SecretStoreError;
use crate::cache::CacheOverride;
use crate::config::ClientCertInfo;
use crate::secret_store::SecretLookup;

use {
    crate::{
        config::Backend,
        error::Error,
        pushpin::{PushpinRedirectInfo, PushpinRedirectRequestInfo},
        session::{AsyncItem, PeekableTask, Session, ViceroyRequestMetadata},
        upstream,
        wiggle_abi::{
            fastly_http_downstream::FastlyHttpDownstream,
            fastly_http_req::FastlyHttpReq,
            headers::HttpHeaders,
            types::{
                BackendConfigOptions, BodyHandle, CacheOverrideTag, ClientCertVerifyResult,
                ContentEncodings, DynamicBackendConfig, FramingHeadersMode, HttpVersion,
                InspectInfo, InspectInfoMask, MultiValueCursor, MultiValueCursorResult,
                PendingRequestHandle, RequestHandle, ResponseHandle,
            },
        },
    },
    fastly_shared::{INVALID_BODY_HANDLE, INVALID_REQUEST_HANDLE, INVALID_RESPONSE_HANDLE},
    http::{HeaderValue, Method, Uri},
    hyper::http::request::Request,
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

    fn cache_override_set(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        req_handle: RequestHandle,
        tag: CacheOverrideTag,
        ttl: u32,
        stale_while_revalidate: u32,
    ) -> Result<(), Error> {
        let overrides = CacheOverride::from_abi(u32::from(tag), ttl, stale_while_revalidate, None)
            .ok_or(Error::InvalidArgument)?;

        self.request_parts_mut(req_handle)?
            .extensions
            .insert(overrides);

        Ok(())
    }

    fn cache_override_v2_set(
        &mut self,
        memory: &mut GuestMemory<'_>,
        req_handle: RequestHandle,
        tag: CacheOverrideTag,
        ttl: u32,
        stale_while_revalidate: u32,
        sk: GuestPtr<[u8]>,
    ) -> Result<(), Error> {
        let sk = if sk.len() > 0 {
            let sk = memory.as_slice(sk)?.ok_or(Error::SharedMemory)?;
            let sk = HeaderValue::from_bytes(&sk).map_err(|_| Error::InvalidArgument)?;
            Some(sk)
        } else {
            None
        };

        let overrides = CacheOverride::from_abi(u32::from(tag), ttl, stale_while_revalidate, sk)
            .ok_or(Error::InvalidArgument)?;

        self.request_parts_mut(req_handle)?
            .extensions
            .insert(overrides);

        Ok(())
    }

    fn downstream_server_ip_addr(
        &mut self,
        memory: &mut GuestMemory<'_>,
        // Must be a 16-byte array:
        addr_octets_ptr: GuestPtr<u8>,
    ) -> Result<u32, Error> {
        FastlyHttpDownstream::downstream_server_ip_addr(
            self,
            memory,
            self.downstream_request(),
            addr_octets_ptr,
        )
    }

    fn downstream_client_ip_addr(
        &mut self,
        memory: &mut GuestMemory<'_>,
        // Must be a 16-byte array:
        addr_octets_ptr: GuestPtr<u8>,
    ) -> Result<u32, Error> {
        FastlyHttpDownstream::downstream_client_ip_addr(
            self,
            memory,
            self.downstream_request(),
            addr_octets_ptr,
        )
    }

    fn downstream_client_h2_fingerprint(
        &mut self,
        memory: &mut GuestMemory<'_>,
        h2fp_out: GuestPtr<u8>,
        h2fp_max_len: u32,
        nwritten_out: GuestPtr<u32>,
    ) -> Result<(), Error> {
        FastlyHttpDownstream::downstream_client_h2_fingerprint(
            self,
            memory,
            self.downstream_request(),
            h2fp_out,
            h2fp_max_len,
            nwritten_out,
        )
    }

    fn downstream_client_request_id(
        &mut self,
        memory: &mut GuestMemory<'_>,
        reqid_out: GuestPtr<u8>,
        reqid_max_len: u32,
        nwritten_out: GuestPtr<u32>,
    ) -> Result<(), Error> {
        FastlyHttpDownstream::downstream_client_request_id(
            self,
            memory,
            self.downstream_request(),
            reqid_out,
            reqid_max_len,
            nwritten_out,
        )
    }

    fn downstream_client_oh_fingerprint(
        &mut self,
        memory: &mut GuestMemory<'_>,
        ohfp_out: GuestPtr<u8>,
        ohfp_max_len: u32,
        nwritten_out: GuestPtr<u32>,
    ) -> Result<(), Error> {
        FastlyHttpDownstream::downstream_client_oh_fingerprint(
            self,
            memory,
            self.downstream_request(),
            ohfp_out,
            ohfp_max_len,
            nwritten_out,
        )
    }

    fn downstream_client_ddos_detected(
        &mut self,
        memory: &mut GuestMemory<'_>,
    ) -> Result<u32, Error> {
        FastlyHttpDownstream::downstream_client_ddos_detected(
            self,
            memory,
            self.downstream_request(),
        )
    }

    fn downstream_tls_cipher_openssl_name(
        &mut self,
        memory: &mut GuestMemory<'_>,
        cipher_out: GuestPtr<u8>,
        cipher_max_len: u32,
        nwritten_out: GuestPtr<u32>,
    ) -> Result<(), Error> {
        FastlyHttpDownstream::downstream_client_oh_fingerprint(
            self,
            memory,
            self.downstream_request(),
            cipher_out,
            cipher_max_len,
            nwritten_out,
        )
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
        let backend_name = memory
            .as_str(backend_name)?
            .ok_or(Error::SharedMemory)?
            .to_string();
        let redirect_info = PushpinRedirectInfo {
            backend_name,
            request_info: None,
        };

        self.redirect_downstream_to_pushpin(redirect_info)?;
        Ok(())
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
        memory: &mut GuestMemory<'_>,
        req_handle: RequestHandle,
        backend_name: GuestPtr<str>,
    ) -> Result<(), Error> {
        let backend_name = memory
            .as_str(backend_name)?
            .ok_or(Error::SharedMemory)?
            .to_string();
        let req = self.request_parts(req_handle)?;
        let redirect_info = PushpinRedirectInfo {
            backend_name,
            request_info: Some(PushpinRedirectRequestInfo::from_parts(req)),
        };

        self.redirect_downstream_to_pushpin(redirect_info)?;
        Ok(())
    }

    fn downstream_tls_protocol(
        &mut self,
        memory: &mut GuestMemory<'_>,
        protocol_out: GuestPtr<u8>,
        protocol_max_len: u32,
        nwritten_out: GuestPtr<u32>,
    ) -> Result<(), Error> {
        FastlyHttpDownstream::downstream_tls_protocol(
            self,
            memory,
            self.downstream_request(),
            protocol_out,
            protocol_max_len,
            nwritten_out,
        )
    }

    fn downstream_tls_client_hello(
        &mut self,
        memory: &mut GuestMemory<'_>,
        chello_out: GuestPtr<u8>,
        chello_max_len: u32,
        nwritten_out: GuestPtr<u32>,
    ) -> Result<(), Error> {
        FastlyHttpDownstream::downstream_tls_client_hello(
            self,
            memory,
            self.downstream_request(),
            chello_out,
            chello_max_len,
            nwritten_out,
        )
    }

    fn downstream_tls_raw_client_certificate(
        &mut self,
        memory: &mut GuestMemory<'_>,
        cert_out: GuestPtr<u8>,
        cert_max_len: u32,
        nwritten_out: GuestPtr<u32>,
    ) -> Result<(), Error> {
        FastlyHttpDownstream::downstream_tls_raw_client_certificate(
            self,
            memory,
            self.downstream_request(),
            cert_out,
            cert_max_len,
            nwritten_out,
        )
    }

    fn downstream_tls_client_cert_verify_result(
        &mut self,
        memory: &mut GuestMemory<'_>,
    ) -> Result<ClientCertVerifyResult, Error> {
        FastlyHttpDownstream::downstream_tls_client_cert_verify_result(
            self,
            memory,
            self.downstream_request(),
        )
    }

    fn downstream_tls_ja3_md5(
        &mut self,
        memory: &mut GuestMemory<'_>,
        ja3_md5_out: GuestPtr<u8>,
    ) -> Result<u32, Error> {
        FastlyHttpDownstream::downstream_tls_ja3_md5(
            self,
            memory,
            self.downstream_request(),
            ja3_md5_out,
        )
    }

    fn downstream_tls_ja4(
        &mut self,
        memory: &mut GuestMemory<'_>,
        ja4_out: GuestPtr<u8>,
        ja4_max_len: u32,
        nwritten_out: GuestPtr<u32>,
    ) -> Result<(), Error> {
        FastlyHttpDownstream::downstream_tls_ja4(
            self,
            memory,
            self.downstream_request(),
            ja4_out,
            ja4_max_len,
            nwritten_out,
        )
    }

    fn downstream_compliance_region(
        &mut self,
        memory: &mut GuestMemory<'_>,
        // Must be a 16-byte array:
        region_out: GuestPtr<u8>,
        region_max_len: u32,
        nwritten_out: GuestPtr<u32>,
    ) -> Result<(), Error> {
        FastlyHttpDownstream::downstream_compliance_region(
            self,
            memory,
            self.downstream_request(),
            region_out,
            region_max_len,
            nwritten_out,
        )
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
        FastlyHttpDownstream::downstream_original_header_names(
            self,
            memory,
            self.downstream_request(),
            buf,
            buf_len,
            cursor,
            ending_cursor_out,
            nwritten_out,
        )
    }

    fn original_header_count(&mut self, memory: &mut GuestMemory<'_>) -> Result<u32, Error> {
        FastlyHttpDownstream::downstream_original_header_count(
            self,
            memory,
            self.downstream_request(),
        )
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

    async fn send_v3(
        &mut self,
        memory: &mut GuestMemory<'_>,
        req_handle: RequestHandle,
        body_handle: BodyHandle,
        backend_bytes: GuestPtr<str>,
        error_detail: GuestPtr<SendErrorDetail>,
    ) -> Result<(ResponseHandle, BodyHandle), Error> {
        self.send_v2(memory, req_handle, body_handle, backend_bytes, error_detail)
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

    async fn send_async_v2(
        &mut self,
        memory: &mut GuestMemory<'_>,
        req_handle: RequestHandle,
        body_handle: BodyHandle,
        backend_bytes: GuestPtr<str>,
        streaming: u32,
    ) -> Result<PendingRequestHandle, Error> {
        if streaming == 1 {
            self.send_async_streaming(memory, req_handle, body_handle, backend_bytes)
                .await
        } else {
            self.send_async(memory, req_handle, body_handle, backend_bytes)
                .await
        }
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

    fn fastly_key_is_valid(&mut self, memory: &mut GuestMemory<'_>) -> Result<u32, Error> {
        FastlyHttpDownstream::fastly_key_is_valid(self, memory, self.downstream_request())
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

    fn inspect(
        &mut self,
        memory: &mut GuestMemory<'_>,
        ds_req: RequestHandle,
        ds_body: BodyHandle,
        info_mask: InspectInfoMask,
        info: GuestPtr<InspectInfo>,
        buf: GuestPtr<u8>,
        buf_len: u32,
    ) -> Result<u32, Error> {
        // Make sure we're given valid handles, even though we won't use them.
        let _ = self.request_parts(ds_req)?;
        let _ = self.body(ds_body)?;

        // Make sure the InspectInfo looks good, even though we won't use it.
        let info = memory.read(info)?;
        let info_string_or_err = |flag, str_field: GuestPtr<u8>, len_field| {
            if info_mask.contains(flag) {
                if len_field == 0 {
                    return Err(Error::InvalidArgument);
                }

                let byte_vec = memory.to_vec(str_field.as_array(len_field))?;
                let s = String::from_utf8(byte_vec).map_err(|_| Error::InvalidArgument)?;

                Ok(s)
            } else {
                // For now, corp and workspace arguments are required to actually generate the hostname,
                // but in the future the lookaside service will be generated using the customer ID, and
                // it will be okay for them to be unspecified or empty.
                Err(Error::InvalidArgument)
            }
        };

        let _ = info_string_or_err(InspectInfoMask::CORP, info.corp, info.corp_len)?;
        let _ = info_string_or_err(
            InspectInfoMask::WORKSPACE,
            info.workspace,
            info.workspace_len,
        )?;

        // Return the mock NGWAF response.
        let ngwaf_resp = self.ngwaf_response();
        let ngwaf_resp_len = ngwaf_resp.len();

        match u32::try_from(ngwaf_resp_len) {
            Ok(ngwaf_resp_len) if ngwaf_resp_len <= buf_len => {
                memory.copy_from_slice(ngwaf_resp.as_bytes(), buf.as_array(ngwaf_resp_len))?;

                Ok(ngwaf_resp_len)
            }
            _ => Err(Error::BufferLengthError {
                buf: "buf",
                len: "buf_len",
            }),
        }
    }

    fn on_behalf_of(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        _ds_req: RequestHandle,
        _service: GuestPtr<str>,
    ) -> Result<(), Error> {
        Err(Error::Unsupported {
            msg: "on_behalf_of is not supported in Viceroy",
        })
    }
}
