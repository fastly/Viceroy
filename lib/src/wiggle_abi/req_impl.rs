//! fastly_req` hostcall implementations.

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
    std::ops::Deref,
    wiggle::GuestPtr,
};

#[wiggle::async_trait]
impl FastlyHttpReq for Session {
    fn body_downstream_get(&mut self) -> Result<(RequestHandle, BodyHandle), Error> {
        let req_handle = self.downstream_request();
        let body_handle = self.downstream_request_body();
        Ok((req_handle, body_handle))
    }

    #[allow(unused_variables)] // FIXME KTM 2020-06-25: Remove this directive once implemented.
    fn cache_override_set(
        &mut self,
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
        req_handle: RequestHandle,
        tag: CacheOverrideTag,
        ttl: u32,
        stale_while_revalidate: u32,
        sk: &GuestPtr<[u8]>,
    ) -> Result<(), Error> {
        // For now, we ignore caching directives because we never cache anything
        Ok(())
    }

    fn downstream_client_ip_addr(
        &mut self,
        // Must be a 16-byte array:
        addr_octets_ptr: &GuestPtr<u8>,
    ) -> Result<u32, Error> {
        use std::net::IpAddr;
        match self.downstream_client_ip() {
            IpAddr::V4(addr) => {
                let octets = addr.octets();
                let octets_bytes = octets.len() as u32;
                debug_assert_eq!(octets_bytes, 4);
                let mut octets_slice = addr_octets_ptr
                    .as_array(octets_bytes)
                    .as_slice_mut()?
                    .ok_or(Error::SharedMemory)?;
                octets_slice.copy_from_slice(&octets);
                Ok(octets_bytes)
            }
            IpAddr::V6(addr) => {
                let octets = addr.octets();
                let octets_bytes = octets.len() as u32;
                debug_assert_eq!(octets_bytes, 16);
                let mut octets_slice = addr_octets_ptr
                    .as_array(octets_bytes)
                    .as_slice_mut()?
                    .ok_or(Error::SharedMemory)?;
                octets_slice.copy_from_slice(&octets);
                Ok(octets_bytes)
            }
        }
    }

    #[allow(unused_variables)] // FIXME JDC 2023-06-18: Remove this directive once implemented.
    fn downstream_client_h2_fingerprint<'a>(
        &mut self,
        h2fp_out: &GuestPtr<'a, u8>,
        h2fp_max_len: u32,
        nwritten_out: &GuestPtr<u32>,
    ) -> Result<(), Error> {
        Err(Error::NotAvailable("Client H2 fingerprint"))
    }

    fn downstream_client_request_id(
        &mut self,
        reqid_out: &GuestPtr<u8>,
        reqid_max_len: u32,
        nwritten_out: &GuestPtr<u32>,
    ) -> Result<(), Error> {
        let reqid_bytes = format!("{:032x}", self.req_id()).into_bytes();

        if reqid_bytes.len() > reqid_max_len as usize {
            // Write out the number of bytes necessary to fit the value, or zero on overflow to
            // signal an error condition.
            nwritten_out.write(reqid_bytes.len().try_into().unwrap_or(0))?;
            return Err(Error::BufferLengthError {
                buf: "reqid_out",
                len: "reqid_max_len",
            });
        }

        let reqid_len =
            u32::try_from(reqid_bytes.len()).expect("smaller u32::MAX means it must fit");

        let mut reqid_slice = reqid_out
            .as_array(reqid_len)
            .as_slice_mut()?
            .ok_or(Error::SharedMemory)?;
        reqid_slice.copy_from_slice(&reqid_bytes);
        nwritten_out.write(reqid_len)?;
        Ok(())
    }

    #[allow(unused_variables)] // FIXME KTM 2020-06-25: Remove this directive once implemented.
    fn downstream_tls_cipher_openssl_name<'a>(
        &mut self,
        cipher_out: &GuestPtr<'a, u8>,
        cipher_max_len: u32,
        nwritten_out: &GuestPtr<u32>,
    ) -> Result<(), Error> {
        Err(Error::NotAvailable("Client TLS data"))
    }

    #[allow(unused_variables)] // FIXME ACF 2022-05-03: Remove this directive once implemented.
    fn upgrade_websocket(&mut self, backend_name: &GuestPtr<str>) -> Result<(), Error> {
        Err(Error::NotAvailable("WebSocket upgrade"))
    }

    #[allow(unused_variables)] // FIXME ACF 2022-10-03: Remove this directive once implemented.
    fn redirect_to_websocket_proxy(&mut self, backend_name: &GuestPtr<str>) -> Result<(), Error> {
        Err(Error::NotAvailable("Redirect to WebSocket proxy"))
    }

    #[allow(unused_variables)] // FIXME ACF 2022-10-03: Remove this directive once implemented.
    fn redirect_to_grip_proxy(&mut self, backend_name: &GuestPtr<str>) -> Result<(), Error> {
        Err(Error::NotAvailable("Redirect to Fanout/GRIP proxy"))
    }

    #[allow(unused_variables)] // FIXME KTM 2020-06-25: Remove this directive once implemented.
    fn downstream_tls_protocol<'a>(
        &mut self,
        protocol_out: &GuestPtr<'a, u8>,
        protocol_max_len: u32,
        nwritten_out: &GuestPtr<u32>,
    ) -> Result<(), Error> {
        Err(Error::NotAvailable("Client TLS data"))
    }

    #[allow(unused_variables)] // FIXME KTM 2020-06-25: Remove this directive once implemented.
    fn downstream_tls_client_hello<'a>(
        &mut self,
        chello_out: &GuestPtr<'a, u8>,
        chello_max_len: u32,
        nwritten_out: &GuestPtr<u32>,
    ) -> Result<(), Error> {
        Err(Error::NotAvailable("Client TLS data"))
    }

    #[allow(unused_variables)] // FIXME HL 2022-09-19: Remove this directive once implemented.
    fn downstream_tls_raw_client_certificate<'a>(
        &mut self,
        _raw_client_cert_out: &GuestPtr<'a, u8>,
        _raw_client_cert_max_len: u32,
        _nwritten_out: &GuestPtr<u32>,
    ) -> Result<(), Error> {
        Err(Error::NotAvailable("Client TLS data"))
    }

    #[allow(unused_variables)] // FIXME HL 2022-09-19: Remove this directive once implemented.
    fn downstream_tls_client_cert_verify_result(
        &mut self,
    ) -> Result<ClientCertVerifyResult, Error> {
        Err(Error::NotAvailable("Client TLS data"))
    }

    #[allow(unused_variables)] // FIXME ACF 2022-05-03: Remove this directive once implemented.
    fn downstream_tls_ja3_md5(&mut self, ja3_md5_out: &GuestPtr<u8>) -> Result<u32, Error> {
        Err(Error::NotAvailable("Client TLS JA3 hash"))
    }

    fn framing_headers_mode_set(
        &mut self,
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

    fn register_dynamic_backend<'a>(
        &mut self,
        name: &GuestPtr<str>,
        upstream_dynamic: &GuestPtr<str>,
        backend_info_mask: BackendConfigOptions,
        backend_info: &GuestPtr<'a, DynamicBackendConfig<'a>>,
    ) -> Result<(), Error> {
        let name_slice = name.as_bytes().as_slice()?.ok_or(Error::SharedMemory)?;
        let name = std::str::from_utf8(&name_slice)?;
        let origin_name_slice = upstream_dynamic
            .as_bytes()
            .as_slice()?
            .ok_or(Error::SharedMemory)?;
        let origin_name = std::str::from_utf8(&origin_name_slice)?;
        let config = backend_info.read()?;

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

            let byte_slice = config
                .host_override
                .as_array(config.host_override_len)
                .as_slice()?
                .ok_or(Error::SharedMemory)?;

            Some(HeaderValue::from_bytes(&byte_slice)?)
        } else {
            None
        };

        let scheme = if backend_info_mask.contains(BackendConfigOptions::USE_SSL) {
            "https"
        } else {
            "http"
        };

        let mut cert_host = if backend_info_mask.contains(BackendConfigOptions::CERT_HOSTNAME) {
            if config.cert_hostname_len == 0 {
                return Err(Error::InvalidArgument);
            }

            if config.cert_hostname_len > 1024 {
                return Err(Error::InvalidArgument);
            }

            let byte_slice = config
                .cert_hostname
                .as_array(config.cert_hostname_len)
                .as_slice()?
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
                let byte_slice = config
                    .sni_hostname
                    .as_array(config.sni_hostname_len)
                    .as_slice()?
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

        let new_backend = Backend {
            uri: Uri::builder()
                .scheme(scheme)
                .authority(origin_name)
                .path_and_query("/")
                .build()?,
            override_host,
            cert_host,
            use_sni,
        };

        if !self.add_backend(name, new_backend) {
            return Err(Error::BackendNameRegistryError(name.to_string()));
        }

        Ok(())
    }

    fn new(&mut self) -> Result<RequestHandle, Error> {
        let (parts, _) = Request::new(()).into_parts();
        Ok(self.insert_request_parts(parts))
    }

    fn header_names_get<'a>(
        &mut self,
        req_handle: RequestHandle,
        buf: &GuestPtr<'a, u8>,
        buf_len: u32,
        cursor: MultiValueCursor,
        ending_cursor_out: &GuestPtr<MultiValueCursorResult>,
        nwritten_out: &GuestPtr<u32>,
    ) -> Result<(), Error> {
        let headers = &self.request_parts(req_handle)?.headers;
        multi_value_result!(
            headers.names_get(buf, buf_len, cursor, nwritten_out),
            ending_cursor_out
        )
    }

    fn original_header_names_get<'a>(
        &mut self,
        buf: &GuestPtr<'a, u8>,
        buf_len: u32,
        cursor: MultiValueCursor,
        ending_cursor_out: &GuestPtr<MultiValueCursorResult>,
        nwritten_out: &GuestPtr<u32>,
    ) -> Result<(), Error> {
        let headers = self.downstream_original_headers();
        multi_value_result!(
            headers.names_get(buf, buf_len, cursor, nwritten_out),
            ending_cursor_out
        )
    }

    fn original_header_count(&mut self) -> Result<u32, Error> {
        let headers = self.downstream_original_headers();
        Ok(headers
            .len()
            .try_into()
            .expect("More than u32::MAX headers"))
    }

    fn header_value_get<'a>(
        &mut self,
        req_handle: RequestHandle,
        name: &GuestPtr<[u8]>,
        value: &GuestPtr<u8>,
        value_max_len: u32,
        nwritten_out: &GuestPtr<u32>,
    ) -> Result<(), Error> {
        let headers = &self.request_parts(req_handle)?.headers;
        headers.value_get(name, value, value_max_len, nwritten_out)
    }

    fn header_values_get<'a>(
        &mut self,
        req_handle: RequestHandle,
        name: &GuestPtr<[u8]>,
        buf: &GuestPtr<u8>,
        buf_len: u32,
        cursor: MultiValueCursor,
        ending_cursor_out: &GuestPtr<MultiValueCursorResult>,
        nwritten_out: &GuestPtr<u32>,
    ) -> Result<(), Error> {
        let headers = &self.request_parts(req_handle)?.headers;
        multi_value_result!(
            headers.values_get(name, buf, buf_len, cursor, nwritten_out),
            ending_cursor_out
        )
    }

    fn header_values_set<'a>(
        &mut self,
        req_handle: RequestHandle,
        name: &GuestPtr<[u8]>,
        values: &GuestPtr<[u8]>,
    ) -> Result<(), Error> {
        let headers = &mut self.request_parts_mut(req_handle)?.headers;
        headers.values_set(name, values)
    }

    fn header_insert<'a>(
        &mut self,
        req_handle: RequestHandle,
        name: &GuestPtr<[u8]>,
        value: &GuestPtr<[u8]>,
    ) -> Result<(), Error> {
        let headers = &mut self.request_parts_mut(req_handle)?.headers;
        HttpHeaders::insert(headers, name, value)
    }

    fn header_append<'a>(
        &mut self,
        req_handle: RequestHandle,
        name: &GuestPtr<[u8]>,
        value: &GuestPtr<[u8]>,
    ) -> Result<(), Error> {
        let headers = &mut self.request_parts_mut(req_handle)?.headers;
        HttpHeaders::append(headers, name, value)
    }

    fn header_remove<'a>(
        &mut self,
        req_handle: RequestHandle,
        name: &GuestPtr<[u8]>,
    ) -> Result<(), Error> {
        let headers = &mut self.request_parts_mut(req_handle)?.headers;
        HttpHeaders::remove(headers, name)
    }

    fn method_get<'a>(
        &mut self,
        req_handle: RequestHandle,
        buf: &GuestPtr<'a, u8>,
        buf_len: u32,
        nwritten_out: &GuestPtr<u32>,
    ) -> Result<(), Error> {
        let req = self.request_parts(req_handle)?;
        let req_method = &req.method;
        let req_method_bytes = req_method.to_string().into_bytes();

        if req_method_bytes.len() > buf_len as usize {
            // Write out the number of bytes necessary to fit this method, or zero on overflow to
            // signal an error condition.
            nwritten_out.write(req_method_bytes.len().try_into().unwrap_or(0))?;
            return Err(Error::BufferLengthError {
                buf: "method",
                len: "method_max_len",
            });
        }

        let req_method_len = u32::try_from(req_method_bytes.len())
            .expect("smaller than method_max_len means it must fit");

        let mut buf_slice = buf
            .as_array(req_method_len)
            .as_slice_mut()?
            .ok_or(Error::SharedMemory)?;
        buf_slice.copy_from_slice(&req_method_bytes);
        nwritten_out.write(req_method_len)?;

        Ok(())
    }

    fn method_set<'a>(
        &mut self,
        req_handle: RequestHandle,
        method: &GuestPtr<'a, str>,
    ) -> Result<(), Error> {
        let method_ref = &mut self.request_parts_mut(req_handle)?.method;
        let method_slice = method.as_bytes().as_slice()?.ok_or(Error::SharedMemory)?;
        *method_ref = Method::from_bytes(method_slice.deref())?;

        Ok(())
    }

    fn uri_get<'a>(
        &mut self,
        req_handle: RequestHandle,
        buf: &GuestPtr<'a, u8>,
        buf_len: u32,
        nwritten_out: &GuestPtr<u32>,
    ) -> Result<(), Error> {
        let req = self.request_parts(req_handle)?;
        let req_uri = &req.uri;
        let req_uri_bytes = req_uri.to_string().into_bytes();

        if req_uri_bytes.len() > buf_len as usize {
            // Write out the number of bytes necessary to fit this method, or zero on overflow to
            // signal an error condition.
            nwritten_out.write(req_uri_bytes.len().try_into().unwrap_or(0))?;
            return Err(Error::BufferLengthError {
                buf: "uri",
                len: "uri_max_len",
            });
        }
        let req_uri_len =
            u32::try_from(req_uri_bytes.len()).expect("smaller than uri_max_len means it must fit");

        let mut buf_slice = buf
            .as_array(req_uri_len)
            .as_slice_mut()?
            .ok_or(Error::SharedMemory)?;
        buf_slice.copy_from_slice(&req_uri_bytes);
        nwritten_out.write(req_uri_len)?;

        Ok(())
    }

    fn uri_set<'a>(
        &mut self,
        req_handle: RequestHandle,
        uri: &GuestPtr<'a, str>,
    ) -> Result<(), Error> {
        let uri_ref = &mut self.request_parts_mut(req_handle)?.uri;
        let req_uri_str = uri.as_str()?.ok_or(Error::SharedMemory)?;
        let req_uri_bytes = req_uri_str.as_bytes();

        *uri_ref = Uri::try_from(req_uri_bytes)?;
        Ok(())
    }

    fn version_get(&mut self, req_handle: RequestHandle) -> Result<HttpVersion, Error> {
        let req = self.request_parts(req_handle)?;
        HttpVersion::try_from(req.version).map_err(|msg| Error::Unsupported { msg })
    }

    fn version_set(
        &mut self,
        req_handle: RequestHandle,
        version: HttpVersion,
    ) -> Result<(), Error> {
        let req = self.request_parts_mut(req_handle)?;

        let version = hyper::Version::try_from(version)?;
        req.version = version;
        Ok(())
    }

    async fn send<'a>(
        &mut self,
        req_handle: RequestHandle,
        body_handle: BodyHandle,
        backend_bytes: &GuestPtr<'a, str>,
    ) -> Result<(ResponseHandle, BodyHandle), Error> {
        let backend_bytes_slice = backend_bytes
            .as_bytes()
            .as_slice()?
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

    async fn send_async<'a>(
        &mut self,
        req_handle: RequestHandle,
        body_handle: BodyHandle,
        backend_bytes: &GuestPtr<'a, str>,
    ) -> Result<PendingRequestHandle, Error> {
        let backend_bytes_slice = backend_bytes
            .as_bytes()
            .as_slice()?
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

    async fn send_async_streaming<'a>(
        &mut self,
        req_handle: RequestHandle,
        body_handle: BodyHandle,
        backend_bytes: &GuestPtr<'a, str>,
    ) -> Result<PendingRequestHandle, Error> {
        let backend_bytes_slice = backend_bytes
            .as_bytes()
            .as_slice()?
            .ok_or(Error::SharedMemory)?;
        let backend_name = std::str::from_utf8(&backend_bytes_slice)?;

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

    async fn pending_req_wait(
        &mut self,
        pending_req_handle: PendingRequestHandle,
    ) -> Result<(ResponseHandle, BodyHandle), Error> {
        let pending_req = self
            .take_pending_request(pending_req_handle)?
            .recv()
            .await?;
        Ok(self.insert_response(pending_req))
    }

    // First element of return tuple is the "done index"
    async fn pending_req_select<'a>(
        &mut self,
        pending_req_handles: &GuestPtr<'a, [PendingRequestHandle]>,
    ) -> Result<(u32, ResponseHandle, BodyHandle), Error> {
        if pending_req_handles.len() == 0 {
            return Err(Error::InvalidArgument);
        }
        let pending_req_handles: GuestPtr<'a, [u32]> =
            GuestPtr::new(pending_req_handles.mem(), pending_req_handles.offset());

        // perform the select operation
        let done_index = self
            .select_impl(
                pending_req_handles
                    .as_slice()?
                    .ok_or(Error::SharedMemory)?
                    .iter()
                    .map(|handle| PendingRequestHandle::from(*handle).into()),
            )
            .await? as u32;

        let item = self.take_async_item(
            PendingRequestHandle::from(pending_req_handles.get(done_index).unwrap().read()?).into(),
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

    fn close(&mut self, req_handle: RequestHandle) -> Result<(), Error> {
        // We don't do anything with the parts, but we do pass the error up if
        // the handle given doesn't exist
        self.take_request_parts(req_handle)?;
        Ok(())
    }

    fn auto_decompress_response_set(
        &mut self,
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
