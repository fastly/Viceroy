//! fastly_req` hostcall implementations.

use {
    crate::{
        error::Error,
        session::Session,
        upstream::{self, PendingRequest},
        wiggle_abi::{
            fastly_http_req::FastlyHttpReq,
            headers::HttpHeaders,
            types::{
                BodyHandle, CacheOverrideTag, ContentEncodings, HttpVersion, MultiValueCursor,
                MultiValueCursorResult, PendingRequestHandle, RequestHandle, ResponseHandle,
            },
        },
    },
    fastly_shared::{INVALID_BODY_HANDLE, INVALID_REQUEST_HANDLE, INVALID_RESPONSE_HANDLE},
    http::{Method, Uri},
    hyper::http::request::Request,
    std::{
        convert::{TryFrom, TryInto},
        ops::Deref,
    },
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
                let mut octets_slice = addr_octets_ptr.as_array(octets_bytes).as_slice_mut()?;
                octets_slice.copy_from_slice(&octets);
                Ok(octets_bytes)
            }
            IpAddr::V6(addr) => {
                let octets = addr.octets();
                let octets_bytes = octets.len() as u32;
                debug_assert_eq!(octets_bytes, 16);
                let mut octets_slice = addr_octets_ptr.as_array(octets_bytes).as_slice_mut()?;
                octets_slice.copy_from_slice(&octets);
                Ok(octets_bytes)
            }
        }
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

        let mut buf_slice = buf.as_array(req_method_len).as_slice_mut()?;
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
        let method_slice = method.as_byte_ptr().as_slice()?;
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

        let mut buf_slice = buf.as_array(req_uri_len).as_slice_mut()?;
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
        let req_uri_str = uri.as_str()?;
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
        let backend_bytes_slice = backend_bytes.as_byte_ptr().as_slice()?;
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

    fn send_async<'a>(
        &mut self,
        req_handle: RequestHandle,
        body_handle: BodyHandle,
        backend_bytes: &GuestPtr<'a, str>,
    ) -> Result<PendingRequestHandle, Error> {
        let backend_bytes_slice = backend_bytes.as_byte_ptr().as_slice()?;
        let backend_name = std::str::from_utf8(&backend_bytes_slice)?;

        // prepare the request
        let req_parts = self.take_request_parts(req_handle)?;
        let req_body = self.take_body(body_handle)?;
        let req = Request::from_parts(req_parts, req_body);
        let backend = self
            .backend(backend_name)
            .ok_or_else(|| Error::UnknownBackend(backend_name.to_owned()))?;

        // asynchronously send the request
        let pending_req =
            PendingRequest::spawn(upstream::send_request(req, backend, self.tls_config()));

        // return a handle to the pending request
        Ok(self.insert_pending_request(pending_req))
    }

    fn send_async_streaming<'a>(
        &mut self,
        req_handle: RequestHandle,
        body_handle: BodyHandle,
        backend_bytes: &GuestPtr<'a, str>,
    ) -> Result<PendingRequestHandle, Error> {
        let backend_bytes_slice = backend_bytes.as_byte_ptr().as_slice()?;
        let backend_name = std::str::from_utf8(&backend_bytes_slice)?;

        // prepare the request
        let req_parts = self.take_request_parts(req_handle)?;
        let req_body = self.begin_streaming(body_handle)?;
        let req = Request::from_parts(req_parts, req_body);
        let backend = self
            .backend(backend_name)
            .ok_or_else(|| Error::UnknownBackend(backend_name.to_owned()))?;

        // asynchronously send the request
        let pending_req =
            PendingRequest::spawn(upstream::send_request(req, backend, self.tls_config()));

        // return a handle to the pending request
        Ok(self.insert_pending_request(pending_req))
    }

    // note: The first value in the return tuple represents whether the request is done: 0 when not
    // done, 1 when done.
    fn pending_req_poll(
        &mut self,
        pending_req_handle: PendingRequestHandle,
    ) -> Result<(u32, ResponseHandle, BodyHandle), Error> {
        let pending_req = self.pending_request_mut(pending_req_handle)?;

        let outcome = match pending_req.poll() {
            None => (0, INVALID_REQUEST_HANDLE.into(), INVALID_BODY_HANDLE.into()),
            Some(resp) => {
                // the request is done; remove it from the map
                drop(self.take_pending_request(pending_req_handle)?);
                let (resp_handle, resp_body_handle) = self.insert_response(resp?);
                (1, resp_handle, resp_body_handle)
            }
        };
        Ok(outcome)
    }

    async fn pending_req_wait(
        &mut self,
        pending_req_handle: PendingRequestHandle,
    ) -> Result<(ResponseHandle, BodyHandle), Error> {
        let pending_req = self.take_pending_request(pending_req_handle)?;
        Ok(self.insert_response(pending_req.wait().await?))
    }

    // First element of return tuple is the "done index"
    async fn pending_req_select<'a>(
        &mut self,
        pending_req_handles: &GuestPtr<'a, [PendingRequestHandle]>,
    ) -> Result<(u32, ResponseHandle, BodyHandle), Error> {
        if pending_req_handles.len() == 0 {
            return Err(Error::InvalidArgument);
        }
        let targets = self.prepare_select_targets(&pending_req_handles.as_slice()?)?;

        // perform the select operation
        let (fut_result, done_index, rest) = futures::future::select_all(targets).await;

        // reinsert the other receivers before doing anything else, so they don't get dropped
        self.reinsert_select_targets(rest);

        let outcome = match fut_result {
            Ok(resp) => {
                let (resp_handle, body_handle) = self.insert_response(resp);
                (done_index as u32, resp_handle, body_handle)
            }
            // Unfortunately, the ABI provides no means of returning error information
            // from completed `select`.
            Err(_) => (
                done_index as u32,
                INVALID_RESPONSE_HANDLE.into(),
                INVALID_BODY_HANDLE.into(),
            ),
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
        _h: RequestHandle,
        encodings: ContentEncodings,
    ) -> Result<(), Error> {
        if u32::from(encodings) == 1 {
            unimplemented!("calling auto_decompress_response_set with GZIP has not yet been implemented in Viceroy");
        } else {
            Ok(())
        }
    }
}
