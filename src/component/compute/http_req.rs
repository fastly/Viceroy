use {
    crate::component::{
        bindings::fastly::compute::{http_body, http_req, http_resp, http_types, types},
        compute::headers::{get_names, get_values},
    },
    crate::{
        error::Error,
        linking::{ComponentCtx, SessionView},
        pushpin::{PushpinRedirectInfo, PushpinRedirectRequestInfo},
        session::{PeekableTask, ViceroyRequestMetadata},
        upstream,
    },
    http::{
        header::{HeaderName, HeaderValue},
        request::Request,
        Method, Uri,
    },
    wasmtime::component::Resource,
};

// NOTE [error-detail]:
//
// The v2 apis return additional error through an send-error-detail outparam, but this is a little
// bit awkward in the context of wit, which lacks the notion of an outparam. As the presence of
// this value is optional, and only serves to augment additional error context, we instead
// represent this as a different error result in compute.wit:
//
// ```
// result<T, tuple<option<send-error-detail>, error>>
// ```
//
// The effect of this is that we can no longer rely on the `trappable_error_types` option to
// `component::bindgen!` to give us a type that represents both an error and a trap. Instead, we
// get the following translated return type:
//
// ```
// Result<Result<T, (Option<SendErrorDetail>, Error)>, anyhow::Error>
// ```
//
// Where the outer result is for managing errors that should be considered traps, and the inner
// result is for managing successful return values, or application-level errors that might include
// additional details. We could wrap up the tuple into an additional error type and declare it as a
// trappable error, but that's a bit more overhead for only four functions that currently don't
// populate the send-error-detail.

const MAX_HEADER_NAME_LEN: usize = (1 << 16) - 1;

impl http_req::Host for ComponentCtx {
    async fn send(
        &mut self,
        h: Resource<http_req::Request>,
        b: Resource<http_body::Body>,
        backend_name: String,
    ) -> Result<http_resp::ResponseWithBody, http_req::ErrorWithDetail> {
        // prepare the request
        let req_parts = self.session_mut().take_request_parts(h.into()).unwrap();
        let req_body = self.session_mut().take_body(b.into()).unwrap();
        let req = Request::from_parts(req_parts, req_body);
        let backend = self
            .session
            .backend(&backend_name)
            .ok_or_else(|| Error::UnknownBackend(backend_name))
            .map_err(Into::into)
            .map_err(types::Error::with_empty_detail)?;

        // synchronously send the request
        // This initial implementation ignores the error detail field
        let tls_config = self.session.tls_config();
        let resp = upstream::send_request(req, backend, tls_config)
            .await
            .map_err(Into::into)
            .map_err(types::Error::with_empty_detail)?;
        let (resp_handle, body_handle) = self.session_mut().insert_response(resp);
        Ok((resp_handle.into(), body_handle.into()))
    }

    async fn send_uncached(
        &mut self,
        h: Resource<http_req::Request>,
        b: Resource<http_body::Body>,
        backend_name: String,
    ) -> Result<http_resp::ResponseWithBody, http_req::ErrorWithDetail> {
        // This initial implementation ignores the error detail field
        self.send(h, b, backend_name).await
    }

    async fn send_async(
        &mut self,
        h: Resource<http_req::Request>,
        b: Resource<http_body::Body>,
        backend_name: String,
    ) -> Result<Resource<http_req::PendingRequest>, types::Error> {
        // prepare the request
        let req_parts = self.session_mut().take_request_parts(h.into())?;
        let req_body = self.session_mut().take_body(b.into())?;
        let req = Request::from_parts(req_parts, req_body);
        let backend = self
            .session
            .backend(&backend_name)
            .ok_or(types::Error::GenericError)?;

        // asynchronously send the request
        let tls_config = self.session.tls_config();
        let task = PeekableTask::spawn(upstream::send_request(req, backend, tls_config)).await;

        // return a handle to the pending request
        Ok(self.session_mut().insert_pending_request(task).into())
    }

    async fn send_async_uncached(
        &mut self,
        h: Resource<http_req::Request>,
        b: Resource<http_body::Body>,
        backend_name: String,
    ) -> Result<Resource<http_req::PendingRequest>, types::Error> {
        self.send_async(h, b, backend_name).await
    }

    async fn send_async_uncached_streaming(
        &mut self,
        h: Resource<http_req::Request>,
        b: Resource<http_body::Body>,
        backend_name: String,
    ) -> Result<Resource<http_req::PendingRequest>, types::Error> {
        self.send_async_streaming(h, b, backend_name).await
    }

    async fn send_async_streaming(
        &mut self,
        h: Resource<http_req::Request>,
        b: Resource<http_body::Body>,
        backend_name: String,
    ) -> Result<Resource<http_req::PendingRequest>, types::Error> {
        // prepare the request
        let req_parts = self.session_mut().take_request_parts(h.into())?;
        let req_body = self.session_mut().begin_streaming(b.into())?;
        let req = Request::from_parts(req_parts, req_body);
        let backend = self
            .session
            .backend(&backend_name)
            .ok_or(types::Error::GenericError)?;

        // asynchronously send the request
        let tls_config = self.session.tls_config();
        let task = PeekableTask::spawn(upstream::send_request(req, backend, tls_config)).await;

        // return a handle to the pending request
        Ok(self.session.insert_pending_request(task).into())
    }

    async fn await_response(
        &mut self,
        h: Resource<http_req::PendingRequest>,
    ) -> Result<http_resp::ResponseWithBody, http_req::ErrorWithDetail> {
        let pending_req = self
            .session_mut()
            .take_pending_request(h.into())
            .unwrap()
            .recv()
            .await
            .map_err(Into::into)
            .map_err(types::Error::with_empty_detail)?;
        let (resp_handle, body_handle) = self.session_mut().insert_response(pending_req);
        Ok((resp_handle.into(), body_handle.into()))
    }

    fn close(&mut self, h: Resource<http_req::Request>) -> Result<(), types::Error> {
        // We don't do anything with the parts, but we do pass the error up if
        // the handle given doesn't exist
        self.session_mut().take_request_parts(h.into())?;
        Ok(())
    }

    fn upgrade_websocket(&mut self, _backend: String) -> Result<(), types::Error> {
        Err(Error::NotAvailable("WebSocket upgrade").into())
    }
}

impl http_req::HostRequest for ComponentCtx {
    fn get_method(
        &mut self,
        h: Resource<http_req::Request>,
        max_len: u64,
    ) -> Result<String, types::Error> {
        let req = self.session.request_parts(h.into())?;
        let req_method = &req.method;

        if req_method.as_str().len() > usize::try_from(max_len).unwrap() {
            return Err(types::Error::BufferLen(
                u64::try_from(req_method.as_str().len()).unwrap(),
            ));
        }

        Ok(req_method.to_string())
    }

    fn get_uri(
        &mut self,
        h: Resource<http_req::Request>,
        max_len: u64,
    ) -> Result<String, types::Error> {
        let req = self.session().request_parts(h.into())?;
        let req_uri = &req.uri;
        let res = req_uri.to_string();

        if res.len() > usize::try_from(max_len).unwrap() {
            return Err(types::Error::BufferLen(u64::try_from(res.len()).unwrap()));
        }

        Ok(res)
    }

    fn set_cache_override(
        &mut self,
        _h: Resource<http_req::Request>,
        _cache_override: http_req::CacheOverride,
    ) -> Result<(), types::Error> {
        // For now, we ignore caching directives because we never cache anything
        Ok(())
    }

    fn new(&mut self) -> Result<Resource<http_req::Request>, types::Error> {
        let (parts, _) = Request::new(()).into_parts();
        Ok(self.session_mut().insert_request_parts(parts).into())
    }

    fn get_header_names(
        &mut self,
        h: Resource<http_req::Request>,
        max_len: u64,
        cursor: u32,
    ) -> Result<(String, Option<u32>), types::Error> {
        let headers = &self.session().request_parts(h.into())?.headers;

        let (buf, next) = get_names(headers.keys(), max_len, cursor)?;

        Ok((buf, next))
    }

    fn get_header_value(
        &mut self,
        h: Resource<http_req::Request>,
        name: String,
        max_len: u64,
    ) -> Result<Option<Vec<u8>>, types::Error> {
        if name.len() > MAX_HEADER_NAME_LEN {
            return Err(Error::InvalidArgument.into());
        }

        let headers = &self.session().request_parts(h.into())?.headers;
        let value = if let Some(value) = headers.get(&name) {
            value
        } else {
            return Ok(None);
        };

        if value.len() > usize::try_from(max_len).unwrap() {
            return Err(types::Error::BufferLen(u64::try_from(value.len()).unwrap()));
        }

        Ok(Some(value.as_bytes().to_owned()))
    }

    fn get_header_values(
        &mut self,
        h: Resource<http_req::Request>,
        name: String,
        max_len: u64,
        cursor: u32,
    ) -> Result<(Vec<u8>, Option<u32>), types::Error> {
        let headers = &self.session().request_parts(h.into()).unwrap().headers;

        let (buf, next) = get_values(headers, &name, max_len, cursor)?;

        Ok((buf, next))
    }

    fn set_header_values(
        &mut self,
        h: Resource<http_req::Request>,
        name: String,
        values: Vec<u8>,
    ) -> Result<(), types::Error> {
        if name.len() > MAX_HEADER_NAME_LEN {
            return Err(Error::InvalidArgument.into());
        }

        let headers = &mut self.session_mut().request_parts_mut(h.into())?.headers;

        let name = HeaderName::from_bytes(name.as_bytes())?;
        let values = {
            // split slice along nul bytes
            let mut iter = values.split(|b| *b == 0);
            // drop the empty item at the end
            iter.next_back();
            iter.map(HeaderValue::from_bytes)
                .collect::<Result<Vec<HeaderValue>, _>>()?
        };

        // Remove any values if they exist
        if let http::header::Entry::Occupied(e) = headers.entry(&name) {
            e.remove_entry_mult();
        }

        for value in values {
            headers.append(&name, value);
        }

        Ok(())
    }

    fn insert_header(
        &mut self,
        h: Resource<http_req::Request>,
        name: String,
        value: Vec<u8>,
    ) -> Result<(), types::Error> {
        if name.len() > MAX_HEADER_NAME_LEN {
            return Err(Error::InvalidArgument.into());
        }

        let headers = &mut self.session_mut().request_parts_mut(h.into())?.headers;
        let name = HeaderName::from_bytes(name.as_bytes())?;
        let value = HeaderValue::from_bytes(value.as_slice())?;
        headers.insert(name, value);

        Ok(())
    }

    fn append_header(
        &mut self,
        h: Resource<http_req::Request>,
        name: String,
        value: Vec<u8>,
    ) -> Result<(), types::Error> {
        if name.len() > MAX_HEADER_NAME_LEN {
            return Err(Error::InvalidArgument.into());
        }

        let headers = &mut self.session_mut().request_parts_mut(h.into())?.headers;
        let name = HeaderName::from_bytes(name.as_bytes())?;
        let value = HeaderValue::from_bytes(value.as_slice())?;
        headers.append(name, value);

        Ok(())
    }

    fn remove_header(
        &mut self,
        h: Resource<http_req::Request>,
        name: String,
    ) -> Result<(), types::Error> {
        if name.len() > MAX_HEADER_NAME_LEN {
            return Err(Error::InvalidArgument.into());
        }

        let headers = &mut self.session_mut().request_parts_mut(h.into())?.headers;
        let name = HeaderName::from_bytes(name.as_bytes())?;
        headers.remove(name).ok_or(types::Error::InvalidArgument)?;

        Ok(())
    }

    fn set_method(
        &mut self,
        h: Resource<http_req::Request>,
        method: String,
    ) -> Result<(), types::Error> {
        let method_ref = &mut self.session_mut().request_parts_mut(h.into())?.method;
        *method_ref = Method::from_bytes(method.as_bytes())?;
        Ok(())
    }

    fn set_uri(&mut self, h: Resource<http_req::Request>, uri: String) -> Result<(), types::Error> {
        let uri_ref = &mut self.session_mut().request_parts_mut(h.into())?.uri;
        *uri_ref = Uri::try_from(uri.as_bytes())?;
        Ok(())
    }

    fn get_version(
        &mut self,
        h: Resource<http_req::Request>,
    ) -> Result<http_types::HttpVersion, types::Error> {
        let req = self.session().request_parts(h.into())?;
        let version = http_types::HttpVersion::try_from(req.version)?;
        Ok(version)
    }

    fn set_version(
        &mut self,
        h: Resource<http_req::Request>,
        version: http_types::HttpVersion,
    ) -> Result<(), types::Error> {
        let req = self.session_mut().request_parts_mut(h.into())?;
        req.version = hyper::Version::from(version);
        Ok(())
    }

    fn set_auto_decompress_response(
        &mut self,
        h: Resource<http_req::Request>,
        encodings: http_types::ContentEncodings,
    ) -> Result<(), types::Error> {
        use crate::wiggle_abi::types;

        // NOTE: We're going to hide this flag in the extensions of the request in order to decrease
        // the book-keeping burden inside Session. The flag will get picked up later, in `send_request`.
        let extensions = &mut self.session_mut().request_parts_mut(h.into())?.extensions;

        let encodings = types::ContentEncodings::try_from(encodings.as_array()[0])?;

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

    fn redirect_to_websocket_proxy(
        &mut self,
        _handle: Resource<http_req::Request>,
        _backend: String,
    ) -> Result<(), types::Error> {
        Err(Error::NotAvailable("Redirect to WebSocket proxy").into())
    }

    fn set_framing_headers_mode(
        &mut self,
        _h: Resource<http_req::Request>,
        mode: http_types::FramingHeadersMode,
    ) -> Result<(), types::Error> {
        match mode {
            http_types::FramingHeadersMode::ManuallyFromHeaders => {
                Err(Error::NotAvailable("Manual framing headers").into())
            }
            http_types::FramingHeadersMode::Automatic => Ok(()),
        }
    }

    fn redirect_to_grip_proxy(
        &mut self,
        req_handle: Resource<http_req::Request>,
        backend_name: String,
    ) -> Result<(), types::Error> {
        let request_info = match self.session().request_parts(req_handle.into()) {
            Ok(req) => Some(PushpinRedirectRequestInfo::from_parts(req)),
            Err(_) => {
                // This function can legitimately be called with an invalid request handle;
                // this may happen when the guest uses a legacy API for pushpin redirection.
                // The legacy behavior is equivalent to simply using None.
                None
            }
        };

        let redirect_info = PushpinRedirectInfo {
            backend_name,
            request_info,
        };

        self.session_mut()
            .redirect_downstream_to_pushpin(redirect_info)?;
        Ok(())
    }

    fn drop(&mut self, _request: Resource<http_req::Request>) -> wasmtime::Result<()> {
        Ok(())
    }
}

impl http_req::HostExtraCacheOverrideDetails for ComponentCtx {
    fn drop(
        &mut self,
        _details: Resource<http_req::ExtraCacheOverrideDetails>,
    ) -> wasmtime::Result<()> {
        Ok(())
    }
}
