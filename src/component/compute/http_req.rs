use {
    crate::component::{
        compute::headers::{get_names, get_values},
        fastly::compute::{http_body, http_req, http_resp, http_types, types},
    },
    crate::{
        config::{Backend, ClientCertInfo},
        error::Error,
        linking::{ComponentCtx, SessionView},
        pushpin::{PushpinRedirectInfo, PushpinRedirectRequestInfo},
        secret_store::SecretLookup,
        session::{PeekableTask, ViceroyRequestMetadata},
        upstream,
        wiggle_abi::types::SecretHandle,
        wiggle_abi::SecretStoreError,
    },
    http::{
        header::{HeaderName, HeaderValue},
        request::Request,
        Method, Uri,
    },
    std::mem::take,
    wasmtime::component::Resource,
    wasmtime_wasi::p2::IoView,
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
            .session()
            .backend(&backend_name)
            .ok_or_else(|| Error::UnknownBackend(backend_name))
            .map_err(Into::into)
            .map_err(types::Error::with_empty_detail)?;

        // synchronously send the request
        // This initial implementation ignores the error detail field
        let resp = upstream::send_request(req, backend, self.session().tls_config())
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
            .session()
            .backend(&backend_name)
            .ok_or(types::Error::from(types::Error::GenericError))?;

        // asynchronously send the request
        let task = PeekableTask::spawn(upstream::send_request(
            req,
            backend,
            self.session().tls_config(),
        ))
        .await;

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
            .session()
            .backend(&backend_name)
            .ok_or(types::Error::from(types::Error::GenericError))?;

        // asynchronously send the request
        let task = PeekableTask::spawn(upstream::send_request(
            req,
            backend,
            self.session().tls_config(),
        ))
        .await;

        // return a handle to the pending request
        Ok(self.session_mut().insert_pending_request(task).into())
    }

    async fn await_request(
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

    async fn close(&mut self, h: Resource<http_req::Request>) -> Result<(), types::Error> {
        // We don't do anything with the parts, but we do pass the error up if
        // the handle given doesn't exist
        self.session_mut().take_request_parts(h.into())?;
        Ok(())
    }

    async fn upgrade_websocket(&mut self, _backend: String) -> Result<(), types::Error> {
        Err(Error::NotAvailable("WebSocket upgrade").into())
    }

    async fn register_dynamic_backend(
        &mut self,
        prefix: String,
        target: String,
        options: Resource<http_req::DynamicBackendOptions>,
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
                return Err(types::Error::InvalidArgument.into());
            }

            if cert_hostname.len() > 1024 {
                return Err(types::Error::InvalidArgument.into());
            }

            Some(cert_hostname)
        } else {
            None
        };

        let use_sni = if let Some(sni_hostname) = options.sni_hostname {
            if sni_hostname.is_empty() {
                false
            } else if sni_hostname.len() > 1024 {
                return Err(types::Error::InvalidArgument.into());
            } else {
                if let Some(cert_host) = &cert_host {
                    if cert_host != &sni_hostname {
                        // because we're using rustls, we cannot support distinct SNI and cert hostnames
                        return Err(types::Error::InvalidArgument.into());
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
            let client_key = client_key.into();
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

        if !self.session_mut().add_backend(name, new_backend) {
            return Err(Error::BackendNameRegistryError(name.to_string()).into());
        }

        Ok(())
    }
}

impl http_req::HostRequest for ComponentCtx {
    async fn get_method(
        &mut self,
        h: Resource<http_req::Request>,
        max_len: u64,
    ) -> Result<String, types::Error> {
        let req = self.session().request_parts(h.into())?;
        let req_method = &req.method;

        if req_method.as_str().len() > usize::try_from(max_len).unwrap() {
            return Err(types::Error::BufferLen(
                u64::try_from(req_method.as_str().len()).unwrap(),
            ));
        }

        Ok(req_method.to_string())
    }

    async fn get_uri(
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

    async fn set_cache_override(
        &mut self,
        _h: Resource<http_req::Request>,
        _cache_override: http_req::CacheOverride,
    ) -> Result<(), types::Error> {
        // For now, we ignore caching directives because we never cache anything
        Ok(())
    }

    async fn new(&mut self) -> Result<Resource<http_req::Request>, types::Error> {
        let (parts, _) = Request::new(()).into_parts();
        Ok(self.session_mut().insert_request_parts(parts).into())
    }

    async fn get_header_names(
        &mut self,
        h: Resource<http_req::Request>,
        max_len: u64,
        cursor: u32,
    ) -> Result<(String, Option<u32>), types::Error> {
        let headers = &self.session().request_parts(h.into())?.headers;

        let (buf, next) = get_names(headers.keys(), max_len, cursor)?;

        Ok((buf, next))
    }

    async fn get_header_value(
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

    async fn get_header_values(
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

    async fn set_header_values(
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

    async fn insert_header(
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

    async fn append_header(
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

    async fn remove_header(
        &mut self,
        h: Resource<http_req::Request>,
        name: String,
    ) -> Result<(), types::Error> {
        if name.len() > MAX_HEADER_NAME_LEN {
            return Err(Error::InvalidArgument.into());
        }

        let headers = &mut self.session_mut().request_parts_mut(h.into())?.headers;
        let name = HeaderName::from_bytes(name.as_bytes())?;
        headers
            .remove(name)
            .ok_or(types::Error::from(types::Error::InvalidArgument))?;

        Ok(())
    }

    async fn set_method(
        &mut self,
        h: Resource<http_req::Request>,
        method: String,
    ) -> Result<(), types::Error> {
        let method_ref = &mut self.session_mut().request_parts_mut(h.into())?.method;
        *method_ref = Method::from_bytes(method.as_bytes())?;
        Ok(())
    }

    async fn set_uri(
        &mut self,
        h: Resource<http_req::Request>,
        uri: String,
    ) -> Result<(), types::Error> {
        let uri_ref = &mut self.session_mut().request_parts_mut(h.into())?.uri;
        *uri_ref = Uri::try_from(uri.as_bytes())?;
        Ok(())
    }

    async fn get_version(
        &mut self,
        h: Resource<http_req::Request>,
    ) -> Result<http_types::HttpVersion, types::Error> {
        let req = self.session().request_parts(h.into())?;
        let version = http_types::HttpVersion::try_from(req.version)?;
        Ok(version)
    }

    async fn set_version(
        &mut self,
        h: Resource<http_req::Request>,
        version: http_types::HttpVersion,
    ) -> Result<(), types::Error> {
        let req = self.session_mut().request_parts_mut(h.into())?;
        req.version = hyper::Version::from(version);
        Ok(())
    }

    async fn set_auto_decompress_response(
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

    async fn redirect_to_websocket_proxy(
        &mut self,
        _handle: Resource<http_req::Request>,
        _backend: String,
    ) -> Result<(), types::Error> {
        Err(Error::NotAvailable("Redirect to WebSocket proxy").into())
    }

    async fn set_framing_headers_mode(
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

    async fn redirect_to_grip_proxy(
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

    async fn inspect(
        &mut self,
        ds_req: Resource<http_req::Request>,
        ds_body: Resource<http_body::Body>,
        info: http_req::InspectOptions,
        buf_max_len: u64,
    ) -> Result<String, types::Error> {
        // Make sure we're given valid handles, even though we won't use them.
        let _ = self.session().request_parts(ds_req.into())?;
        let _ = self.session().body(ds_body.into())?;

        // For now, corp and workspace arguments are required to actually generate the hostname,
        // but in the future the lookaside service will be generated using the customer ID, and
        // it will be okay for them to be unspecified or empty.
        if info.corp.is_none() || info.workspace.is_none() {
            return Err(Error::InvalidArgument.into());
        }

        if info.corp.unwrap().is_empty() || info.workspace.unwrap().is_empty() {
            return Err(Error::InvalidArgument.into());
        }

        // Return the mock NGWAF response.
        let ngwaf_resp = self.session().ngwaf_response();
        let ngwaf_resp_len = ngwaf_resp.len();

        match u64::try_from(ngwaf_resp_len) {
            Ok(ngwaf_resp_len) if ngwaf_resp_len <= buf_max_len => Ok(ngwaf_resp),
            too_large => Err(types::Error::BufferLen(too_large.unwrap_or(0))),
        }
    }

    async fn on_behalf_of(
        &mut self,
        _: Resource<http_req::Request>,
        _: String,
    ) -> Result<(), types::Error> {
        Err(Error::Unsupported {
            msg: "http-req.on-behalf-of is not supported in Viceroy",
        }
        .into())
    }

    async fn drop(&mut self, _request: Resource<http_req::Request>) -> wasmtime::Result<()> {
        Ok(())
    }
}

impl http_req::HostExtraCacheOverrideDetails for ComponentCtx {
    async fn drop(
        &mut self,
        _details: Resource<http_req::ExtraCacheOverrideDetails>,
    ) -> wasmtime::Result<()> {
        Ok(())
    }
}

impl http_req::HostExtraInspectOptions for ComponentCtx {
    async fn drop(
        &mut self,
        _options: Resource<http_req::ExtraInspectOptions>,
    ) -> wasmtime::Result<()> {
        Ok(())
    }
}

impl http_req::HostDynamicBackendOptions for ComponentCtx {
    async fn new(&mut self) -> wasmtime::Result<Resource<http_req::DynamicBackendOptions>> {
        let builder = BackendBuilder::default();

        Ok(self.table().push(builder)?)
    }

    async fn host_override(
        &mut self,
        config: Resource<http_req::DynamicBackendOptions>,
        value: String,
    ) {
        self.table().get_mut(&config).unwrap().host_override = Some(value);
    }
    async fn connect_timeout(
        &mut self,
        config: Resource<http_req::DynamicBackendOptions>,
        value: u32,
    ) {
        self.table().get_mut(&config).unwrap().connect_timeout = value;
    }
    async fn first_byte_timeout(
        &mut self,
        config: Resource<http_req::DynamicBackendOptions>,
        value: u32,
    ) {
        self.table().get_mut(&config).unwrap().first_byte_timeout = value;
    }
    async fn between_bytes_timeout(
        &mut self,
        config: Resource<http_req::DynamicBackendOptions>,
        value: u32,
    ) {
        self.table().get_mut(&config).unwrap().between_bytes_timeout = value;
    }
    async fn use_tls(&mut self, config: Resource<http_req::DynamicBackendOptions>, value: bool) {
        self.table().get_mut(&config).unwrap().use_tls = value;
    }
    async fn tls_min_version(
        &mut self,
        config: Resource<http_req::DynamicBackendOptions>,
        value: http_req::TlsVersion,
    ) {
        self.table().get_mut(&config).unwrap().tls_min_version = Some(value);
    }
    async fn tls_max_version(
        &mut self,
        config: Resource<http_req::DynamicBackendOptions>,
        value: http_req::TlsVersion,
    ) {
        self.table().get_mut(&config).unwrap().tls_max_version = Some(value);
    }
    async fn cert_hostname(
        &mut self,
        config: Resource<http_req::DynamicBackendOptions>,
        value: String,
    ) {
        self.table().get_mut(&config).unwrap().cert_hostname = Some(value);
    }
    async fn ca_cert(&mut self, config: Resource<http_req::DynamicBackendOptions>, value: String) {
        self.table().get_mut(&config).unwrap().ca_cert = Some(value);
    }
    async fn ciphers(&mut self, config: Resource<http_req::DynamicBackendOptions>, value: String) {
        self.table().get_mut(&config).unwrap().ciphers = Some(value);
    }
    async fn sni_hostname(
        &mut self,
        config: Resource<http_req::DynamicBackendOptions>,
        value: String,
    ) {
        self.table().get_mut(&config).unwrap().sni_hostname = Some(value);
    }
    async fn client_cert(
        &mut self,
        config: Resource<http_req::DynamicBackendOptions>,
        client_cert: String,
        client_key: Resource<http_req::Secret>,
    ) {
        let client_key = SecretHandle::from(client_key);
        self.table().get_mut(&config).unwrap().client_cert = Some((client_cert, client_key));
    }
    async fn http_keepalive_time_ms(
        &mut self,
        config: Resource<http_req::DynamicBackendOptions>,
        value: u32,
    ) {
        let config = self.table().get_mut(&config).unwrap();
        config.keepalive = true;
        config.http_keepalive_time_ms = value;
    }
    async fn tcp_keepalive_enable(
        &mut self,
        config: Resource<http_req::DynamicBackendOptions>,
        value: u32,
    ) {
        let config = self.table().get_mut(&config).unwrap();
        config.keepalive = true;
        config.tcp_keepalive_enable = value;
    }
    async fn tcp_keepalive_interval_secs(
        &mut self,
        config: Resource<http_req::DynamicBackendOptions>,
        value: u32,
    ) {
        let config = self.table().get_mut(&config).unwrap();
        config.keepalive = true;
        config.tcp_keepalive_interval_secs = value;
    }
    async fn tcp_keepalive_probes(
        &mut self,
        config: Resource<http_req::DynamicBackendOptions>,
        value: u32,
    ) {
        let config = self.table().get_mut(&config).unwrap();
        config.keepalive = true;
        config.tcp_keepalive_probes = value;
    }
    async fn tcp_keepalive_time_secs(
        &mut self,
        config: Resource<http_req::DynamicBackendOptions>,
        value: u32,
    ) {
        let config = self.table().get_mut(&config).unwrap();
        config.keepalive = true;
        config.tcp_keepalive_time_secs = value;
    }
    async fn grpc(&mut self, config: Resource<http_req::DynamicBackendOptions>, value: bool) {
        self.table().get_mut(&config).unwrap().grpc = value;
    }
    async fn pooling(&mut self, config: Resource<http_req::DynamicBackendOptions>, value: bool) {
        self.table().get_mut(&config).unwrap().pooling = value;
    }

    async fn drop(
        &mut self,
        options: Resource<http_req::DynamicBackendOptions>,
    ) -> wasmtime::Result<()> {
        self.table().delete(options).unwrap();
        Ok(())
    }
}

#[derive(Debug)]
pub struct BackendBuilder {
    host_override: Option<String>,
    connect_timeout: u32,
    first_byte_timeout: u32,
    between_bytes_timeout: u32,
    use_tls: bool,
    tls_min_version: Option<http_req::TlsVersion>,
    tls_max_version: Option<http_req::TlsVersion>,
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
            grpc: false,
            pooling: true,
        }
    }
}
