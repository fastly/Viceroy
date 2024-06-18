use {
    super::{
        fastly::api::{http_req, http_types, types},
        headers::write_values,
        types::TrappableError,
    },
    crate::{
        config::{Backend, ClientCertInfo},
        error::Error,
        secret_store::SecretLookup,
        session::{AsyncItem, AsyncItemHandle, PeekableTask, Session, ViceroyRequestMetadata},
        upstream,
        wiggle_abi::SecretStoreError,
    },
    fastly_shared::{INVALID_BODY_HANDLE, INVALID_RESPONSE_HANDLE},
    http::{
        header::{HeaderName, HeaderValue},
        request::Request,
        Method, Uri,
    },
    std::str::FromStr,
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

#[async_trait::async_trait]
impl http_req::Host for Session {
    async fn method_get(
        &mut self,
        h: http_types::RequestHandle,
        max_len: u64,
    ) -> Result<String, types::Error> {
        let req = self.request_parts(h.into())?;
        let req_method = &req.method;

        if req_method.as_str().len() > usize::try_from(max_len).unwrap() {
            return Err(types::Error::BufferLen(
                u64::try_from(req_method.as_str().len()).unwrap(),
            ));
        }

        Ok(req_method.to_string())
    }

    async fn uri_get(
        &mut self,
        h: http_types::RequestHandle,
        max_len: u64,
    ) -> Result<String, types::Error> {
        let req = self.request_parts(h.into())?;
        let req_uri = &req.uri;
        let res = req_uri.to_string();

        if res.len() > usize::try_from(max_len).unwrap() {
            return Err(types::Error::BufferLen(u64::try_from(res.len()).unwrap()));
        }

        Ok(res)
    }

    async fn cache_override_set(
        &mut self,
        _h: http_types::RequestHandle,
        _tag: http_req::CacheOverrideTag,
        _ttl: u32,
        _stale_while_revalidate: u32,
    ) -> Result<(), types::Error> {
        // For now, we ignore caching directives because we never cache anything
        Ok(())
    }

    async fn cache_override_v2_set(
        &mut self,
        _h: http_types::RequestHandle,
        _tag: http_req::CacheOverrideTag,
        _ttl: u32,
        _stale_while_revalidate: u32,
        _sk: Option<String>,
    ) -> Result<(), types::Error> {
        // For now, we ignore caching directives because we never cache anything
        Ok(())
    }

    async fn downstream_client_ip_addr(&mut self) -> Result<Vec<u8>, types::Error> {
        use std::net::IpAddr;
        match self.downstream_client_ip() {
            IpAddr::V4(addr) => {
                let octets = addr.octets();
                debug_assert_eq!(octets.len(), 4);
                Ok(Vec::from(octets))
            }
            IpAddr::V6(addr) => {
                let octets = addr.octets();
                debug_assert_eq!(octets.len(), 16);
                Ok(Vec::from(octets))
            }
        }
    }

    async fn downstream_server_ip_addr(&mut self) -> Result<Vec<u8>, types::Error> {
        Err(Error::NotAvailable("Downstream server ip address").into())
    }

    async fn downstream_tls_cipher_openssl_name(
        &mut self,
        _max_len: u64,
    ) -> Result<String, types::Error> {
        Err(Error::NotAvailable("Client TLS data").into())
    }

    async fn downstream_tls_protocol(&mut self, _max_len: u64) -> Result<String, types::Error> {
        Err(Error::NotAvailable("Client TLS data").into())
    }

    async fn downstream_tls_client_hello(
        &mut self,
        _max_len: u64,
    ) -> Result<Vec<u8>, types::Error> {
        Err(Error::NotAvailable("Client TLS data").into())
    }

    async fn downstream_tls_raw_client_certificate(
        &mut self,
        _max_len: u64,
    ) -> Result<Vec<u8>, types::Error> {
        Err(Error::NotAvailable("Client TLS data").into())
    }

    async fn downstream_tls_client_cert_verify_result(
        &mut self,
    ) -> Result<http_req::ClientCertVerifyResult, types::Error> {
        Err(Error::NotAvailable("Client TLS data").into())
    }

    async fn downstream_tls_ja3_md5(&mut self) -> Result<Vec<u8>, types::Error> {
        Err(Error::NotAvailable("Client TLS JA3 hash").into())
    }

    async fn new(&mut self) -> Result<http_types::RequestHandle, types::Error> {
        let (parts, _) = Request::new(()).into_parts();
        Ok(self.insert_request_parts(parts).into())
    }

    async fn header_names_get(
        &mut self,
        h: http_types::RequestHandle,
        max_len: u64,
        cursor: u32,
    ) -> Result<Option<(Vec<u8>, Option<u32>)>, types::Error> {
        let headers = &self.request_parts(h.into())?.headers;

        let (buf, next) = write_values(
            headers.keys(),
            b'\0',
            usize::try_from(max_len).unwrap(),
            cursor,
        )
        .map_err(|needed| types::Error::BufferLen(u64::try_from(needed).unwrap_or(0)))?;

        // At this point we know that the buffer being empty will also mean that there are no
        // remaining entries to read.
        if buf.is_empty() {
            debug_assert!(next.is_none());
            Ok(None)
        } else {
            Ok(Some((buf, next)))
        }
    }

    async fn header_value_get(
        &mut self,
        h: http_types::RequestHandle,
        name: String,
        max_len: u64,
    ) -> Result<Option<Vec<u8>>, types::Error> {
        if name.len() > MAX_HEADER_NAME_LEN {
            return Err(Error::InvalidArgument.into());
        }

        let headers = &self.request_parts(h.into())?.headers;
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

    async fn header_values_get(
        &mut self,
        h: http_types::RequestHandle,
        name: String,
        max_len: u64,
        cursor: u32,
    ) -> Result<Option<(Vec<u8>, Option<u32>)>, TrappableError> {
        let headers = &self.request_parts(h.into())?.headers;

        let values = headers.get_all(HeaderName::from_str(&name)?);

        let (buf, next) = write_values(
            values.into_iter(),
            b'\0',
            usize::try_from(max_len).unwrap(),
            cursor,
        )
        .map_err(|needed| types::Error::BufferLen(u64::try_from(needed).unwrap_or(0)))?;

        // At this point we know that the buffer being empty will also mean that there are no
        // remaining entries to read.
        if buf.is_empty() {
            debug_assert!(next.is_none());
            Ok(None)
        } else {
            Ok(Some((buf, next)))
        }
    }

    async fn header_values_set(
        &mut self,
        h: http_types::RequestHandle,
        name: String,
        values: Vec<u8>,
    ) -> Result<(), types::Error> {
        if name.len() > MAX_HEADER_NAME_LEN {
            return Err(Error::InvalidArgument.into());
        }

        let headers = &mut self.request_parts_mut(h.into())?.headers;

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

    async fn header_insert(
        &mut self,
        h: http_types::RequestHandle,
        name: String,
        value: Vec<u8>,
    ) -> Result<(), types::Error> {
        if name.len() > MAX_HEADER_NAME_LEN {
            return Err(Error::InvalidArgument.into());
        }

        let headers = &mut self.request_parts_mut(h.into())?.headers;
        let name = HeaderName::from_bytes(name.as_bytes())?;
        let value = HeaderValue::from_bytes(value.as_slice())?;
        headers.insert(name, value);

        Ok(())
    }

    async fn header_append(
        &mut self,
        h: http_types::RequestHandle,
        name: String,
        value: Vec<u8>,
    ) -> Result<(), types::Error> {
        if name.len() > MAX_HEADER_NAME_LEN {
            return Err(Error::InvalidArgument.into());
        }

        let headers = &mut self.request_parts_mut(h.into())?.headers;
        let name = HeaderName::from_bytes(name.as_bytes())?;
        let value = HeaderValue::from_bytes(value.as_slice())?;
        headers.append(name, value);

        Ok(())
    }

    async fn header_remove(
        &mut self,
        h: http_types::RequestHandle,
        name: String,
    ) -> Result<(), types::Error> {
        if name.len() > MAX_HEADER_NAME_LEN {
            return Err(Error::InvalidArgument.into());
        }

        let headers = &mut self.request_parts_mut(h.into())?.headers;
        let name = HeaderName::from_bytes(name.as_bytes())?;
        headers
            .remove(name)
            .ok_or(types::Error::from(types::Error::InvalidArgument))?;

        Ok(())
    }

    async fn method_set(
        &mut self,
        h: http_types::RequestHandle,
        method: String,
    ) -> Result<(), types::Error> {
        let method_ref = &mut self.request_parts_mut(h.into())?.method;
        *method_ref = Method::from_bytes(method.as_bytes())?;
        Ok(())
    }

    async fn uri_set(
        &mut self,
        h: http_types::RequestHandle,
        uri: String,
    ) -> Result<(), types::Error> {
        let uri_ref = &mut self.request_parts_mut(h.into())?.uri;
        *uri_ref = Uri::try_from(uri.as_bytes())?;
        Ok(())
    }

    async fn version_get(
        &mut self,
        h: http_types::RequestHandle,
    ) -> Result<http_types::HttpVersion, types::Error> {
        let req = self.request_parts(h.into())?;
        let version = http_types::HttpVersion::try_from(req.version)?;
        Ok(version)
    }

    async fn version_set(
        &mut self,
        h: http_types::RequestHandle,
        version: http_types::HttpVersion,
    ) -> Result<(), types::Error> {
        let req = self.request_parts_mut(h.into())?;
        req.version = hyper::Version::from(version);
        Ok(())
    }

    async fn send(
        &mut self,
        h: http_types::RequestHandle,
        b: http_types::BodyHandle,
        backend_name: String,
    ) -> Result<http_types::Response, types::Error> {
        // prepare the request
        let req_parts = self.take_request_parts(h.into())?;
        let req_body = self.take_body(b.into())?;
        let req = Request::from_parts(req_parts, req_body);
        let backend = self
            .backend(&backend_name)
            .ok_or(types::Error::from(types::Error::UnknownError))?;

        // synchronously send the request
        let resp = upstream::send_request(req, backend, self.tls_config()).await?;
        let (resp_handle, body_handle) = self.insert_response(resp);
        Ok((resp_handle.into(), body_handle.into()))
    }

    async fn send_v2(
        &mut self,
        h: http_types::RequestHandle,
        b: http_types::BodyHandle,
        backend_name: String,
    ) -> Result<http_types::Response, (Option<http_req::SendErrorDetail>, types::Error)> {
        // This initial implementation ignores the error detail field
        self.send(h, b, backend_name)
            .await
            .map_err(types::Error::with_empty_detail)
    }

    async fn send_async(
        &mut self,
        h: http_types::RequestHandle,
        b: http_types::BodyHandle,
        backend_name: String,
    ) -> Result<http_types::PendingRequestHandle, types::Error> {
        // prepare the request
        let req_parts = self.take_request_parts(h.into())?;
        let req_body = self.take_body(b.into())?;
        let req = Request::from_parts(req_parts, req_body);
        let backend = self
            .backend(&backend_name)
            .ok_or(types::Error::from(types::Error::UnknownError))?;

        // asynchronously send the request
        let task =
            PeekableTask::spawn(upstream::send_request(req, backend, self.tls_config())).await;

        // return a handle to the pending request
        Ok(self.insert_pending_request(task).into())
    }

    async fn send_async_streaming(
        &mut self,
        h: http_types::RequestHandle,
        b: http_types::BodyHandle,
        backend_name: String,
    ) -> Result<http_types::PendingRequestHandle, types::Error> {
        // prepare the request
        let req_parts = self.take_request_parts(h.into())?;
        let req_body = self.begin_streaming(b.into())?;
        let req = Request::from_parts(req_parts, req_body);
        let backend = self
            .backend(&backend_name)
            .ok_or(types::Error::from(types::Error::UnknownError))?;

        // asynchronously send the request
        let task =
            PeekableTask::spawn(upstream::send_request(req, backend, self.tls_config())).await;

        // return a handle to the pending request
        Ok(self.insert_pending_request(task).into())
    }

    async fn pending_req_poll(
        &mut self,
        h: http_types::PendingRequestHandle,
    ) -> Result<Option<http_types::Response>, types::Error> {
        if self
            .async_item_mut(AsyncItemHandle::from_u32(h))?
            .is_ready()
        {
            let resp = self.take_pending_request(h.into())?.recv().await?;
            let (resp_handle, resp_body_handle) = self.insert_response(resp);
            Ok(Some((resp_handle.into(), resp_body_handle.into())))
        } else {
            Ok(None)
        }
    }

    async fn pending_req_poll_v2(
        &mut self,
        h: http_types::PendingRequestHandle,
    ) -> Result<Option<http_types::Response>, (Option<http_req::SendErrorDetail>, types::Error)>
    {
        self.pending_req_poll(h)
            .await
            .map_err(types::Error::with_empty_detail)
    }

    async fn pending_req_wait(
        &mut self,
        h: http_types::PendingRequestHandle,
    ) -> Result<http_types::Response, types::Error> {
        let pending_req = self.take_pending_request(h.into())?.recv().await?;
        let (resp_handle, body_handle) = self.insert_response(pending_req);
        Ok((resp_handle.into(), body_handle.into()))
    }

    async fn pending_req_wait_v2(
        &mut self,
        h: http_types::PendingRequestHandle,
    ) -> Result<http_types::Response, (Option<http_req::SendErrorDetail>, types::Error)> {
        self.pending_req_wait(h)
            .await
            .map_err(types::Error::with_empty_detail)
    }

    async fn pending_req_select(
        &mut self,
        h: Vec<http_types::PendingRequestHandle>,
    ) -> Result<(u32, http_types::Response), types::Error> {
        use crate::wiggle_abi::types;

        if h.is_empty() {
            return Err(Error::InvalidArgument.into());
        }

        // perform the select operation
        let done_index = self
            .select_impl(
                h.iter()
                    .map(|handle| types::PendingRequestHandle::from(*handle).into()),
            )
            .await?;

        let item = self.take_async_item(
            types::PendingRequestHandle::from(h.get(done_index).cloned().unwrap()).into(),
        )?;

        let outcome = match item {
            AsyncItem::PendingReq(res) => match res {
                PeekableTask::Complete(resp) => match resp {
                    Ok(resp) => {
                        let (resp_handle, body_handle) = self.insert_response(resp);
                        (done_index as u32, (resp_handle.into(), body_handle.into()))
                    }
                    // Unfortunately, the ABI provides no means of returning error information
                    // from completed `select`.
                    Err(_) => (
                        done_index as u32,
                        (INVALID_RESPONSE_HANDLE, INVALID_BODY_HANDLE),
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
        h: Vec<http_types::PendingRequestHandle>,
    ) -> Result<(u32, http_types::Response), (Option<http_req::SendErrorDetail>, types::Error)>
    {
        self.pending_req_select(h)
            .await
            .map_err(types::Error::with_empty_detail)
    }

    async fn fastly_key_is_valid(&mut self) -> Result<bool, types::Error> {
        Err(Error::NotAvailable("FASTLY_KEY is valid").into())
    }

    async fn close(&mut self, h: http_types::RequestHandle) -> Result<(), types::Error> {
        // We don't do anything with the parts, but we do pass the error up if
        // the handle given doesn't exist
        self.take_request_parts(h.into())?;
        Ok(())
    }

    async fn auto_decompress_response_set(
        &mut self,
        h: http_types::RequestHandle,
        encodings: http_types::ContentEncodings,
    ) -> Result<(), types::Error> {
        use crate::wiggle_abi::types;

        // NOTE: We're going to hide this flag in the extensions of the request in order to decrease
        // the book-keeping burden inside Session. The flag will get picked up later, in `send_request`.
        let extensions = &mut self.request_parts_mut(h.into())?.extensions;

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

    async fn upgrade_websocket(&mut self, _backend: String) -> Result<(), types::Error> {
        Err(Error::NotAvailable("WebSocket upgrade").into())
    }

    async fn redirect_to_websocket_proxy(&mut self, _backend: String) -> Result<(), types::Error> {
        Err(Error::NotAvailable("Redirect to WebSocket proxy").into())
    }

    async fn redirect_to_websocket_proxy_v2(
        &mut self,
        _handle: http_req::RequestHandle,
        _backend: String,
    ) -> Result<(), types::Error> {
        Err(Error::NotAvailable("Redirect to WebSocket proxy").into())
    }

    async fn redirect_to_grip_proxy(&mut self, _backend: String) -> Result<(), types::Error> {
        Err(Error::NotAvailable("Redirect to Fanout/GRIP proxy").into())
    }

    async fn redirect_to_grip_proxy_v2(
        &mut self,
        _handle: http_req::RequestHandle,
        _backend: String,
    ) -> Result<(), types::Error> {
        Err(Error::NotAvailable("Redirect to Fanout/GRIP proxy").into())
    }

    async fn framing_headers_mode_set(
        &mut self,
        _h: http_types::RequestHandle,
        mode: http_types::FramingHeadersMode,
    ) -> Result<(), types::Error> {
        match mode {
            http_types::FramingHeadersMode::ManuallyFromHeaders => {
                Err(Error::NotAvailable("Manual framing headers").into())
            }
            http_types::FramingHeadersMode::Automatic => Ok(()),
        }
    }

    async fn register_dynamic_backend(
        &mut self,
        prefix: String,
        target: String,
        options: http_types::BackendConfigOptions,
        config: http_types::DynamicBackendConfig,
    ) -> Result<(), types::Error> {
        let name = prefix.as_str();
        let origin_name = target.as_str();

        let override_host = if options.contains(http_types::BackendConfigOptions::HOST_OVERRIDE) {
            if config.host_override.is_empty() {
                return Err(types::Error::InvalidArgument.into());
            }

            if config.host_override.len() > 1024 {
                return Err(types::Error::InvalidArgument.into());
            }

            Some(HeaderValue::from_bytes(config.host_override.as_bytes())?)
        } else {
            None
        };

        let scheme = if options.contains(http_types::BackendConfigOptions::USE_SSL) {
            "https"
        } else {
            "http"
        };

        let mut cert_host = if options.contains(http_types::BackendConfigOptions::CERT_HOSTNAME) {
            if config.cert_hostname.is_empty() {
                return Err(types::Error::InvalidArgument.into());
            }

            if config.cert_hostname.len() > 1024 {
                return Err(types::Error::InvalidArgument.into());
            }

            Some(config.cert_hostname)
        } else {
            None
        };

        let use_sni = if options.contains(http_types::BackendConfigOptions::SNI_HOSTNAME) {
            if config.sni_hostname.len() > 1024 {
                return Err(types::Error::InvalidArgument.into());
            }

            if config.sni_hostname.is_empty() {
                false
            } else {
                if let Some(cert_host) = &cert_host {
                    if cert_host != &config.sni_hostname {
                        // because we're using rustls, we cannot support distinct SNI and cert hostnames
                        return Err(types::Error::InvalidArgument.into());
                    }
                } else {
                    cert_host = Some(config.sni_hostname);
                }

                true
            }
        } else {
            true
        };

        let client_cert = if options.contains(http_types::BackendConfigOptions::CLIENT_CERT) {
            let key_lookup =
                self.secret_lookup(config.client_key.into())
                    .ok_or(Error::SecretStoreError(
                        SecretStoreError::InvalidSecretHandle(config.client_key.into()),
                    ))?;
            let key = match &key_lookup {
                SecretLookup::Standard {
                    store_name,
                    secret_name,
                } => self
                    .secret_stores()
                    .get_store(store_name)
                    .ok_or(Error::SecretStoreError(
                        SecretStoreError::InvalidSecretHandle(config.client_key.into()),
                    ))?
                    .get_secret(secret_name)
                    .ok_or(Error::SecretStoreError(
                        SecretStoreError::InvalidSecretHandle(config.client_key.into()),
                    ))?
                    .plaintext(),

                SecretLookup::Injected { plaintext } => plaintext,
            };

            Some(ClientCertInfo::new(config.client_cert.as_bytes(), key)?)
        } else {
            None
        };

        let grpc = false;

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
            ca_certs: Vec::new(),
        };

        if !self.add_backend(name, new_backend) {
            return Err(Error::BackendNameRegistryError(name.to_string()).into());
        }

        Ok(())
    }

    async fn downstream_client_h2_fingerprint(
        &mut self,
        _max_len: u64,
    ) -> Result<Vec<u8>, types::Error> {
        Err(Error::NotAvailable("Client H2 fingerprint").into())
    }

    async fn downstream_client_request_id(&mut self, max_len: u64) -> Result<String, types::Error> {
        let result = format!("{:032x}", self.req_id());

        if result.len() > usize::try_from(max_len).unwrap() {
            return Err(types::Error::BufferLen(
                u64::try_from(result.len()).unwrap(),
            ));
        }

        Ok(result)
    }

    async fn downstream_client_oh_fingerprint(
        &mut self,
        _max_len: u64,
    ) -> Result<Vec<u8>, types::Error> {
        Err(Error::NotAvailable("Client original header fingerprint").into())
    }

    async fn downstream_tls_ja4(&mut self, _max_len: u64) -> Result<Vec<u8>, types::Error> {
        Err(Error::NotAvailable("Client TLS JA4 hash").into())
    }

    async fn downstream_compliance_region(
        &mut self,
        _max_len: u64,
    ) -> Result<Vec<u8>, types::Error> {
        Err(Error::NotAvailable("Client TLS JA4 hash").into())
    }

    async fn original_header_names_get(
        &mut self,
        _max_len: u64,
        _cursor: u32,
    ) -> Result<Option<(Vec<u8>, Option<u32>)>, types::Error> {
        Err(Error::NotAvailable("Client Compliance Region").into())
    }

    async fn original_header_count(&mut self) -> Result<u32, types::Error> {
        Ok(self
            .downstream_original_headers()
            .len()
            .try_into()
            .expect("More than u32::MAX headers"))
    }
}
