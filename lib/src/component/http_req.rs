use {
    super::fastly::api::{http_req, http_types, types},
    super::FastlyError,
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
};

const MAX_HEADER_NAME_LEN: usize = (1 << 16) - 1;

#[async_trait::async_trait]
impl http_req::Host for Session {
    async fn method_get(&mut self, h: http_types::RequestHandle) -> Result<String, FastlyError> {
        let req = self.request_parts(h.into())?;
        let req_method = &req.method;
        Ok(req_method.to_string())
    }

    async fn uri_get(&mut self, h: http_types::RequestHandle) -> Result<String, FastlyError> {
        let req = self.request_parts(h.into())?;
        let req_uri = &req.uri;
        Ok(req_uri.to_string())
    }

    async fn cache_override_set(
        &mut self,
        _h: http_types::RequestHandle,
        _tag: http_req::CacheOverrideTag,
        _ttl: Option<u32>,
        _stale_while_revalidate: Option<u32>,
        _sk: Option<String>,
    ) -> Result<(), FastlyError> {
        // For now, we ignore caching directives because we never cache anything
        Ok(())
    }

    async fn downstream_client_ip_addr(&mut self) -> Result<Vec<u8>, FastlyError> {
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

    async fn downstream_tls_cipher_openssl_name(&mut self) -> Result<String, FastlyError> {
        Err(Error::NotAvailable("Client TLS data").into())
    }

    async fn downstream_tls_protocol(&mut self) -> Result<String, FastlyError> {
        Err(Error::NotAvailable("Client TLS data").into())
    }

    async fn downstream_tls_client_hello(&mut self) -> Result<Vec<u8>, FastlyError> {
        Err(Error::NotAvailable("Client TLS data").into())
    }

    async fn downstream_tls_raw_client_certificate(&mut self) -> Result<Vec<u8>, FastlyError> {
        Err(Error::NotAvailable("Client TLS data").into())
    }

    async fn downstream_tls_client_cert_verify_result(&mut self) -> Result<(), FastlyError> {
        Err(Error::NotAvailable("Client TLS data").into())
    }

    async fn downstream_tls_ja3_md5(&mut self) -> Result<Vec<u8>, FastlyError> {
        Err(Error::NotAvailable("Client TLS JA3 hash").into())
    }

    async fn new(&mut self) -> Result<http_types::RequestHandle, FastlyError> {
        let (parts, _) = Request::new(()).into_parts();
        Ok(self.insert_request_parts(parts).into())
    }

    async fn header_names_get(
        &mut self,
        h: http_types::RequestHandle,
    ) -> Result<Vec<String>, FastlyError> {
        let headers = &self.request_parts(h.into())?.headers;
        Ok(headers
            .keys()
            .map(|name| String::from(name.as_str()))
            .collect())
    }

    async fn header_value_get(
        &mut self,
        h: http_types::RequestHandle,
        name: String,
    ) -> Result<Option<String>, FastlyError> {
        if name.len() > MAX_HEADER_NAME_LEN {
            return Err(Error::InvalidArgument.into());
        }

        let headers = &self.request_parts(h.into())?.headers;
        if let Some(value) = headers.get(&name) {
            Ok(Some(String::from(value.to_str()?)))
        } else {
            Ok(None)
        }
    }

    async fn header_values_get(
        &mut self,
        h: http_types::RequestHandle,
        name: String,
    ) -> Result<Option<Vec<String>>, FastlyError> {
        if name.len() > MAX_HEADER_NAME_LEN {
            return Err(Error::InvalidArgument.into());
        }

        let headers = &self.request_parts(h.into())?.headers;
        let mut values = Vec::new();
        for value in headers.get_all(&name).iter() {
            values.push(String::from(value.to_str()?));
        }

        if values.is_empty() {
            Ok(None)
        } else {
            Ok(Some(values))
        }
    }

    async fn header_values_set(
        &mut self,
        h: http_types::RequestHandle,
        name: String,
        values: Vec<String>,
    ) -> Result<(), FastlyError> {
        if name.len() > MAX_HEADER_NAME_LEN {
            return Err(Error::InvalidArgument.into());
        }

        let headers = &mut self.request_parts_mut(h.into())?.headers;

        let name = HeaderName::from_bytes(name.as_bytes())?;

        // Remove any values if they exist
        if let http::header::Entry::Occupied(e) = headers.entry(&name) {
            e.remove_entry_mult();
        }

        // Add all the new values
        for value in values {
            headers.append(&name, HeaderValue::from_bytes(value.as_bytes())?);
        }

        Ok(())
    }

    async fn header_insert(
        &mut self,
        h: http_types::RequestHandle,
        name: String,
        value: String,
    ) -> Result<(), FastlyError> {
        if name.len() > MAX_HEADER_NAME_LEN {
            return Err(Error::InvalidArgument.into());
        }

        let headers = &mut self.request_parts_mut(h.into())?.headers;
        let name = HeaderName::from_bytes(name.as_bytes())?;
        let value = HeaderValue::from_bytes(value.as_bytes())?;
        headers.insert(name, value);

        Ok(())
    }

    async fn header_append(
        &mut self,
        h: http_types::RequestHandle,
        name: String,
        value: String,
    ) -> Result<(), FastlyError> {
        if name.len() > MAX_HEADER_NAME_LEN {
            return Err(Error::InvalidArgument.into());
        }

        let headers = &mut self.request_parts_mut(h.into())?.headers;
        let name = HeaderName::from_bytes(name.as_bytes())?;
        let value = HeaderValue::from_bytes(value.as_bytes())?;
        headers.append(name, value);

        Ok(())
    }

    async fn header_remove(
        &mut self,
        h: http_types::RequestHandle,
        name: String,
    ) -> Result<(), FastlyError> {
        if name.len() > MAX_HEADER_NAME_LEN {
            return Err(Error::InvalidArgument.into());
        }

        let headers = &mut self.request_parts_mut(h.into())?.headers;
        let name = HeaderName::from_bytes(name.as_bytes())?;
        headers
            .remove(name)
            .ok_or(FastlyError::from(types::Error::InvalidArgument))?;

        Ok(())
    }

    async fn method_set(
        &mut self,
        h: http_types::RequestHandle,
        method: String,
    ) -> Result<(), FastlyError> {
        let method_ref = &mut self.request_parts_mut(h.into())?.method;
        *method_ref = Method::from_bytes(method.as_bytes())?;
        Ok(())
    }

    async fn uri_set(
        &mut self,
        h: http_types::RequestHandle,
        uri: String,
    ) -> Result<(), FastlyError> {
        let uri_ref = &mut self.request_parts_mut(h.into())?.uri;
        *uri_ref = Uri::try_from(uri.as_bytes())?;
        Ok(())
    }

    async fn version_get(
        &mut self,
        h: http_types::RequestHandle,
    ) -> Result<http_types::HttpVersion, FastlyError> {
        let req = self.request_parts(h.into())?;
        let version = http_types::HttpVersion::try_from(req.version)?;
        Ok(version)
    }

    async fn version_set(
        &mut self,
        h: http_types::RequestHandle,
        version: http_types::HttpVersion,
    ) -> Result<(), FastlyError> {
        let req = self.request_parts_mut(h.into())?;
        req.version = hyper::Version::from(version);
        Ok(())
    }

    async fn send(
        &mut self,
        h: http_types::RequestHandle,
        b: http_types::BodyHandle,
        backend_name: String,
    ) -> Result<http_types::Response, FastlyError> {
        // prepare the request
        let req_parts = self.take_request_parts(h.into())?;
        let req_body = self.take_body(b.into())?;
        let req = Request::from_parts(req_parts, req_body);
        let backend = self
            .backend(&backend_name)
            .ok_or(FastlyError::from(types::Error::UnknownError))?;

        // synchronously send the request
        let resp = upstream::send_request(req, backend, self.tls_config()).await?;
        let (resp_handle, body_handle) = self.insert_response(resp);
        Ok((resp_handle.into(), body_handle.into()))
    }

    async fn send_async(
        &mut self,
        h: http_types::RequestHandle,
        b: http_types::BodyHandle,
        backend_name: String,
    ) -> Result<http_types::PendingRequestHandle, FastlyError> {
        // prepare the request
        let req_parts = self.take_request_parts(h.into())?;
        let req_body = self.take_body(b.into())?;
        let req = Request::from_parts(req_parts, req_body);
        let backend = self
            .backend(&backend_name)
            .ok_or(FastlyError::from(types::Error::UnknownError))?;

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
    ) -> Result<http_types::PendingRequestHandle, FastlyError> {
        // prepare the request
        let req_parts = self.take_request_parts(h.into())?;
        let req_body = self.begin_streaming(b.into())?;
        let req = Request::from_parts(req_parts, req_body);
        let backend = self
            .backend(&backend_name)
            .ok_or(FastlyError::from(types::Error::UnknownError))?;

        // asynchronously send the request
        let task =
            PeekableTask::spawn(upstream::send_request(req, backend, self.tls_config())).await;

        // return a handle to the pending request
        Ok(self.insert_pending_request(task).into())
    }

    async fn pending_req_poll(
        &mut self,
        h: http_types::PendingRequestHandle,
    ) -> Result<Option<http_types::Response>, FastlyError> {
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

    async fn pending_req_wait(
        &mut self,
        h: http_types::PendingRequestHandle,
    ) -> Result<http_types::Response, FastlyError> {
        let pending_req = self.take_pending_request(h.into())?.recv().await?;
        let (resp_handle, body_handle) = self.insert_response(pending_req);
        Ok((resp_handle.into(), body_handle.into()))
    }

    async fn pending_req_select(
        &mut self,
        h: Vec<http_types::PendingRequestHandle>,
    ) -> Result<(u32, http_types::Response), FastlyError> {
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

    async fn close(&mut self, h: http_types::RequestHandle) -> Result<(), FastlyError> {
        // We don't do anything with the parts, but we do pass the error up if
        // the handle given doesn't exist
        self.take_request_parts(h.into())?;
        Ok(())
    }

    async fn auto_decompress_response_set(
        &mut self,
        h: http_types::RequestHandle,
        encodings: http_types::ContentEncodings,
    ) -> Result<(), FastlyError> {
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

    async fn upgrade_websocket(&mut self, _backend: String) -> Result<(), FastlyError> {
        Err(Error::NotAvailable("WebSocket upgrade").into())
    }

    async fn redirect_to_websocket_proxy(&mut self, _backend: String) -> Result<(), FastlyError> {
        Err(Error::NotAvailable("Redirect to WebSocket proxy").into())
    }

    async fn redirect_to_grip_proxy(&mut self, _backend: String) -> Result<(), FastlyError> {
        Err(Error::NotAvailable("Redirect to Fanout/GRIP proxy").into())
    }

    async fn framing_headers_mode_set(
        &mut self,
        _h: http_types::RequestHandle,
        mode: http_types::FramingHeadersMode,
    ) -> Result<(), FastlyError> {
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
        config: http_types::DynamicBackendConfig,
    ) -> Result<(), FastlyError> {
        let name = prefix.as_str();
        let origin_name = target.as_str();

        let override_host = if let Some(override_host) = config.host_override {
            if override_host.is_empty() {
                return Err(types::Error::InvalidArgument.into());
            }

            if override_host.len() > 1024 {
                return Err(types::Error::InvalidArgument.into());
            }

            Some(HeaderValue::from_bytes(override_host.as_bytes())?)
        } else {
            None
        };

        let scheme = if config.use_ssl.unwrap_or(false) {
            "https"
        } else {
            "http"
        };

        let mut cert_host = if let Some(cert_host) = config.cert_hostname {
            if cert_host.is_empty() {
                return Err(types::Error::InvalidArgument.into());
            }

            if cert_host.len() > 1024 {
                return Err(types::Error::InvalidArgument.into());
            }

            Some(cert_host)
        } else {
            None
        };

        let use_sni = if let Some(sni_hostname) = config.sni_hostname {
            if sni_hostname.len() > 1024 {
                return Err(types::Error::InvalidArgument.into());
            }

            if sni_hostname.is_empty() {
                false
            } else {
                if let Some(cert_host) = &cert_host {
                    if cert_host != &sni_hostname {
                        // because we're using rustls, we cannot support distinct SNI and cert hostnames
                        return Err(types::Error::InvalidArgument.into());
                    }
                } else {
                    cert_host = Some(sni_hostname.to_owned());
                }

                true
            }
        } else {
            true
        };

        let client_cert = if let Some(cert) = config.client_cert {
            let key_lookup =
                self.secret_lookup(cert.client_key.into())
                    .ok_or(Error::SecretStoreError(
                        SecretStoreError::InvalidSecretHandle(cert.client_key.into()),
                    ))?;
            let key = match &key_lookup {
                SecretLookup::Standard {
                    store_name,
                    secret_name,
                } => self
                    .secret_stores()
                    .get_store(store_name)
                    .ok_or(Error::SecretStoreError(
                        SecretStoreError::InvalidSecretHandle(cert.client_key.into()),
                    ))?
                    .get_secret(secret_name)
                    .ok_or(Error::SecretStoreError(
                        SecretStoreError::InvalidSecretHandle(cert.client_key.into()),
                    ))?
                    .plaintext(),

                SecretLookup::Injected { plaintext } => plaintext,
            };

            Some(ClientCertInfo::new(
                cert.client_cert.as_str().as_bytes(),
                key,
            )?)
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

    async fn downstream_client_h2_fingerprint(&mut self) -> Result<Vec<u8>, FastlyError> {
        Err(Error::NotAvailable("Client H2 fingerprint").into())
    }

    async fn downstream_client_request_id(&mut self) -> Result<String, FastlyError> {
        Ok(format!("{:032x}", self.req_id()))
    }

    async fn original_header_names_get(&mut self) -> Result<Vec<String>, FastlyError> {
        Ok(self
            .downstream_original_headers()
            .keys()
            .map(|name| String::from(name.as_str()))
            .collect())
    }

    async fn original_header_count(&mut self) -> Result<u32, FastlyError> {
        Ok(self
            .downstream_original_headers()
            .len()
            .try_into()
            .expect("More than u32::MAX headers"))
    }
}
