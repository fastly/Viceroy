//! Session type and related facilities.

mod async_item;
mod downstream;

pub use async_item::{
    AsyncItem, PeekableTask, PendingKvDeleteTask, PendingKvInsertTask, PendingKvLookupTask,
};

use std::collections::HashMap;
use std::future::Future;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use {
    self::downstream::DownstreamResponse,
    crate::{
        body::Body,
        config::{Backend, Backends, DeviceDetection, Dictionaries, Geolocation, LoadedDictionary},
        error::{Error, HandleError},
        logging::LogEndpoint,
        object_store::{ObjectKey, ObjectStoreError, ObjectStoreKey, ObjectStores},
        secret_store::{SecretLookup, SecretStores},
        streaming_body::StreamingBody,
        upstream::{SelectTarget, TlsConfig},
        wiggle_abi::types::{
            self, BodyHandle, ContentEncodings, DictionaryHandle, EndpointHandle,
            ObjectStoreHandle, PendingKvDeleteHandle, PendingKvInsertHandle, PendingKvLookupHandle,
            PendingRequestHandle, RequestHandle, ResponseHandle, SecretHandle, SecretStoreHandle,
        },
        ExecuteCtx,
    },
    cranelift_entity::{entity_impl, PrimaryMap},
    futures::future::{self, FutureExt},
    http::{request, response, HeaderMap, Request, Response},
    tokio::sync::oneshot::Sender,
};

/// Data specific to an individual request, including any host-side
/// allocations on behalf of the guest processing the request.
pub struct Session {
    /// The downstream IP address and port for this session.
    downstream_client_addr: SocketAddr,
    /// The IP address and port that received this session.
    downstream_server_addr: SocketAddr,
    /// Handle for the downstream request "parts". NB the backing parts data can be mutated
    /// or even removed from the relevant map.
    downstream_req_handle: RequestHandle,
    /// Handle for the downstream request body. NB the backing body data can be mutated
    /// or even removed from the relevant map.
    downstream_req_body_handle: BodyHandle,
    /// A copy of the [`Parts`][parts] for the downstream request.
    ///
    /// This copy is populated prior to guest execution, and never mutated.
    ///
    /// [parts]: https://docs.rs/http/latest/http/request/struct.Parts.html
    downstream_req_original_headers: HeaderMap,
    /// A channel for sending a [`Response`][resp] downstream to the client.
    ///
    /// [resp]: https://docs.rs/http/latest/http/response/struct.Response.html
    downstream_resp: DownstreamResponse,
    /// A handle map for items that provide blocking operations. These items are grouped together
    /// in order to support generic async operations that work across different object types.
    async_items: PrimaryMap<AsyncItemHandle, Option<AsyncItem>>,
    /// A handle map for the component [`Parts`][parts] of the session's HTTP [`Request`][req]s.
    ///
    /// [parts]: https://docs.rs/http/latest/http/request/struct.Parts.html
    /// [req]: https://docs.rs/http/latest/http/request/struct.Request.html
    req_parts: PrimaryMap<RequestHandle, Option<request::Parts>>,
    /// A handle map for the component [`Parts`][parts] of the session's HTTP [`Response`][resp]s.
    ///
    /// [parts]: https://docs.rs/http/latest/http/response/struct.Parts.html
    /// [resp]: https://docs.rs/http/latest/http/response/struct.Response.html
    resp_parts: PrimaryMap<ResponseHandle, Option<response::Parts>>,
    /// Where to direct logging endpoint messages.
    capture_logs: Arc<Mutex<dyn Write + Send>>,
    /// A handle map for logging endpoints.
    log_endpoints: PrimaryMap<EndpointHandle, LogEndpoint>,
    /// A by-name map for logging endpoints.
    log_endpoints_by_name: HashMap<Vec<u8>, EndpointHandle>,
    /// The backends configured for this execution.
    ///
    /// Populated prior to guest execution, and never modified.
    backends: Arc<Backends>,
    /// The Device Detection configured for this execution.
    ///
    /// Populated prior to guest execution, and never modified.
    device_detection: Arc<DeviceDetection>,
    /// The Geolocations configured for this execution.
    ///
    /// Populated prior to guest execution, and never modified.
    geolocation: Arc<Geolocation>,
    /// The backends dynamically added by the program. This is separated from
    /// `backends` because we do not want one session to effect the backends
    /// available to any other session.
    dynamic_backends: Backends,
    /// The TLS configuration for this execution.
    ///
    /// Populated prior to guest execution, and never modified.
    tls_config: TlsConfig,
    /// The dictionaries configured for this execution.
    ///
    /// Populated prior to guest execution, and never modified.
    dictionaries: Arc<Dictionaries>,
    /// The dictionaries that have been opened by the guest.
    loaded_dictionaries: PrimaryMap<DictionaryHandle, LoadedDictionary>,
    /// The ObjectStore configured for this execution.
    ///
    /// Populated prior to guest execution and can be modified during requests.
    pub(crate) object_store: ObjectStores,
    /// The object stores configured for this execution.
    ///
    /// Populated prior to guest execution.
    object_store_by_name: PrimaryMap<ObjectStoreHandle, ObjectStoreKey>,
    /// The secret stores configured for this execution.
    ///
    /// Populated prior to guest execution, and never modified.
    secret_stores: Arc<SecretStores>,
    /// The secret stores configured for this execution.
    ///
    /// Populated prior to guest execution, and never modified.
    secret_stores_by_name: PrimaryMap<SecretStoreHandle, String>,
    /// The secrets for this execution.
    ///
    /// Populated prior to guest execution, and never modified.
    secrets_by_name: PrimaryMap<SecretHandle, SecretLookup>,
    /// The path to the configuration file used for this invocation of Viceroy.
    ///
    /// Created prior to guest execution, and never modified.
    config_path: Arc<Option<PathBuf>>,
    /// The ID for the client request being processed.
    req_id: u64,
}

impl Session {
    /// Create an empty session.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        req_id: u64,
        req: Request<Body>,
        resp_sender: Sender<Response<Body>>,
        server_addr: SocketAddr,
        client_addr: SocketAddr,
        ctx: &ExecuteCtx,
        backends: Arc<Backends>,
        device_detection: Arc<DeviceDetection>,
        geolocation: Arc<Geolocation>,
        tls_config: TlsConfig,
        dictionaries: Arc<Dictionaries>,
        config_path: Arc<Option<PathBuf>>,
        object_store: ObjectStores,
        secret_stores: Arc<SecretStores>,
    ) -> Session {
        let (parts, body) = req.into_parts();
        let downstream_req_original_headers = parts.headers.clone();

        let mut async_items: PrimaryMap<AsyncItemHandle, Option<AsyncItem>> = PrimaryMap::new();
        let mut req_parts = PrimaryMap::new();

        let downstream_req_handle = req_parts.push(Some(parts));
        let downstream_req_body_handle = async_items.push(Some(AsyncItem::Body(body))).into();

        Session {
            downstream_server_addr: server_addr,
            downstream_client_addr: client_addr,
            downstream_req_handle,
            downstream_req_body_handle,
            downstream_req_original_headers,
            async_items,
            req_parts,
            resp_parts: PrimaryMap::new(),
            downstream_resp: DownstreamResponse::new(resp_sender),
            capture_logs: ctx.capture_logs(),
            log_endpoints: PrimaryMap::new(),
            log_endpoints_by_name: HashMap::new(),
            backends,
            device_detection,
            geolocation,
            dynamic_backends: Backends::default(),
            tls_config,
            dictionaries,
            loaded_dictionaries: PrimaryMap::new(),
            object_store,
            object_store_by_name: PrimaryMap::new(),
            secret_stores,
            secret_stores_by_name: PrimaryMap::new(),
            secrets_by_name: PrimaryMap::new(),
            config_path,
            req_id,
        }
    }

    // ----- Downstream Request API -----

    /// Retrieve the downstream client IP address associated with this session.
    pub fn downstream_client_ip(&self) -> IpAddr {
        self.downstream_client_addr.ip()
    }

    /// Retrieve the IP address the downstream client connected to for this session.
    pub fn downstream_server_ip(&self) -> IpAddr {
        self.downstream_server_addr.ip()
    }

    /// Retrieve the handle corresponding to the downstream request.
    pub fn downstream_request(&self) -> RequestHandle {
        self.downstream_req_handle
    }

    /// Retrieve the handle corresponding to the downstream request body.
    pub fn downstream_request_body(&self) -> BodyHandle {
        self.downstream_req_body_handle
    }

    /// Access the header map that was copied from the original downstream request.
    pub fn downstream_original_headers(&self) -> &HeaderMap {
        &self.downstream_req_original_headers
    }

    // ----- Downstream Response API -----

    /// Send the downstream response.
    ///
    /// Yield an error if a response has already been sent.
    ///
    /// # Panics
    ///
    /// This method must only be called once, *after* a channel has been opened with
    /// [`Session::set_downstream_response_sender`][set], and *before* the associated
    /// [oneshot::Receiver][receiver] has been dropped.
    ///
    /// This method will panic if:
    ///   * the downstream response channel was never opened
    ///   * the associated receiver was dropped prematurely
    ///
    /// [set]: struct.Session.html#method.set_downstream_response_sender
    /// [receiver]: https://docs.rs/tokio/latest/tokio/sync/oneshot/struct.Receiver.html
    pub fn send_downstream_response(&mut self, resp: Response<Body>) -> Result<(), Error> {
        self.downstream_resp.send(resp)
    }

    /// Close the downstream response sender, potentially without sending any response.
    pub fn close_downstream_response_sender(&mut self) {
        self.downstream_resp.close()
    }

    // ----- Bodies API -----

    /// Insert a [`Body`][body] into the session.
    ///
    /// This method returns the [`BodyHandle`][handle], which can then be used to access and mutate
    /// the response parts.
    ///
    /// [handle]: ../wiggle_abi/types/struct.BodyHandle.html
    /// [body]: ../body/struct.Body.html
    pub fn insert_body(&mut self, body: Body) -> BodyHandle {
        self.async_items.push(Some(AsyncItem::Body(body))).into()
    }

    /// Get a reference to a [`Body`][body], given its [`BodyHandle`][handle].
    ///
    /// Returns a [`HandleError`][err] if the handle is not associated with a body in the session.
    ///
    /// [body]: ../body/struct.Body.html
    /// [err]: ../error/enum.HandleError.html
    /// [handle]: ../wiggle_abi/types/struct.BodyHandle.html
    pub fn body(&self, handle: BodyHandle) -> Result<&Body, HandleError> {
        self.async_items
            .get(handle.into())
            .and_then(Option::as_ref)
            .and_then(AsyncItem::as_body)
            .ok_or(HandleError::InvalidBodyHandle(handle))
    }

    /// Get a mutable reference to a [`Body`][body], given its [`BodyHandle`][handle].
    ///
    /// Returns a [`HandleError`][err] if the handle is not associated with a body in the session.
    ///
    /// [body]: ../body/struct.Body.html
    /// [err]: ../error/enum.HandleError.html
    /// [handle]: ../wiggle_abi/types/struct.BodyHandle.html
    pub fn body_mut(&mut self, handle: BodyHandle) -> Result<&mut Body, HandleError> {
        self.async_items
            .get_mut(handle.into())
            .and_then(Option::as_mut)
            .and_then(AsyncItem::as_body_mut)
            .ok_or(HandleError::InvalidBodyHandle(handle))
    }

    /// Take ownership of a [`Body`][body], given its [`BodyHandle`][handle].
    ///
    /// Returns a [`HandleError`][err] if the handle is not associated with a body in the session.
    ///
    /// [body]: ../body/struct.Body.html
    /// [err]: ../error/enum.HandleError.html
    /// [handle]: ../wiggle_abi/types/struct.BodyHandle.html
    pub fn take_body(&mut self, handle: BodyHandle) -> Result<Body, HandleError> {
        self.async_items
            .get_mut(handle.into())
            .and_then(Option::take)
            .and_then(AsyncItem::into_body)
            .ok_or(HandleError::InvalidBodyHandle(handle))
    }

    /// Drop a [`Body`][crate::body::Body] from the [`Session`], given its [`BodyHandle`][crate::wiggle_abi::types::BodyHandle].
    ///
    /// Returns a [`HandleError`][crate::error::HandleError] if the handle is not associated with a body in the session.
    pub fn drop_body(&mut self, handle: BodyHandle) -> Result<(), HandleError> {
        self.async_items
            .get_mut(handle.into())
            .and_then(Option::take)
            .map(drop)
            .ok_or(HandleError::InvalidBodyHandle(handle))
    }

    /// Transition a normal [`Body`][body] into the write end of a streaming body, returning
    /// the original body with the read end appended.
    ///
    /// Returns a [`HandleError`][err] if the handle is not associated with a body in the session.
    ///
    /// [body]: ../body/struct.Body.html
    /// [err]: ../error/enum.HandleError.html
    pub fn begin_streaming(&mut self, handle: BodyHandle) -> Result<Body, HandleError> {
        self.async_items
            .get_mut(handle.into())
            .and_then(Option::as_mut)
            .and_then(AsyncItem::begin_streaming)
            .ok_or(HandleError::InvalidBodyHandle(handle))
    }

    /// Returns `true` if and only if the provided `BodyHandle` is the downstream body being sent.
    ///
    /// To get a mutable reference to the streaming body `Sender`, see
    /// [`Session::streaming_body_mut`](struct.Session.html#method.streaming_body_mut).
    pub fn is_streaming_body(&self, handle: BodyHandle) -> bool {
        if let Some(Some(body)) = self.async_items.get(handle.into()) {
            body.is_streaming()
        } else {
            false
        }
    }

    /// Get a mutable reference to the streaming body `Sender`, if and only if the provided
    /// `BodyHandle` is the downstream body being sent.
    ///
    /// To check if a handle is the currently-streaming downstream response body, see
    /// [`Session::is_streaming_body`](struct.Session.html#method.is_streaming_body).
    ///
    /// Returns a [`HandleError`][err] if the handle is not associated with a body in the session.
    ///
    /// [err]: ../error/enum.HandleError.html
    pub fn streaming_body_mut(
        &mut self,
        handle: BodyHandle,
    ) -> Result<&mut StreamingBody, HandleError> {
        self.async_items
            .get_mut(handle.into())
            .and_then(Option::as_mut)
            .and_then(AsyncItem::as_streaming_mut)
            .ok_or(HandleError::InvalidBodyHandle(handle))
    }

    /// Take ownership of a streaming body `Sender`, if and only if the provided
    /// `BodyHandle` is the downstream body being sent.
    ///
    /// To check if a handle is the currently-streaming downstream response body, see
    /// [`Session::is_streaming_body`](struct.Session.html#method.is_streaming_body).
    ///
    /// Returns a [`HandleError`][err] if the handle is not associated with a body in the session.
    ///
    /// [err]: ../error/enum.HandleError.html
    pub fn take_streaming_body(
        &mut self,
        handle: BodyHandle,
    ) -> Result<StreamingBody, HandleError> {
        self.async_items
            .get_mut(handle.into())
            .and_then(Option::take)
            .and_then(AsyncItem::into_streaming)
            .ok_or(HandleError::InvalidBodyHandle(handle))
    }

    // ----- Request Parts API -----

    /// Insert the [`Parts`][parts] of a [`Request`][req] into the session.
    ///
    /// This method returns a new [`RequestHandle`][handle], which can then be used to access
    /// and mutate the request parts.
    ///
    /// [handle]: ../wiggle_abi/types/struct.RequestHandle.html
    /// [parts]: https://docs.rs/http/latest/http/request/struct.Parts.html
    /// [req]: https://docs.rs/http/latest/http/request/struct.Request.html
    pub fn insert_request_parts(&mut self, parts: request::Parts) -> RequestHandle {
        self.req_parts.push(Some(parts))
    }

    /// Get a reference to the [`Parts`][parts] of a [`Request`][req], given its
    /// [`RequestHandle`][handle].
    ///
    /// Returns a [`HandleError`][err] if the handle is not associated with a request in the
    /// session.
    ///
    /// [err]: ../error/enum.HandleError.html
    /// [handle]: ../wiggle_abi/types/struct.RequestHandle.html
    /// [parts]: https://docs.rs/http/latest/http/request/struct.Parts.html
    /// [req]: https://docs.rs/http/latest/http/request/struct.Request.html
    pub fn request_parts(&self, handle: RequestHandle) -> Result<&request::Parts, HandleError> {
        self.req_parts
            .get(handle)
            .and_then(Option::as_ref)
            .ok_or(HandleError::InvalidRequestHandle(handle))
    }

    /// Get a mutable reference to the [`Parts`][parts] of a [`Request`][req], given its
    /// [`RequestHandle`][handle].
    ///
    /// Returns a [`HandleError`][err] if the handle is not associated with a request in the
    /// session.
    ///
    /// [err]: ../error/enum.HandleError.html
    /// [handle]: ../wiggle_abi/types/struct.RequestHandle.html
    /// [parts]: https://docs.rs/http/latest/http/request/struct.Parts.html
    /// [req]: https://docs.rs/http/latest/http/request/struct.Request.html
    pub fn request_parts_mut(
        &mut self,
        handle: RequestHandle,
    ) -> Result<&mut request::Parts, HandleError> {
        self.req_parts
            .get_mut(handle)
            .and_then(Option::as_mut)
            .ok_or(HandleError::InvalidRequestHandle(handle))
    }

    /// Take ownership of the [`Parts`][parts] of a [`Request`][req], given its
    /// [`RequestHandle`][handle].
    ///
    /// Returns a [`HandleError`][err] if the handle is not associated with a request in the
    /// session.
    ///
    /// [err]: ../error/enum.HandleError.html
    /// [handle]: ../wiggle_abi/types/struct.RequestHandle.html
    /// [parts]: https://docs.rs/http/latest/http/request/struct.Parts.html
    /// [req]: https://docs.rs/http/latest/http/request/struct.Request.html
    pub fn take_request_parts(
        &mut self,
        handle: RequestHandle,
    ) -> Result<request::Parts, HandleError> {
        self.req_parts
            .get_mut(handle)
            .and_then(Option::take)
            .ok_or(HandleError::InvalidRequestHandle(handle))
    }

    // ----- Response Parts API -----

    /// Insert the [`Parts`][parts] of a [`Response`][resp] into the session.
    ///
    /// This method returns a new [`ResponseHandle`][handle], which can then be used to access
    /// and mutate the response parts.
    ///
    /// [handle]: ../wiggle_abi/types/struct.ResponseHandle.html
    /// [parts]: https://docs.rs/http/latest/http/response/struct.Parts.html
    /// [resp]: https://docs.rs/http/latest/http/response/struct.Response.html
    pub fn insert_response_parts(&mut self, parts: response::Parts) -> ResponseHandle {
        self.resp_parts.push(Some(parts))
    }

    /// Get a reference to the [`Parts`][parts] of a [`Response`][resp], given its
    /// [`ResponseHandle`][handle].
    ///
    /// Returns a [`HandleError`][err] if the handle is not associated with a response in the
    /// session.
    ///
    /// [err]: ../error/enum.HandleError.html
    /// [handle]: ../wiggle_abi/types/struct.ResponseHandle.html
    /// [parts]: https://docs.rs/http/latest/http/response/struct.Parts.html
    /// [resp]: https://docs.rs/http/latest/http/response/struct.Response.html
    pub fn response_parts(&self, handle: ResponseHandle) -> Result<&response::Parts, HandleError> {
        self.resp_parts
            .get(handle)
            .and_then(Option::as_ref)
            .ok_or(HandleError::InvalidResponseHandle(handle))
    }

    /// Get a mutable reference to the [`Parts`][parts] of a [`Response`][resp], given its
    /// [`ResponseHandle`][handle].
    ///
    /// Returns a [`HandleError`][err] if the handle is not associated with a response in the
    /// session.
    ///
    /// [err]: ../error/enum.HandleError.html
    /// [handle]: ../wiggle_abi/types/struct.ResponseHandle.html
    /// [parts]: https://docs.rs/http/latest/http/response/struct.Parts.html
    /// [resp]: https://docs.rs/http/latest/http/response/struct.Response.html
    pub fn response_parts_mut(
        &mut self,
        handle: ResponseHandle,
    ) -> Result<&mut response::Parts, HandleError> {
        self.resp_parts
            .get_mut(handle)
            .and_then(Option::as_mut)
            .ok_or(HandleError::InvalidResponseHandle(handle))
    }

    /// Take ownership of the [`Parts`][parts] of a [`Response`][resp], given its
    /// [`ResponseHandle`][handle].
    ///
    /// Returns a [`HandleError`][err] if the handle is not associated with a response in the
    /// session.
    ///
    /// [err]: ../error/enum.HandleError.html
    /// [handle]: ../wiggle_abi/types/struct.ResponseHandle.html
    /// [parts]: https://docs.rs/http/latest/http/response/struct.Parts.html
    /// [resp]: https://docs.rs/http/latest/http/response/struct.Response.html
    pub fn take_response_parts(
        &mut self,
        handle: ResponseHandle,
    ) -> Result<response::Parts, HandleError> {
        self.resp_parts
            .get_mut(handle)
            .and_then(Option::take)
            .ok_or(HandleError::InvalidResponseHandle(handle))
    }

    pub fn insert_response(&mut self, resp: Response<Body>) -> (ResponseHandle, BodyHandle) {
        let (resp_parts, resp_body) = resp.into_parts();
        let resp_handle = self.insert_response_parts(resp_parts);
        let body_handle = self.insert_body(resp_body);
        (resp_handle, body_handle)
    }

    // ----- Logging Endpoints API -----

    /// Get an [`EndpointHandle`][handle] from the session, corresponding to the provided
    /// endpoint name. A new backing [`LogEndpoint`] will be created if one does not
    /// already exist.
    ///
    /// [handle]: ../wiggle_abi/types/struct.EndpointHandle.html
    /// [endpoint]: ../logging/struct.LogEndpoint.html
    pub fn log_endpoint_handle(&mut self, name: &[u8]) -> EndpointHandle {
        if let Some(handle) = self.log_endpoints_by_name.get(name).copied() {
            return handle;
        }
        let endpoint = LogEndpoint::new(name, self.capture_logs.clone());
        let handle = self.log_endpoints.push(endpoint);
        self.log_endpoints_by_name.insert(name.to_owned(), handle);
        handle
    }

    /// Get a reference to a [`LogEndpoint`][endpoint], given its [`EndpointHandle`][handle].
    ///
    /// Returns a [`HandleError`][err] if the handle is not associated with an endpoint in the
    /// session.
    ///
    /// [err]: ../error/enum.HandleError.html
    /// [handle]: ../wiggle_abi/types/struct.EndpointHandle.html
    /// [endpoint]: ../logging/struct.LogEndpoint.html
    pub fn log_endpoint(&self, handle: EndpointHandle) -> Result<&LogEndpoint, HandleError> {
        self.log_endpoints
            .get(handle)
            .ok_or(HandleError::InvalidEndpointHandle(handle))
    }

    // ----- Backends API -----

    /// Look up a backend by name.
    pub fn backend(&self, name: &str) -> Option<&Arc<Backend>> {
        // it doesn't actually matter what order we do this search, because
        // the namespaces should be unique.
        self.backends
            .get(name)
            .or_else(|| self.dynamic_backends.get(name))
    }

    /// Look up a dynamic backend (only) by name.
    pub fn dynamic_backend(&self, name: &str) -> Option<&Arc<Backend>> {
        self.dynamic_backends.get(name)
    }

    /// Return the full list of static and dynamic backend names as an [`Iterator`].
    pub fn backend_names(&self) -> impl Iterator<Item = &String> {
        self.backends.keys().chain(self.dynamic_backends.keys())
    }

    /// Try to add a backend with the given name prefix to our set of current backends.
    /// Upon success, return true. If the name already exists somewhere, return false;
    /// the caller should signal an appropriate error.
    pub fn add_backend(&mut self, name: &str, info: Backend) -> bool {
        // if this name already exists, either as a built in or dynamic backend, say no
        if self.backends.contains_key(name) || self.dynamic_backends.contains_key(name) {
            return false;
        }

        self.dynamic_backends
            .insert(name.to_string(), Arc::new(info));

        true
    }

    // ----- TLS config -----

    /// Access the TLS configuration.
    pub fn tls_config(&self) -> &TlsConfig {
        &self.tls_config
    }

    // ----- Device Detection API -----

    pub fn device_detection_lookup(&self, user_agent: &str) -> Option<String> {
        self.device_detection
            .lookup(user_agent)
            .map(|data| data.to_string())
    }

    // ----- Dictionaries API -----

    /// Look up a dictionary-handle by name.
    pub fn dictionary_handle(&mut self, name: &str) -> Result<DictionaryHandle, Error> {
        if let Some(dict) = self.dictionaries.get(name) {
            let loaded = dict.load().map_err(|err| Error::Other(err.into()))?;
            Ok(self.loaded_dictionaries.push(loaded))
        } else {
            Err(Error::DictionaryError(
                crate::wiggle_abi::DictionaryError::UnknownDictionary(name.to_owned()),
            ))
        }
    }

    /// Look up a dictionary by dictionary-handle.
    pub fn dictionary(&self, handle: DictionaryHandle) -> Result<&LoadedDictionary, HandleError> {
        self.loaded_dictionaries
            .get(handle)
            .ok_or(HandleError::InvalidDictionaryHandle(handle))
    }

    /// Access the dictionary map.
    pub fn dictionaries(&self) -> &Arc<Dictionaries> {
        &self.dictionaries
    }

    // ----- Geolocation API -----

    pub fn geolocation_lookup(&self, addr: &IpAddr) -> Option<String> {
        self.geolocation.lookup(addr).map(|data| data.to_string())
    }

    // ----- Object Store API -----
    pub fn obj_store_handle(&mut self, key: &str) -> Result<ObjectStoreHandle, Error> {
        let obj_key = ObjectStoreKey::new(key);
        Ok(self.object_store_by_name.push(obj_key))
    }

    pub fn get_obj_store_key(&self, handle: ObjectStoreHandle) -> Option<&ObjectStoreKey> {
        self.object_store_by_name.get(handle)
    }

    pub fn obj_insert(
        &self,
        obj_store_key: ObjectStoreKey,
        obj_key: ObjectKey,
        obj: Vec<u8>,
    ) -> Result<(), ObjectStoreError> {
        self.object_store.insert(obj_store_key, obj_key, obj)
    }

    /// Insert a [`PendingKvInsert`] into the session.
    ///
    /// This method returns a new [`PendingKvInsertHandle`], which can then be used to access
    /// and mutate the pending insert.
    pub fn insert_pending_kv_insert(
        &mut self,
        pending: PendingKvInsertTask,
    ) -> PendingKvInsertHandle {
        self.async_items
            .push(Some(AsyncItem::PendingKvInsert(pending)))
            .into()
    }

    /// Take ownership of a [`PendingKvInsert`], given its [`PendingKvInsertHandle`].
    ///
    /// Returns a [`HandleError`] if the handle is not associated with a pending insert in the
    /// session.
    pub fn take_pending_kv_insert(
        &mut self,
        handle: PendingKvInsertHandle,
    ) -> Result<PendingKvInsertTask, HandleError> {
        // check that this is a pending request before removing it
        let _ = self.pending_kv_insert(handle)?;

        self.async_items
            .get_mut(handle.into())
            .and_then(Option::take)
            .and_then(AsyncItem::into_pending_kv_insert)
            .ok_or(HandleError::InvalidPendingKvInsertHandle(handle))
    }

    /// Get a reference to a [`PendingInsert`], given its [`PendingKvInsertHandle`].
    ///
    /// Returns a [`HandleError`] if the handle is not associated with a insert in the
    /// session.
    pub fn pending_kv_insert(
        &self,
        handle: PendingKvInsertHandle,
    ) -> Result<&PendingKvInsertTask, HandleError> {
        self.async_items
            .get(handle.into())
            .and_then(Option::as_ref)
            .and_then(AsyncItem::as_pending_kv_insert)
            .ok_or(HandleError::InvalidPendingKvInsertHandle(handle))
    }

    pub fn obj_delete(
        &self,
        obj_store_key: ObjectStoreKey,
        obj_key: ObjectKey,
    ) -> Result<(), ObjectStoreError> {
        self.object_store.delete(obj_store_key, obj_key)
    }

    /// Insert a [`PendingKvDelete`] into the session.
    ///
    /// This method returns a new [`PendingKvDeleteHandle`], which can then be used to access
    /// and mutate the pending delete.
    pub fn insert_pending_kv_delete(
        &mut self,
        pending: PendingKvDeleteTask,
    ) -> PendingKvDeleteHandle {
        self.async_items
            .push(Some(AsyncItem::PendingKvDelete(pending)))
            .into()
    }

    /// Take ownership of a [`PendingKvDelete`], given its [`PendingKvDeleteHandle`].
    ///
    /// Returns a [`HandleError`] if the handle is not associated with a pending delete in the
    /// session.
    pub fn take_pending_kv_delete(
        &mut self,
        handle: PendingKvDeleteHandle,
    ) -> Result<PendingKvDeleteTask, HandleError> {
        // check that this is a pending request before removing it
        let _ = self.pending_kv_delete(handle)?;

        self.async_items
            .get_mut(handle.into())
            .and_then(Option::take)
            .and_then(AsyncItem::into_pending_kv_delete)
            .ok_or(HandleError::InvalidPendingKvDeleteHandle(handle))
    }

    /// Get a reference to a [`PendingDelete`], given its [`PendingKvDeleteHandle`].
    ///
    /// Returns a [`HandleError`] if the handle is not associated with a delete in the
    /// session.
    pub fn pending_kv_delete(
        &self,
        handle: PendingKvDeleteHandle,
    ) -> Result<&PendingKvDeleteTask, HandleError> {
        self.async_items
            .get(handle.into())
            .and_then(Option::as_ref)
            .and_then(AsyncItem::as_pending_kv_delete)
            .ok_or(HandleError::InvalidPendingKvDeleteHandle(handle))
    }

    pub fn obj_lookup(
        &self,
        obj_store_key: &ObjectStoreKey,
        obj_key: &ObjectKey,
    ) -> Result<Vec<u8>, ObjectStoreError> {
        self.object_store.lookup(obj_store_key, obj_key)
    }

    /// Insert a [`PendingLookup`] into the session.
    ///
    /// This method returns a new [`PendingKvLookupHandle`], which can then be used to access
    /// and mutate the pending lookup.
    pub fn insert_pending_kv_lookup(
        &mut self,
        pending: PendingKvLookupTask,
    ) -> PendingKvLookupHandle {
        self.async_items
            .push(Some(AsyncItem::PendingKvLookup(pending)))
            .into()
    }

    /// Take ownership of a [`PendingLookup`], given its [`PendingKvLookupHandle`].
    ///
    /// Returns a [`HandleError`] if the handle is not associated with a pending lookup in the
    /// session.
    pub fn take_pending_kv_lookup(
        &mut self,
        handle: PendingKvLookupHandle,
    ) -> Result<PendingKvLookupTask, HandleError> {
        // check that this is a pending request before removing it
        let _ = self.pending_kv_lookup(handle)?;

        self.async_items
            .get_mut(handle.into())
            .and_then(Option::take)
            .and_then(AsyncItem::into_pending_kv_lookup)
            .ok_or(HandleError::InvalidPendingKvLookupHandle(handle))
    }

    /// Get a reference to a [`PendingLookup`], given its [`PendingKvLookupHandle`].
    ///
    /// Returns a [`HandleError`] if the handle is not associated with a lookup in the
    /// session.
    pub fn pending_kv_lookup(
        &self,
        handle: PendingKvLookupHandle,
    ) -> Result<&PendingKvLookupTask, HandleError> {
        self.async_items
            .get(handle.into())
            .and_then(Option::as_ref)
            .and_then(AsyncItem::as_pending_kv_lookup)
            .ok_or(HandleError::InvalidPendingKvLookupHandle(handle))
    }

    // ----- Secret Store API -----

    pub fn secret_store_handle(&mut self, name: &str) -> Option<SecretStoreHandle> {
        self.secret_stores.get_store(name)?;
        Some(self.secret_stores_by_name.push(name.to_string()))
    }

    pub fn secret_store_name(&self, handle: SecretStoreHandle) -> Option<String> {
        self.secret_stores_by_name.get(handle).cloned()
    }

    pub fn secret_handle(&mut self, store_name: &str, secret_name: &str) -> Option<SecretHandle> {
        self.secret_stores
            .get_store(store_name)?
            .get_secret(secret_name)?;
        Some(self.secrets_by_name.push(SecretLookup::Standard {
            store_name: store_name.to_string(),
            secret_name: secret_name.to_string(),
        }))
    }

    pub fn secret_lookup(&self, handle: SecretHandle) -> Option<SecretLookup> {
        self.secrets_by_name.get(handle).cloned()
    }

    pub fn add_secret(&mut self, plaintext: Vec<u8>) -> SecretHandle {
        self.secrets_by_name
            .push(SecretLookup::Injected { plaintext })
    }

    pub fn secret_stores(&self) -> &Arc<SecretStores> {
        &self.secret_stores
    }

    // ----- Pending Requests API -----

    /// Insert a [`PendingRequest`] into the session.
    ///
    /// This method returns a new [`PendingRequestHandle`], which can then be used to access
    /// and mutate the pending request.
    pub fn insert_pending_request(
        &mut self,
        pending: PeekableTask<Response<Body>>,
    ) -> PendingRequestHandle {
        self.async_items
            .push(Some(AsyncItem::PendingReq(pending)))
            .into()
    }

    /// Get a reference to a [`PendingRequest`], given its [`PendingRequestHandle`].
    ///
    /// Returns a [`HandleError`] if the handle is not associated with a request in the
    /// session.
    pub fn pending_request(
        &self,
        handle: PendingRequestHandle,
    ) -> Result<&PeekableTask<Response<Body>>, HandleError> {
        self.async_items
            .get(handle.into())
            .and_then(Option::as_ref)
            .and_then(AsyncItem::as_pending_req)
            .ok_or(HandleError::InvalidPendingRequestHandle(handle))
    }

    /// Get a mutable reference to a [`PendingRequest`], given its [`PendingRequestHandle`].
    ///
    /// Returns a [`HandleError`] if the handle is not associated with a request in the
    /// session.
    pub fn pending_request_mut(
        &mut self,
        handle: PendingRequestHandle,
    ) -> Result<&mut PeekableTask<Response<Body>>, HandleError> {
        self.async_items
            .get_mut(handle.into())
            .and_then(Option::as_mut)
            .and_then(AsyncItem::as_pending_req_mut)
            .ok_or(HandleError::InvalidPendingRequestHandle(handle))
    }

    /// Take ownership of a [`PendingRequest`], given its [`PendingRequestHandle`].
    ///
    /// Returns a [`HandleError`] if the handle is not associated with a pending request in the
    /// session.
    pub fn take_pending_request(
        &mut self,
        handle: PendingRequestHandle,
    ) -> Result<PeekableTask<Response<Body>>, HandleError> {
        // check that this is a pending request before removing it
        let _ = self.pending_request(handle)?;

        self.async_items
            .get_mut(handle.into())
            .and_then(Option::take)
            .and_then(AsyncItem::into_pending_req)
            .ok_or(HandleError::InvalidPendingRequestHandle(handle))
    }

    pub fn reinsert_pending_request(
        &mut self,
        handle: PendingRequestHandle,
        pending_req: PeekableTask<Response<Body>>,
    ) -> Result<(), HandleError> {
        *self
            .async_items
            .get_mut(handle.into())
            .ok_or(HandleError::InvalidPendingRequestHandle(handle))? =
            Some(AsyncItem::PendingReq(pending_req));
        Ok(())
    }

    /// Take ownership of multiple [`PendingRequest`]s in preparation for a `select`.
    ///
    /// Returns a [`HandleError`] if any of the handles are not associated with a pending
    /// request in the session.
    pub fn prepare_select_targets(
        &mut self,
        handles: impl IntoIterator<Item = AsyncItemHandle>,
    ) -> Result<Vec<SelectTarget>, HandleError> {
        // Prepare a vector of targets from the given handles; if any of the handles are invalid,
        // put back all the targets we've extracted so far
        let mut targets = vec![];
        for handle in handles {
            if let Ok(item) = self.take_async_item(handle) {
                targets.push(SelectTarget { handle, item });
            } else {
                self.reinsert_select_targets(targets);
                return Err(HandleError::InvalidPendingRequestHandle(handle.into()));
            }
        }
        Ok(targets)
    }

    /// Put the given vector of `select` targets back into the pending request table, using the handles
    /// stored within each [`SelectTarget`].
    pub fn reinsert_select_targets(&mut self, targets: Vec<SelectTarget>) {
        for target in targets {
            self.async_items[target.handle] = Some(target.item);
        }
    }

    /// Returns the unique identifier for the request this session is processing.
    pub fn req_id(&self) -> u64 {
        self.req_id
    }

    /// Access the path to the configuration file for this invocation.
    pub fn config_path(&self) -> &Arc<Option<PathBuf>> {
        &self.config_path
    }

    pub fn async_item_mut(
        &mut self,
        handle: AsyncItemHandle,
    ) -> Result<&mut AsyncItem, HandleError> {
        match self.async_items.get_mut(handle).and_then(|ai| ai.as_mut()) {
            Some(item) => Ok(item),
            None => Err(HandleError::InvalidAsyncItemHandle(handle.into()))?,
        }
    }

    pub fn take_async_item(&mut self, handle: AsyncItemHandle) -> Result<AsyncItem, HandleError> {
        // check that this is an async item before removing it
        let _ = self.async_item_mut(handle)?;

        self.async_items
            .get_mut(handle)
            .and_then(|tracked| tracked.take())
            .ok_or_else(|| HandleError::InvalidAsyncItemHandle(handle.into()))
    }

    pub async fn select_impl(
        &mut self,
        handles: impl IntoIterator<Item = AsyncItemHandle>,
    ) -> Result<usize, Error> {
        // we have to temporarily move the async items out of the session table,
        // because we need &mut borrows of all of them simultaneously.
        let targets = self.prepare_select_targets(handles)?;
        let mut selected = SelectedTargets::new(self, targets);
        let done_index = selected.future().await;

        Ok(done_index)
    }
}

pub struct SelectedTargets<'session> {
    session: &'session mut Session,
    targets: Vec<SelectTarget>,
}

impl<'session> SelectedTargets<'session> {
    fn new(session: &'session mut Session, targets: Vec<SelectTarget>) -> Self {
        Self { session, targets }
    }

    fn future(&mut self) -> Box<dyn Future<Output = usize> + Unpin + Send + Sync + '_> {
        // for each target, we produce a future for checking on the "readiness"
        // of the associated primary I/O operation
        let mut futures = Vec::new();
        for target in &mut *self.targets {
            futures.push(Box::pin(target.item.await_ready()))
        }
        if futures.is_empty() {
            // if there are no futures, we wait forever; this waiting will always be bounded by a timeout,
            // since the `select` hostcall requires a timeout when no handles are given.
            Box::new(future::pending())
        } else {
            Box::new(future::select_all(futures).map(|f| f.1))
        }
    }
}

impl<'session> Drop for SelectedTargets<'session> {
    fn drop(&mut self) {
        let targets = std::mem::take(&mut self.targets);
        self.session.reinsert_select_targets(targets);
    }
}

/// Additional Viceroy-specific metadata for requests.
#[derive(Clone, Debug)]
pub struct ViceroyRequestMetadata {
    pub auto_decompress_encodings: ContentEncodings,
}

impl Default for ViceroyRequestMetadata {
    fn default() -> Self {
        ViceroyRequestMetadata {
            auto_decompress_encodings: ContentEncodings::empty(),
        }
    }
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct AsyncItemHandle(u32);

entity_impl!(AsyncItemHandle, "async_item");

// The ABI uses distinct entity types for each kind of async item because most host calls operate on
// only one type at a type. But the underlying tables for all async items are combined, so the handles
// are interchangeable. Keeping them as separate types helps ensure intentional view shifts between
// them, using `.into()`.

impl From<BodyHandle> for AsyncItemHandle {
    fn from(h: BodyHandle) -> AsyncItemHandle {
        AsyncItemHandle::from_u32(h.into())
    }
}

impl From<AsyncItemHandle> for BodyHandle {
    fn from(h: AsyncItemHandle) -> BodyHandle {
        BodyHandle::from(h.as_u32())
    }
}

impl From<PendingRequestHandle> for AsyncItemHandle {
    fn from(h: PendingRequestHandle) -> AsyncItemHandle {
        AsyncItemHandle::from_u32(h.into())
    }
}

impl From<AsyncItemHandle> for PendingRequestHandle {
    fn from(h: AsyncItemHandle) -> PendingRequestHandle {
        PendingRequestHandle::from(h.as_u32())
    }
}

impl From<types::AsyncItemHandle> for AsyncItemHandle {
    fn from(h: types::AsyncItemHandle) -> AsyncItemHandle {
        AsyncItemHandle::from_u32(h.into())
    }
}

impl From<AsyncItemHandle> for types::AsyncItemHandle {
    fn from(h: AsyncItemHandle) -> types::AsyncItemHandle {
        types::AsyncItemHandle::from(h.as_u32())
    }
}

impl From<PendingKvLookupHandle> for AsyncItemHandle {
    fn from(h: PendingKvLookupHandle) -> AsyncItemHandle {
        AsyncItemHandle::from_u32(h.into())
    }
}

impl From<AsyncItemHandle> for PendingKvLookupHandle {
    fn from(h: AsyncItemHandle) -> PendingKvLookupHandle {
        PendingKvLookupHandle::from(h.as_u32())
    }
}

impl From<PendingKvInsertHandle> for AsyncItemHandle {
    fn from(h: PendingKvInsertHandle) -> AsyncItemHandle {
        AsyncItemHandle::from_u32(h.into())
    }
}

impl From<AsyncItemHandle> for PendingKvInsertHandle {
    fn from(h: AsyncItemHandle) -> PendingKvInsertHandle {
        PendingKvInsertHandle::from(h.as_u32())
    }
}

impl From<PendingKvDeleteHandle> for AsyncItemHandle {
    fn from(h: PendingKvDeleteHandle) -> AsyncItemHandle {
        AsyncItemHandle::from_u32(h.into())
    }
}

impl From<AsyncItemHandle> for PendingKvDeleteHandle {
    fn from(h: AsyncItemHandle) -> PendingKvDeleteHandle {
        PendingKvDeleteHandle::from(h.as_u32())
    }
}
