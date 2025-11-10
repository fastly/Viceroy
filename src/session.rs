//! Session type and related facilities.

mod async_item;
mod downstream;

pub use async_item::{
    AsyncItem, PeekableTask, PendingCacheTask, PendingDownstreamReqTask, PendingKvDeleteTask,
    PendingKvInsertTask, PendingKvListTask, PendingKvLookupTask,
};

use std::collections::HashMap;
use std::future::Future;
use std::io::Write;
use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::cache::{Cache, CacheEntry};
use crate::object_store::KvStoreError;
use crate::wiggle_abi::types::{CacheBusyHandle, CacheHandle};

use {
    self::downstream::DownstreamResponseState,
    crate::{
        acl::Acl,
        body::Body,
        config::{Backend, Backends, Dictionaries, LoadedDictionary},
        downstream::{DownstreamMetadata, DownstreamRequest},
        error::{Error, HandleError},
        logging::LogEndpoint,
        object_store::{ObjectKey, ObjectStoreKey, ObjectStores, ObjectValue},
        pushpin::PushpinRedirectInfo,
        secret_store::{SecretLookup, SecretStores},
        shielding_site::ShieldingSites,
        streaming_body::StreamingBody,
        upstream::{SelectTarget, TlsConfig},
        wiggle_abi::types::{
            self, AclHandle, BodyHandle, ContentEncodings, DictionaryHandle, EndpointHandle,
            KvInsertMode, KvStoreDeleteHandle, KvStoreHandle, KvStoreInsertHandle,
            KvStoreListHandle, KvStoreLookupHandle, PendingKvDeleteHandle, PendingKvInsertHandle,
            PendingKvListHandle, PendingKvLookupHandle, PendingRequestHandle, RequestHandle,
            RequestPromiseHandle, ResponseHandle, SecretHandle, SecretStoreHandle,
        },
        ExecuteCtx,
    },
    cranelift_entity::{entity_impl, PrimaryMap},
    futures::future::{self, FutureExt},
    http::{request, response, HeaderMap, Response},
};

const NEXT_REQ_ACCEPT_MAX: usize = 5;
const NEXT_REQ_TIMEOUT: Duration = Duration::from_secs(10);
const NGWAF_ALLOW_VERDICT: &str = "allow";

pub struct RequestParts {
    parts: Option<request::Parts>,
    metadata: Option<DownstreamMetadata>,
}

/// Data specific to an individual request, including any host-side
/// allocations on behalf of the guest processing the request.
pub struct Session {
    session_id: u64,
    /// The amount of time we've spent on this session in microseconds.
    pub active_cpu_time_us: Arc<AtomicU64>,
    /// Handle for the downstream request "parts". NB the backing parts data can be mutated
    /// or even removed from the relevant map.
    downstream_req_handle: RequestHandle,
    /// Handle for the downstream request body. NB the backing body data can be mutated
    /// or even removed from the relevant map.
    downstream_req_body_handle: BodyHandle,
    /// A channel for sending a [`Response`][resp] downstream to the client.
    ///
    /// [resp]: https://docs.rs/http/latest/http/response/struct.Response.html
    downstream_resp: DownstreamResponseState,
    /// Handle for receiving a new downstream request.
    downstream_pending_handle: Option<AsyncItemHandle>,
    /// A handle map for items that provide blocking operations. These items are grouped together
    /// in order to support generic async operations that work across different object types.
    async_items: PrimaryMap<AsyncItemHandle, Option<AsyncItem>>,
    /// The context for executing the service that is shared between sessions.
    ctx: Arc<ExecuteCtx>,
    /// A handle map for the component [`Parts`][parts] of the session's HTTP [`Request`][req]s.
    ///
    /// [parts]: https://docs.rs/http/latest/http/request/struct.Parts.html
    /// [req]: https://docs.rs/http/latest/http/request/struct.Request.html
    req_parts: PrimaryMap<RequestHandle, RequestParts>,
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
    /// Active ACL handles.
    acl_handles: PrimaryMap<AclHandle, Arc<Acl>>,
    /// The NGWAF verdict to return when using the `inspect` hostcall.
    ngwaf_verdict: String,
    /// The backends dynamically added by the program. This is separated from
    /// `backends` because we do not want one session to effect the backends
    /// available to any other session.
    dynamic_backends: Backends,
    /// The dictionaries that have been opened by the guest.
    loaded_dictionaries: PrimaryMap<DictionaryHandle, LoadedDictionary>,
    /// The object stores configured for this execution.
    ///
    /// Populated prior to guest execution.
    kv_store_by_name: PrimaryMap<KvStoreHandle, ObjectStoreKey>,
    /// The secret stores configured for this execution.
    ///
    /// Populated prior to guest execution, and never modified.
    secret_stores_by_name: PrimaryMap<SecretStoreHandle, String>,
    /// The secrets for this execution.
    ///
    /// Populated prior to guest execution, and never modified.
    secrets_by_name: PrimaryMap<SecretHandle, SecretLookup>,
    /// How many additional downstream requests have been receive by this Session.
    next_req_accepted: usize,
}

impl Session {
    /// Create an empty session.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        downstream: DownstreamRequest,
        active_cpu_time_us: Arc<AtomicU64>,
        ctx: Arc<ExecuteCtx>,
    ) -> Session {
        let (parts, body) = downstream.req.into_parts();

        let mut async_items: PrimaryMap<AsyncItemHandle, Option<AsyncItem>> = PrimaryMap::new();
        let mut req_parts = PrimaryMap::new();

        let session_id = downstream.metadata.req_id;
        let downstream_req_handle = req_parts.push(RequestParts {
            parts: Some(parts),
            metadata: Some(downstream.metadata),
        });
        let downstream_req_body_handle = async_items.push(Some(AsyncItem::Body(body))).into();

        Session {
            session_id,
            downstream_req_handle,
            downstream_req_body_handle,
            active_cpu_time_us,
            async_items,
            req_parts,
            resp_parts: PrimaryMap::new(),
            downstream_resp: DownstreamResponseState::new(downstream.sender),
            capture_logs: ctx.capture_logs(),
            log_endpoints: PrimaryMap::new(),
            log_endpoints_by_name: HashMap::new(),
            acl_handles: PrimaryMap::new(),
            ngwaf_verdict: NGWAF_ALLOW_VERDICT.to_string(),
            dynamic_backends: Backends::default(),
            loaded_dictionaries: PrimaryMap::new(),
            kv_store_by_name: PrimaryMap::new(),
            secret_stores_by_name: PrimaryMap::new(),
            secrets_by_name: PrimaryMap::new(),
            downstream_pending_handle: None,
            next_req_accepted: 0,

            ctx,
        }
    }

    // ----- Downstream Request API -----

    /// Retrieve the downstream metadata address associated with a request handle.
    pub fn downstream_metadata(
        &self,
        handle: RequestHandle,
    ) -> Result<Option<&DownstreamMetadata>, HandleError> {
        self.req_parts
            .get(handle)
            .ok_or(HandleError::InvalidRequestHandle(handle))
            .map(|r| r.metadata.as_ref())
    }

    /// Retrieve the downstream client IP address associated with a request handle.
    pub fn downstream_client_ip(
        &self,
        handle: RequestHandle,
    ) -> Result<Option<IpAddr>, HandleError> {
        Ok(self
            .downstream_metadata(handle)?
            .map(|md| md.client_addr.ip()))
    }

    /// Retrieve the IP address the downstream client connected to a request handle.
    pub fn downstream_server_ip(
        &self,
        handle: RequestHandle,
    ) -> Result<Option<IpAddr>, HandleError> {
        Ok(self
            .downstream_metadata(handle)?
            .map(|md| md.server_addr.ip()))
    }

    /// Retrieve the compliance region that received the request for the given handle.
    pub fn downstream_compliance_region(
        &self,
        handle: RequestHandle,
    ) -> Result<Option<&str>, HandleError> {
        Ok(self
            .downstream_metadata(handle)?
            .map(|md| md.compliance_region.as_str()))
    }

    /// Retrieve the request ID for the given request handle.
    pub fn downstream_request_id(&self, handle: RequestHandle) -> Result<Option<u64>, HandleError> {
        Ok(self.downstream_metadata(handle)?.map(|md| md.req_id))
    }

    /// Retrieve the handle corresponding to the most recent downstream request.
    pub fn downstream_request(&self) -> RequestHandle {
        self.downstream_req_handle
    }

    /// Retrieve the handle corresponding to the downstream request body.
    pub fn downstream_request_body(&self) -> BodyHandle {
        self.downstream_req_body_handle
    }

    /// Access the header map that was copied from the original downstream request.
    pub fn downstream_original_headers(
        &self,
        handle: RequestHandle,
    ) -> Result<Option<&HeaderMap>, HandleError> {
        Ok(self
            .downstream_metadata(handle)?
            .map(|md| &md.original_headers))
    }

    // ----- Downstream Response API -----

    /// Send the downstream response.
    ///
    /// Yield an error if a response has already been sent.
    ///
    /// # Panics
    ///
    /// This method must only be called once per downstream request, after which attempting
    /// to send another response will trigger a panic.
    pub fn send_downstream_response(&mut self, resp: Response<Body>) -> Result<(), Error> {
        self.downstream_resp.send(resp)
    }

    /// Redirect the downstream request to Pushpin.
    ///
    /// Yield an error if a response has already been sent.
    ///
    /// # Panics
    ///
    /// This method must only be called once per downstream request, after which attempting
    /// to send another response will trigger a panic.
    pub fn redirect_downstream_to_pushpin(
        &mut self,
        redirect_info: PushpinRedirectInfo,
    ) -> Result<(), Error> {
        self.downstream_resp.redirect_to_pushpin(redirect_info)
    }

    /// Ensure the downstream response sender is closed, and send the provided response if it
    /// isn't.
    pub fn close_downstream_response_sender(&mut self, resp: Response<Body>) {
        let _ = self.downstream_resp.send(resp);
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
        self.req_parts.push(RequestParts {
            parts: Some(parts),
            metadata: None,
        })
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
            .and_then(|r| r.parts.as_ref())
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
            .and_then(|r| r.parts.as_mut())
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
            .and_then(|r| r.parts.take())
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

    // ----- ACLs API -----

    pub fn acl_handle_by_name(&mut self, name: &str) -> Option<AclHandle> {
        let acl = self.ctx.acls().get_acl(name)?;
        Some(self.acl_handles.push(acl.clone()))
    }

    pub fn acl_by_handle(&self, handle: AclHandle) -> Option<Arc<Acl>> {
        self.acl_handles.get(handle).map(Arc::clone)
    }

    // ----- Backends API -----

    /// Get the collection of static backends.
    pub fn backends(&self) -> &Backends {
        self.ctx.backends()
    }

    /// Look up a backend by name.
    pub fn backend(&self, name: &str) -> Option<&Arc<Backend>> {
        // it doesn't actually matter what order we do this search, because
        // the namespaces should be unique.
        self.backends()
            .get(name)
            .or_else(|| self.dynamic_backends.get(name))
    }

    /// Look up a dynamic backend (only) by name.
    pub fn dynamic_backend(&self, name: &str) -> Option<&Arc<Backend>> {
        self.dynamic_backends.get(name)
    }

    /// Return the full list of static and dynamic backend names as an [`Iterator`].
    pub fn backend_names(&self) -> impl Iterator<Item = &String> {
        self.backends().keys().chain(self.dynamic_backends.keys())
    }

    /// Try to add a backend with the given name prefix to our set of current backends.
    /// Upon success, return true. If the name already exists somewhere, return false;
    /// the caller should signal an appropriate error.
    pub fn add_backend(&mut self, name: &str, info: Backend) -> bool {
        // if this name already exists, either as a built in or dynamic backend, say no
        if self.backends().contains_key(name) || self.dynamic_backends.contains_key(name) {
            return false;
        }

        self.dynamic_backends
            .insert(name.to_string(), Arc::new(info));

        true
    }

    // ----- TLS config -----

    /// Access the TLS configuration.
    pub fn tls_config(&self) -> &TlsConfig {
        self.ctx.tls_config()
    }

    // ----- Device Detection API -----

    pub fn device_detection_lookup(&self, user_agent: &str) -> Option<String> {
        self.ctx
            .device_detection()
            .lookup(user_agent)
            .map(|data| data.to_string())
    }

    // ----- Dictionaries API -----

    /// Look up a dictionary-handle by name.
    pub fn dictionary_handle(&mut self, name: &str) -> Result<DictionaryHandle, Error> {
        if let Some(dict) = self.dictionaries().get(name) {
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
    pub fn dictionaries(&self) -> &Dictionaries {
        self.ctx.dictionaries()
    }

    // ----- Geolocation API -----

    pub fn geolocation_lookup(&self, addr: &IpAddr) -> Option<String> {
        self.ctx
            .geolocation()
            .lookup(addr)
            .map(|data| data.to_string())
    }

    // ----- NGWAF Inspect API -----

    /// Retrieve the compliance region that received the request for this session.
    pub fn ngwaf_response(&self) -> String {
        format!(
            r#"{{"waf_response":200,"redirect_url":"","tags":[],"verdict":"{}","decision_ms":0}}"#,
            self.ngwaf_verdict
        )
    }

    // ----- KV Store API -----

    pub fn kv_store(&self) -> &ObjectStores {
        self.ctx.object_store()
    }

    pub fn kv_store_handle(&mut self, key: &str) -> KvStoreHandle {
        let obj_key = ObjectStoreKey::new(key);
        self.kv_store_by_name.push(obj_key)
    }

    pub fn get_kv_store_key(&self, handle: KvStoreHandle) -> Option<&ObjectStoreKey> {
        self.kv_store_by_name.get(handle)
    }

    pub fn kv_insert(
        &self,
        obj_store_key: ObjectStoreKey,
        obj_key: ObjectKey,
        obj: Vec<u8>,
        mode: Option<KvInsertMode>,
        generation: Option<u64>,
        metadata: Option<String>,
        ttl: Option<Duration>,
    ) -> Result<(), KvStoreError> {
        let mode = match mode {
            None => KvInsertMode::Overwrite,
            Some(m) => m,
        };

        self.kv_store()
            .insert(obj_store_key, obj_key, obj, mode, generation, metadata, ttl)
    }

    /// Insert a [`PendingKvInsert`] into the session.
    ///
    /// This method returns a new [`PendingKvInsertHandle`], which can then be used to access
    /// and mutate the pending insert.
    pub fn insert_pending_kv_insert(
        &mut self,
        pending: PendingKvInsertTask,
    ) -> KvStoreInsertHandle {
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

    pub fn kv_delete(
        &self,
        obj_store_key: ObjectStoreKey,
        obj_key: ObjectKey,
    ) -> Result<bool, KvStoreError> {
        self.kv_store().delete(obj_store_key, obj_key)
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
        obj_store_key: ObjectStoreKey,
        obj_key: ObjectKey,
    ) -> Result<Option<ObjectValue>, KvStoreError> {
        self.kv_store().lookup(obj_store_key, obj_key)
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

    pub fn kv_list(
        &self,
        obj_store_key: ObjectStoreKey,
        cursor: Option<String>,
        prefix: Option<String>,
        limit: Option<u32>,
    ) -> Result<Vec<u8>, KvStoreError> {
        let limit = limit.unwrap_or(1000);

        self.kv_store().list(obj_store_key, cursor, prefix, limit)
    }

    /// Insert a [`PendingList`] into the session.
    ///
    /// This method returns a new [`PendingKvListHandle`], which can then be used to access
    /// and mutate the pending list.
    pub fn insert_pending_kv_list(&mut self, pending: PendingKvListTask) -> PendingKvListHandle {
        self.async_items
            .push(Some(AsyncItem::PendingKvList(pending)))
            .into()
    }

    /// Take ownership of a [`PendingList`], given its [`PendingKvListHandle`].
    ///
    /// Returns a [`HandleError`] if the handle is not associated with a pending list in the
    /// session.
    pub fn take_pending_kv_list(
        &mut self,
        handle: PendingKvListHandle,
    ) -> Result<PendingKvListTask, HandleError> {
        // check that this is a pending request before removing it
        let _ = self.pending_kv_list(handle)?;

        self.async_items
            .get_mut(handle.into())
            .and_then(Option::take)
            .and_then(AsyncItem::into_pending_kv_list)
            .ok_or(HandleError::InvalidPendingKvListHandle(handle))
    }

    /// Get a reference to a [`PendingList`], given its [`PendingKvListHandle`].
    ///
    /// Returns a [`HandleError`] if the handle is not associated with a list in the
    /// session.
    pub fn pending_kv_list(
        &self,
        handle: PendingKvListHandle,
    ) -> Result<&PendingKvListTask, HandleError> {
        self.async_items
            .get(handle.into())
            .and_then(Option::as_ref)
            .and_then(AsyncItem::as_pending_kv_list)
            .ok_or(HandleError::InvalidPendingKvListHandle(handle))
    }

    // ----- Secret Store API -----

    pub fn secret_store_handle(&mut self, name: &str) -> Option<SecretStoreHandle> {
        self.secret_stores().get_store(name)?;
        Some(self.secret_stores_by_name.push(name.to_string()))
    }

    pub fn secret_store_name(&self, handle: SecretStoreHandle) -> Option<String> {
        self.secret_stores_by_name.get(handle).cloned()
    }

    pub fn secret_handle(&mut self, store_name: &str, secret_name: &str) -> Option<SecretHandle> {
        self.secret_stores()
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

    pub fn secret_stores(&self) -> &SecretStores {
        self.ctx.secret_stores()
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

    // ------- Core Cache API ------

    /// Insert a pending cache operation: CacheHandle or CacheBusyHandle
    pub fn insert_cache_op(&mut self, task: PendingCacheTask) -> AsyncItemHandle {
        self.async_items.push(Some(AsyncItem::PendingCache(task)))
    }

    /// Get mutable access to a cache entry, which may require blocking until the entry is
    /// available.
    pub(crate) async fn cache_entry_mut(
        &mut self,
        handle: CacheHandle,
    ) -> Result<&mut CacheEntry, HandleError> {
        self.async_items
            .get_mut(handle.into())
            .and_then(Option::as_mut)
            .and_then(AsyncItem::as_pending_cache_mut)
            .map(PendingCacheTask::as_mut)
            .ok_or(HandleError::InvalidCacheHandle(handle))?
            .await
            .as_mut()
            .map_err(|e| {
                tracing::error!("in completion of cache lookup: {e}");
                HandleError::InvalidCacheHandle(handle)
            })
    }

    /// Get immutable access to a cache entry, which may require blocking until the entry is
    /// available.
    pub(crate) async fn cache_entry(
        &mut self,
        handle: CacheHandle,
    ) -> Result<&CacheEntry, HandleError> {
        self.async_items
            .get_mut(handle.into())
            .and_then(Option::as_mut)
            .and_then(AsyncItem::as_pending_cache_mut)
            .map(PendingCacheTask::as_mut)
            .ok_or(HandleError::InvalidCacheHandle(handle))?
            .await
            .as_ref()
            .map_err(|e| {
                tracing::error!("in completion of cache lookup: {e}");
                HandleError::InvalidCacheHandle(handle)
            })
    }

    /// Take ownership of a `CacheEntry` given its handle.
    ///
    /// Returns a `HandleError` if the handle is not associated with a cache lookup.
    pub(crate) fn take_cache_entry(
        &mut self,
        handle: CacheHandle,
    ) -> Result<PendingCacheTask, HandleError> {
        self.async_items
            .get_mut(handle.into())
            .and_then(Option::take)
            .and_then(AsyncItem::into_pending_cache)
            .ok_or(HandleError::InvalidCacheHandle(handle))
    }

    /// Access the cache.
    pub fn cache(&self) -> &Arc<Cache> {
        self.ctx.cache()
    }

    // -------- Scheduling APIs ----------

    /// Take ownership of multiple AsyncItems in preparation for a `select`.
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
            self.reinsert_async_handle(target.handle, target.item);
        }
    }

    pub fn reinsert_async_handle(&mut self, handle: AsyncItemHandle, item: AsyncItem) {
        // Invalid handle, reinsert the item.
        debug_assert!(self.async_items[handle].is_none());
        self.async_items[handle] = Some(item);
    }

    pub fn new_ready(&mut self) -> AsyncItemHandle {
        self.async_items.push(Some(AsyncItem::Ready))
    }

    /// Returns the unique identifier for the current session.
    ///
    /// While this corresponds to the request ID for the initial request that spawned
    /// the session, subsequent downstream requests received by the session will have
    /// their own unique identifier. Care should be taken to not conflate the two, and
    /// to use [Session::downstream_request_id] whenever a request needs to be identified.
    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    /// Access the path to the configuration file for this invocation.
    pub fn config_path(&self) -> Option<&Path> {
        self.ctx.config_path()
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

        let item = self
            .async_items
            .get_mut(handle)
            .and_then(|tracked| tracked.take())
            .ok_or(HandleError::InvalidAsyncItemHandle(handle.into()))?;

        // We just took the handle out of the table, so if it was "the"
        // downstream pending handle, it no longer is.
        if let AsyncItem::PendingDownstream(_) = item {
            self.downstream_pending_handle = None;
        }

        Ok(item)
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

    pub fn shielding_sites(&self) -> &ShieldingSites {
        self.ctx.shielding_sites()
    }

    pub async fn register_pending_downstream_req(
        &mut self,
        timeout: Option<Duration>,
    ) -> Result<AsyncItemHandle, Error> {
        if self.downstream_pending_handle.is_some() {
            return Err(Error::LimitExceeded {
                msg: "Too many pending downstream request handles have been created",
            });
        }

        let rx = if self.next_req_accepted < NEXT_REQ_ACCEPT_MAX {
            self.ctx.register_pending_downstream().await
        } else {
            None
        };

        if rx.is_none() {
            self.next_req_accepted = NEXT_REQ_ACCEPT_MAX;
        } else {
            self.next_req_accepted += 1;
        }

        let timeout = timeout.unwrap_or(NEXT_REQ_TIMEOUT).min(NEXT_REQ_TIMEOUT);
        let task = PendingDownstreamReqTask::new(rx, timeout);
        let handle = self.async_items.push(Some(AsyncItem::from(task)));
        self.downstream_pending_handle = Some(handle);

        Ok(handle)
    }

    pub fn take_pending_downstream_req(
        &mut self,
        handle: AsyncItemHandle,
    ) -> Result<PendingDownstreamReqTask, HandleError> {
        let task = self
            .async_items
            .get_mut(handle)
            .and_then(|maybe_item| {
                if maybe_item
                    .as_mut()
                    .and_then(AsyncItem::as_pending_downstream_req_mut)
                    .is_some()
                {
                    maybe_item
                        .take()
                        .and_then(AsyncItem::into_pending_downstream_req)
                } else {
                    None
                }
            })
            .ok_or_else(|| HandleError::InvalidPendingDownstreamHandle(handle.into()))?;

        self.downstream_pending_handle = None;

        Ok(task)
    }

    /// Wait for a [PendingDownstreamReqTask] to finish, then fetch its request and body handles.
    pub async fn await_downstream_req(
        &mut self,
        handle: AsyncItemHandle,
    ) -> Result<Option<(RequestHandle, BodyHandle)>, Error> {
        if self.downstream_resp.is_unsent() {
            return Err(Error::Unsupported {
                msg: "cannot accept requests w/o handling the outstanding one",
            });
        }

        let item = self.take_pending_downstream_req(handle)?;
        let Some(downstream) = item.recv().await? else {
            return Ok(None);
        };

        let (parts, body) = downstream.req.into_parts();
        let body_handle = self.async_items.push(Some(AsyncItem::Body(body)));
        let req_handle = self.req_parts.push(RequestParts {
            parts: Some(parts),
            metadata: Some(downstream.metadata),
        });

        self.downstream_resp = DownstreamResponseState::new(downstream.sender);
        self.downstream_req_handle = req_handle;
        self.downstream_req_body_handle = body_handle.into();

        Ok(Some((req_handle, body_handle.into())))
    }

    pub fn abandon_pending_downstream_req(
        &mut self,
        handle: AsyncItemHandle,
    ) -> Result<(), HandleError> {
        self.take_pending_downstream_req(handle).map(|_| ())
    }

    pub fn ctx(&self) -> &Arc<ExecuteCtx> {
        &self.ctx
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
    pub manual_framing_headers: bool,
}

impl Default for ViceroyRequestMetadata {
    fn default() -> Self {
        ViceroyRequestMetadata {
            auto_decompress_encodings: ContentEncodings::empty(),
            manual_framing_headers: false,
        }
    }
}

/// Additional Viceroy-specific metadata for responses.
#[derive(Clone, Debug, Default)]
pub struct ViceroyResponseMetadata {
    pub manual_framing_headers: bool,
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

impl From<PendingKvListHandle> for AsyncItemHandle {
    fn from(h: PendingKvListHandle) -> AsyncItemHandle {
        AsyncItemHandle::from_u32(h.into())
    }
}

impl From<AsyncItemHandle> for PendingKvListHandle {
    fn from(h: AsyncItemHandle) -> PendingKvListHandle {
        PendingKvListHandle::from(h.as_u32())
    }
}

impl From<KvStoreLookupHandle> for AsyncItemHandle {
    fn from(h: KvStoreLookupHandle) -> AsyncItemHandle {
        AsyncItemHandle::from_u32(h.into())
    }
}

impl From<AsyncItemHandle> for KvStoreLookupHandle {
    fn from(h: AsyncItemHandle) -> KvStoreLookupHandle {
        KvStoreLookupHandle::from(h.as_u32())
    }
}

impl From<KvStoreInsertHandle> for AsyncItemHandle {
    fn from(h: KvStoreInsertHandle) -> AsyncItemHandle {
        AsyncItemHandle::from_u32(h.into())
    }
}

impl From<AsyncItemHandle> for KvStoreInsertHandle {
    fn from(h: AsyncItemHandle) -> KvStoreInsertHandle {
        KvStoreInsertHandle::from(h.as_u32())
    }
}

impl From<KvStoreDeleteHandle> for AsyncItemHandle {
    fn from(h: KvStoreDeleteHandle) -> AsyncItemHandle {
        AsyncItemHandle::from_u32(h.into())
    }
}

impl From<AsyncItemHandle> for KvStoreDeleteHandle {
    fn from(h: AsyncItemHandle) -> KvStoreDeleteHandle {
        KvStoreDeleteHandle::from(h.as_u32())
    }
}

impl From<KvStoreListHandle> for AsyncItemHandle {
    fn from(h: KvStoreListHandle) -> AsyncItemHandle {
        AsyncItemHandle::from_u32(h.into())
    }
}

impl From<AsyncItemHandle> for KvStoreListHandle {
    fn from(h: AsyncItemHandle) -> KvStoreListHandle {
        KvStoreListHandle::from(h.as_u32())
    }
}

impl From<AsyncItemHandle> for CacheHandle {
    fn from(h: AsyncItemHandle) -> CacheHandle {
        CacheHandle::from(h.as_u32())
    }
}

impl From<CacheHandle> for AsyncItemHandle {
    fn from(h: CacheHandle) -> AsyncItemHandle {
        AsyncItemHandle::from_u32(h.into())
    }
}

impl From<AsyncItemHandle> for CacheBusyHandle {
    fn from(h: AsyncItemHandle) -> CacheBusyHandle {
        CacheBusyHandle::from(h.as_u32())
    }
}

impl From<CacheBusyHandle> for AsyncItemHandle {
    fn from(h: CacheBusyHandle) -> AsyncItemHandle {
        AsyncItemHandle::from_u32(h.into())
    }
}

impl From<AsyncItemHandle> for RequestPromiseHandle {
    fn from(h: AsyncItemHandle) -> RequestPromiseHandle {
        RequestPromiseHandle::from(h.as_u32())
    }
}

impl From<RequestPromiseHandle> for AsyncItemHandle {
    fn from(h: RequestPromiseHandle) -> AsyncItemHandle {
        AsyncItemHandle::from_u32(h.into())
    }
}

// CacheBusyHandle and CacheHandle are equivalent; CacheHandle is just a "later" resolution.
impl From<CacheBusyHandle> for CacheHandle {
    fn from(h: CacheBusyHandle) -> CacheHandle {
        let raw: u32 = h.into();
        CacheHandle::from(raw)
    }
}
