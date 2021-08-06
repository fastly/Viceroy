//! Session type and related facilities.

mod body_variant;
mod downstream;

use {
    self::{body_variant::BodyVariant, downstream::DownstreamResponse},
    crate::{
        body::Body,
        config::{Backend, Backends, Dictionaries},
        error::{Error, HandleError},
        logging::LogEndpoint,
        streaming_body::StreamingBody,
        upstream::{PendingRequest, SelectTarget},
        wiggle_abi::types::{
            BodyHandle, EndpointHandle, PendingRequestHandle, RequestHandle, ResponseHandle,
        },
    },
    cranelift_entity::PrimaryMap,
    http::{request, response, HeaderMap, Request, Response},
    std::{collections::HashMap, net::IpAddr, path::PathBuf, sync::Arc},
    tokio::sync::oneshot::Sender,
};

/// Data specific to an individual request, including any host-side
/// allocations on behalf of the guest processing the request.
pub struct Session {
    /// The downstream IP address for this session.
    downstream_client_ip: IpAddr,
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
    /// A handle map for the session's HTTP request and response bodies. These bodies are
    /// represented as a [`BodyVariant`][body_variant]s, since the same handle is used for
    /// both a full body, and the write end of a streaming body.
    ///
    /// [body_variant]: struct.BodyVariant.html
    bodies: PrimaryMap<BodyHandle, Option<BodyVariant>>,
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
    /// A handle map for logging endpoints.
    log_endpoints: PrimaryMap<EndpointHandle, LogEndpoint>,
    /// A by-name map for logging endpoints.
    log_endpoints_by_name: HashMap<Vec<u8>, EndpointHandle>,
    /// The backends configured for this execution.
    ///
    /// Populated prior to guest execution, and never modified.
    pub(crate) backends: Arc<Backends>,
    /// The dictionaries configured for this execution.
    ///
    /// Populated prior to guest execution, and never modified.
    pub(crate) dictionaries: Arc<Dictionaries>,
    /// The path to the configuration file used for this invocation of Viceroy.
    ///
    /// Created prior to guest execution, and never modified.
    pub(crate) config_path: Arc<Option<PathBuf>>,
    /// A handle map for pending asynchronous requests.
    pending_reqs: PrimaryMap<PendingRequestHandle, Option<PendingRequest>>,
    /// The ID for the client request being processed.
    req_id: u64,
}

impl Session {
    /// Create an empty session.
    pub fn new(
        req_id: u64,
        req: Request<Body>,
        resp_sender: Sender<Response<Body>>,
        client_ip: IpAddr,
        backends: Arc<Backends>,
        dictionaries: Arc<Dictionaries>,
        config_path: Arc<Option<PathBuf>>,
    ) -> Session {
        let (parts, body) = req.into_parts();
        let downstream_req_original_headers = parts.headers.clone();

        let mut bodies = PrimaryMap::new();
        let mut req_parts = PrimaryMap::new();

        let downstream_req_handle = req_parts.push(Some(parts));
        let downstream_req_body_handle = bodies.push(Some(BodyVariant::Body(body)));

        Session {
            downstream_client_ip: client_ip,
            downstream_req_handle,
            downstream_req_body_handle,
            downstream_req_original_headers,
            bodies,
            req_parts,
            resp_parts: PrimaryMap::new(),
            downstream_resp: DownstreamResponse::new(resp_sender),
            log_endpoints: PrimaryMap::new(),
            log_endpoints_by_name: HashMap::new(),
            backends,
            dictionaries,
            config_path,
            pending_reqs: PrimaryMap::new(),
            req_id,
        }
    }

    /// We need to create a Session in order to typecheck a module into an
    /// InstancePre, but we will never actually execute code that accesses the
    /// Session. Therefore, all of the data inside this Session is bogus.
    ///
    /// Do not use the Session created by this constructor for any other
    /// purpose.
    pub(crate) fn mock() -> Session {
        let (sender, _receiver) = tokio::sync::oneshot::channel();
        Session::new(
            0,
            Request::new(Body::empty()),
            sender,
            "0.0.0.0".parse().unwrap(),
            Arc::new(HashMap::new()),
            Arc::new(HashMap::new()),
            Arc::new(None),
        )
    }

    // ----- Downstream Request API -----

    /// Retrieve the downstream client IP address associated with this session.
    pub fn downstream_client_ip(&self) -> &IpAddr {
        &self.downstream_client_ip
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
        self.bodies.push(Some(BodyVariant::Body(body)))
    }

    /// Get a reference to a [`Body`][body], given its [`BodyHandle`][handle].
    ///
    /// Returns a [`HandleError`][err] if the handle is not associated with a body in the session.
    ///
    /// [body]: ../body/struct.Body.html
    /// [err]: ../error/enum.HandleError.html
    /// [handle]: ../wiggle_abi/types/struct.BodyHandle.html
    pub fn body(&self, handle: BodyHandle) -> Result<&Body, HandleError> {
        self.bodies
            .get(handle)
            .and_then(Option::as_ref)
            .and_then(BodyVariant::as_body)
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
        self.bodies
            .get_mut(handle)
            .and_then(Option::as_mut)
            .and_then(BodyVariant::as_body_mut)
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
        self.bodies
            .get_mut(handle)
            .and_then(Option::take)
            .and_then(BodyVariant::into_body)
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
        self.bodies
            .get_mut(handle)
            .and_then(Option::as_mut)
            .and_then(BodyVariant::begin_streaming)
            .ok_or(HandleError::InvalidBodyHandle(handle))
    }

    /// Returns `true` if and only if the provided `BodyHandle` is the downstream body being sent.
    ///
    /// To get a mutable reference to the streaming body `Sender`, see
    /// [`Session::streaming_body_mut`](struct.Session.html#method.streaming_body_mut).
    pub fn is_streaming_body(&self, handle: BodyHandle) -> bool {
        if let Some(Some(body)) = self.bodies.get(handle) {
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
        self.bodies
            .get_mut(handle)
            .and_then(Option::as_mut)
            .and_then(BodyVariant::as_streaming_mut)
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
        self.bodies
            .get_mut(handle)
            .and_then(Option::take)
            .and_then(BodyVariant::into_streaming)
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
        let endpoint = LogEndpoint::new(name);
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
    pub fn backend(&self, name: &str) -> Option<&Backend> {
        self.backends.get(name).map(std::ops::Deref::deref)
    }

    // ----- Pending Requests API -----

    /// Insert a [`PendingRequest`] into the session.
    ///
    /// This method returns a new [`PendingRequestHandle`], which can then be used to access
    /// and mutate the pending request.
    pub fn insert_pending_request(&mut self, pending: PendingRequest) -> PendingRequestHandle {
        self.pending_reqs.push(Some(pending))
    }

    /// Get a reference to a [`PendingRequest`], given its [`PendingRequestHandle`].
    ///
    /// Returns a [`HandleError`] if the handle is not associated with a request in the
    /// session.
    pub fn pending_request(
        &self,
        handle: PendingRequestHandle,
    ) -> Result<&PendingRequest, HandleError> {
        self.pending_reqs
            .get(handle)
            .and_then(Option::as_ref)
            .ok_or(HandleError::InvalidPendingRequestHandle(handle))
    }

    /// Get a mutable reference to a [`PendingRequest`], given its [`PendingRequestHandle`].
    ///
    /// Returns a [`HandleError`] if the handle is not associated with a request in the
    /// session.
    pub fn pending_request_mut(
        &mut self,
        handle: PendingRequestHandle,
    ) -> Result<&mut PendingRequest, HandleError> {
        self.pending_reqs
            .get_mut(handle)
            .and_then(Option::as_mut)
            .ok_or(HandleError::InvalidPendingRequestHandle(handle))
    }

    /// Take ownership of a [`PendingRequest`], given its [`PendingRequestHandle`].
    ///
    /// Returns a [`HandleError`] if the handle is not associated with a pending request in the
    /// session.
    pub fn take_pending_request(
        &mut self,
        handle: PendingRequestHandle,
    ) -> Result<PendingRequest, HandleError> {
        self.pending_reqs
            .get_mut(handle)
            .and_then(Option::take)
            .ok_or(HandleError::InvalidPendingRequestHandle(handle))
    }

    /// Take ownership of multiple [`PendingRequest`]s in preparation for a `select`.
    ///
    /// Returns a [`HandleError`] if any of the handles are not associated with a pending
    /// request in the session.
    pub fn prepare_select_targets(
        &mut self,
        handles: &[PendingRequestHandle],
    ) -> Result<Vec<SelectTarget>, HandleError> {
        // Prepare a vector of targets from the given handles; if any of the handles are invalid,
        // put back all the targets we've extracted so far
        let mut targets = vec![];
        for handle in handles.iter().copied() {
            if let Ok(pending_req) = self.take_pending_request(handle) {
                targets.push(SelectTarget {
                    handle,
                    pending_req,
                });
            } else {
                self.reinsert_select_targets(targets);
                return Err(HandleError::InvalidPendingRequestHandle(handle));
            }
        }
        Ok(targets)
    }

    /// Put the given vector of `select` targets back into the pending request table, using the handles
    /// stored within each [`SelectTarget`].
    pub fn reinsert_select_targets(&mut self, targets: Vec<SelectTarget>) {
        for target in targets {
            self.pending_reqs[target.handle] = Some(target.pending_req);
        }
    }

    /// Returns the unique identifier for the request this session is processing.
    pub fn req_id(&self) -> u64 {
        self.req_id
    }
}
