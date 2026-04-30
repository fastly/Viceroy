use {
    crate::component::bindings::fastly::compute::{http_body, http_req, http_resp, types},
    crate::pushpin::{PushpinRedirectInfo, PushpinRedirectRequestInfo},
    crate::{error::Error, sandbox::PeekableTask, sandbox::Sandbox, upstream},
    http::request::Request,
    wasmtime::component::Resource,
};

pub(crate) fn redirect_to_websocket_proxy(
    _sandbox: &mut Sandbox,
    _handle: Resource<http_req::Request>,
    _backend: &str,
) -> Result<(), types::Error> {
    Err(Error::NotAvailable("Redirect to WebSocket proxy").into())
}

pub(crate) fn redirect_to_grip_proxy(
    sandbox: &mut Sandbox,
    req_handle: Resource<http_req::Request>,
    backend_name: &str,
) -> Result<(), types::Error> {
    let request_info = match sandbox.request_parts(req_handle.into()) {
        Ok(req) => Some(PushpinRedirectRequestInfo::from_parts(req)),
        Err(_) => {
            // This function can legitimately be called with an invalid request handle;
            // this may happen when the guest uses a legacy API for pushpin redirection.
            // The legacy behavior is equivalent to simply using None.
            None
        }
    };

    let redirect_info = PushpinRedirectInfo {
        backend_name: backend_name.to_owned(),
        request_info,
    };

    sandbox.redirect_downstream_to_pushpin(redirect_info)?;
    Ok(())
}

pub(crate) fn upgrade_websocket(
    _sandbox: &mut Sandbox,
    _backend: &str,
) -> Result<(), types::Error> {
    Err(Error::NotAvailable("WebSocket upgrade").into())
}

pub(crate) async fn send(
    sandbox: &mut Sandbox,
    h: Resource<http_req::Request>,
    b: Resource<http_body::Body>,
    backend_name: &str,
) -> Result<http_resp::ResponseWithBody, http_req::ErrorWithDetail> {
    // prepare the request
    let req_parts = sandbox.take_request_parts(h.into()).unwrap();
    let req_body = sandbox.take_body(b.into()).unwrap();
    let req = Request::from_parts(req_parts, req_body);
    let backend = sandbox
        .backend(backend_name)
        .ok_or_else(|| Error::UnknownBackend(backend_name.to_owned()))
        .map_err(Into::into)
        .map_err(types::Error::with_empty_detail)?;

    // synchronously send the request
    // This initial implementation ignores the error detail field
    let tls_config = sandbox.tls_config();
    let resp = upstream::send_request(req, backend, tls_config)
        .await
        .map_err(Into::into)
        .map_err(types::Error::with_empty_detail)?;
    let (resp_handle, body_handle) = sandbox.insert_response(resp);
    Ok((resp_handle.into(), body_handle.into()))
}

pub(crate) async fn send_uncached(
    sandbox: &mut Sandbox,
    h: Resource<http_req::Request>,
    b: Resource<http_body::Body>,
    backend_name: &str,
) -> Result<http_resp::ResponseWithBody, http_req::ErrorWithDetail> {
    // This initial implementation ignores the error detail field
    send(sandbox, h, b, backend_name).await
}

pub(crate) async fn send_async(
    sandbox: &mut Sandbox,
    h: Resource<http_req::Request>,
    b: Resource<http_body::Body>,
    backend_name: &str,
) -> Result<Resource<http_req::PendingRequest>, types::Error> {
    // prepare the request
    let req_parts = sandbox.take_request_parts(h.into())?;
    let req_body = sandbox.take_body(b.into())?;
    let req = Request::from_parts(req_parts, req_body);
    let backend = sandbox
        .backend(backend_name)
        .ok_or(types::Error::GenericError)?;

    // asynchronously send the request
    let tls_config = sandbox.tls_config();
    let task = PeekableTask::spawn(upstream::send_request(req, backend, tls_config)).await;

    // return a handle to the pending request
    Ok(sandbox.insert_pending_request(task).into())
}

pub(crate) async fn send_async_uncached(
    sandbox: &mut Sandbox,
    h: Resource<http_req::Request>,
    b: Resource<http_body::Body>,
    backend_name: &str,
) -> Result<Resource<http_req::PendingRequest>, types::Error> {
    send_async(sandbox, h, b, backend_name).await
}

pub(crate) async fn send_async_uncached_streaming(
    sandbox: &mut Sandbox,
    h: Resource<http_req::Request>,
    b: Resource<http_body::Body>,
    backend_name: &str,
) -> Result<Resource<http_req::PendingRequest>, types::Error> {
    send_async_streaming(sandbox, h, b, backend_name).await
}

pub(crate) async fn send_async_streaming(
    sandbox: &mut Sandbox,
    h: Resource<http_req::Request>,
    b: Resource<http_body::Body>,
    backend_name: &str,
) -> Result<Resource<http_req::PendingRequest>, types::Error> {
    // prepare the request
    let req_parts = sandbox.take_request_parts(h.into())?;
    let req_body = sandbox.begin_streaming(b.into())?;
    let req = Request::from_parts(req_parts, req_body);
    let backend = sandbox
        .backend(backend_name)
        .ok_or(types::Error::GenericError)?;

    // asynchronously send the request
    let tls_config = sandbox.tls_config();
    let task = PeekableTask::spawn(upstream::send_request(req, backend, tls_config)).await;

    // return a handle to the pending request
    Ok(sandbox.insert_pending_request(task).into())
}
