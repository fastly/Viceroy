use {
    http::{header, HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode, Uri, request::Parts},
    hyper::{
        Body,
        client::conn::{Builder, Parts as ConnParts},
        http::Result as HttpResult,
        upgrade::OnUpgrade,
    },
    tokio::{io::copy_bidirectional, net::TcpStream, task::JoinHandle},
    tracing::{debug, error, info, warn},
};

/// The list of request header names that cannot be modified during handoff.
const PROTECTED_REQ_HEADERS: &[&str] = &[
    // WebSocket control
    "host",
    "connection",
    "sec-websocket-version",
    "sec-websocket-key",
    "upgrade",
    // Internal Fastly
    "pushpin-route",
    // VCL
    "content-length",
    "content-range",
    "expect",
    "fastly-ff",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    // Other
    "cdn-loop",
];

/// A signal to redirect the request to Pushpin
#[derive(Debug)]
pub struct HandoffInfo {
    pub backend_name: String,
    pub request_info: Option<HandoffRequestInfo>,
}

/// Information about the Pushpin request being redirected
#[derive(Debug)]
pub struct HandoffRequestInfo {
    pub method: String,
    pub scheme: Option<String>,
    pub authority: Option<String>,
    pub path_and_query: Option<String>,
    pub headers: HeaderMap,
}

impl HandoffRequestInfo {
    pub fn from_parts(parts: &Parts) -> Self {
        HandoffRequestInfo {
            method: parts.method.to_string(),
            scheme: parts.uri.scheme().map(|x| x.to_string()),
            authority: parts.uri.authority().map(|x| x.to_string()),
            path_and_query: parts.uri.path_and_query().map(|p| p.to_string()),
            headers: parts.headers.clone(),
        }
    }
}

/// Hands off the current request to the target address.
///
/// - The method and request URI (path + query) are taken from request_info
///   if provided, or orig_request_info otherwise.
/// - The body is taken from orig_body.
/// - Headers are taken from request_info if provided (except for certain protected
///   headers, which will keep their values from orig_request_info), or
///   orig_request_info otherwise.
/// - The Host header is always replaced by the parameter `host_header`.
/// - `extra_headers`, if provided, are applied. This always replaces existing
///   headers of the same name.
/// - The `path_prefix`, if provided, is prepended to the request path.
///
/// The request is forwarded to `target_addr` and the resulting connection
/// is held open until disconnected by either end.
/// If the handoff target responds with `101 Switching Protocols`, then the
/// `on_upgrade` future is used to take over the incoming request connection and
/// wire it up with the handoff connection.
pub async fn perform_handoff(
    target_addr: String,
    host_header: String,
    display_name: String,
    path_prefix: Option<String>,
    extra_headers: Vec<(String, String)>,
    request_info: Option<HandoffRequestInfo>,
    orig_request_info: HandoffRequestInfo,
    orig_body: Body,
    on_upgrade: OnUpgrade,
) -> Response<Body> {

    let mut proxy_req = match create_request_for_handoff(
        &host_header,
        request_info,
        orig_request_info,
        orig_body,
    ) {
        Ok(req) => req,
        Err(e) => {
            error!("Failed to build {display_name} request: {e}");
            return build_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to build {display_name} request: {e}"),
            );
        }
    };

    // Prepend path prefix if the backend has one (e.g., http://localhost:3000/api/v1)
    if let Some(prefix) = path_prefix {
        let mut parts = proxy_req.uri().clone().into_parts();
        let original_path = parts
            .path_and_query
            .as_ref()
            .map(|pq| pq.as_str())
            .unwrap_or("");

        // Ensure we don't end up with // if the prefix and path both have slashes
        let prefix = prefix.trim_end_matches('/');
        let original_path = if !original_path.starts_with('/') && !original_path.is_empty() {
            format!("/{original_path}")
        } else {
            original_path.to_string()
        };

        let new_path = format!("{prefix}{original_path}");
        if let Ok(pq) = new_path.parse() {
            parts.path_and_query = Some(pq);
            if let Ok(uri) = Uri::from_parts(parts) {
                *proxy_req.uri_mut() = uri;
            }
        }
    }

    // Insert additional headers
    for (name, value) in extra_headers {
        if let (Ok(header_name), Ok(header_val)) = (HeaderName::try_from(name), value.parse()) {
            proxy_req.headers_mut().insert(header_name, header_val);
        }
    }

    // Initiate the connection, and manage/stream/upgrade it 
    execute_handoff(target_addr, display_name, proxy_req, on_upgrade).await
}

/// Creates a request suitable for use with execute_handoff().
fn create_request_for_handoff(
    backend_host: &str,
    redirect_request_info: Option<HandoffRequestInfo>,
    original_request_info: HandoffRequestInfo,
    body: Body,
) -> HttpResult<Request<Body>> {
    let (path_and_query, method) = if let Some(ref info) = redirect_request_info {
        (
            info.path_and_query.as_deref().unwrap_or(""),
            info.method.as_str(),
        )
    } else {
        (
            original_request_info
                .path_and_query
                .as_deref()
                .unwrap_or(""),
            original_request_info.method.as_str(),
        )
    };
    let mut req = Request::builder().method(method).uri(path_and_query);

    if let Some(redirect_request_info) = redirect_request_info {
        // move the original headers defined in `PROTECTED_REQ_HEADERS` to the top of the req.headers
        for (name, value) in &original_request_info.headers {
            if PROTECTED_REQ_HEADERS
                .iter()
                .any(|h| h.eq_ignore_ascii_case(name.as_str()))
            {
                req = req.header(name, value);
            }
        }
        // add the req headers received via pushpin_redirect, except for the ones in `PROTECTED_REQ_HEADERS`
        for (name, value) in &redirect_request_info.headers {
            if !PROTECTED_REQ_HEADERS
                .iter()
                .any(|h| h.eq_ignore_ascii_case(name.as_str()))
            {
                req = req.header(name, value);
            }
        }
    } else {
        for (name, value) in &original_request_info.headers {
            req = req.header(name, value);
        }
    }

    let mut req = req.body(body)?;
    req.headers_mut().insert(
        header::HOST,
        HeaderValue::from_str(backend_host).expect("Invalid host header")
    );
    Ok(req)
}

/// Executes a handoff by forwarding the request and managing connection upgrades.
/// If the handoff target responds with `101 Switching Protocols`, then use the
/// provided `OnUpgrade` future to take over the incoming request connection and
/// wire it up with the handoff connection.
async fn execute_handoff(
    target_addr: String,
    target_name: String,
    req: Request<Body>,
    downstream_on_upgrade: OnUpgrade,
) -> Response<Body> {
    debug!("Proxying through handoff target '{target_name}'.");

    let handoff_stream = match TcpStream::connect(target_addr).await {
        Ok(str) => str,
        Err(e) => {
            error!("Could not connect to handoff target: {e}.");
            return build_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Could not connect to handoff target",
            );
        }
    };

    let (mut sender, conn) = match Builder::new().handshake(handoff_stream).await {
        Ok(res) => res,
        Err(e) => {
            error!("Handoff handshake failed: {e}");
            return build_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Could not connect to upstream service: {e}"),
            );
        }
    };

    // Spawn the connection driver and keep a handle to it.
    // We need this future to complete so we can get the raw IO stream back after the HTTP response is parsed.
    // `without_shutdown` prevents hyper from trying to gracefully close the connection,
    // which is what we want when taking it over for a WebSocket.
    let conn_fut = tokio::spawn(conn.without_shutdown());

    let upstream_resp = match sender.send_request(req).await {
        Ok(proxy_resp) => {
            info!("Received response from handoff target '{target_name}'. Proxying response.");
            proxy_resp
        }
        Err(e) => {
            error!("Handoff request failed: {e}");
            return build_error_response(
                StatusCode::BAD_GATEWAY,
                format!("Handoff request failed: {e}"),
            );
        }
    };

    // If handoff target responds with `101 Switching Protocols`, then we spawn an async task
    // to attempt an upgrade
    if upstream_resp.status() == StatusCode::SWITCHING_PROTOCOLS {
        debug!("Handoff target requested 101 Switching Protocols; upgrading...");
        tokio::spawn(proxy_upgraded_connection(downstream_on_upgrade, conn_fut));
    }

    upstream_resp
}

/// A background task to proxy an upgraded (e.g., WebSocket) connection
async fn proxy_upgraded_connection(
    downstream_req_on_upgrade: OnUpgrade,
    upstream_conn_fut: JoinHandle<Result<ConnParts<TcpStream>, hyper::Error>>,
) {
    // Await the client-side upgrade. This future will not resolve until
    // the `101` response is sent to the client by the main service.
    let mut downstream_upgraded = match downstream_req_on_upgrade.await {
        Ok(upgraded) => upgraded,
        Err(e) => {
            error!("Downstream client upgrade failed: {}", e);
            return;
        }
    };

    debug!("Downstream client connection upgraded.");

    // Await the server-side connection driver to get the raw IO back.
    let mut upstream_parts = match upstream_conn_fut.await {
        Ok(Ok(parts)) => parts,
        Ok(Err(e)) => {
            error!("Upstream connection error: {}", e);
            return;
        }
        Err(e) => {
            warn!("Upstream connection task failed: {}", e);
            return;
        }
    };

    debug!("Upstream connection IO stream obtained.");

    match copy_bidirectional(&mut downstream_upgraded, &mut upstream_parts.io).await {
        Ok((from_client, from_server)) => {
            info!(
                "Upgraded proxy connection finished gracefully. Bytes transferred: client->server: {}, server->client: {}",
                from_client, from_server
            );
        }
        Err(e) => {
            error!("Upgraded proxy I/O error: {e}");
        }
    }
}

/// A helper function to build a simple error response.
fn build_error_response(status: StatusCode, message: impl ToString) -> Response<Body> {
    Response::builder()
        .status(status)
        .body(Body::from(format!("Error: {}", message.to_string())))
        .expect("Could not build error response")
}
