// Pushpin GRIP proxy

use tracing::debug;
use {
    http::{
        request::{Parts, Request},
        HeaderMap, Response, StatusCode,
    },
    hyper::{client::conn::Parts as ConnParts, upgrade::OnUpgrade, Body},
    std::net::SocketAddr,
    tokio::{io::copy_bidirectional, net::TcpStream, task::JoinHandle},
    tracing::{error, info, warn},
};

/// A signal to redirect the request to Pushpin
#[derive(Debug)]
pub struct PushpinRedirectInfo {
    pub backend_name: String,
    pub request_info: Option<PushpinRedirectRequestInfo>,
}

/// Information about the Pushpin request being redirected
#[derive(Debug)]
pub struct PushpinRedirectRequestInfo {
    pub method: String,
    pub scheme: Option<String>,
    pub authority: Option<String>,
    pub path_and_query: Option<String>,
    pub headers: HeaderMap,
}

impl PushpinRedirectRequestInfo {
    pub fn from_parts(parts: &Parts) -> Self {
        PushpinRedirectRequestInfo {
            method: parts.method.to_string(),
            scheme: parts.uri.scheme().map(|x| x.to_string()),
            authority: parts.uri.authority().map(|x| x.to_string()),
            path_and_query: parts.uri.path_and_query().map(|p| p.to_string()),
            headers: parts.headers.clone(),
        }
    }
}
/// The list of request header names that cannot be modified by backends in proxy_through_pushpin.
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

/// Perform a proxy request to Pushpin using the provided request information and request body.
/// If Pushpin responds with `101 Switching Protocols`, then use the provided `OnUpgrade` future
/// to take over the incoming request connection and wire it up with the Pushpin connection.
///
/// To distinguish backends, the HTTP request header `pushpin-route: <backend_name>` is sent with
/// the request. Pushpin routes should be configured with `id=<backend_name>`.
pub async fn proxy_through_pushpin(
    pushpin_addr: SocketAddr,
    backend_name: String,
    redirect_request_info: Option<PushpinRedirectRequestInfo>,
    original_request_info: PushpinRedirectRequestInfo,
    original_request_body: Body,
    original_request_on_upgrade: OnUpgrade,
) -> Response<Body> {
    info!(
        "proxy_through_pushpin(): Proxying through Pushpin backend '{}'.",
        backend_name
    );

    debug!("TcpStream connect() to '{}'.", pushpin_addr);

    let pushpin_stream = match TcpStream::connect(pushpin_addr).await {
        Ok(str) => {
            debug!("Connected to Pushpin.");
            str
        }
        Err(e) => {
            error!("Could not connect to Pushpin: {e}.");
            return build_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Could not connect to Pushpin",
            );
        }
    };

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

    debug!("Building request '{}' '{}'.", method, path_and_query);

    let mut req = Request::builder().method(method).uri(path_and_query);

    if let Some(redirect_request_info) = redirect_request_info {
        // move the original headers defined in `PROTECTED_REQ_HEADERS` to the top of the req.headers
        for (name, value) in &original_request_info.headers {
            if PROTECTED_REQ_HEADERS
                .iter()
                .any(|h| h.eq_ignore_ascii_case(name.as_str()))
            {
                debug!("Add header '{}' '{:?}'.", name.as_str(), value);
                req = req.header(name, value);
            }
        }
        // add the req headers received via pushpin_redirect, except for the ones in `PROTECTED_REQ_HEADERS`
        for (name, value) in &redirect_request_info.headers {
            if !PROTECTED_REQ_HEADERS
                .iter()
                .any(|h| h.eq_ignore_ascii_case(name.as_str()))
            {
                debug!("Add header '{}' '{:?}'.", name.as_str(), value);
                req = req.header(name, value);
            }
        }
    } else {
        for (name, value) in &original_request_info.headers {
            debug!("Add header '{}' '{:?}'.", name.as_str(), value);
            req = req.header(name, value);
        }
    }
    req = req.header("host", pushpin_addr.to_string());
    req = req.header("pushpin-route", backend_name.to_string());

    debug!("Add body");

    let req = match req.body(original_request_body) {
        Ok(req) => {
            debug!("Created Pushpin proxy request");
            req
        }
        Err(e) => {
            error!("Failed to build Pushpin proxy request: {}", e);
            return build_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Could not build proxy request",
            );
        }
    };

    debug!("Constructing connection");

    let (mut sender, conn) = match hyper::client::conn::Builder::new()
        .handshake(pushpin_stream)
        .await
    {
        Ok(res) => {
            debug!("Pushpin handshake success");
            res
        }
        Err(e) => {
            error!("Pushpin handshake failed: {}", e);
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
    debug!("Spawning connection driver");
    let conn_fut = tokio::spawn(conn.without_shutdown());

    let upstream_resp = match sender.send_request(req).await {
        Ok(proxy_resp) => {
            info!(
                "Received response from Pushpin backend '{}'. Proxying response.",
                backend_name
            );
            proxy_resp
        }
        Err(e) => {
            error!("Pushpin proxy request failed: {}", e);
            return build_error_response(
                StatusCode::BAD_GATEWAY,
                format!("Pushpin request failed: {e}"),
            );
        }
    };

    // If Pushpin responds with `101 Switching Protocols`, then we spawn an async task
    // to attempt an upgrade
    if upstream_resp.status() == StatusCode::SWITCHING_PROTOCOLS {
        debug!("Pushpin responded with `101 Switching Protocols`, attempting upgrade...");
        tokio::spawn(proxy_upgraded_connection(
            original_request_on_upgrade,
            conn_fut,
        ));
    }

    info!("proxy_through_pushpin(): Returning upstream response");

    upstream_resp
}

/// A background task to proxy an upgraded (e.g., WebSocket) connection
async fn proxy_upgraded_connection(
    downstream_req_on_upgrade: OnUpgrade,
    upstream_conn_fut: JoinHandle<Result<ConnParts<TcpStream>, hyper::Error>>,
) {
    info!("proxy_upgraded_connection(): Background task upgrading connection");

    // Await the client-side upgrade. This future will not resolve until
    // the `101` response is sent to the client by the main service.
    let mut downstream_upgraded = match downstream_req_on_upgrade.await {
        Ok(upgraded) => {
            debug!("Downstream client connection upgraded.");
            upgraded
        }
        Err(e) => {
            error!("Downstream client upgrade failed: {}", e);
            return;
        }
    };

    // Await the server-side connection driver to get the raw IO back.
    let mut upstream_parts = match upstream_conn_fut.await {
        Ok(Ok(parts)) => {
            debug!("Upstream connection IO stream obtained.");
            parts
        }
        Ok(Err(e)) => {
            error!("Upstream connection error: {}", e);
            return;
        }
        Err(e) => {
            warn!("Upstream connection task failed: {}", e);
            return;
        }
    };

    info!("proxy_upgraded_connection(): Background task starting bidirectional copy...");

    match copy_bidirectional(&mut downstream_upgraded, &mut upstream_parts.io).await {
        Ok((from_client, from_server)) => {
            info!(
                "proxy_upgraded_connection(): Upgraded proxy connection finished gracefully. Bytes transferred: client->server: {}, server->client: {}",
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
