use {
    crate::{config::ClientCertInfo, upstream::TlsConfig},
    http::{
        HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode, Uri, header,
        request::Parts,
    },
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

/// A signal to hand off the request to Pushpin or a backend
#[derive(Debug)]
pub struct HandoffInfo {
    pub backend_name: String,
    pub request_info: Option<HandoffRequestInfo>,
}

/// Information about the request being handed off
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

pub struct HandoffConfig {
    pub target_addr: String,
    pub host_header: String,
    pub display_name: String,
    pub path_prefix: Option<String>,
    pub extra_headers: Vec<(String, String)>,
    pub tls_config: Option<HandoffTlsConfig>,
}

pub struct HandoffTlsConfig {
    pub ca_certs: Vec<rustls::Certificate>,
    pub client_cert: Option<ClientCertInfo>, // Viceroy's existing cert wrapper
    pub use_sni: bool,
    pub cert_host: Option<String>,
    pub dns_name_fallback: String,
    pub is_grpc: bool,
    pub base_tls_config: TlsConfig,
}

pub enum Connection {
    Http(TcpStream),
    Https(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl tokio::io::AsyncRead for Connection {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match std::pin::Pin::get_mut(self) {
            Connection::Http(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            Connection::Https(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for Connection {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match std::pin::Pin::get_mut(self) {
            Connection::Http(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            Connection::Https(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match std::pin::Pin::get_mut(self) {
            Connection::Http(s) => std::pin::Pin::new(s).poll_flush(cx),
            Connection::Https(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match std::pin::Pin::get_mut(self) {
            Connection::Http(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            Connection::Https(s) => std::pin::Pin::new(s).poll_shutdown(cx),
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
///   headers of the same name (including protected headers).
/// - The `path_prefix`, if provided, is prepended to the request path.
///
/// The request is forwarded to `target_addr` and the resulting connection
/// is held open until disconnected by either end.
/// If the handoff target responds with `101 Switching Protocols`, then the
/// `on_upgrade` future is used to take over the incoming request connection and
/// wire it up with the handoff connection.
pub async fn perform_handoff(
    request_info: Option<HandoffRequestInfo>,
    orig_request_info: HandoffRequestInfo,
    orig_body: Body,
    on_upgrade: OnUpgrade,
    perform_handoff_config: HandoffConfig,
) -> Response<Body> {
    let mut proxy_req = match create_request_for_handoff(
        &perform_handoff_config.host_header,
        request_info,
        orig_request_info,
        orig_body,
    ) {
        Ok(req) => req,
        Err(e) => {
            error!(
                "Failed to build {} request: {}",
                perform_handoff_config.display_name, e
            );
            return build_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!(
                    "Failed to build {} request: {}",
                    perform_handoff_config.display_name, e
                ),
            );
        }
    };

    // Prepend path prefix if the backend has one (e.g., http://localhost:3000/api/v1)
    if let Some(prefix) = perform_handoff_config.path_prefix {
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
    for (name, value) in perform_handoff_config.extra_headers {
        if let (Ok(header_name), Ok(header_val)) = (HeaderName::try_from(name), value.parse()) {
            proxy_req.headers_mut().insert(header_name, header_val);
        }
    }

    // Initiate the connection, and manage/stream/upgrade it
    execute_handoff(
        perform_handoff_config.target_addr,
        perform_handoff_config.display_name,
        proxy_req,
        on_upgrade,
        perform_handoff_config.tls_config,
    )
    .await
}

/// Creates a request suitable for use with execute_handoff().
fn create_request_for_handoff(
    backend_host: &str,
    handoff_request_info: Option<HandoffRequestInfo>,
    original_request_info: HandoffRequestInfo,
    body: Body,
) -> HttpResult<Request<Body>> {
    let (path_and_query, method) = if let Some(ref handoff_request_info) = handoff_request_info {
        (
            handoff_request_info.path_and_query.as_deref().unwrap_or(""),
            handoff_request_info.method.as_str(),
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

    if let Some(handoff_request_info) = handoff_request_info {
        // move the original headers defined in `PROTECTED_REQ_HEADERS` to the top of the req.headers
        for (name, value) in &original_request_info.headers {
            if PROTECTED_REQ_HEADERS
                .iter()
                .any(|h| h.eq_ignore_ascii_case(name.as_str()))
            {
                req = req.header(name, value);
            }
        }
        // add the req headers received via the handoff call, except for the ones in `PROTECTED_REQ_HEADERS`
        for (name, value) in &handoff_request_info.headers {
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
        HeaderValue::from_str(backend_host).expect("`backend_host` should be a valid header value"),
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
    tls_config: Option<HandoffTlsConfig>,
) -> Response<Body> {
    debug!("Proxying through handoff target '{target_name}'.");

    let handoff_stream = match TcpStream::connect(&target_addr).await {
        Ok(str) => str,
        Err(e) => {
            error!("Could not connect to handoff target: {e}.");
            return build_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Could not connect to handoff target: {e}."),
            );
        }
    };

    let handoff_connection = if let Some(config) = tls_config {
        debug!("TLS Handoff triggered for {}", target_name);

        // Finalize Root Certificates
        let mut custom_roots = rustls::RootCertStore::empty();
        let (added, _) = custom_roots.add_parsable_certificates(&config.ca_certs);
        debug!("Using {added} certificates from provided CA certificate.");

        let builder = if config.ca_certs.is_empty() {
            config
                .base_tls_config
                .partial_config
                .with_root_certificates(config.base_tls_config.default_roots)
        } else {
            config
                .base_tls_config
                .partial_config
                .with_root_certificates(custom_roots)
        };

        // Finalize Client Authentication
        let mut client_config = if let Some(client_cert_info) = &config.client_cert {
            builder
                .with_client_auth_cert(client_cert_info.certs(), client_cert_info.key())
                .expect("`backend.client_cert` should have valid private key")
        } else {
            builder.with_no_client_auth()
        };

        client_config.enable_sni = config.use_sni;
        if config.is_grpc {
            client_config.alpn_protocols = vec![b"h2".to_vec()];
        }

        // Resolve SNI Host
        let cert_host = config
            .cert_host
            .as_deref()
            .unwrap_or(&config.dns_name_fallback);
        let dnsname = rustls::client::ServerName::try_from(cert_host)
            .expect("`backend.cert_host` should be a valid DNS name");

        let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(client_config));
        let tls = connector
            .connect(dnsname, handoff_stream)
            .await
            .expect("Should be able to initiate TLS stream");

        Connection::Https(Box::new(tls))
    } else {
        Connection::Http(handoff_stream)
    };

    let (mut sender, conn) = match Builder::new().handshake(handoff_connection).await {
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
            info!(
                "Handoff target '{}' responded with status: {}. Proxying response.",
                target_name,
                proxy_resp.status()
            );
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
    upstream_conn_fut: JoinHandle<Result<ConnParts<Connection>, hyper::Error>>,
) {
    // Await the client-side upgrade. This future will not resolve until
    // the `101` response is sent to the client by the main service.
    let mut downstream_upgraded = match downstream_req_on_upgrade.await {
        Ok(upgraded) => upgraded,
        Err(e) => {
            error!("Downstream client upgrade failed: {e}");
            return;
        }
    };

    debug!("Downstream client connection upgraded.");

    // Await the server-side connection driver to get the raw IO back.
    let mut upstream_parts = match upstream_conn_fut.await {
        Ok(Ok(parts)) => parts,
        Ok(Err(e)) => {
            error!("Upstream connection error: {e}");
            return;
        }
        Err(e) => {
            warn!("Upstream connection task failed: {e}");
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
    let mut resp = Response::new(Body::from(format!("Error: {}", message.to_string())));
    *resp.status_mut() = status;
    resp
}
