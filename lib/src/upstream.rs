use crate::{
    body::Body, config::Backend, error::Error, headers::filter_outgoing_headers,
    wiggle_abi::types::PendingRequestHandle,
};
use futures::Future;
use http::{uri, HeaderValue};
use hyper::{client::HttpConnector, Client, HeaderMap, Request, Response, Uri};
use std::{
    io,
    pin::Pin,
    str::FromStr,
    sync::Arc,
    task::{self, Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
    sync::oneshot,
};
use tokio_rustls::{client::TlsStream, TlsConnector};
use webpki::DNSNameRef;

/// A custom Hyper client connector, which is needed to override Hyper's default behavior of
/// connecting to host specified by the request's URI; we instead want to connect to the host
/// specified by our backend configuration, regardless of what the URI says.
///
/// This connector internally wraps Hyper's TLS connector, automatically providing TLS-based
/// connections when indicated by the backend URI's scheme.
#[derive(Clone)]
pub struct BackendConnector {
    backend_uri: Uri,
    http: HttpConnector,
    tls_config: Arc<rustls::ClientConfig>,
}

impl BackendConnector {
    pub fn new(backend: &Backend, tls_config: Arc<rustls::ClientConfig>) -> Self {
        let mut http = HttpConnector::new();
        http.enforce_http(false);

        Self {
            backend_uri: backend.uri.clone(),
            http,
            tls_config,
        }
    }
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;

pub enum Connection {
    Http(TcpStream),
    Https(Box<TlsStream<TcpStream>>),
}

impl hyper::service::Service<Uri> for BackendConnector {
    type Response = Connection;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, BoxError>> + Send>>;

    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.http.poll_ready(cx).map_err(Into::into)
    }

    // We ignore the URI argument and instead provide the backend's URI.
    // NB this does _not_ affect the URI provided in the request itself.
    fn call(&mut self, _: Uri) -> Self::Future {
        let uri = self.backend_uri.clone();
        let config = self.tls_config.clone();
        let hostname = uri.host().unwrap_or_default().to_string();
        let is_https = uri.scheme_str() == Some("https");

        let connect_fut = self.http.call(uri);
        Box::pin(async move {
            let tcp = connect_fut.await.map_err(Box::new)?;

            if is_https {
                let connector = TlsConnector::from(config);
                let dnsname = DNSNameRef::try_from_ascii_str(&hostname).map_err(Box::new)?;
                let tls = connector.connect(dnsname, tcp).await.map_err(Box::new)?;
                Ok(Connection::Https(Box::new(tls)))
            } else {
                Ok(Connection::Http(tcp))
            }
        })
    }
}

fn canonical_host_header(
    original_headers: &HeaderMap,
    original_uri: &Uri,
    backend: &Backend,
) -> HeaderValue {
    backend
        .override_host
        .clone()
        .or_else(|| original_headers.get(hyper::header::HOST).cloned())
        .or_else(|| {
            original_uri
                .authority()
                .and_then(|auth| HeaderValue::from_str(auth.as_str()).ok())
        })
        .expect("Could determine a Host header")
}

fn canonical_uri(original_uri: &Uri, canonical_host: &str, backend: &Backend) -> Uri {
    let original_path = original_uri
        .path_and_query()
        .map_or("/", uri::PathAndQuery::as_str);

    let mut canonical_uri = String::new();

    // Hyper's `Client` API _requires_ a URI in "absolute form", including scheme, authority,
    // and path.

    // We start with the scheme, taken from the backend (which determines what we're actually
    // communicating over).
    canonical_uri.push_str(
        backend
            .uri
            .scheme_str()
            .expect("Backend URL included a scheme"),
    );
    canonical_uri.push_str("://");

    // We get the authority from the canonical host. In some cases that might actually come
    // from the `original_uri`, but usually it's from an explicit `Host` header.
    canonical_uri.push_str(canonical_host);

    // The path begins with the "path prefix" present in the backend's URI. This is often just
    // an empty path or `/`.
    canonical_uri.push_str(backend.uri.path());
    if !canonical_uri.ends_with('/') {
        canonical_uri.push('/');
    }

    // Finally we incorporate the requested path, taking care not to introduce extra `/`
    // separators when gluing things together.
    if let Some(stripped) = original_path.strip_prefix('/') {
        canonical_uri.push_str(stripped)
    } else {
        canonical_uri.push_str(original_path)
    }

    Uri::from_str(&canonical_uri).expect("URI could be parsed")
}

/// Sends the given request to the given backend.
///
/// Note that the backend's URI is used to determine which host to route the request to; the URI
/// and any HOST header in `req` is _not_ used for routing. If the request does not contain a HOST
/// header, one will be added, using the authority from the request's URI.
pub fn send_request(
    mut req: Request<Body>,
    backend: &Backend,
    tls_config: &Arc<rustls::ClientConfig>,
) -> impl Future<Output = Result<Response<Body>, Error>> {
    let connector = BackendConnector::new(backend, tls_config.clone());

    let host = canonical_host_header(req.headers(), req.uri(), backend);
    let uri = canonical_uri(
        req.uri(),
        std::str::from_utf8(host.as_bytes()).expect("Host was in UTF-8"),
        backend,
    );

    filter_outgoing_headers(req.headers_mut());
    req.headers_mut().insert(hyper::header::HOST, host);
    *req.uri_mut() = uri;

    async move {
        Ok(Client::builder()
            .set_host(false)
            .build(connector)
            .request(req)
            .await
            .map_err(|e| {
                eprintln!("Error: {:?}", e);
                e
            })?
            .map(Body::from))
    }
}

/// The type ultimately yielded by a `PendingRequest`.
pub type ResponseResult = Result<Response<Body>, Error>;

/// An asynchronous request awaiting a response.
#[derive(Debug)]
pub struct PendingRequest {
    // NB: we use channels rather than a `JoinHandle` in order to support the `poll` API.
    receiver: oneshot::Receiver<ResponseResult>,
}

impl PendingRequest {
    /// Create a `PendingRequest` for the given request by spawning a Tokio task to drive sending
    /// and receiving to completion.
    pub fn spawn(
        req: impl Future<Output = Result<Response<Body>, Error>> + Send + 'static,
    ) -> Self {
        let (sender, receiver) = oneshot::channel();
        tokio::task::spawn(async move { sender.send(req.await) });
        Self { receiver }
    }

    /// Check whether a response happens to be available for this pending request.
    ///
    /// This function does _not_ block, nor does it require being in an `async` context.
    pub fn poll(&mut self) -> Option<ResponseResult> {
        match self.receiver.try_recv() {
            Err(oneshot::error::TryRecvError::Closed) => {
                panic!("Pending request sender was dropped")
            }
            // the request is still in flight
            Err(oneshot::error::TryRecvError::Empty) => None,
            Ok(res) => Some(res),
        }
    }

    /// Block until the response is ready, and then return it.
    pub async fn wait(self) -> ResponseResult {
        self.receiver.await.expect("Pending request reciever error")
    }
}

/// A pair of a pending request and the handle that pointed to it in the session, suitable for
/// invoking the futures select API.
///
/// We need this type because `future::select_all` does not guarantee anything about the order of
/// the leftover futures. We have to build our own future to keep the handle-receiver association.
#[derive(Debug)]
pub struct SelectTarget {
    pub handle: PendingRequestHandle,
    pub pending_req: PendingRequest,
}

impl Future for SelectTarget {
    type Output = ResponseResult;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context,
    ) -> std::task::Poll<Self::Output> {
        std::pin::Pin::new(&mut self.pending_req.receiver)
            .poll(cx)
            .map(|res| res.expect("Pending request receiver was dropped"))
    }
}

// Boilerplate forwarding implementations for `Connection`:

impl hyper::client::connect::Connection for Connection {
    fn connected(&self) -> hyper::client::connect::Connected {
        hyper::client::connect::Connected::new()
    }
}

impl AsyncRead for Connection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), io::Error>> {
        match Pin::get_mut(self) {
            Connection::Http(s) => Pin::new(s).poll_read(cx, buf),
            Connection::Https(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Connection {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        match Pin::get_mut(self) {
            Connection::Http(s) => Pin::new(s).poll_write(cx, buf),
            Connection::Https(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match Pin::get_mut(self) {
            Connection::Http(s) => Pin::new(s).poll_flush(cx),
            Connection::Https(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match Pin::get_mut(self) {
            Connection::Http(s) => Pin::new(s).poll_shutdown(cx),
            Connection::Https(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}
