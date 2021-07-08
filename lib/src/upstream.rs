use crate::{
    body::Body, config::Backend, error::Error, headers::filter_outgoing_headers,
    wiggle_abi::types::PendingRequestHandle,
};
use futures::Future;
use http::uri;
use hyper::{client::HttpConnector, Client, Request, Response, Uri};
use hyper_tls::{HttpsConnecting, HttpsConnector, MaybeHttpsStream};
use std::task::{self, Poll};
use tokio::{net::TcpStream, sync::oneshot};

/// A custom Hyper client connector, which is needed to override Hyper's default behavior of
/// connecting to host specified by the request's URI; we instead want to connect to the host
/// specified by our backend configuration, regardless of what the URI says.
///
/// This connector internally wraps Hyper's TLS connector, automatically providing TLS-based
/// connections when indicated by the backend URI's scheme.
#[derive(Debug, Clone)]
struct Connector {
    backend_uri: Uri,
    https: HttpsConnector<HttpConnector>,
}

impl Connector {
    fn new(backend: &Backend) -> Self {
        Self {
            backend_uri: backend.uri.clone(),
            https: HttpsConnector::new(),
        }
    }
}

impl hyper::service::Service<Uri> for Connector {
    type Response = MaybeHttpsStream<TcpStream>;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = HttpsConnecting<TcpStream>;

    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.https.poll_ready(cx)
    }

    fn call(&mut self, _: Uri) -> Self::Future {
        // here we ignore the URI argument and instead provide the backend's URI.
        // NB this does _not_ affect the URI provided in the request itself.
        self.https.call(self.backend_uri.clone())
    }
}

/// Sends the given request to the given backend.
///
/// Note that the backend's URI is used to determine which host to route the request to; the URI
/// and any HOST header in `req` is _not_ used for routing. If the request does not contain a HOST
/// header, one will be added, using the authority from the request's URI.
pub fn send_request(
    mut req: Request<Body>,
    backend: &Backend,
) -> Result<impl Future<Output = Result<Response<Body>, Error>>, Error> {
    let connector = Connector::new(backend);

    // stitch on the backend path prefix, if it has one
    if backend.uri.path() != "/" {
        // first, we have to fully break apart the request into parts, to get access to the path component
        let (mut req_parts, req_body) = req.into_parts();
        let mut uri_parts = req_parts.uri.into_parts();
        let path_and_query = uri_parts
            .path_and_query
            .as_ref()
            .map_or("", uri::PathAndQuery::as_str);

        // build up a prefixed path, taking care to ensure there's exactly one `/` separator between the
        // backend path prefix and the request's URL path
        let mut prefixed_path = backend.uri.path().to_owned();
        if !prefixed_path.ends_with('/') {
            prefixed_path.push('/');
        }
        if let Some(stripped) = path_and_query.strip_prefix('/') {
            prefixed_path.push_str(stripped)
        } else {
            prefixed_path.push_str(path_and_query)
        };

        // now stitch back up the request
        uri_parts.path_and_query =
            Some(prefixed_path.parse().expect("Prefixed URI failed to parse"));
        req_parts.uri = Uri::from_parts(uri_parts).expect("Prefixed URI failed to parse");
        req = Request::from_parts(req_parts, req_body);
    }

    filter_outgoing_headers(req.headers_mut());

    Ok(async move {
        Ok(Client::builder()
            .build(connector)
            .request(req)
            .await?
            .map(Body::from))
    })
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
