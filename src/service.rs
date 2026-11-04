//! Service types.

use {
    crate::{
        Error,
        body::Body,
        downstream_tls::{DownstreamTlsConfig, DownstreamTlsInfo, HandshakeRecorder},
        execute::ExecuteCtx,
    },
    futures::future::{self, Ready},
    hyper::{
        http::{Request, Response},
        server::conn::{AddrStream, Http},
        service::Service,
    },
    std::{
        convert::Infallible,
        future::Future,
        net::SocketAddr,
        pin::Pin,
        sync::Arc,
        task::{self, Poll},
        time::Duration,
    },
    tokio::net::TcpListener,
    tokio_rustls::TlsAcceptor,
    tracing::{Level, event},
};

/// How long a client gets to complete the TLS handshake before the connection is dropped.
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// A Viceroy service uses a Wasm module and a handler function to respond to HTTP requests.
///
/// This service type is used to compile a Wasm [`Module`][mod], and perform the actions necessary
/// to initialize a [`Server`][serv] and bind the service to a local port.
///
/// Each time a connection is received, a [`RequestService`][req-svc] will be created, to
/// instantiate the module and return a [`Response`][resp].
///
/// [mod]: https://docs.rs/wasmtime/latest/wasmtime/struct.Module.html
/// [req-svc]: struct.RequestService.html
/// [resp]: https://docs.rs/http/latest/http/response/struct.Response.html
/// [serv]: https://docs.rs/hyper/latest/hyper/server/struct.Server.html
pub struct ViceroyService {
    ctx: Arc<ExecuteCtx>,
}

impl ViceroyService {
    /// Create a new Viceroy service, using the given handler function and module path.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use std::collections::HashSet;
    /// # use wasmtime::WasmFeatures;
    /// use viceroy_lib::{Error, ExecuteCtx, ProfilingConfig, ViceroyService};
    /// # use viceroy_lib::config::UnknownImportBehavior;
    /// # fn f() -> Result<(), Error> {
    /// let adapt_core_wasm = false;
    /// let wasm_features = WasmFeatures::default();
    /// let ctx = ExecuteCtx::new(
    ///     "path/to/a/file.wasm",
    ///     ProfilingConfig::None,
    ///     HashSet::new(),
    ///     UnknownImportBehavior::LinkError,
    ///     adapt_core_wasm,
    ///     wasm_features,
    /// )?;
    /// let svc = ViceroyService::new(ctx);
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(ctx: Arc<ExecuteCtx>) -> Self {
        Self { ctx }
    }

    /// An internal helper, create a [`RequestService`](struct.RequestService.html).
    fn make_service(&self, remote: &AddrStream) -> RequestService {
        RequestService::new(self.ctx.clone(), remote)
    }

    /// Bind this service to the given address and start serving responses.
    ///
    /// This will consume the service, using it to start a server that will execute the given module
    /// each time a new request is sent. This function will only return if an error occurs.
    // FIXME KTM 2020-06-22: Once `!` is stabilized, this should be `Result<!, hyper::Error>`.
    pub async fn serve(self, addr: SocketAddr) -> Result<(), hyper::Error> {
        let server = hyper::Server::bind(&addr).serve(self);
        event!(Level::INFO, "Listening on http://{}", server.local_addr());
        server.await?;
        Ok(())
    }

    /// Bind this service to the given address and serve responses over HTTPS.
    ///
    /// TLS is terminated by Viceroy using `tls`. Guests see `https://` request URLs, and the
    /// downstream TLS metadata hostcalls report the negotiated protocol, cipher suite, SNI server
    /// name and raw ClientHello.
    ///
    /// Like [`ViceroyService::serve`], this function will only return if an error occurs.
    pub async fn serve_tls(self, addr: SocketAddr, tls: DownstreamTlsConfig) -> Result<(), Error> {
        let listener = TcpListener::bind(addr).await?;
        self.serve_tls_on(listener, tls).await
    }

    /// Serve responses over HTTPS on an already-bound listener.
    ///
    /// This is the same as [`ViceroyService::serve_tls`], but lets the caller pick the listener,
    /// for example one bound to an ephemeral port.
    pub async fn serve_tls_on(
        self,
        listener: TcpListener,
        tls: DownstreamTlsConfig,
    ) -> Result<(), Error> {
        event!(
            Level::INFO,
            "Listening on https://{}",
            listener.local_addr()?
        );
        let acceptor = TlsAcceptor::from(tls.server_config());

        loop {
            let (tcp, remote_addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    // Mirror hyper's default for plain HTTP: errors such as running out of file
                    // descriptors are logged, then we back off briefly instead of spinning.
                    event!(Level::ERROR, "failed to accept connection: {}", e);
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };
            let local_addr = match tcp.local_addr() {
                Ok(addr) => addr,
                Err(e) => {
                    event!(
                        Level::DEBUG,
                        "dropping connection from {}: {}",
                        remote_addr,
                        e
                    );
                    continue;
                }
            };
            let ctx = self.ctx.clone();
            let acceptor = acceptor.clone();

            tokio::spawn(async move {
                let handshake = acceptor.accept(HandshakeRecorder::new(tcp));
                let mut stream = match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, handshake).await
                {
                    Ok(Ok(stream)) => stream,
                    Ok(Err(e)) => {
                        event!(
                            Level::DEBUG,
                            "TLS handshake with {} failed: {}",
                            remote_addr,
                            e
                        );
                        return;
                    }
                    Err(_) => {
                        event!(Level::DEBUG, "TLS handshake with {} timed out", remote_addr);
                        return;
                    }
                };

                let (recorder, conn) = stream.get_mut();
                let tls_info = DownstreamTlsInfo::from_connection(conn)
                    .with_client_hello(&recorder.take_recorded());
                let svc = RequestService {
                    ctx,
                    local_addr,
                    remote_addr,
                    tls: Some(Arc::new(tls_info)),
                };

                if let Err(e) = Http::new()
                    .serve_connection(stream, svc)
                    .with_upgrades()
                    .await
                {
                    event!(
                        Level::DEBUG,
                        "error serving connection from {}: {}",
                        remote_addr,
                        e
                    );
                }
            });
        }
    }
}

impl<'addr> Service<&'addr AddrStream> for ViceroyService {
    type Response = RequestService;
    type Error = Infallible;
    type Future = Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, addr: &'addr AddrStream) -> Self::Future {
        future::ok(self.make_service(addr))
    }
}

/// A request service is responsible for handling a single request.
///
/// Most importantly, this structure implements the [`tower::Service`][service] trait, which allows
/// it to be dispatched by [`ViceroyService`][viceroy] to handle a single request.
///
/// This object does not need to be used directly; users most likely should use
/// [`ViceroyService::serve`][serve] to bind a service to a port, or
/// [`ExecuteCtx::handle_request`][handle_request] to generate a response for a request when writing
/// test cases.
///
/// [handle_request]: ../execute/struct.ExecuteCtx.html#method.handle_request
/// [serve]: struct.ViceroyService.html#method.serve
/// [service]: https://docs.rs/tower/latest/tower/trait.Service.html
/// [viceroy]: struct.ViceroyService.html
#[derive(Clone)]
pub struct RequestService {
    ctx: Arc<ExecuteCtx>,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    tls: Option<Arc<DownstreamTlsInfo>>,
}

impl RequestService {
    /// Create a new request service.
    fn new(ctx: Arc<ExecuteCtx>, addr: &AddrStream) -> Self {
        let local_addr = addr.local_addr();
        let remote_addr = addr.remote_addr();

        Self {
            ctx,
            local_addr,
            remote_addr,
            tls: None,
        }
    }
}

type ServiceFuture = dyn Future<Output = Result<Response<Body>, Error>> + Send;

impl Service<Request<hyper::Body>> for RequestService {
    type Response = Response<Body>;
    type Error = Error;
    type Future = Pin<Box<ServiceFuture>>;

    fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    /// Process the request and return the response asynchronously.
    fn call(&mut self, mut req: Request<hyper::Body>) -> Self::Future {
        // Requests on a TLS connection carry the connection's TLS details, which `handle_request`
        // picks up to build the downstream metadata.
        if let Some(tls) = &self.tls {
            req.extensions_mut().insert(tls.clone());
        }

        // Request handling currently takes ownership of the context, which is cheaply cloneable.
        let ctx = self.ctx.clone();
        let local = self.local_addr;
        let remote = self.remote_addr;

        // Now, use the execution context to handle the request.
        Box::pin(async move {
            ctx.handle_request(req, local, remote)
                .await
                .map(|result| result.0)
        })
    }
}
