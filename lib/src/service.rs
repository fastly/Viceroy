//! Service types.

use {
    crate::{body::Body, execute::ExecuteCtx, Error},
    futures::future::{self, Ready},
    hyper::{
        http::{Request, Response},
        server::conn::AddrStream,
        service::Service,
    },
    std::{
        convert::Infallible,
        future::Future,
        net::{IpAddr, SocketAddr},
        pin::Pin,
        task::{self, Poll},
    },
    tracing::{event, Level},
};

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
    ctx: ExecuteCtx,
}

impl ViceroyService {
    /// Create a new Viceroy service, using the given handler function and module path.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use std::collections::HashSet;
    /// use viceroy_lib::{Error, ExecuteCtx, ProfilingStrategy, ViceroyService};
    /// # fn f() -> Result<(), Error> {
    /// let adapt_core_wasm = false;
    /// let ctx = ExecuteCtx::new("path/to/a/file.wasm", ProfilingStrategy::None, HashSet::new(), None, Default::default(), adapt_core_wasm)?;
    /// let svc = ViceroyService::new(ctx);
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(ctx: ExecuteCtx) -> Self {
        Self { ctx }
    }

    /// An internal helper, create a [`RequestService`](struct.RequestService.html).
    fn make_service(&self, remote: IpAddr) -> RequestService {
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
}

impl<'addr> Service<&'addr AddrStream> for ViceroyService {
    type Response = RequestService;
    type Error = Infallible;
    type Future = Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, addr: &'addr AddrStream) -> Self::Future {
        future::ok(self.make_service(addr.remote_addr().ip()))
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
    ctx: ExecuteCtx,
    remote_addr: IpAddr,
}

impl RequestService {
    /// Create a new request service.
    fn new(ctx: ExecuteCtx, remote_addr: IpAddr) -> Self {
        Self { ctx, remote_addr }
    }
}

impl Service<Request<hyper::Body>> for RequestService {
    type Response = Response<Body>;
    type Error = Error;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    /// Process the request and return the response asynchronously.
    fn call(&mut self, req: Request<hyper::Body>) -> Self::Future {
        // Request handling currently takes ownership of the context, which is cheaply cloneable.
        let ctx = self.ctx.clone();
        let remote = self.remote_addr;

        // Now, use the execution context to handle the request.
        Box::pin(async move { ctx.handle_request(req, remote).await.map(|result| result.0) })
    }
}
