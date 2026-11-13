//! Service types.

use {
    crate::{Error, body::Body, execute::ExecuteCtx},
    hyper::{
        body::Incoming,
        http::{Request, Response},
        service::Service,
    },
    hyper_util::{
        rt::{TokioExecutor, TokioIo},
        server::conn::auto::Builder,
    },
    std::{future::Future, io, net::SocketAddr, pin::Pin, sync::Arc},
    tokio::net::TcpListener,
    tracing::{Level, event},
};

/// A Viceroy service uses a Wasm module and a handler function to respond to HTTP requests.
///
/// This service type is used to compile a Wasm [`Module`][mod], and perform the actions necessary
/// to initialize an HTTP server and bind the service to a local port.
///
/// Each time a connection is received, a [`RequestService`][req-svc] will be created, to
/// instantiate the module and return a [`Response`][resp].
///
/// [mod]: https://docs.rs/wasmtime/latest/wasmtime/struct.Module.html
/// [req-svc]: struct.RequestService.html
/// [resp]: https://docs.rs/http/latest/http/response/struct.Response.html
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
    fn make_service(&self, local_addr: SocketAddr, remote_addr: SocketAddr) -> RequestService {
        RequestService::new(self.ctx.clone(), local_addr, remote_addr)
    }

    /// Bind this service to the given address and start serving responses.
    ///
    /// This will consume the service, using it to start a server that will execute the given module
    /// each time a new request is sent. This function will only return if an error occurs.
    // FIXME KTM 2020-06-22: Once `!` is stabilized, this should be `Result<!, hyper::Error>`.
    pub async fn serve(self, addr: SocketAddr) -> Result<(), io::Error> {
        let listener = TcpListener::bind(addr).await?;
        event!(
            Level::INFO,
            "Listening on http://{}",
            listener.local_addr()?
        );

        loop {
            let (stream, remote_addr) = listener.accept().await?;
            let service = self.make_service(stream.local_addr()?, remote_addr);

            tokio::spawn(async move {
                let builder = Builder::new(TokioExecutor::new());
                if let Err(error) = builder
                    .serve_connection_with_upgrades(TokioIo::new(stream), service)
                    .await
                {
                    event!(Level::WARN, %remote_addr, %error, "Error serving connection");
                }
            });
        }
    }
}

/// A request service is responsible for handling a single request.
///
/// Most importantly, this structure implements the [`hyper::service::Service`] trait, which allows
/// it to be dispatched by [`ViceroyService`] to handle a single request.
///
/// This object does not need to be used directly; users most likely should use
/// [`ViceroyService::serve`] to bind a service to a port, or
/// [`ExecuteCtx::handle_request`] to generate a response for a request when writing
/// test cases.
#[derive(Clone)]
pub struct RequestService {
    ctx: Arc<ExecuteCtx>,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
}

impl RequestService {
    /// Create a new request service for a connection with the given local and remote addresses.
    pub fn new(ctx: Arc<ExecuteCtx>, local_addr: SocketAddr, remote_addr: SocketAddr) -> Self {
        Self {
            ctx,
            local_addr,
            remote_addr,
        }
    }
}

type ServiceFuture = dyn Future<Output = Result<Response<Body>, Error>> + Send;

impl Service<Request<Incoming>> for RequestService {
    type Response = Response<Body>;
    type Error = Error;
    type Future = Pin<Box<ServiceFuture>>;

    /// Process the request and return the response asynchronously.
    fn call(&self, req: Request<Incoming>) -> Self::Future {
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
