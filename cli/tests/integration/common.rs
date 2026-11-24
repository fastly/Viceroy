//! Common values and types used by test fixtures

use bytes::Bytes;
use http_body::{Frame, SizeHint};
use http_body_util::{BodyExt, Empty, Full, StreamBody, channel::Channel, combinators::BoxBody};
use hyper::{Request, Response, Uri, body::Incoming, service::service_fn};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto,
};
use std::{
    convert::Infallible,
    future::Future,
    io,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    pin::Pin,
    sync::{Arc, LazyLock, Mutex},
    task::{Context, Poll},
    time::Duration,
};
use test_fixtures_artifacts::FIXTURE_DIR;
use tracing_subscriber::filter::EnvFilter;
use viceroy_lib::{ExecuteCtx, ExecuteCtxBuilder};
use viceroy_lib::{RequestService, body::Body, config::FastlyConfig};

pub use self::backends::TestBackends;

mod backends;

#[macro_export]
macro_rules! viceroy_test {
    ($name:ident, |$is_component:ident| $body:block) => {
        mod $name {
            use super::*;

            async fn test_impl($is_component: bool) -> TestResult {
                $body
            }

            #[tokio::test(flavor = "multi_thread")]
            async fn core_wasm() -> TestResult {
                test_impl(false).await
            }

            #[tokio::test(flavor = "multi_thread")]
            async fn component() -> TestResult {
                test_impl(true).await
            }
        }
    };
}

/// Build a [`Test`] for a Go fixture, or skip the enclosing test if that fixture was not
/// built.
///
/// Expands to a `return Ok(())`, so it only works inside a test returning [`TestResult`].
#[macro_export]
macro_rules! go_fixture {
    ($toolchain:expr, $fixture:expr) => {
        match $crate::common::Test::using_go_fixture($toolchain, $fixture) {
            Some(test) => test,
            None => {
                eprintln!(
                    "skipping {}: the Go fixture `{}` was not built. Rebuild the fixtures \
                     with `FIXTURE_LANGS=rust,go,tinygo` and the toolchain on `PATH`.",
                    module_path!(),
                    $fixture,
                );
                return Ok(());
            }
        }
    };
}

/// The Go toolchain that built a fixture.
///
/// One fixture source can be built by both toolchains, so the artifacts are kept apart by
/// toolchain. The distinction matters because the bugs they cover are toolchain-specific:
/// [issue #491][491] is TinyGo and [issue #498][498] is "big" Go.
///
/// [491]: https://github.com/fastly/Viceroy/issues/491
/// [498]: https://github.com/fastly/Viceroy/issues/498
#[derive(Debug, Clone, Copy)]
pub enum GoToolchain {
    /// "big" Go: `GOOS=wasip1 GOARCH=wasm go build`.
    Go,
    /// TinyGo: `tinygo build -target=wasip1`.
    TinyGo,
}

impl GoToolchain {
    /// The directory the fixture build script writes this toolchain's artifacts to.
    fn artifact_dir(self) -> &'static str {
        match self {
            Self::Go => "go",
            Self::TinyGo => "tinygo",
        }
    }
}

/// A shorthand for the path to our test fixtures' build artifacts for WAT tests.
///
/// This value can be appended with the name of a fixture's `.wat` in a test program, using the
/// [`format!`][fmt] macro. For example:
///
/// ```
/// let module_path = format!("{}/guest.wat", WAT_FIXTURE_PATH);
/// ```
///
/// Anchored on `CARGO_MANIFEST_DIR` so it resolves regardless of the process's current
/// working directory, e.g. when launched directly by an editor/debugger.
pub static WAT_FIXTURE_PATH: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../test-fixtures/src/wat/");

/// A catch-all error, so we can easily use `?` in test cases.
pub type Error = Box<dyn std::error::Error + Send + Sync>;

/// Handy alias for the return type of async Tokio tests
pub type TestResult = Result<(), Error>;

/// A builder for running individual requests through a wasm fixture.
pub struct Test {
    builder: ExecuteCtxBuilder,
    backends: TestBackends,
    via_hyper: bool,
}

#[derive(Clone)]
pub struct TestSession {
    /// http client and server address for when `Test::via_hyper()` is used.
    /// Otherwise, the request is passed directly to the guest.
    hyper: Option<(Client<HttpConnector, Full<Bytes>>, String)>,
    ctx: Arc<ExecuteCtx>,
}

impl TestSession {
    pub async fn request(
        &self,
        mut req: Request<impl Into<Bytes>>,
    ) -> Result<Response<Body>, Error> {
        let authority = if let Some((_, server)) = &self.hyper {
            server.clone()
        } else {
            "localhost".to_string()
        };

        let new_uri = Uri::builder()
            .scheme("http")
            .authority(authority)
            .path_and_query(
                req.uri()
                    .path_and_query()
                    .map(|p_and_q| p_and_q.as_str())
                    .unwrap_or(""),
            )
            .build()
            .unwrap();
        *req.uri_mut() = new_uri;

        if let Some((client, _)) = &self.hyper {
            let resp = client.request(req.map(|b| Full::new(b.into()))).await?;
            Ok(resp.map(Into::into))
        } else {
            // We do not have to worry about an ephemeral port in the non-hyper scenario, but we
            // still normalize the request URI for consistency.
            let local = (Ipv4Addr::LOCALHOST, 80).into();
            let remote = (Ipv4Addr::LOCALHOST, 0).into();
            let resp = self
                .ctx
                .clone()
                .handle_request(req.map(|b| Full::new(b.into())), local, remote)
                .await
                .map(|result| {
                    match result {
                        (resp, None) => resp,
                        (_, Some(err)) => {
                            // Splat the string representation of the runtime error into a synthetic
                            // 500. This is a bit of a hack, but good enough to check for expected error
                            // strings.
                            let body = err.to_string();
                            Response::builder()
                                .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
                                .body(Body::from(body.as_bytes()))
                                .unwrap()
                        }
                    }
                })?;
            Ok(resp)
        }
    }
}

impl Test {
    /// A builder for the guest at `module_path`, sharing a compilation cache with every other test.
    ///
    /// Many tests run the same fixture, and nextest runs each test in its own process, so without
    /// an on-disk cache each of them would compile its fixture from scratch.
    fn builder(module_path: PathBuf) -> ExecuteCtxBuilder {
        static CACHE: LazyLock<wasmtime::Cache> = LazyLock::new(|| {
            let mut config = wasmtime::CacheConfig::new();
            config.with_directory(concat!(env!("CARGO_TARGET_TMPDIR"), "/compilation-cache"));
            wasmtime::Cache::new(config).expect("can create the compilation cache")
        });
        let mut builder = ExecuteCtxBuilder::new(module_path);
        builder.set_compilation_cache(Some(CACHE.clone()));
        builder
    }

    /// Create a new test given the file name for its wasm fixture, its target architecture,
    /// and the release mode.
    pub fn using_wasm_fixture(module_path: PathBuf) -> Self {
        Self {
            builder: Self::builder(module_path),
            backends: TestBackends::new(),
            via_hyper: false,
        }
    }

    /// Create a new test given the file name for its wasm fixture.
    /// Only supports rust fixtures with the `wasm32-wasip1` target and `debug` profile.
    /// For other source languages, targets, or profiles, use [`Test::using_wasm_fixture()`] instead.
    pub fn using_fixture(fixture: &str) -> Self {
        let path = PathBuf::from(FIXTURE_DIR)
            .join("rust")
            .join("wasm32-wasip1")
            .join("debug")
            .join(fixture);
        Self::using_wasm_fixture(path)
    }

    /// Create a new test for a Go fixture built by `toolchain`, or `None` if that fixture
    /// was not built.
    ///
    /// Neither Go toolchain is a prerequisite for a Viceroy checkout, so these fixtures are
    /// only built when `FIXTURE_LANGS` asks for them. Callers therefore have to tolerate a
    /// missing artifact; [`go_fixture!`][crate::go_fixture] does so by skipping the test.
    pub fn using_go_fixture(toolchain: GoToolchain, fixture: &str) -> Option<Self> {
        let path = PathBuf::from(FIXTURE_DIR)
            .join(toolchain.artifact_dir())
            .join("wasm32-wasip1")
            .join(fixture);
        path.exists().then(|| Self::using_wasm_fixture(path))
    }

    /// Create a new test given the file name for its wasm fixture.
    pub fn using_wat_fixture(fixture: &str) -> Self {
        let mut module_path = PathBuf::from(WAT_FIXTURE_PATH);
        module_path.push(fixture);

        Self {
            builder: Self::builder(module_path),
            backends: TestBackends::new(),
            via_hyper: false,
        }
    }

    /// Directly configure the execute context builder for this test.
    /// The backends on the builder will be ignored, use
    /// [Self::backend] or [Self::async_backend] instead.
    pub fn configure_ctx(self, f: impl FnOnce(&mut ExecuteCtxBuilder)) -> Self {
        Self {
            builder: self.builder.with(f),
            ..self
        }
    }

    /// Use backend and dictionary settings provided in a `fastly.toml` file.
    pub fn using_fastly_toml(mut self, fastly_toml: &str) -> Result<Self, Error> {
        let config = fastly_toml.parse::<FastlyConfig>()?;
        self.builder.use_config(&config);
        Ok(Self {
            backends: TestBackends::from_backend_configs(config.backends()),
            ..self
        })
    }

    /// Add a backend definition to this test.
    ///
    /// The `name` is the static backend name that can be passed as, for example, the argument to
    /// `Request::send()`.
    ///
    /// The `path` is the path that will be prepended to the URLs of requests sent to this
    /// backend. Note that the host and port used to send requests to this backend will be
    /// automatically determined when the test servers are started.
    ///
    /// `override_host` optionally sets the corresponding parameter in the backend definition.
    ///
    /// `service` is the synchronous function that the test server will run on each request this
    /// backend receives in order to determine what response to send.
    pub async fn backend<ServiceFn>(
        self,
        name: &str,
        path: &str,
        override_host: Option<&str>,
        service: ServiceFn,
    ) -> Self
    where
        ServiceFn: Fn(Request<Vec<u8>>) -> Response<Vec<u8>>,
        ServiceFn: Send + Sync + 'static,
    {
        let uri: Uri = path.parse().expect("invalid backend URL");
        let mut builder = self
            .backends
            .test_backend(name)
            .path(uri.path())
            .use_sni(true)
            .test_service(service);
        if let Some(override_host) = override_host {
            builder = builder.override_host(override_host);
        }
        builder.build().await;
        self
    }

    /// Add a backend definition to this test with an asynchronous test server function and
    /// (optionally) a first and between-byte timeout.
    ///
    /// The `name` is the static backend name that can be passed as, for example, the argument to
    /// `Request::send()`.
    ///
    /// The `path` is the path that will be prepended to the URLs of requests sent to this
    /// backend. Note that the host and port used to send requests to this backend will be
    /// automatically determined when the test servers are started.
    ///
    /// `override_host` optionally sets the corresponding parameter in the backend definition.
    ///
    /// `service` is the asynchronous function that the test server will run on each request this
    /// backend receives in order to determine what response to send.
    pub async fn async_backend_with_timeouts<ServiceFn>(
        self,
        name: &str,
        url: &str,
        override_host: Option<&str>,
        first_byte_timeout: Option<Duration>,
        between_bytes_timeout: Option<Duration>,
        service: ServiceFn,
    ) -> Self
    where
        ServiceFn: Fn(Request<Incoming>) -> AsyncResp,
        ServiceFn: Send + Sync + 'static,
    {
        let uri: Uri = url.parse().expect("invalid backend URL");
        let mut builder = self
            .backends
            .test_backend(name)
            .path(uri.path())
            .use_sni(true)
            .async_test_service(service);
        if let Some(override_host) = override_host {
            builder = builder.override_host(override_host);
        }
        if let Some(timeout) = first_byte_timeout {
            builder = builder.first_byte_timeout(timeout);
        }
        if let Some(timeout) = between_bytes_timeout {
            builder = builder.between_bytes_timeout(timeout);
        }
        builder.build().await;
        self
    }

    /// Add a backend definition to this test with an asynchronous test server function.
    ///
    /// The `name` is the static backend name that can be passed as, for example, the argument to
    /// `Request::send()`.
    ///
    /// The `path` is the path that will be prepended to the URLs of requests sent to this
    /// backend. Note that the host and port used to send requests to this backend will be
    /// automatically determined when the test servers are started.
    ///
    /// `override_host` optionally sets the corresponding parameter in the backend definition.
    ///
    /// `service` is the asynchronous function that the test server will run on each request this
    /// backend receives in order to determine what response to send.
    pub async fn async_backend<ServiceFn>(
        self,
        name: &str,
        url: &str,
        override_host: Option<&str>,
        service: ServiceFn,
    ) -> Self
    where
        ServiceFn: Fn(Request<Incoming>) -> AsyncResp,
        ServiceFn: Send + Sync + 'static,
    {
        let uri: Uri = url.parse().expect("invalid backend URL");
        let mut builder = self
            .backends
            .test_backend(name)
            .path(uri.path())
            .use_sni(true)
            .async_test_service(service);
        if let Some(override_host) = override_host {
            builder = builder.override_host(override_host);
        }
        builder.build().await;
        self
    }

    /// Actually spin up a hyper server and client for this test, rather than just
    /// passing the request through the guest code.
    pub fn via_hyper(self) -> Self {
        Self {
            via_hyper: true,
            ..self
        }
    }

    /// Automatically adapt the wasm to a component before running.
    pub fn adapt_component(mut self, adapt: bool) -> Self {
        self.builder.set_adapt_components(adapt);
        self
    }

    /// Start the backends and create the [`ExecuteCtx`], returning a
    /// [`TestSession`] that can be used to to send requests through the guest,
    /// and a handle to the running test server, if `Test::via_hyper()` was used.
    ///
    /// Shut down the test server with [`TestServer::shutdown()`] when done.
    pub async fn start(&self) -> Result<(TestSession, Option<TestServer>), Error> {
        // Install a tracing subscriber. We use a human-readable event formatter in tests, using a
        // writer that supports input capturing for `cargo test`. This subscribes to all events in
        // the `viceroy-lib` library.
        tracing_subscriber::fmt()
            .with_env_filter(
                EnvFilter::from_default_env().add_directive("viceroy_lib=trace".parse().unwrap()),
            )
            .pretty()
            .with_test_writer()
            // `try_init` returns an `Err` if the initialization was unsuccessful, likely because a
            // global subscriber was already installed. we will ignore this error if it happens.
            .try_init()
            .ok();

        // Start the backend test servers so that we can ask `TestBackends` for the final backend
        // configurations, including the ephemeral ports we'll need for requests to actually land on
        // the right servers. The test servers will remain running until after this [`Test`] is
        // dropped.
        if !self.backends.servers_are_running().await {
            self.backends.start_servers().await;
        }

        let mut builder = self.builder.clone();
        builder.set_backends(self.backends.backend_configs().await);
        let ctx = builder.finish()?;

        if !self.via_hyper {
            return Ok((TestSession { hyper: None, ctx }, None));
        }

        let inner = ctx.clone();
        // NB the server is spawned onto a dedicated async task; we are going to use the
        // _current_ task to act as the client.
        // Bind the server to an ephemeral port to allow for parallel test execution.
        let server = spawn_server((Ipv4Addr::LOCALHOST, 0).into(), move |local, remote| {
            RequestService::new(inner.clone(), local, remote)
        })?;
        let client = Client::builder(TokioExecutor::new())
            .timer(TokioTimer::new())
            .pool_timer(TokioTimer::new())
            .build_http();
        Ok((
            TestSession {
                hyper: Some((client, server.bound_addr.to_string())),
                ctx,
            },
            Some(server),
        ))
    }

    /// Pass the given requests through this test, returning the associated responses.
    ///
    /// A `Test` can be used repeatedly against different requests, either individually (as with
    /// `against()`) or in batches (as with `against_many()`).
    ///
    /// The difference between calling this function with many requests, rather than calling
    /// `against()` multiple times, is that the requests shared in an `against_many()` call will
    /// share the same Wasm execution context. This can be useful when validating interactions
    /// across shared state in the context. Subsequent calls to `against_many()` (or `against()`)
    /// will use a fresh context.
    ///
    /// When this function is called, the test servers for its defined backends will be started, if
    /// they have not been already. Those test servers will remain running for the lifetime of this
    /// [`Test`] object, and are therefore potentially reused for multiple `against*()` invocations.
    pub async fn against_many(
        &self,
        mut reqs: Vec<Request<impl Into<Bytes>>>,
    ) -> Result<Vec<Response<Body>>, Error> {
        let mut responses = Vec::with_capacity(reqs.len());
        let (session, server) = self.start().await?;

        for req in reqs.drain(..) {
            let resp = session.request(req).await?;
            responses.push(resp);
        }

        // We're done with these test requests, so stop accepting connections and reap the
        // listener task. Open connections can finish streaming their responses.
        if let Some(server) = server {
            server.shutdown().await?;
        }

        Ok(responses)
    }

    /// Pass the given request to a Viceroy execution context defined by this test.
    ///
    /// Only the path, query, and fragment of the request URI will be used; the host and port will
    /// be rewritten as appropriate to connect to the Viceroy context.
    ///
    /// A `Test` can be used repeatedly against different requests. Note, however, that
    /// a fresh execution context is set up each time.
    pub async fn against(&self, req: Request<impl Into<Bytes>>) -> Result<Response<Body>, Error> {
        Ok(self
            .against_many(vec![req])
            .await?
            .pop()
            .expect("singleton back from against_many"))
    }

    /// Pass an empty `GET /` request through this test.
    pub async fn against_empty(&self) -> Result<Response<Body>, Error> {
        self.against(Request::get("/").body("").unwrap()).await
    }

    /// Start the test servers for this test's [`TestBackends`].
    ///
    /// Panics if a test service has not been set for all configured backends. This is unlikely to
    /// occur unless using [`Test::using_fastly_toml()] or [`Test::using_backends()`], as the
    /// convenience methods for defining backends require a test service.
    pub async fn start_backend_servers(&self) {
        self.backends.start_servers().await;
    }

    /// Get the [`Uri`] suitable for sending a request to a running backend test server.
    ///
    /// Specifically, this `Uri` will include the ephemeral port assigned when the test server was
    /// started, which must be known in advance to properly test fixtures using dynamic backends.
    ///
    /// Panics if no backend by this name is defined, or if the backend test servers have not yet
    /// been started.
    pub async fn uri_for_backend_server(&self, name: &str) -> Uri {
        self.backends.uri_for_backend_server(name).await
    }
}

/// The response body type for test backends.
pub struct TestBody(BoxBody<Bytes, Error>);

impl TestBody {
    /// Wrap an arbitrary body.
    pub fn new<B>(body: B) -> Self
    where
        B: http_body::Body<Data = Bytes> + Send + Sync + 'static,
        B::Error: Into<Error>,
    {
        Self(body.map_err(Into::into).boxed())
    }

    /// An empty body.
    pub fn empty() -> Self {
        Self::new(Empty::new())
    }

    /// A body with the given contents.
    pub fn full(bytes: impl Into<Bytes>) -> Self {
        Self::new(Full::new(bytes.into()))
    }

    /// A body that is written to via the returned sender.
    pub fn channel() -> (http_body_util::channel::Sender<Bytes, Error>, Self) {
        let (sender, body) = Channel::new(1);
        (sender, Self::new(body))
    }

    /// A body that never completes.
    pub fn pending() -> Self {
        Self::new(StreamBody::new(futures::stream::pending::<
            Result<Frame<Bytes>, Error>,
        >()))
    }
}

impl http_body::Body for TestBody {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Pin::new(&mut self.0).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.0.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.0.size_hint()
    }
}

/// A handle to a running test server, used to keep track of its assigned ephemeral port and to
/// shut down the server when it's no longer needed.
///
/// Dropping this handle stops accepting connections. Open connections are left to finish, so
/// responses still being streamed after the [`Test`] is dropped are not cut off.
#[derive(Debug)]
pub struct TestServer {
    pub bound_addr: SocketAddr,
    terminate_signal: Option<tokio::sync::oneshot::Sender<()>>,
    task_handle: tokio::task::JoinHandle<()>,
}

impl TestServer {
    /// Stop accepting connections and wait for the listener task to exit.
    pub async fn shutdown(mut self) -> Result<(), tokio::task::JoinError> {
        self.stop_accepting();
        (&mut self.task_handle).await
    }

    fn stop_accepting(&mut self) {
        if let Some(signal) = self.terminate_signal.take() {
            let _ = signal.send(());
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.stop_accepting();
    }
}

/// Spawn a test server bound to `addr` onto a dedicated Tokio task.
///
/// `make_service` is called for each accepted connection with its local and remote addresses
/// to create the service that handles requests on it.
pub fn spawn_server<MakeService, S, B>(
    addr: SocketAddr,
    make_service: MakeService,
) -> io::Result<TestServer>
where
    MakeService: Fn(SocketAddr, SocketAddr) -> S + Send + 'static,
    S: hyper::service::Service<Request<Incoming>, Response = Response<B>> + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<Error>,
    B: http_body::Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Error>,
{
    // Bind synchronously, so that the bound address is known before returning.
    let listener = std::net::TcpListener::bind(addr)?;
    listener.set_nonblocking(true)?;
    let listener = tokio::net::TcpListener::from_std(listener)?;
    let bound_addr = listener.local_addr()?;
    // We set up shutdown with a oneshot channel signaling the listener to stop accepting.
    let (terminate_signal, mut receiver) = tokio::sync::oneshot::channel();
    let builder = auto::Builder::new(TokioExecutor::new());

    let task_handle = tokio::spawn(async move {
        loop {
            let accepted = tokio::select! {
                biased;
                _ = &mut receiver => break,
                accepted = listener.accept() => accepted,
            };
            let (stream, remote_addr) = match accepted {
                Ok(accepted) => accepted,
                Err(e) => {
                    tracing::warn!("test server failed to accept connection: {e}");
                    continue;
                }
            };
            let service = make_service(bound_addr, remote_addr);
            let builder = builder.clone();
            // Connections run independently of the listener so shutdown does not cut off bodies.
            tokio::spawn(async move {
                if let Err(e) = builder
                    .serve_connection_with_upgrades(TokioIo::new(stream), service)
                    .await
                {
                    tracing::warn!("test server connection error: {e}");
                }
            });
        }
    });

    Ok(TestServer {
        bound_addr,
        terminate_signal: Some(terminate_signal),
        task_handle,
    })
}

#[tokio::test]
async fn server_shutdown_preserves_streaming_responses() -> TestResult {
    let (mut sender, body) = TestBody::channel();
    let body = Arc::new(Mutex::new(Some(body)));
    let server = spawn_server((Ipv4Addr::LOCALHOST, 0).into(), move |_, _| {
        let body = body.clone();
        service_fn(move |_| {
            let body = body.lock().unwrap().take().expect("only one request");
            async move { Ok::<_, Infallible>(Response::new(body)) }
        })
    })?;
    let addr = server.bound_addr;
    let client = Client::builder(TokioExecutor::new()).build_http::<Empty<Bytes>>();
    let request = client.get(format!("http://{addr}/").parse()?);
    // Send an initial chunk so Hyper flushes the headers before we shut down the listener.
    let (response, sent) = tokio::join!(request, sender.send_data(Bytes::from_static(b"before ")));
    sent?;
    let response = response?;

    server.shutdown().await?;
    assert!(tokio::net::TcpStream::connect(addr).await.is_err());
    sender.send_data(Bytes::from_static(b"after")).await?;
    drop(sender);
    let body = response.into_body().collect().await?.to_bytes();
    assert_eq!(body, "before after");
    Ok(())
}

type SyncService = dyn Fn(Request<Vec<u8>>) -> Response<Vec<u8>> + Send + Sync;

pub type AsyncResp = Box<dyn Future<Output = Response<TestBody>> + Send + Sync>;
type AsyncService = dyn Fn(Request<Incoming>) -> AsyncResp + Send + Sync;

#[derive(Clone)]
enum TestService {
    Sync(Arc<SyncService>),
    Async(Arc<AsyncService>),
}

impl std::fmt::Debug for TestService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sync(_) => f.debug_tuple("Sync").finish(),
            Self::Async(_) => f.debug_tuple("Async").finish(),
        }
    }
}

impl TestService {
    /// Spawn a test server onto a dedicated Tokio task, returning a handle that shuts down the
    /// server when it is no longer needed.
    fn spawn(&self) -> TestServer {
        let service = self.clone();

        // we transform `service` into an async function that consumes Hyper bodies. that requires a bit
        // of `Arc` and `move` operations because each invocation needs to produce a distinct `Future`
        let async_service = Arc::new(move |req: Request<Incoming>| {
            let service = service.clone();

            async move {
                let resp = match service {
                    TestService::Sync(s) => {
                        let (parts, body) = req.into_parts();
                        // read out all of the bytes from the body into a vector, then re-assemble the request
                        let body_bytes = body.collect().await.unwrap().to_bytes().to_vec();
                        let req = Request::from_parts(parts, body_bytes);

                        // pass the request through the service function, then convert its body into
                        // the form that Hyper wants
                        s(req).map(TestBody::full)
                    }
                    TestService::Async(s) => Box::into_pin(s(req)).await,
                };

                let res: Result<_, hyper::Error> = Ok(resp);
                res
            }
        });

        // Now wrap the async service in a per-connection Hyper service.
        // Bind the test server to an ephemeral port to avoid conflicts between
        // concurrently-executing tests.
        spawn_server((Ipv4Addr::LOCALHOST, 0).into(), move |_, _| {
            let async_service = async_service.clone();
            service_fn(move |req| async_service(req))
        })
        .expect("could not bind test server")
    }
}
