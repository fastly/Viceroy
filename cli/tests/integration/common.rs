//! Common values and types used by test fixtures

use futures::stream::StreamExt;
use hyper::{service, Body as HyperBody, Request, Response, Server, Uri};
use std::net::Ipv4Addr;
use std::{
    collections::HashSet, convert::Infallible, future::Future, net::SocketAddr, path::PathBuf,
    sync::Arc,
};
use tracing_subscriber::filter::EnvFilter;
use viceroy_lib::config::UnknownImportBehavior;
use viceroy_lib::{
    body::Body,
    config::{
        DeviceDetection, Dictionaries, FastlyConfig, Geolocation, ObjectStores, SecretStores,
    },
    ExecuteCtx, ProfilingStrategy, ViceroyService,
};

pub use self::backends::TestBackends;

mod backends;

/// A shorthand for the path to our test fixtures' build artifacts for Rust tests.
///
/// This value can be appended with the name of a fixture's `.wasm` in a test program, using the
/// [`format!`][fmt] macro. For example:
///
/// ```
/// let module_path = format!("{}/guest.wasm", RUST_FIXTURE_PATH);
/// ```
pub static RUST_FIXTURE_PATH: &str = "../test-fixtures/target/wasm32-wasi/debug/";

/// A shorthand for the path to our test fixtures' build artifacts for WAT tests.
///
/// This value can be appended with the name of a fixture's `.wat` in a test program, using the
/// [`format!`][fmt] macro. For example:
///
/// ```
/// let module_path = format!("{}/guest.wat", WAT_FIXTURE_PATH);
/// ```
pub static WAT_FIXTURE_PATH: &str = "../test-fixtures/";

/// A catch-all error, so we can easily use `?` in test cases.
pub type Error = Box<dyn std::error::Error + Send + Sync>;

/// Handy alias for the return type of async Tokio tests
pub type TestResult = Result<(), Error>;

/// A builder for running individual requests through a wasm fixture.
pub struct Test {
    module_path: PathBuf,
    backends: TestBackends,
    device_detection: DeviceDetection,
    dictionaries: Dictionaries,
    geolocation: Geolocation,
    object_stores: ObjectStores,
    secret_stores: SecretStores,
    log_stdout: bool,
    log_stderr: bool,
    via_hyper: bool,
    unknown_import_behavior: UnknownImportBehavior,
}

impl Test {
    /// Create a new test given the file name for its wasm fixture.
    pub fn using_fixture(fixture: &str) -> Self {
        let mut module_path = PathBuf::from(RUST_FIXTURE_PATH);
        module_path.push(fixture);

        Self {
            module_path,
            backends: TestBackends::new(),
            device_detection: DeviceDetection::new(),
            dictionaries: Dictionaries::new(),
            geolocation: Geolocation::new(),
            object_stores: ObjectStores::new(),
            secret_stores: SecretStores::new(),
            log_stdout: false,
            log_stderr: false,
            via_hyper: false,
            unknown_import_behavior: Default::default(),
        }
    }

    /// Create a new test given the file name for its wasm fixture.
    pub fn using_wat_fixture(fixture: &str) -> Self {
        let mut module_path = PathBuf::from(WAT_FIXTURE_PATH);
        module_path.push(fixture);

        Self {
            module_path,
            backends: TestBackends::new(),
            device_detection: DeviceDetection::new(),
            dictionaries: Dictionaries::new(),
            geolocation: Geolocation::new(),
            object_stores: ObjectStores::new(),
            secret_stores: SecretStores::new(),
            log_stdout: false,
            log_stderr: false,
            via_hyper: false,
            unknown_import_behavior: Default::default(),
        }
    }

    /// Use backend and dictionary settings provided in a `fastly.toml` file.
    pub fn using_fastly_toml(self, fastly_toml: &str) -> Result<Self, Error> {
        let config = fastly_toml.parse::<FastlyConfig>()?;
        Ok(Self {
            backends: TestBackends::from_backend_configs(config.backends()),
            device_detection: config.device_detection().to_owned(),
            dictionaries: config.dictionaries().to_owned(),
            geolocation: config.geolocation().to_owned(),
            object_stores: config.object_stores().to_owned(),
            secret_stores: config.secret_stores().to_owned(),
            ..self
        })
    }

    /// Use existing [`TestBackends`] for this test, replacing any previously existing backends.
    #[allow(unused)] // It's not used for now, but could be useful for advanced backend chicanery.
    pub fn using_test_backends(mut self, test_backends: &TestBackends) -> Self {
        self.backends = test_backends.clone();
        self
    }

    /// Use the specified [`UnknownImportBehavior`] for this test.
    pub fn using_unknown_import_behavior(
        mut self,
        unknown_import_behavior: UnknownImportBehavior,
    ) -> Self {
        self.unknown_import_behavior = unknown_import_behavior;
        self
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
        ServiceFn: Fn(Request<HyperBody>) -> AsyncResp,
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

    /// Treat stderr as a logging endpoint for this test.
    pub fn log_stderr(self) -> Self {
        Self {
            log_stderr: true,
            ..self
        }
    }

    /// Treat stdout as a logging endpoint for this test.
    pub fn log_stdout(self) -> Self {
        Self {
            log_stdout: true,
            ..self
        }
    }

    /// Actually spin up a hyper server and client for this test, rather than just
    /// passing the request through the guest code.
    pub fn via_hyper(self) -> Self {
        Self {
            via_hyper: true,
            ..self
        }
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
        mut reqs: Vec<Request<impl Into<HyperBody>>>,
    ) -> Result<Vec<Response<Body>>, Error> {
        let mut responses = Vec::with_capacity(reqs.len());

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

        let adapt_core_wasm = false;
        let ctx = ExecuteCtx::new(
            &self.module_path,
            ProfilingStrategy::None,
            HashSet::new(),
            None,
            self.unknown_import_behavior,
            adapt_core_wasm,
        )?
        .with_backends(self.backends.backend_configs().await)
        .with_dictionaries(self.dictionaries.clone())
        .with_device_detection(self.device_detection.clone())
        .with_geolocation(self.geolocation.clone())
        .with_object_stores(self.object_stores.clone())
        .with_secret_stores(self.secret_stores.clone())
        .with_log_stderr(self.log_stderr)
        .with_log_stdout(self.log_stdout);

        if self.via_hyper {
            let svc = ViceroyService::new(ctx);
            // We use the "graceful shutdown" capability of Hyper, with a oneshot channel signaling
            // completion:
            let (tx, rx) = tokio::sync::oneshot::channel();
            // NB the server is spawned onto a dedicated async task; we are going to use the
            // _current_ task to act as the client.
            let (server_handle, server_addr) = {
                // Bind the server to an ephemeral port to allow for parallel test execution.
                let server = hyper::Server::bind(&([127, 0, 0, 1], 0).into()).serve(svc);
                let server_addr = server.local_addr();
                let server_handle = tokio::spawn(server.with_graceful_shutdown(async {
                    rx.await
                        .expect("receiver error while shutting down hyper server")
                }));
                (server_handle, server_addr)
            };

            for mut req in reqs.drain(..) {
                // Fix up the request URI to include the ephemeral port assignment. The `http::Uri`
                // interface makes this unfortunately verbose.
                let new_uri = Uri::builder()
                    .scheme("http")
                    .authority(server_addr.to_string())
                    .path_and_query(
                        req.uri()
                            .path_and_query()
                            .map(|p_and_q| p_and_q.as_str())
                            .unwrap_or(""),
                    )
                    .build()
                    .unwrap();
                *req.uri_mut() = new_uri;

                // Pass the request to the server via a Hyper client on the _current_ task:
                let resp = hyper::Client::new().request(req.map(Into::into)).await?;
                responses.push(resp.map(Into::into));
            }

            // We're done with these test requests, so shut down the server.
            tx.send(())
                .expect("sender error while shutting down hyper server");
            // Reap the task handle to ensure that the server did indeed shut down.
            let _ = server_handle.await?;
        } else {
            for mut req in reqs.drain(..) {
                // We do not have to worry about an ephemeral port in the non-hyper scenario, but we
                // still normalize the request URI for consistency.
                let new_uri = Uri::builder()
                    .scheme("http")
                    .authority("localhost")
                    .path_and_query(
                        req.uri()
                            .path_and_query()
                            .map(|p_and_q| p_and_q.as_str())
                            .unwrap_or(""),
                    )
                    .build()
                    .unwrap();
                *req.uri_mut() = new_uri;
                let resp = ctx
                    .clone()
                    .handle_request(req.map(Into::into), Ipv4Addr::LOCALHOST.into())
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
                responses.push(resp);
            }
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
    pub async fn against(
        &self,
        req: Request<impl Into<HyperBody>>,
    ) -> Result<Response<Body>, Error> {
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

/// A handle to a running test server, used to keep track of its assigned ephemeral port and to
/// gracefully shut down the server when it's no longer needed.
#[derive(Debug)]
struct TestServer {
    bound_addr: SocketAddr,
    terminate_signal: Option<tokio::sync::oneshot::Sender<()>>,
    task_handle: tokio::task::JoinHandle<()>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.terminate_signal
            .take()
            .unwrap()
            .send(())
            .expect("could not send terminate signal to test server");
        if !self.task_handle.is_finished() {
            self.task_handle.abort();
        }
    }
}

#[derive(Clone)]
enum TestService {
    Sync(Arc<dyn Fn(Request<Vec<u8>>) -> Response<Vec<u8>> + Send + Sync>),
    Async(Arc<dyn Fn(Request<HyperBody>) -> AsyncResp + Send + Sync>),
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
    /// Spawn a test server onto a dedicated Tokio task, returning a handle to allow for graceful
    /// termination of the server when it is no longer needed.
    fn spawn(&self) -> TestServer {
        let service = self.clone();

        // we transform `service` into an async function that consumes Hyper bodies. that requires a bit
        // of `Arc` and `move` operations because each invocation needs to produce a distinct `Future`
        let async_service = Arc::new(move |req: Request<HyperBody>| {
            let service = service.clone();

            async move {
                let resp = match service {
                    TestService::Sync(s) => {
                        let (parts, body) = req.into_parts();
                        let mut body = Box::new(body); // for pinning
                                                       // read out all of the bytes from the body into a vector, then re-assemble the request
                        let mut body_bytes = Vec::new();
                        while let Some(chunk) = body.next().await {
                            body_bytes.extend_from_slice(&chunk.unwrap());
                        }
                        let req = Request::from_parts(parts, body_bytes);

                        // pass the request through the service function, then convert its body into
                        // the form that Hyper wants
                        s(req).map(HyperBody::from)
                    }
                    TestService::Async(s) => Box::into_pin(s(req)).await.map(HyperBody::from),
                };

                let res: Result<_, hyper::Error> = Ok(resp);
                res
            }
        });

        // now we go through Tower's service layers, wrapping `async_host`
        let make_service = service::make_service_fn(move |_conn| {
            let async_host = async_service.clone();
            async move { Ok::<_, Infallible>(service::service_fn(move |req| async_host(req))) }
        });

        // we set up a "graceful shutdown" for the server, with a oneshot channel signaling completion.
        let (terminate_signal, rx) = tokio::sync::oneshot::channel();
        // Bind the test server to an ephemeral port to avoid conflicts between
        // concurrently-executing tests.
        let server = Server::bind(&([127, 0, 0, 1], 0).into()).serve(make_service);
        let bound_addr = server.local_addr();
        let graceful_server = server.with_graceful_shutdown(async {
            rx.await
                .expect("receiver error while shutting down mock host")
        });
        let task_handle = tokio::spawn(async {
            graceful_server
                .await
                .expect("mock host shut down with hyper error")
        });
        TestServer {
            bound_addr,
            terminate_signal: Some(terminate_signal),
            task_handle,
        }
    }
}

type AsyncResp = Box<dyn Future<Output = Response<HyperBody>> + Send + Sync>;
