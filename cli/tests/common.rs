//! Common values and types used by test fixtures
#![allow(dead_code)] // The exported values are used by other modules in the test suite

use futures::stream::StreamExt;
use hyper::{service, Body as HyperBody, Request, Response, Server};
use std::{convert::Infallible, net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::sync::Mutex;
use tracing_subscriber::filter::EnvFilter;
use viceroy_lib::{
    body::Body,
    config::{Backend, Backends},
    ExecuteCtx, ViceroyService,
};

/// A shorthand for the path to our test fixtures' build artifacts.
///
/// This value can be appended with the name of a fixture's `.wasm` in a test program, using the
/// [`format!`][fmt] macro. For example:
///
/// ```
/// let module_path = format!("{}/guest.wasm", FIXTURE_PATH);
/// ```
///
/// [format]: https://doc.rust-lang.org/std/fmt/fn.format.html
pub static FIXTURE_PATH: &str = "../test-fixtures/target/wasm32-wasi/debug/";

/// A catch-all error, so we can easily use `?` in test cases.
pub type Error = Box<dyn std::error::Error + Send + Sync>;

/// Handy alias for the return type of async Tokio tests
pub type TestResult = Result<(), Error>;

/// We use a lock to serialize execution of test harnesses, becasue they involve spinning
/// up hosts on ports that may overlap with other tests.
static TEST_LOCK: Mutex<()> = Mutex::const_new(());

/// A builder for running individual requests through a wasm fixture.
pub struct Test {
    fixture: String,
    backends: Backends,
    hosts: Vec<HostSpec>,
    log_stdout: bool,
    log_stderr: bool,
    via_hyper: bool,
}

impl Test {
    /// Create a new test given the file name for its wasm fixture.
    pub fn using_fixture(fixture: &str) -> Self {
        Self {
            fixture: fixture.to_owned(),
            backends: Backends::new(),
            hosts: Vec::new(),
            log_stdout: false,
            log_stderr: false,
            via_hyper: false,
        }
    }

    /// Add a backend definition to this test.
    pub fn backend(mut self, name: &str, url: &str, override_host: Option<&str>) -> Self {
        let backend = Backend {
            uri: url.parse().expect("invalid backend URL"),
            override_host: override_host.map(|s| s.parse().expect("can parse override_host")),
        };
        self.backends.insert(name.to_owned(), Arc::new(backend));
        self
    }

    /// Add a mock backend host, serving on `port` at localhost.
    ///
    /// Mock hosts are specified as a synchronous function taking a `Request<Vec<u8>>` and returning
    /// a `Response<Vec<u8>>`. Each one is spawned onto a dedicated Tokio task, which will be
    /// gracefully shut down when the test completes.
    pub fn host<HostFn>(mut self, port: u16, service: HostFn) -> Self
    where
        HostFn: Fn(Request<Vec<u8>>) -> Response<Vec<u8>>,
        HostFn: Send + Sync + 'static,
    {
        let service = Arc::new(service);
        self.hosts.push(HostSpec { port, service });
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

    /// Pass the given request through this test.
    ///
    /// A `Test` can be used repeatedly against different requests. Note, however, that
    /// a fresh execution context is set up each time.
    pub async fn against(&self, req: Request<impl Into<HyperBody>>) -> Response<Body> {
        let _test_lock_guard = TEST_LOCK.lock().await;

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

        let mut module_path = PathBuf::from(FIXTURE_PATH);
        module_path.push(&self.fixture);

        let ctx = ExecuteCtx::new(module_path)
            .expect("failed to set up execution context")
            .with_backends(self.backends.clone())
            .with_log_stderr(self.log_stderr)
            .with_log_stdout(self.log_stdout);
        let addr: SocketAddr = "127.0.0.1:7878".parse().unwrap();

        // spawn any mock hosts, keeping a handle on each host task for clean termination.
        let host_handles: Vec<_> = self.hosts.iter().map(HostSpec::spawn).collect();

        let resp = if self.via_hyper {
            let svc = ViceroyService::new(ctx);
            // We are going to host the service at port 7878, and so it's vital to make sure
            // that we shut down the service after our test request, so that if there are
            // additional tests we can spin up a fresh service at the same port.
            //
            // We do this using the "graceful shutdown" capability of Hyper, with a oneshot
            // channel signaling completion:
            let (tx, rx) = tokio::sync::oneshot::channel();
            // NB the server is spawned onto a dedicated async task; we are going to use the
            // _current_ task to act as the client.
            let server_handle = tokio::spawn(
                hyper::Server::bind(&addr)
                    .serve(svc)
                    .with_graceful_shutdown(async {
                        rx.await
                            .expect("receiver error while shutting down hyper server")
                    }),
            );
            // Pass the request to the server via a Hyper client on the _current_ task:
            let resp = hyper::Client::new()
                .request(req.map(Into::into))
                .await
                .expect("hyper client error making test request");
            // We're done with this test request, so shut down the server.
            tx.send(())
                .expect("sender error while shutting down hyper server");
            // Reap the task handle to ensure that the server did indeed shut down.
            let _ = server_handle.await.expect("hyper server yielded an error");
            resp.map(Into::into)
        } else {
            ctx.handle_request(req.map(Into::into), addr.ip())
                .await
                .expect("failed to handle the request")
        };

        for host in host_handles {
            host.shutdown().await;
        }

        resp
    }

    /// Pass an empty `GET 127.0.0.1:7878` request through this test.
    pub async fn against_empty(&self) -> Response<Body> {
        self.against(Request::get("http://127.0.0.1:7878/").body("").unwrap())
            .await
    }
}

/// The specification of a mock host, as part of a `Test` builder.
struct HostSpec {
    port: u16,
    service: Arc<dyn Fn(Request<Vec<u8>>) -> Response<Vec<u8>> + Send + Sync>,
}

/// A handle to a running mock host, used to gracefully shut down the host on test completion.
struct HostHandle {
    terminate_signal: tokio::sync::oneshot::Sender<()>,
    task_handle: tokio::task::JoinHandle<()>,
}

impl HostSpec {
    /// Spawn a mock host onto its own dedicated Tokio task, returning a handle to allow for graceful
    /// termination of the host on test completion.
    fn spawn(&self) -> HostHandle {
        let port = self.port;
        let service = self.service.clone();

        // we transform `service` into an async function that consumes Hyper bodies. that requires a bit
        // of `Arc` and `move` operations because each invocation needs to produce a distinct `Future`
        let async_service = Arc::new(move |req: Request<HyperBody>| {
            let (parts, body) = req.into_parts();
            let mut body = Box::new(body); // for pinning
            let service = service.clone();

            async move {
                // read out all of the bytes from the body into a vector, then re-assemble the request
                let mut body_bytes = Vec::new();
                while let Some(chunk) = body.next().await {
                    body_bytes.extend_from_slice(&chunk.unwrap());
                }
                let req = Request::from_parts(parts, body_bytes);

                // pass the request through the host function, then convert its body into the form
                // that Hyper wants
                let resp = service(req).map(HyperBody::from);

                let res: Result<_, hyper::Error> = Ok(resp);
                res
            }
        });

        // now we go through Tower's service layers, wrapping `async_host`
        let make_service = service::make_service_fn(move |_conn| {
            let async_host = async_service.clone();
            async move { Ok::<_, Infallible>(service::service_fn(move |req| async_host(req))) }
        });

        // finally we can set up and spawn the actual server on localhost
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        // we set up a "graceful shutdown" for the host, with a oneshot channel signaling completion.
        // that way multiple tests can be run (serially) with mock hosts at the same port; we ensure
        // shutdown at the end of a test.
        let (terminate_signal, rx) = tokio::sync::oneshot::channel();
        let server = Server::bind(&addr)
            .serve(make_service)
            .with_graceful_shutdown(async {
                rx.await
                    .expect("receiver error while shutting down mock host")
            });
        let task_handle =
            tokio::spawn(async { server.await.expect("mock host shut down with hyper error") });
        HostHandle {
            terminate_signal,
            task_handle,
        }
    }
}

impl HostHandle {
    async fn shutdown(self) {
        self.terminate_signal
            .send(())
            .expect("could not send terminate signal to mock host");
        self.task_handle
            .await
            .expect("mock host did not terminate cleanly")
    }
}
