use std::collections::HashMap;
use std::sync::{Arc, Weak};

use hyper::http::uri::PathAndQuery;
use hyper::http::HeaderValue;
use hyper::{Body as HyperBody, Request, Response, Uri};
use tokio::sync::Mutex;

use super::{AsyncResp, TestServer, TestService};

pub type BackendName = String;

/// A set of test backend definitions and possibly-running test servers for those backends.
#[derive(Clone, Debug)]
pub struct TestBackends {
    inner: Arc<Mutex<Inner>>,
}

impl TestBackends {
    /// Create a new, empty set of test backends.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner::new())),
        }
    }

    /// Initialize a set of test backends from [`viceroy_lib::config::Backends`] that probably came
    /// from a `fastly.toml` file.
    ///
    /// Note that this constructor adds backend definitions without an associated test service. A
    /// test service must be set for each backend with [`TestBackends::set_test_service()`] or
    /// [`TestBackends::set_async_test_service()`] before starting the test servers.
    pub fn from_backend_configs(backend_configs: &viceroy_lib::config::Backends) -> Self {
        let mut inner = Inner::new();
        for (name, backend_config) in backend_configs {
            let test_backend = TestBackend {
                path: backend_config
                    .uri
                    .path_and_query()
                    .cloned()
                    .unwrap_or_else(|| PathAndQuery::from_static("/")),
                override_host: backend_config.override_host.clone(),
                cert_host: backend_config.cert_host.clone(),
                use_sni: backend_config.use_sni,
                test_service: None,
                test_server: None,
            };
            inner.map.insert(name.clone(), test_backend);
        }
        Self {
            inner: Arc::new(Mutex::new(inner)),
        }
    }

    /// Get [`viceroy_lib::config::Backends`] for the defined test backends and their test servers.
    ///
    /// Panics if the test servers have not been started, as the ephemeral ports bound during test
    /// server startup are required in order to provide complete complete backend configurations.
    pub async fn backend_configs(&self) -> viceroy_lib::config::Backends {
        let inner = self.inner.lock().await;
        let mut backends = viceroy_lib::config::Backends::new();
        for (name, backend) in inner.map.iter() {
            let addr = backend
                .test_server
                .as_ref()
                .expect("TestBackend servers must be running to get backend configurations")
                .bound_addr;
            let uri = format!("http://{addr}{}", backend.path)
                .parse()
                .expect("backend uri must be valid");
            let backend_config = viceroy_lib::config::Backend {
                uri,
                override_host: backend.override_host.clone(),
                cert_host: backend.cert_host.clone(),
                use_sni: backend.use_sni,
                client_cert: None,
            };
            backends.insert(name.to_string(), Arc::new(backend_config));
        }
        backends
    }

    /// Get a [`TestBackendBuilder`] that will add a backend of the given name when built.
    pub fn test_backend(&self, name: &str) -> TestBackendBuilder {
        TestBackendBuilder {
            inner: Arc::downgrade(&self.inner),
            name: name.to_string(),
            path: "/".to_string(),
            override_host: None,
            use_sni: true,
            test_service: None,
        }
    }

    /// Set the test service for the backend of the given name.
    ///
    /// Panics if the test servers have already been started.
    #[allow(unused)] // It's not used for now, but could be useful for advanced backend chicanery.
    pub async fn set_test_service<TestServiceFn>(&self, name: &str, test_service: TestServiceFn)
    where
        TestServiceFn: Fn(Request<Vec<u8>>) -> Response<Vec<u8>>,
        TestServiceFn: Send + Sync + 'static,
    {
        let mut inner = self.inner.lock().await;
        assert!(
            !inner.servers_are_running,
            "cannot set a test service once servers are running"
        );
        inner
            .map
            .get_mut(name)
            .unwrap_or_else(|| panic!("backend {name:?} not found"))
            .test_service = Some(TestService::Sync(Arc::new(test_service)));
    }

    /// Set the asynchronous test service for the backend of the given name.
    ///
    /// Panics if the test servers have already been started.
    #[allow(unused)] // It's not used for now, but could be useful for advanced backend chicanery.
    pub async fn set_async_test_service<TestServiceFn>(
        &self,
        name: &str,
        test_service: TestServiceFn,
    ) where
        TestServiceFn: Fn(Request<HyperBody>) -> AsyncResp,
        TestServiceFn: Send + Sync + 'static,
    {
        let mut inner = self.inner.lock().await;
        assert!(
            !inner.servers_are_running,
            "cannot set a test service once servers are running"
        );
        inner
            .map
            .get_mut(name)
            .unwrap_or_else(|| panic!("backend {name:?} not found"))
            .test_service = Some(TestService::Async(Arc::new(test_service)));
    }

    /// Are the backend test servers running?
    pub async fn servers_are_running(&self) -> bool {
        self.inner.lock().await.servers_are_running
    }

    /// Start the backend test servers.
    ///
    /// Panics if the servers are already running, or if any backend is missing a test service.
    pub async fn start_servers(&self) {
        let mut inner = self.inner.lock().await;
        assert!(
            !inner.servers_are_running,
            "cannot start TestBackend servers more than once"
        );
        for (name, backend) in inner.map.iter_mut() {
            let Some(service) = backend.test_service.as_ref() else {
                panic!("no service defined for backend {name}");
            };
            backend.test_server = Some(Arc::new(service.spawn()));
        }
        inner.servers_are_running = true;
    }

    /// Get the [`Uri`] suitable for sending a request to a running backend test server.
    ///
    /// Specifically, this `Uri` will include the ephemeral port assigned when the test server was
    /// started, which must be known in advance to properly test fixtures using dynamic backends.
    ///
    /// Panics if no backend by this name is defined, or if the backend test servers have not yet been
    /// started.
    pub async fn uri_for_backend_server(&self, name: &str) -> Uri {
        let inner = self.inner.lock().await;
        let backend = inner.map.get(name).expect("backend not found");
        let addr = backend
            .test_server
            .as_ref()
            .expect("TestBackend servers must be running to get backend configurations")
            .bound_addr;
        format!("http://{addr}{}", backend.path)
            .parse()
            .expect("backend uri must be valid")
    }
}

#[derive(Debug)]
struct Inner {
    map: HashMap<BackendName, TestBackend>,
    servers_are_running: bool,
}

impl Inner {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            servers_are_running: false,
        }
    }
}

#[derive(Clone, Debug)]
pub struct TestBackend {
    path: PathAndQuery,
    override_host: Option<HeaderValue>,
    cert_host: Option<String>,
    use_sni: bool,
    test_service: Option<TestService>,
    test_server: Option<Arc<TestServer>>,
}

#[derive(Debug)]
pub struct TestBackendBuilder {
    inner: Weak<Mutex<Inner>>,
    name: String,
    path: String,
    override_host: Option<String>,
    use_sni: bool,
    test_service: Option<TestService>,
}

impl TestBackendBuilder {
    /// Set the path to be prepended to requests sent to this backend (`/` by default).
    pub fn path(mut self, path: &str) -> Self {
        self.path = path.to_owned();
        self
    }

    /// Set the `override_host` parameter on this backend (not set by default).
    pub fn override_host(mut self, override_host: &str) -> Self {
        self.override_host = Some(override_host.to_string());
        self
    }

    /// Set the `use_sni` parameter on this backend (`true` by default).
    pub fn use_sni(mut self, use_sni: bool) -> Self {
        self.use_sni = use_sni;
        self
    }

    /// Set the synchronous service function to use for this backend.
    ///
    /// The service function takes a request argument with a byte vector body, and returns a
    /// response with a byte vector body. It will be called for each request sent to this backend's
    /// test server.
    ///
    /// A test service (sync or async) must be set before starting the test servers.
    pub fn test_service<TestServiceFn>(mut self, test_service: TestServiceFn) -> Self
    where
        TestServiceFn: Fn(Request<Vec<u8>>) -> Response<Vec<u8>>,
        TestServiceFn: Send + Sync + 'static,
    {
        self.test_service = Some(TestService::Sync(Arc::new(test_service)));
        self
    }

    /// Set the asynchronous service function to use for this backend.
    ///
    /// The service function takes a request argument with a `hyper::Body`, and returns a response
    /// with a `hyper::Body`. It will be called for each request sent to this backend's test server.
    ///
    /// A test service (sync or async) must be set before starting the test servers.
    pub fn async_test_service<TestServiceFn>(mut self, test_service: TestServiceFn) -> Self
    where
        TestServiceFn: Fn(Request<HyperBody>) -> AsyncResp,
        TestServiceFn: Send + Sync + 'static,
    {
        self.test_service = Some(TestService::Async(Arc::new(test_service)));
        self
    }

    /// Finish building this backend and add it to the [`TestBackends`] that created this builder.
    ///
    /// Panics if:
    ///
    /// * The `TestBackends` that created this builder no longer exists, or its test servers have
    /// already been started
    ///
    /// * The `path` does not parse as a valid `PathAndQuery`
    ///
    /// * The `override_host` does not parse as a valid `HeaderValue`
    pub async fn build(self) {
        let inner_arc = self.inner.upgrade().expect("TestBackends dropped");
        let path = self.path.parse().expect("invalid backend path");
        let override_host = self
            .override_host
            .map(|s| s.parse().expect("can parse override_host"));
        let mut inner = inner_arc.lock().await;
        if inner.servers_are_running {
            panic!("cannot add test backends after starting servers");
        }
        inner.map.insert(
            self.name,
            TestBackend {
                path,
                override_host,
                cert_host: None,
                use_sni: self.use_sni,
                test_service: self.test_service,
                test_server: None,
            },
        );
    }
}
