//! Guest code execution.

use {
    crate::{
        body::Body,
        config::{Backends, Dictionaries},
        downstream::prepare_request,
        error::ExecutionError,
        linking::{create_store, dummy_store, link_host_functions, WasmCtx},
        session::Session,
        Error,
    },
    cfg_if::cfg_if,
    hyper::{Request, Response},
    std::{
        net::IpAddr,
        path::{Path, PathBuf},
        sync::atomic::AtomicU64,
        sync::Arc,
    },
    tokio::sync::oneshot::{self, Sender},
    tracing::{event, info, info_span, warn, Instrument, Level},
    wasmtime::{Engine, InstancePre, Linker, Module},
};

/// Execution context used by a [`ViceroyService`](struct.ViceroyService.html).
///
/// This is all of the state needed to instantiate a module, in order to respond to an HTTP
/// request. Note that it is very important that `ExecuteCtx` be cheaply clonable, as it is cloned
/// every time that a viceroy service handles an incoming connection.
#[derive(Clone)]
pub struct ExecuteCtx {
    /// A reference to the global context for Wasm compilation.
    engine: Engine,
    /// An almost-linked Instance: each import function is linked, just needs a Store
    instance_pre: Arc<InstancePre<WasmCtx>>,
    /// The backends for this execution.
    backends: Arc<Backends>,
    /// Preloaded TLS certificates and configuration
    tls_config: Arc<rustls::ClientConfig>,
    /// The dictionaries for this execution.
    dictionaries: Arc<Dictionaries>,
    /// Path to the config, defaults to None
    config_path: Arc<Option<PathBuf>>,
    /// Whether to treat stdout as a logging endpoint
    log_stdout: bool,
    /// Whether to treat stderr as a logging endpoint
    log_stderr: bool,
    /// The ID to assign the next incoming request
    next_req_id: Arc<AtomicU64>,
}

impl ExecuteCtx {
    /// Create a new execution context, given the path to a module.
    pub fn new(module_path: impl AsRef<Path>) -> Result<Self, Error> {
        let engine = Engine::new(&configure_wasmtime())?;
        let mut linker = Linker::new(&engine);
        link_host_functions(&mut linker)?;
        let module = Module::from_file(&engine, module_path)?;

        let mut dummy_store = dummy_store(&engine);
        let instance_pre = linker.instantiate_pre(&mut dummy_store, &module)?;

        Ok(Self {
            engine,
            instance_pre: Arc::new(instance_pre),
            backends: Arc::new(Backends::default()),
            tls_config: Arc::new(configure_tls()?),
            dictionaries: Arc::new(Dictionaries::default()),
            config_path: Arc::new(None),
            log_stdout: false,
            log_stderr: false,
            next_req_id: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Get the engine for this execution context.
    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// Get the backends for this execution context.
    pub fn backends(&self) -> &Backends {
        &self.backends
    }

    /// Set the backends for this execution context.
    pub fn with_backends(self, backends: Backends) -> Self {
        Self {
            backends: Arc::new(backends),
            ..self
        }
    }

    /// Get the dictionaries for this execution context.
    pub fn dictionaries(&self) -> &Dictionaries {
        &self.dictionaries
    }

    /// Set the dictionaries for this execution context.
    pub fn with_dictionaries(self, dictionaries: Dictionaries) -> Self {
        Self {
            dictionaries: Arc::new(dictionaries),
            ..self
        }
    }

    /// Set the path to the config for this execution context.
    pub fn with_config_path(self, config_path: PathBuf) -> Self {
        Self {
            config_path: Arc::new(Some(config_path)),
            ..self
        }
    }

    /// Whether to treat stdout as a logging endpoint.
    pub fn log_stdout(&self) -> bool {
        self.log_stdout
    }

    /// Set the stdout logging policy for this execution context.
    pub fn with_log_stdout(self, log_stdout: bool) -> Self {
        Self { log_stdout, ..self }
    }

    /// Whether to treat stderr as a logging endpoint.
    pub fn log_stderr(&self) -> bool {
        self.log_stderr
    }

    /// Set the stderr logging policy for this execution context.
    pub fn with_log_stderr(self, log_stderr: bool) -> Self {
        Self { log_stderr, ..self }
    }

    /// Gets the TLS configuration
    pub fn tls_config(&self) -> &Arc<rustls::ClientConfig> {
        &self.tls_config
    }

    /// Asynchronously handle a request.
    ///
    /// This method fully instantiates the wasm module housed within the `ExecuteCtx`,
    /// including running the wasm start function. It then proceeds to execute the
    /// instantiated module's WASI entry point, running to completion. If execution
    /// results in an error, a response is still produced, but with a 500 status code.
    ///
    /// Build time: Before you build or test your code, we recommend to set the release flag
    /// e.g. `cargo test --release` otherwise the execution will be very slow. This has to do
    /// with the Cranelift compiler, which is extremely slow when compiled in debug mode.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use hyper::{Body, http::Request};
    /// # use viceroy_lib::{Error, ExecuteCtx, ViceroyService};
    /// # async fn f() -> Result<(), Error> {
    /// # let req = Request::new(Body::from(""));
    /// let ctx = ExecuteCtx::new("path/to/a/file.wasm")?;
    /// let resp = ctx.handle_request(req, "127.0.0.1".parse().unwrap()).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn handle_request(
        self,
        incoming_req: Request<hyper::Body>,
        remote: IpAddr,
    ) -> Result<Response<Body>, Error> {
        let req = prepare_request(incoming_req)?;
        let (sender, receiver) = oneshot::channel();

        let req_id = self
            .next_req_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        // Spawn a separate task to run the guest code. That allows _this_ method to return a response early
        // if the guest sends one, while the guest continues to run afterward within its task.
        let guest_handle = tokio::task::spawn(
            self.run_guest(req, req_id, sender, remote)
                .instrument(info_span!("request", id = req_id)),
        );

        let resp = match receiver.await {
            Ok(resp) => resp,
            Err(_) => match guest_handle
                .await
                .expect("guest worker finished without panicking")
            {
                Ok(_) => Response::new(Body::empty()),
                Err(ExecutionError::WasmTrap(_e)) => {
                    #[allow(unused_mut)]
                    let mut response = Response::builder()
                        .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Body::empty())
                        .unwrap();

                    cfg_if! {
                        // The special functionality sequestered here in this cfg_if! block allows the trap-test
                        // fixture to affirm that the FatalError was experienced by the Guest.
                        if #[cfg(feature = "test-fatalerror-config")] {

                            // Slice off the first line of the error message returned in the GuestError.
                            let error_msg = _e.to_string();
                            let msg = error_msg.split('\n').next().unwrap();

                            // Create a HeaderValue from the error message and place it in the response.
                            let hdr_val =
                                http::header::HeaderValue::from_str(&msg).expect("error message is a valid header");

                            response.headers_mut().insert(http::header::WARNING, hdr_val);
                        }
                    }

                    response
                }
                Err(e) => panic!("failed to run guest: {}", e),
            },
        };

        Ok(resp)
    }

    async fn run_guest(
        self,
        req: Request<Body>,
        req_id: u64,
        sender: Sender<Response<Body>>,
        remote: IpAddr,
    ) -> Result<(), ExecutionError> {
        info!("handling request {} {}", req.method(), req.uri());

        let session = Session::new(
            req_id,
            req,
            sender,
            remote,
            self.backends.clone(),
            self.tls_config.clone(),
            self.dictionaries.clone(),
            self.config_path.clone(),
        );
        // We currently have to postpone linking and instantiation to the guest task
        // due to wasmtime limitations, in particular the fact that `Instance` is not `Send`.
        // However, the fact that the module itself is created within `ExecuteCtx::new`
        // means that the heavy lifting happens only once.
        let mut store = create_store(&self, session).map_err(ExecutionError::Context)?;

        let instance = self
            .instance_pre
            .instantiate_async(&mut store)
            .await
            .map_err(ExecutionError::Instantiation)?;

        // Pull out the `_start` function, which by convention with WASI is the main entry point for
        // an application.
        let main_func = instance
            .get_typed_func::<(), (), _>(&mut store, "_start")
            .map_err(ExecutionError::Typechecking)?;

        // Invoke the entrypoint function, which may or may not send a downstream response.
        let outcome = main_func
            .call_async(&mut store, ())
            .await
            .map(|_| ())
            .map_err(|trap| {
                event!(Level::ERROR, "WebAssembly trapped: {}", trap);
                ExecutionError::WasmTrap(trap)
            });

        // Ensure the downstream response channel is closed, whether or not a response was
        // sent during execution.
        store.data_mut().close_downstream_response_sender();

        let heap_pages = instance
            .get_memory(&mut store, "memory")
            .expect("`memory` is exported")
            .size(&store);

        info!(
            "request completed using {} of WebAssembly heap",
            bytesize::ByteSize::kib(heap_pages as u64 * 64)
        );

        outcome
    }
}

fn configure_wasmtime() -> wasmtime::Config {
    use wasmtime::{
        Config, InstanceAllocationStrategy, InstanceLimits, ModuleLimits,
        PoolingAllocationStrategy, WasmBacktraceDetails,
    };

    let mut config = Config::new();
    config.debug_info(false); // Keep this disabled - wasmtime will hang if enabled
    config.wasm_backtrace_details(WasmBacktraceDetails::Enable);
    config.async_support(true);
    config.consume_fuel(true);

    let module_limits = ModuleLimits {
        // allow for up to 128MiB of linear memory
        memory_pages: 2048,
        // Default limit on types is 100, but some js programs have hit this.
        // We may have to go higher at some point.
        types: 200,
        // AssemblyScript applications tend to create a fair number of globals
        globals: 64,
        // Some applications create a large number of functions, in particular in debug mode
        functions: 20000,
        ..ModuleLimits::default()
    };

    config.allocation_strategy(InstanceAllocationStrategy::Pooling {
        strategy: PoolingAllocationStrategy::NextAvailable,
        module_limits,
        instance_limits: InstanceLimits::default(),
    });

    config
}

fn configure_tls() -> Result<rustls::ClientConfig, Error> {
    let mut config = rustls::ClientConfig::new();
    config.root_store = match rustls_native_certs::load_native_certs() {
        Ok(store) => store,
        Err((Some(store), err)) => {
            warn!(%err, "some certificates could not be loaded");
            store
        }
        Err((None, err)) => return Err(Error::BadCerts(err)),
    };
    if config.root_store.is_empty() {
        warn!("no CA certificates available");
    }
    config.alpn_protocols.clear();
    Ok(config)
}
