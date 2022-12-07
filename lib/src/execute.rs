//! Guest code execution.

use {
    crate::{
        body::Body,
        config::{Backends, Dictionaries, Geolocation, ExperimentalModule},
        downstream::prepare_request,
        error::ExecutionError,
        linking::{create_store, dummy_store, link_host_functions, WasmCtx},
        object_store::ObjectStore,
        session::Session,
        upstream::TlsConfig,
        Error,
    },
    hyper::{Request, Response},
    std::{
        collections::HashSet,
        net::IpAddr,
        path::{Path, PathBuf},
        sync::atomic::AtomicU64,
        sync::Arc,
        time::Instant,
    },
    tokio::sync::oneshot::{self, Sender},
    tracing::{event, info, info_span, Instrument, Level},
    wasi_common::I32Exit,
    wasmtime::{Engine, InstancePre, Linker, Module, ProfilingStrategy},
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
    /// The geolocation mappings for this execution.
    geolocation: Arc<Geolocation>,
    /// Preloaded TLS certificates and configuration
    tls_config: TlsConfig,
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
    /// The ObjectStore associated with this instance of Viceroy
    object_store: Arc<ObjectStore>,
    // Whether to enable wasi-nn functionality
    // wasi_modules: HashSet<WasiModule>,
}

impl ExecuteCtx {
    /// Create a new execution context, given the path to a module.
    pub fn new(
        module_path: impl AsRef<Path>,
        profiling_strategy: ProfilingStrategy,
        wasi_modules: HashSet<ExperimentalModule>,
    ) -> Result<Self, Error> {
        let config = &configure_wasmtime(profiling_strategy);
        let engine = Engine::new(config)?;
        let mut linker = Linker::new(&engine);
        link_host_functions(&mut linker, &wasi_modules)?;
        let module = Module::from_file(&engine, module_path)?;

        let mut dummy_store = dummy_store(&engine);
        let instance_pre = linker.instantiate_pre(&mut dummy_store, &module)?;

        Ok(Self {
            engine,
            instance_pre: Arc::new(instance_pre),
            backends: Arc::new(Backends::default()),
            geolocation: Arc::new(Geolocation::default()),
            tls_config: TlsConfig::new()?,
            dictionaries: Arc::new(Dictionaries::default()),
            config_path: Arc::new(None),
            log_stdout: false,
            log_stderr: false,
            next_req_id: Arc::new(AtomicU64::new(0)),
            object_store: Arc::new(ObjectStore::new()),
            // wasi_modules,
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

    /// Get the geolocation mappings for this execution context.
    pub fn geolocation(&self) -> &Geolocation {
        &self.geolocation
    }

    /// Set the geolocation mappings for this execution context.
    pub fn with_geolocation(self, geolocation: Geolocation) -> Self {
        Self {
            geolocation: Arc::new(geolocation),
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

    /// Set the object store for this execution context.
    pub fn with_object_store(self, object_store: ObjectStore) -> Self {
        Self {
            object_store: Arc::new(object_store),
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
    pub fn tls_config(&self) -> &TlsConfig {
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
    /// # use viceroy_lib::{Error, ExecuteCtx, ProfilingStrategy, ViceroyService};
    /// # async fn f() -> Result<(), Error> {
    /// # let req = Request::new(Body::from(""));
    /// let ctx = ExecuteCtx::new("path/to/a/file.wasm", ProfilingStrategy::None)?;
    /// let resp = ctx.handle_request(req, "127.0.0.1".parse().unwrap()).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn handle_request(
        self,
        incoming_req: Request<hyper::Body>,
        remote: IpAddr,
    ) -> Result<(Response<Body>, Option<anyhow::Error>), Error> {
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
            Ok(resp) => (resp, None),
            Err(_) => match guest_handle
                .await
                .expect("guest worker finished without panicking")
            {
                Ok(_) => (Response::new(Body::empty()), None),
                Err(ExecutionError::WasmTrap(_e)) => {
                    println!("There was an error handling the request {}", _e.to_string());
                    #[allow(unused_mut)]
                    let mut response = Response::builder()
                        .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Body::empty())
                        .unwrap();
                    (response, Some(_e))
                }
                Err(e) => panic!("failed to run guest: {}", e),
            },
        };

        Ok(resp)
    }

    pub async fn handle_request_with_runtime_error(
        self,
        incoming_req: Request<hyper::Body>,
        remote: IpAddr,
    ) -> Result<Response<Body>, Error> {
        let result = self.handle_request(incoming_req, remote).await?;
        let resp = match result.1 {
            None => result.0,
            Some(err) => {
                let body = format!("{:?}", err);
                Response::builder()
                    .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from(body.as_bytes()))
                    .unwrap()
            }
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
        let start_timestamp = Instant::now();
        let session = Session::new(
            req_id,
            req,
            sender,
            remote,
            self.backends.clone(),
            self.geolocation.clone(),
            self.tls_config.clone(),
            self.dictionaries.clone(),
            self.config_path.clone(),
            self.object_store.clone(),
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
        let outcome = match main_func.call_async(&mut store, ()).await {
            Ok(_) => Ok(()),
            Err(e) => {
                if let Some(exit) = e.downcast_ref::<I32Exit>() {
                    if exit.0 == 0 {
                        Ok(())
                    } else {
                        event!(Level::ERROR, "WebAssembly exited with error: {:?}", e);
                        Err(ExecutionError::WasmTrap(e))
                    }
                } else {
                    event!(Level::ERROR, "WebAssembly trapped: {:?}", e);
                    Err(ExecutionError::WasmTrap(e))
                }
            }
        };

        // Ensure the downstream response channel is closed, whether or not a response was
        // sent during execution.
        store.data_mut().close_downstream_response_sender();

        let heap_pages = instance
            .get_memory(&mut store, "memory")
            .expect("`memory` is exported")
            .size(&store);

        let request_duration = Instant::now().duration_since(start_timestamp);

        info!(
            "request completed using {} of WebAssembly heap",
            bytesize::ByteSize::kib(heap_pages as u64 * 64)
        );

        info!("request completed in {:.0?}", request_duration);

        outcome
    }
}

fn configure_wasmtime(profiling_strategy: ProfilingStrategy) -> wasmtime::Config {
    use wasmtime::{
        Config, InstanceAllocationStrategy, PoolingAllocationConfig, PoolingAllocationStrategy,
        WasmBacktraceDetails,
    };

    let mut config = Config::new();
    config.debug_info(false); // Keep this disabled - wasmtime will hang if enabled
    config.wasm_backtrace_details(WasmBacktraceDetails::Enable);
    config.async_support(true);
    config.consume_fuel(true);
    config.profiler(profiling_strategy);

    const MB: usize = 1 << 20;
    let mut pooling_allocation_config = PoolingAllocationConfig::default();

    // This number matches C@E production
    pooling_allocation_config.instance_size(MB);

    // Core wasm programs have 1 memory
    pooling_allocation_config.instance_memories(1);

    // allow for up to 128MiB of linear memory. Wasm pages are 64k
    pooling_allocation_config.instance_memory_pages(128 * (MB as u64) / (64 * 1024));

    // Core wasm programs have 1 table
    pooling_allocation_config.instance_tables(1);

    // Some applications create a large number of functions, in particular
    // when compiled in debug mode or applications written in swift. Every
    // function can end up in the table
    pooling_allocation_config.instance_table_elements(98765);

    // Number of instances: the pool will allocate virtual memory for this
    // many instances, which limits the number of requests which can be
    // handled concurrently.
    pooling_allocation_config.strategy(PoolingAllocationStrategy::NextAvailable);

    config.allocation_strategy(InstanceAllocationStrategy::Pooling(
        pooling_allocation_config,
    ));

    config
}
