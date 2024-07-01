//! Guest code execution.

use {
    crate::{
        adapt,
        body::Body,
        component as compute,
        config::{
            Backends, DeviceDetection, Dictionaries, ExperimentalModule, Geolocation,
            UnknownImportBehavior,
        },
        downstream::prepare_request,
        error::ExecutionError,
        linking::{create_store, link_host_functions, ComponentCtx, WasmCtx},
        object_store::ObjectStores,
        secret_store::SecretStores,
        session::Session,
        upstream::TlsConfig,
        Error,
    },
    hyper::{Request, Response},
    std::{
        collections::HashSet,
        fs,
        io::Write,
        net::{IpAddr, Ipv4Addr},
        path::{Path, PathBuf},
        sync::atomic::{AtomicBool, AtomicU64, Ordering},
        sync::{Arc, Mutex},
        thread::{self, JoinHandle},
        time::{Duration, Instant, SystemTime},
    },
    tokio::sync::oneshot::{self, Sender},
    tracing::{event, info, info_span, warn, Instrument, Level},
    wasmtime::{
        component::{self, Component},
        Engine, GuestProfiler, InstancePre, Linker, Module, ProfilingStrategy,
    },
    wasmtime_wasi::I32Exit,
};

pub const EPOCH_INTERRUPTION_PERIOD: Duration = Duration::from_micros(50);

enum Instance {
    Module(Module, InstancePre<WasmCtx>),
    Component(component::InstancePre<ComponentCtx>),
}

impl Instance {
    fn unwrap_module(&self) -> (&Module, &InstancePre<WasmCtx>) {
        match self {
            Instance::Module(m, i) => (m, i),
            Instance::Component(_) => panic!("unwrap_module called on a component"),
        }
    }
}

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
    instance_pre: Arc<Instance>,
    /// The backends for this execution.
    backends: Arc<Backends>,
    /// The device detection mappings for this execution.
    device_detection: Arc<DeviceDetection>,
    /// The geolocation mappings for this execution.
    geolocation: Arc<Geolocation>,
    /// Preloaded TLS certificates and configuration
    tls_config: TlsConfig,
    /// The dictionaries for this execution.
    dictionaries: Arc<Dictionaries>,
    /// Path to the config, defaults to None
    config_path: Arc<Option<PathBuf>>,
    /// Where to direct logging endpoint messages, defaults to stdout
    capture_logs: Arc<Mutex<dyn Write + Send>>,
    /// Whether to treat stdout as a logging endpoint
    log_stdout: bool,
    /// Whether to treat stderr as a logging endpoint
    log_stderr: bool,
    /// The ID to assign the next incoming request
    next_req_id: Arc<AtomicU64>,
    /// The ObjectStore associated with this instance of Viceroy
    object_store: ObjectStores,
    /// The secret stores for this execution.
    secret_stores: Arc<SecretStores>,
    // `Arc` for the two fields below because this struct must be `Clone`.
    epoch_increment_thread: Option<Arc<JoinHandle<()>>>,
    epoch_increment_stop: Arc<AtomicBool>,
    /// Path to write profiling results from the guest. In serve mode,
    /// this must refer to a directory, while in run mode it names
    /// a file.
    guest_profile_path: Arc<Option<PathBuf>>,
}

impl ExecuteCtx {
    /// Create a new execution context, given the path to a module and a set of experimental wasi modules.
    pub fn new(
        module_path: impl AsRef<Path>,
        profiling_strategy: ProfilingStrategy,
        wasi_modules: HashSet<ExperimentalModule>,
        guest_profile_path: Option<PathBuf>,
        unknown_import_behavior: UnknownImportBehavior,
        adapt_components: bool,
    ) -> Result<Self, Error> {
        let input = fs::read(&module_path)?;

        let is_wat = module_path
            .as_ref()
            .extension()
            .map(|str| str == "wat")
            .unwrap_or(false);

        // When the input wasn't a component, but we're automatically adapting,
        // apply the component adapter.
        let is_component = adapt::is_component(&input);
        let (is_wat, is_component, input) = if !is_component && adapt_components {
            let input = if is_wat {
                let text = String::from_utf8(input).map_err(|_| {
                    anyhow::anyhow!("Failed to parse {}", module_path.as_ref().display())
                })?;
                adapt::adapt_wat(&text)?
            } else {
                adapt::adapt_bytes(&input)?
            };

            (false, true, input)
        } else {
            (is_wat, is_component, input)
        };

        let config = &configure_wasmtime(is_component, profiling_strategy);
        let engine = Engine::new(config)?;
        let instance_pre = if is_component {
            if unknown_import_behavior != UnknownImportBehavior::LinkError {
                return Err(Error::Other(anyhow::anyhow!(
                    "Wasm components do not support unknown import behaviors other than link-time errors"
                )));
            }

            warn!(
                "

   +------------------------------------------------------------------------+
   |                                                                        |
   | Wasm Component support in viceroy is in active development, and is not |
   |                    supported for general consumption.                  |
   |                                                                        |
   +------------------------------------------------------------------------+

            "
            );

            let mut linker: component::Linker<ComponentCtx> = component::Linker::new(&engine);
            compute::link_host_functions(&mut linker)?;
            let component = if is_wat {
                Component::from_file(&engine, &module_path)?
            } else {
                Component::from_binary(&engine, &input)?
            };
            let instance_pre = linker.instantiate_pre(&component)?;
            Instance::Component(instance_pre)
        } else {
            let mut linker = Linker::new(&engine);
            link_host_functions(&mut linker, &wasi_modules)?;
            let module = if is_wat {
                Module::from_file(&engine, &module_path)?
            } else {
                Module::from_binary(&engine, &input)?
            };

            match unknown_import_behavior {
                UnknownImportBehavior::LinkError => (),
                UnknownImportBehavior::Trap => linker.define_unknown_imports_as_traps(&module)?,
                UnknownImportBehavior::ZeroOrNull => {
                    linker.define_unknown_imports_as_default_values(&module)?
                }
            }

            let instance_pre = linker.instantiate_pre(&module)?;
            Instance::Module(module, instance_pre)
        };

        // Create the epoch-increment thread.

        let epoch_increment_stop = Arc::new(AtomicBool::new(false));
        let engine_clone = engine.clone();
        let epoch_increment_stop_clone = epoch_increment_stop.clone();
        let epoch_increment_thread = Some(Arc::new(thread::spawn(move || {
            while !epoch_increment_stop_clone.load(Ordering::Relaxed) {
                thread::sleep(EPOCH_INTERRUPTION_PERIOD);
                engine_clone.increment_epoch();
            }
        })));

        Ok(Self {
            engine,
            instance_pre: Arc::new(instance_pre),
            backends: Arc::new(Backends::default()),
            device_detection: Arc::new(DeviceDetection::default()),
            geolocation: Arc::new(Geolocation::default()),
            tls_config: TlsConfig::new()?,
            dictionaries: Arc::new(Dictionaries::default()),
            config_path: Arc::new(None),
            capture_logs: Arc::new(Mutex::new(std::io::stdout())),
            log_stdout: false,
            log_stderr: false,
            next_req_id: Arc::new(AtomicU64::new(0)),
            object_store: ObjectStores::new(),
            secret_stores: Arc::new(SecretStores::new()),
            epoch_increment_thread,
            epoch_increment_stop,
            guest_profile_path: Arc::new(guest_profile_path),
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
    pub fn with_backends(mut self, backends: Backends) -> Self {
        self.backends = Arc::new(backends);
        self
    }

    /// Get the device detection mappings for this execution context.
    pub fn device_detection(&self) -> &DeviceDetection {
        &self.device_detection
    }

    /// Set the device detection mappings for this execution context.
    pub fn with_device_detection(mut self, device_detection: DeviceDetection) -> Self {
        self.device_detection = Arc::new(device_detection);
        self
    }

    /// Get the geolocation mappings for this execution context.
    pub fn geolocation(&self) -> &Geolocation {
        &self.geolocation
    }

    /// Set the geolocation mappings for this execution context.
    pub fn with_geolocation(mut self, geolocation: Geolocation) -> Self {
        self.geolocation = Arc::new(geolocation);
        self
    }

    /// Get the dictionaries for this execution context.
    pub fn dictionaries(&self) -> &Dictionaries {
        &self.dictionaries
    }

    /// Set the dictionaries for this execution context.
    pub fn with_dictionaries(mut self, dictionaries: Dictionaries) -> Self {
        self.dictionaries = Arc::new(dictionaries);
        self
    }

    /// Set the object store for this execution context.
    pub fn with_object_stores(mut self, object_store: ObjectStores) -> Self {
        self.object_store = object_store;
        self
    }

    /// Set the secret stores for this execution context.
    pub fn with_secret_stores(mut self, secret_stores: SecretStores) -> Self {
        self.secret_stores = Arc::new(secret_stores);
        self
    }

    /// Set the path to the config for this execution context.
    pub fn with_config_path(mut self, config_path: PathBuf) -> Self {
        self.config_path = Arc::new(Some(config_path));
        self
    }

    /// Where to direct logging endpoint messages. Defaults to stdout.
    pub fn capture_logs(&self) -> Arc<Mutex<dyn Write + Send>> {
        self.capture_logs.clone()
    }

    /// Set where to direct logging endpoint messages for this execution
    /// context. Defaults to stdout.
    pub fn with_capture_logs(mut self, capture_logs: Arc<Mutex<dyn Write + Send>>) -> Self {
        self.capture_logs = capture_logs;
        self
    }

    /// Whether to treat stdout as a logging endpoint.
    pub fn log_stdout(&self) -> bool {
        self.log_stdout
    }

    /// Set the stdout logging policy for this execution context.
    pub fn with_log_stdout(mut self, log_stdout: bool) -> Self {
        self.log_stdout = log_stdout;
        self
    }

    /// Whether to treat stderr as a logging endpoint.
    pub fn log_stderr(&self) -> bool {
        self.log_stderr
    }

    /// Set the stderr logging policy for this execution context.
    pub fn with_log_stderr(mut self, log_stderr: bool) -> Self {
        self.log_stderr = log_stderr;
        self
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
    /// # use std::collections::HashSet;
    /// use hyper::{Body, http::Request};
    /// # use viceroy_lib::{Error, ExecuteCtx, ProfilingStrategy, ViceroyService};
    /// # async fn f() -> Result<(), Error> {
    /// # let req = Request::new(Body::from(""));
    /// let adapt_core_wasm = false;
    /// let ctx = ExecuteCtx::new("path/to/a/file.wasm", ProfilingStrategy::None, HashSet::new(), None, Default::default(), adapt_core_wasm)?;
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
                    event!(
                        Level::ERROR,
                        "There was an error handling the request {}",
                        _e.to_string()
                    );
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
                let body = err.root_cause().to_string();
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
            &self,
            self.backends.clone(),
            self.device_detection.clone(),
            self.geolocation.clone(),
            self.tls_config.clone(),
            self.dictionaries.clone(),
            self.config_path.clone(),
            self.object_store.clone(),
            self.secret_stores.clone(),
        );

        let guest_profile_path = self.guest_profile_path.as_deref().map(|path| {
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            path.join(format!("{}-{}.json", now, req_id))
        });

        match self.instance_pre.as_ref() {
            Instance::Component(instance_pre) => {
                if self.guest_profile_path.is_some() {
                    warn!("Components do not currently support the guest profiler");
                }

                let req = session.downstream_request();
                let body = session.downstream_request_body();

                let mut store = ComponentCtx::create_store(&self, session, None, |ctx| {
                    ctx.arg("compute-app");
                })
                .map_err(ExecutionError::Context)?;

                let (compute, _instance) =
                    compute::Compute::instantiate_pre(&mut store, instance_pre)
                        .await
                        .map_err(ExecutionError::Instantiation)?;

                let result = compute
                    .fastly_api_reactor()
                    .call_serve(&mut store, req.into(), body.into())
                    .await;

                let outcome = match result {
                    Ok(Ok(())) => Ok(()),

                    Ok(Err(())) => {
                        event!(Level::ERROR, "WebAssembly exited with an error");
                        Err(ExecutionError::WasmTrap(anyhow::Error::msg("failed")))
                    }

                    Err(e) => {
                        event!(Level::ERROR, "WebAssembly trapped: {:?}", e);
                        Err(ExecutionError::WasmTrap(e))
                    }
                };

                // Ensure the downstream response channel is closed, whether or not a response was
                // sent during execution.
                store.data_mut().close_downstream_response_sender();

                let request_duration = Instant::now().duration_since(start_timestamp);

                info!(
                    "request completed using {} of WebAssembly heap",
                    bytesize::ByteSize::b(store.data().limiter().memory_allocated as u64),
                );

                info!("request completed in {:.0?}", request_duration);

                outcome
            }

            Instance::Module(module, instance_pre) => {
                let profiler = self.guest_profile_path.is_some().then(|| {
                    let program_name = "main";
                    GuestProfiler::new(
                        program_name,
                        EPOCH_INTERRUPTION_PERIOD,
                        vec![(program_name.to_string(), module.clone())],
                    )
                });

                // We currently have to postpone linking and instantiation to the guest task
                // due to wasmtime limitations, in particular the fact that `Instance` is not `Send`.
                // However, the fact that the module itself is created within `ExecuteCtx::new`
                // means that the heavy lifting happens only once.
                let mut store = create_store(&self, session, profiler, |ctx| {
                    ctx.arg("compute-app");
                })
                .map_err(ExecutionError::Context)?;

                let instance = instance_pre
                    .instantiate_async(&mut store)
                    .await
                    .map_err(ExecutionError::Instantiation)?;

                // Pull out the `_start` function, which by convention with WASI is the main entry point for
                // an application.
                let main_func = instance
                    .get_typed_func::<(), ()>(&mut store, "_start")
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

                // If we collected a profile, write it to the file
                write_profile(&mut store, guest_profile_path.as_ref());

                // Ensure the downstream response channel is closed, whether or not a response was
                // sent during execution.
                store.data_mut().close_downstream_response_sender();

                let request_duration = Instant::now().duration_since(start_timestamp);

                info!(
                    "request completed using {} of WebAssembly heap",
                    bytesize::ByteSize::b(store.data().limiter().memory_allocated as u64)
                );

                info!("request completed in {:.0?}", request_duration);

                outcome
            }
        }
    }

    pub async fn run_main(self, program_name: &str, args: &[String]) -> Result<(), anyhow::Error> {
        // placeholders for request, result sender channel, and remote IP
        let req = Request::get("http://example.com/").body(Body::empty())?;
        let req_id = 0;
        let (sender, receiver) = oneshot::channel();
        let remote = Ipv4Addr::LOCALHOST.into();

        let session = Session::new(
            req_id,
            req,
            sender,
            remote,
            &self,
            self.backends.clone(),
            self.device_detection.clone(),
            self.geolocation.clone(),
            self.tls_config.clone(),
            self.dictionaries.clone(),
            self.config_path.clone(),
            self.object_store.clone(),
            self.secret_stores.clone(),
        );

        if let Instance::Component(_) = self.instance_pre.as_ref() {
            panic!("components not currently supported with `run`");
        }

        let (module, instance_pre) = self.instance_pre.unwrap_module();

        let profiler = self.guest_profile_path.is_some().then(|| {
            GuestProfiler::new(
                program_name,
                EPOCH_INTERRUPTION_PERIOD,
                vec![(program_name.to_string(), module.clone())],
            )
        });
        let mut store = create_store(&self, session, profiler, |builder| {
            builder.arg(program_name);
            for arg in args {
                builder.arg(arg);
            }
        })
        .map_err(ExecutionError::Context)?;

        let instance = instance_pre
            .instantiate_async(&mut store)
            .await
            .map_err(ExecutionError::Instantiation)?;

        // Pull out the `_start` function, which by convention with WASI is the main entry point for
        // an application.
        let main_func = instance
            .get_typed_func::<(), ()>(&mut store, "_start")
            .map_err(ExecutionError::Typechecking)?;

        // Invoke the entrypoint function and collect its exit code
        let result = main_func.call_async(&mut store, ()).await;

        // If we collected a profile, write it to the file
        write_profile(&mut store, self.guest_profile_path.as_ref().as_ref());

        // Ensure the downstream response channel is closed, whether or not a response was
        // sent during execution.
        store.data_mut().close_downstream_response_sender();

        // We don't do anything with any response on the receiver, but
        // it's important to keep it alive until after the program has
        // finished.
        drop(receiver);

        result
    }
}

fn write_profile(store: &mut wasmtime::Store<WasmCtx>, guest_profile_path: Option<&PathBuf>) {
    if let (Some(profile), Some(path)) =
        (store.data_mut().take_guest_profiler(), guest_profile_path)
    {
        if let Err(e) = std::fs::File::create(path)
            .map_err(anyhow::Error::new)
            .and_then(|output| profile.finish(std::io::BufWriter::new(output)))
        {
            event!(
                Level::ERROR,
                "failed writing profile at {}: {e:#}",
                path.display()
            );
        } else {
            event!(
                Level::INFO,
                "\nProfile written to: {}\nView this profile at https://profiler.firefox.com/.",
                path.display()
            );
        }
    }
}

impl Drop for ExecuteCtx {
    fn drop(&mut self) {
        if let Some(arc) = self.epoch_increment_thread.take() {
            if let Ok(join_handle) = Arc::try_unwrap(arc) {
                self.epoch_increment_stop.store(true, Ordering::Relaxed);
                join_handle.join().unwrap();
            }
        }
    }
}

fn configure_wasmtime(
    allow_components: bool,
    profiling_strategy: ProfilingStrategy,
) -> wasmtime::Config {
    use wasmtime::{Config, InstanceAllocationStrategy, WasmBacktraceDetails};

    let mut config = Config::new();
    config.debug_info(false); // Keep this disabled - wasmtime will hang if enabled
    config.wasm_backtrace_details(WasmBacktraceDetails::Enable);
    config.async_support(true);
    config.epoch_interruption(true);
    config.profiler(profiling_strategy);

    config.allocation_strategy(InstanceAllocationStrategy::OnDemand);

    if allow_components {
        config.wasm_component_model(true);
    }

    config
}
