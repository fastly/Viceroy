//! Guest code execution.

use {
    crate::{
        acl::Acls,
        adapt,
        body::Body,
        body_tee::tee,
        cache::Cache,
        component as compute,
        config::{
            Backends, DeviceDetection, Dictionaries, ExperimentalModule, Geolocation,
            UnknownImportBehavior,
        },
        downstream::{prepare_request, DownstreamMetadata, DownstreamRequest, DownstreamResponse},
        error::{ExecutionError, NonHttpResponse},
        linking::{create_store, link_host_functions, ComponentCtx, WasmCtx},
        object_store::ObjectStores,
        pushpin::{proxy_through_pushpin, PushpinRedirectRequestInfo},
        secret_store::SecretStores,
        session::Session,
        shielding_site::ShieldingSites,
        upstream::TlsConfig,
        Error,
    },
    futures::{
        task::{Context, Poll},
        Future,
    },
    http::StatusCode,
    hyper::{Request, Response},
    pin_project::pin_project,
    std::{
        collections::HashSet,
        fmt, fs,
        io::Write,
        net::{Ipv4Addr, SocketAddr},
        path::{Path, PathBuf},
        pin::Pin,
        sync::{
            atomic::{AtomicBool, AtomicU64, Ordering},
            Arc, Mutex,
        },
        thread::{self, JoinHandle},
        time::{Duration, Instant, SystemTime},
    },
    tokio::sync::oneshot::{self, Sender},
    tokio::sync::Mutex as AsyncMutex,
    tracing::{error, event, info, info_span, warn, Instrument, Level},
    wasmtime::{
        component::{self, Component},
        Engine, GuestProfiler, InstancePre, Linker, Module, ProfilingStrategy,
    },
    wasmtime_wasi::I32Exit,
};

pub const DEFAULT_EPOCH_INTERRUPTION_PERIOD: Duration = Duration::from_micros(50);

const NEXT_REQ_PENDING_MAX: usize = 5;
const REGION_NONE: &str = "none";

enum Instance {
    Module(Module, InstancePre<WasmCtx>),
    Component(compute::bindings::AdapterServicePre<ComponentCtx>),
}

impl Instance {
    fn unwrap_module(&self) -> (&Module, &InstancePre<WasmCtx>) {
        match self {
            Instance::Module(m, i) => (m, i),
            Instance::Component(_) => panic!("unwrap_module called on a component"),
        }
    }
}

#[derive(Clone)]
pub struct GuestProfileConfig {
    /// Path to write profiling results from the guest. In serve mode,
    /// this must refer to a directory, while in run mode it names
    /// a file.
    pub path: PathBuf,
    /// Period at which the guest should be profiled.
    pub sample_period: Duration,
}

pub struct NextRequest(Option<(DownstreamRequest, Arc<ExecuteCtx>)>);

impl NextRequest {
    pub fn into_request(mut self) -> Option<DownstreamRequest> {
        self.0.take().map(|(r, _)| r)
    }
}

impl fmt::Debug for NextRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let debug = self.0.as_ref().map(|(r, _)| r);
        f.debug_tuple("NextRequest")
            .field(&debug)
            .finish_non_exhaustive()
    }
}

impl Drop for NextRequest {
    fn drop(&mut self) {
        let Some((req, ctx)) = self.0.take() else {
            return;
        };

        ctx.retry_request(req);
    }
}

/// Execution context used by a [`ViceroyService`](struct.ViceroyService.html).
///
/// This is all of the state needed to instantiate a module, in order to respond to an HTTP
/// request. Note that it is very important that `ExecuteCtx` be cheaply clonable, as it is cloned
/// every time that a viceroy service handles an incoming connection.
pub struct ExecuteCtx {
    /// A reference to the global context for Wasm compilation.
    engine: Engine,
    /// An almost-linked Instance: each import function is linked, just needs a Store
    instance_pre: Arc<Instance>,
    /// The acls for this execution.
    acls: Acls,
    /// The backends for this execution.
    backends: Backends,
    /// The device detection mappings for this execution.
    device_detection: DeviceDetection,
    /// The geolocation mappings for this execution.
    geolocation: Geolocation,
    /// Preloaded TLS certificates and configuration
    tls_config: TlsConfig,
    /// The dictionaries for this execution.
    dictionaries: Dictionaries,
    /// Path to the config, defaults to None
    config_path: Option<PathBuf>,
    /// Where to direct logging endpoint messages, defaults to stdout
    capture_logs: Arc<Mutex<dyn Write + Send>>,
    /// Whether to treat stdout as a logging endpoint
    log_stdout: bool,
    /// Whether to treat stderr as a logging endpoint
    log_stderr: bool,
    /// The local Pushpin proxy port
    local_pushpin_proxy_port: Option<u16>,
    /// The ID to assign the next incoming request
    next_req_id: Arc<AtomicU64>,
    /// The ObjectStore associated with this instance of Viceroy
    object_store: ObjectStores,
    /// The secret stores for this execution.
    secret_stores: SecretStores,
    /// The shielding sites for this execution.
    shielding_sites: ShieldingSites,
    /// The cache for this service.
    cache: Arc<Cache>,
    /// Senders waiting for new requests for reusable sessions.
    pending_reuse: Arc<AsyncMutex<Vec<Sender<NextRequest>>>>,
    epoch_increment_thread: Option<JoinHandle<()>>,
    // `Arc` so that it can be tracked both by this context and `epoch_increment_thread`.
    epoch_increment_stop: Arc<AtomicBool>,
    /// Configuration for guest profiling if enabled
    guest_profile_config: Option<Arc<GuestProfileConfig>>,
}

impl ExecuteCtx {
    /// Build a new execution context, given the path to a module and a set of experimental wasi modules.
    pub fn build(
        module_path: impl AsRef<Path>,
        profiling_strategy: ProfilingStrategy,
        wasi_modules: HashSet<ExperimentalModule>,
        guest_profile_config: Option<GuestProfileConfig>,
        unknown_import_behavior: UnknownImportBehavior,
        adapt_components: bool,
    ) -> Result<ExecuteCtxBuilder, Error> {
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

            // If logging isn't enabled, print the notice to stderr.
            if !tracing::enabled!(Level::WARN) {
                eprintln!(
                    "

   +------------------------------------------------------------------------+
   |                                                                        |
   | Wasm Component support in viceroy is in active development, and is not |
   |                    supported for general consumption.                  |
   |                                                                        |
   +------------------------------------------------------------------------+

            "
                );
            }

            let mut linker: component::Linker<ComponentCtx> = component::Linker::new(&engine);
            compute::link_host_functions(&mut linker)?;
            let component = if is_wat {
                Component::from_file(&engine, &module_path)?
            } else {
                Component::from_binary(&engine, &input)?
            };

            match unknown_import_behavior {
                UnknownImportBehavior::LinkError => (),
                UnknownImportBehavior::Trap => {
                    linker.define_unknown_imports_as_traps(&component)?
                }
            }

            let instance_pre = linker.instantiate_pre(&component)?;
            Instance::Component(compute::bindings::AdapterServicePre::new(instance_pre)?)
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
            }

            let instance_pre = linker.instantiate_pre(&module)?;
            Instance::Module(module, instance_pre)
        };

        // Create the epoch-increment thread. Note that the period for epoch
        // interruptions is driven by the guest profiling sample period if
        // provided as guest stack sampling is done from the epoch
        // interruption callback.

        let epoch_increment_stop = Arc::new(AtomicBool::new(false));
        let engine_clone = engine.clone();
        let epoch_increment_stop_clone = epoch_increment_stop.clone();
        let sample_period = guest_profile_config
            .as_ref()
            .map(|c| c.sample_period)
            .unwrap_or(DEFAULT_EPOCH_INTERRUPTION_PERIOD);
        let epoch_increment_thread = Some(thread::spawn(move || {
            while !epoch_increment_stop_clone.load(Ordering::Relaxed) {
                thread::sleep(sample_period);
                engine_clone.increment_epoch();
            }
        }));

        let inner = Self {
            engine,
            instance_pre: Arc::new(instance_pre),
            acls: Acls::new(),
            backends: Backends::default(),
            device_detection: DeviceDetection::default(),
            geolocation: Geolocation::default(),
            tls_config: TlsConfig::new()?,
            dictionaries: Dictionaries::default(),
            config_path: None,
            capture_logs: Arc::new(Mutex::new(std::io::stdout())),
            log_stdout: false,
            log_stderr: false,
            local_pushpin_proxy_port: None,
            next_req_id: Arc::new(AtomicU64::new(0)),
            object_store: ObjectStores::new(),
            secret_stores: SecretStores::new(),
            shielding_sites: ShieldingSites::new(),
            epoch_increment_thread,
            epoch_increment_stop,
            guest_profile_config: guest_profile_config.map(|c| Arc::new(c)),
            cache: Arc::new(Cache::default()),
            pending_reuse: Arc::new(AsyncMutex::new(vec![])),
        };

        Ok(ExecuteCtxBuilder { inner })
    }

    /// Create a new execution context, given the path to a module and a set of experimental wasi modules.
    pub fn new(
        module_path: impl AsRef<Path>,
        profiling_strategy: ProfilingStrategy,
        wasi_modules: HashSet<ExperimentalModule>,
        guest_profile_config: Option<GuestProfileConfig>,
        unknown_import_behavior: UnknownImportBehavior,
        adapt_components: bool,
    ) -> Result<Arc<Self>, Error> {
        ExecuteCtx::build(
            module_path,
            profiling_strategy,
            wasi_modules,
            guest_profile_config,
            unknown_import_behavior,
            adapt_components,
        )?
        .finish()
    }

    /// Get the engine for this execution context.
    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// Get the acls for this execution context.
    pub fn acls(&self) -> &Acls {
        &self.acls
    }

    /// Get the backends for this execution context.
    pub fn backends(&self) -> &Backends {
        &self.backends
    }

    /// Get the device detection mappings for this execution context.
    pub fn device_detection(&self) -> &DeviceDetection {
        &self.device_detection
    }

    /// Get the geolocation mappings for this execution context.
    pub fn geolocation(&self) -> &Geolocation {
        &self.geolocation
    }

    /// Get the dictionaries for this execution context.
    pub fn dictionaries(&self) -> &Dictionaries {
        &self.dictionaries
    }

    /// Where to direct logging endpoint messages. Defaults to stdout.
    pub fn capture_logs(&self) -> Arc<Mutex<dyn Write + Send>> {
        self.capture_logs.clone()
    }

    /// Whether to treat stdout as a logging endpoint.
    pub fn log_stdout(&self) -> bool {
        self.log_stdout
    }

    /// Whether to treat stderr as a logging endpoint.
    pub fn log_stderr(&self) -> bool {
        self.log_stderr
    }

    /// Gets the TLS configuration
    pub fn tls_config(&self) -> &TlsConfig {
        &self.tls_config
    }

    async fn maybe_receive_response(
        receiver: oneshot::Receiver<DownstreamResponse>,
    ) -> Option<(Response<Body>, Option<anyhow::Error>)> {
        match receiver.await.ok()? {
            DownstreamResponse::Http(resp) => Some((resp, None)),
            DownstreamResponse::RedirectToPushpin(info) => Some((
                Response::new(Body::empty()),
                Some(NonHttpResponse::PushpinRedirect(info).into()),
            )),
        }
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
    /// let local = "127.0.0.1:80".parse().unwrap();
    /// let remote = "127.0.0.1:0".parse().unwrap();
    /// let resp = ctx.handle_request(req, local, remote).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn handle_request(
        self: Arc<Self>,
        mut incoming_req: Request<hyper::Body>,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> Result<(Response<Body>, Option<anyhow::Error>), Error> {
        let orig_req_on_upgrade = hyper::upgrade::on(&mut incoming_req);
        let (incoming_req_parts, incoming_req_body) = incoming_req.into_parts();
        let local_pushpin_proxy_port = self.local_pushpin_proxy_port;

        let (body_for_wasm, orig_body_tee) = tee(incoming_req_body).await;
        let orig_request_info_for_pushpin =
            PushpinRedirectRequestInfo::from_parts(&incoming_req_parts);

        let original_headers = incoming_req_parts.headers.clone();
        let req = prepare_request(Request::from_parts(incoming_req_parts, body_for_wasm))?;

        let req_id = self
            .next_req_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        let metadata = DownstreamMetadata {
            req_id,
            server_addr: local,
            client_addr: remote,
            compliance_region: String::from(REGION_NONE),
            original_headers,
        };

        let (resp, mut err) = self.reuse_or_spawn_guest(req, metadata).await;

        let span = info_span!("request", id = req_id);
        let _span = span.enter();

        info!("response status: {:?}", resp.status());

        if let Some(e) = err {
            match e.downcast::<NonHttpResponse>() {
                Ok(NonHttpResponse::PushpinRedirect(redirect_info)) => {
                    let backend_name = redirect_info.backend_name;
                    let redirect_request_info = redirect_info.request_info;
                    info!("Pushpin redirect signaled to backend '{}'", backend_name);

                    let local_pushpin_proxy_port = match local_pushpin_proxy_port {
                        None => {
                            error!("Pushpin redirect signaled, but Pushpin mode not enabled.");
                            let err = anyhow::anyhow!(
                                "Pushpin redirect signaled, but Pushpin mode not enabled."
                            );
                            let resp = Response::builder()
                                .status(StatusCode::INTERNAL_SERVER_ERROR)
                                .body(Body::from(hyper::Body::from(err.to_string())))?;
                            return Ok((resp, Some(err)));
                        }
                        Some(port) => port,
                    };

                    let proxy_resp = proxy_through_pushpin(
                        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), local_pushpin_proxy_port),
                        backend_name,
                        redirect_request_info,
                        orig_request_info_for_pushpin,
                        orig_body_tee,
                        orig_req_on_upgrade,
                    )
                    .await;

                    let (p, hyper_body) = proxy_resp.into_parts();
                    return Ok((Response::from_parts(p, Body::from(hyper_body)), None));
                }
                Err(e) => {
                    err = Some(e);
                }
            }
        }

        Ok((resp, err))
    }

    /// Spawn a new guest to process a request whose processing was never attempted by
    /// a reused session.
    pub(crate) fn retry_request(self: Arc<Self>, mut downstream: DownstreamRequest) {
        if downstream.sender.is_closed() {
            return;
        }

        tokio::task::spawn(async move {
            let (sender, receiver) = oneshot::channel();
            let original = std::mem::replace(&mut downstream.sender, sender);
            let (resp, err) = self.spawn_guest(downstream, receiver).await;
            let resp = guest_result_to_response(resp, err);
            let _ = original.send(DownstreamResponse::Http(resp));
        });
    }

    pub async fn handle_request_with_runtime_error(
        self: Arc<Self>,
        incoming_req: Request<hyper::Body>,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> Result<Response<Body>, Error> {
        let result = self.handle_request(incoming_req, local, remote).await?;
        let resp = guest_result_to_response(result.0, result.1);

        Ok(resp)
    }

    async fn reuse_or_spawn_guest(
        self: Arc<Self>,
        req: Request<Body>,
        metadata: DownstreamMetadata,
    ) -> (Response<Body>, Option<anyhow::Error>) {
        let (sender, receiver) = oneshot::channel();
        let downstream = DownstreamRequest {
            req,
            sender,
            metadata,
        };

        let mut next_req = NextRequest(Some((downstream, self.clone())));
        let mut reusable = self.pending_reuse.lock().await;

        while let Some(pending) = reusable.pop() {
            match pending.send(next_req) {
                Ok(()) => {
                    // Drop lock and wait for the guest to process our request.
                    drop(reusable);

                    if let Some(response) = Self::maybe_receive_response(receiver).await {
                        return response;
                    }
                    return (Response::default(), None);
                }
                Err(nr) => next_req = nr,
            }
        }

        drop(reusable);

        let downstream = next_req
            .into_request()
            .expect("request should still be unprocessed");
        self.spawn_guest(downstream, receiver).await
    }

    async fn spawn_guest(
        self: Arc<Self>,
        downstream: DownstreamRequest,
        receiver: oneshot::Receiver<DownstreamResponse>,
    ) -> (Response<Body>, Option<anyhow::Error>) {
        let active_cpu_time_us = Arc::new(AtomicU64::new(0));

        // Spawn a separate task to run the guest code. That allows _this_ method to return a response early
        // if the guest sends one, while the guest continues to run afterward within its task.
        let req_id = downstream.metadata.req_id;
        let guest_handle = tokio::task::spawn(CpuTimeTracking::new(
            active_cpu_time_us.clone(),
            self.run_guest(downstream, active_cpu_time_us)
                .instrument(info_span!("request", id = req_id)),
        ));

        if let Some(response) = Self::maybe_receive_response(receiver).await {
            return response;
        }

        match guest_handle
            .await
            .expect("guest worker finished without panicking")
        {
            Ok(_) => (Response::new(Body::empty()), None),
            Err(ExecutionError::WasmTrap(e)) => {
                event!(
                    Level::ERROR,
                    "There was an error handling the request {}",
                    e.to_string()
                );
                (anyhow_response(&e), Some(e))
            }
            Err(e) => panic!("failed to run guest: {}", e),
        }
    }

    async fn run_guest(
        self: Arc<Self>,
        downstream: DownstreamRequest,
        active_cpu_time_us: Arc<AtomicU64>,
    ) -> Result<(), ExecutionError> {
        info!(
            "handling request {} {}",
            downstream.req.method(),
            downstream.req.uri()
        );
        let start_timestamp = Instant::now();
        let req_id = downstream.metadata.req_id;
        let session = Session::new(downstream, active_cpu_time_us, self.clone());

        let guest_profile_path = self.guest_profile_config.as_deref().map(|pcfg| {
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            pcfg.path.join(format!("{}-{}.json", now, req_id))
        });

        match self.instance_pre.as_ref() {
            Instance::Component(instance_pre) => {
                if self.guest_profile_config.is_some() {
                    warn!("Components do not currently support the guest profiler");
                }

                let req = session.downstream_request();
                let body = session.downstream_request_body();

                let mut store = ComponentCtx::create_store(&self, session, None, |ctx| {
                    ctx.arg("compute-app");
                })
                .map_err(ExecutionError::Context)?;

                let compute = instance_pre
                    .instantiate_async(&mut store)
                    .await
                    .map_err(ExecutionError::Instantiation)?;

                let result = compute
                    .fastly_compute_http_incoming()
                    .call_handle(&mut store, req.into(), body.into())
                    .await;

                let outcome = match result {
                    Ok(Ok(())) => Ok(()),

                    Ok(Err(())) => {
                        event!(Level::ERROR, "WebAssembly exited with an error");
                        Err(ExecutionError::WasmTrap(anyhow::Error::msg("failed")))
                    }

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

                // If we collected a recording trace, write to a file
                if !store.data().logger.is_empty() {
                    let trace = serde_json::to_string(&store.data().logger).unwrap();
                    std::fs::write("trace.out", &trace).unwrap();
                }

                // Ensure the downstream response channel is closed, whether or not a response was
                // sent during execution.
                let resp = outcome
                    .as_ref()
                    .err()
                    .map(exec_err_to_response)
                    .unwrap_or_default();
                store
                    .data_mut()
                    .session
                    .close_downstream_response_sender(resp);

                let request_duration = Instant::now().duration_since(start_timestamp);

                info!(
                    "guest completed using {} of WebAssembly heap",
                    bytesize::ByteSize::b(store.data().limiter().memory_allocated as u64),
                );

                info!("guest completed in {:.0?}", request_duration);

                outcome
            }

            Instance::Module(module, instance_pre) => {
                let profiler = self.guest_profile_config.as_deref().map(|pcfg| {
                    let program_name = "main";
                    GuestProfiler::new(
                        program_name,
                        pcfg.sample_period,
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
                let resp = outcome
                    .as_ref()
                    .err()
                    .map(exec_err_to_response)
                    .unwrap_or_default();
                store.data_mut().close_downstream_response_sender(resp);

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

    pub async fn run_main(
        self: Arc<Self>,
        program_name: &str,
        args: &[String],
    ) -> Result<(), anyhow::Error> {
        // placeholders for request, result sender channel, and remote IP
        let req = Request::get("http://example.com/").body(Body::empty())?;
        let metadata = DownstreamMetadata {
            req_id: 0,
            server_addr: (Ipv4Addr::LOCALHOST, 80).into(),
            client_addr: (Ipv4Addr::LOCALHOST, 0).into(),
            compliance_region: String::from(REGION_NONE),
            original_headers: Default::default(),
        };
        let (sender, receiver) = oneshot::channel();
        let downstream = DownstreamRequest {
            req,
            sender,
            metadata,
        };
        let active_cpu_time_us = Arc::new(AtomicU64::new(0));

        let session = Session::new(downstream, active_cpu_time_us.clone(), self.clone());

        if let Instance::Component(_) = self.instance_pre.as_ref() {
            panic!("components not currently supported with `run`");
        }

        let (module, instance_pre) = self.instance_pre.unwrap_module();

        let profiler = self.guest_profile_config.as_deref().map(|pcfg| {
            GuestProfiler::new(
                program_name,
                pcfg.sample_period,
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
        let result =
            CpuTimeTracking::new(active_cpu_time_us, main_func.call_async(&mut store, ())).await;

        // If we collected a profile, write it to the file
        write_profile(
            &mut store,
            self.guest_profile_config.as_deref().map(|cfg| &cfg.path),
        );

        // Ensure the downstream response channel is closed, whether or not a response was
        // sent during execution.
        store
            .data_mut()
            .close_downstream_response_sender(Response::default());

        // We don't do anything with any response on the receiver, but
        // it's important to keep it alive until after the program has
        // finished.
        drop(receiver);

        result
    }

    pub fn cache(&self) -> &Arc<Cache> {
        &self.cache
    }

    pub fn config_path(&self) -> Option<&Path> {
        self.config_path.as_deref()
    }

    pub fn object_store(&self) -> &ObjectStores {
        &self.object_store
    }

    pub fn secret_stores(&self) -> &SecretStores {
        &self.secret_stores
    }

    pub fn shielding_sites(&self) -> &ShieldingSites {
        &self.shielding_sites
    }

    pub async fn register_pending_downstream(&self) -> Option<oneshot::Receiver<NextRequest>> {
        let mut pending = self.pending_reuse.lock().await;

        if pending.len() >= NEXT_REQ_PENDING_MAX {
            return None;
        }

        let (tx, rx) = oneshot::channel();
        pending.push(tx);

        Some(rx)
    }
}

pub struct ExecuteCtxBuilder {
    inner: ExecuteCtx,
}

impl ExecuteCtxBuilder {
    pub fn finish(self) -> Result<Arc<ExecuteCtx>, Error> {
        Ok(Arc::new(self.inner))
    }

    /// Set the acls for this execution context.
    pub fn with_acls(mut self, acls: Acls) -> Self {
        self.inner.acls = acls;
        self
    }

    /// Set the backends for this execution context.
    pub fn with_backends(mut self, backends: Backends) -> Self {
        self.inner.backends = backends;
        self
    }

    /// Set the device detection mappings for this execution context.
    pub fn with_device_detection(mut self, device_detection: DeviceDetection) -> Self {
        self.inner.device_detection = device_detection;
        self
    }

    /// Set the geolocation mappings for this execution context.
    pub fn with_geolocation(mut self, geolocation: Geolocation) -> Self {
        self.inner.geolocation = geolocation;
        self
    }

    /// Set the dictionaries for this execution context.
    pub fn with_dictionaries(mut self, dictionaries: Dictionaries) -> Self {
        self.inner.dictionaries = dictionaries;
        self
    }

    /// Set the object store for this execution context.
    pub fn with_object_stores(mut self, object_store: ObjectStores) -> Self {
        self.inner.object_store = object_store;
        self
    }

    /// Set the secret stores for this execution context.
    pub fn with_secret_stores(mut self, secret_stores: SecretStores) -> Self {
        self.inner.secret_stores = secret_stores;
        self
    }
    /// Set the shielding sites for this execution context.
    pub fn with_shielding_sites(mut self, shielding_sites: ShieldingSites) -> Self {
        self.inner.shielding_sites = shielding_sites;
        self
    }

    /// Set the path to the config for this execution context.
    pub fn with_config_path(mut self, config_path: PathBuf) -> Self {
        self.inner.config_path = Some(config_path);
        self
    }

    /// Set where to direct logging endpoint messages for this execution
    /// context. Defaults to stdout.
    pub fn with_capture_logs(mut self, capture_logs: Arc<Mutex<dyn Write + Send>>) -> Self {
        self.inner.capture_logs = capture_logs;
        self
    }

    /// Set the stdout logging policy for this execution context.
    pub fn with_log_stdout(mut self, log_stdout: bool) -> Self {
        self.inner.log_stdout = log_stdout;
        self
    }

    /// Set the stderr logging policy for this execution context.
    pub fn with_log_stderr(mut self, log_stderr: bool) -> Self {
        self.inner.log_stderr = log_stderr;
        self
    }

    /// Set the local Pushpin proxy port
    pub fn with_local_pushpin_proxy_port(mut self, local_pushpin_proxy_port: Option<u16>) -> Self {
        self.inner.local_pushpin_proxy_port = local_pushpin_proxy_port;
        self
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

fn guest_result_to_response(resp: Response<Body>, err: Option<anyhow::Error>) -> Response<Body> {
    err.as_ref().map(anyhow_response).unwrap_or(resp)
}

fn exec_err_to_response(err: &ExecutionError) -> Response<Body> {
    if let ExecutionError::WasmTrap(e) = err {
        anyhow_response(e)
    } else {
        panic!("failed to run guest: {err}")
    }
}

fn anyhow_response(err: &anyhow::Error) -> Response<Body> {
    Response::builder()
        .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
        .body(Body::from(format!("{err:?}").into_bytes()))
        .unwrap()
}

impl Drop for ExecuteCtx {
    fn drop(&mut self) {
        if let Some(join_handle) = self.epoch_increment_thread.take() {
            self.epoch_increment_stop.store(true, Ordering::Relaxed);
            join_handle.join().unwrap();
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

    // Wasm permits the "relaxed" instructions to be nondeterministic
    // between runs, but requires them to be deterministic within runs.
    // Snapshotting a program's execution to avoid redundantly running
    // initialization code on each request is an important optimization,
    // so we enable deterministic lowerings for relaxed SIMD to ensure
    // that it works consistently even if the initialization runs on a
    // different host architecture.
    config.relaxed_simd_deterministic(true);

    config
}

#[pin_project]
struct CpuTimeTracking<F> {
    #[pin]
    future: F,
    time_spent: Arc<AtomicU64>,
}

impl<F> CpuTimeTracking<F> {
    fn new(time_spent: Arc<AtomicU64>, future: F) -> Self {
        CpuTimeTracking { future, time_spent }
    }
}

impl<E, F: Future<Output = Result<(), E>>> Future for CpuTimeTracking<F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let me = self.project();

        let start = Instant::now();
        let result = me.future.poll(cx);
        // 2^64 microseconds is over half a million years, so I'm not terribly
        // worried about this cast.
        let runtime = start.elapsed().as_micros() as u64;
        let _ = me.time_spent.fetch_add(runtime, Ordering::SeqCst);
        result
    }
}
