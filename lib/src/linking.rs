//! Linking and name resolution.

use {
    crate::{
        config::ExperimentalModule, execute::ExecuteCtx, logging::LogEndpoint, session::Session,
        wiggle_abi, Error,
    },
    std::collections::HashSet,
    wasmtime::{GuestProfiler, Linker, Store, StoreLimits, StoreLimitsBuilder, UpdateDeadline},
    wasmtime_wasi::{preview1::WasiP1Ctx, WasiCtxBuilder},
    wasmtime_wasi_nn::WasiNnCtx,
};

pub struct Limiter {
    /// Total memory allocated so far.
    pub memory_allocated: usize,
    /// The internal limiter we use to actually answer calls
    internal: StoreLimits,
}

impl Default for Limiter {
    fn default() -> Self {
        Limiter::new(1, 1)
    }
}

impl Limiter {
    fn new(max_instances: usize, max_tables: usize) -> Self {
        Limiter {
            memory_allocated: 0,
            internal: StoreLimitsBuilder::new()
                .instances(max_instances)
                .memories(1)
                .memory_size(128 * 1024 * 1024)
                .table_elements(98765)
                .tables(max_tables)
                .build(),
        }
    }
}

impl wasmtime::ResourceLimiter for Limiter {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> anyhow::Result<bool> {
        // limit the amount of memory that an instance can use to (roughly) 128MB, erring on
        // the side of letting things run that might get killed on Compute, because we are not
        // tracking some runtime factors in this count.
        let result = self.internal.memory_growing(current, desired, maximum);

        if matches!(result, Ok(true)) {
            // Track the diff in memory allocated over time. As each instance will start with 0 and
            // gradually resize, this will track the total allocations throughout the lifetime of the
            // instance.
            self.memory_allocated += desired - current;
        }

        result
    }

    fn table_growing(
        &mut self,
        current: u32,
        desired: u32,
        maximum: Option<u32>,
    ) -> anyhow::Result<bool> {
        self.internal.table_growing(current, desired, maximum)
    }

    fn memory_grow_failed(&mut self, error: anyhow::Error) -> anyhow::Result<()> {
        self.internal.memory_grow_failed(error)
    }

    fn table_grow_failed(&mut self, error: anyhow::Error) -> anyhow::Result<()> {
        self.internal.table_grow_failed(error)
    }

    fn instances(&self) -> usize {
        self.internal.instances()
    }

    fn tables(&self) -> usize {
        self.internal.tables()
    }

    fn memories(&self) -> usize {
        self.internal.memories()
    }
}

#[allow(unused)]
pub struct ComponentCtx {
    table: wasmtime_wasi::ResourceTable,
    wasi: wasmtime_wasi::WasiCtx,
    session: Session,
    guest_profiler: Option<Box<GuestProfiler>>,
    limiter: Limiter,
}

impl ComponentCtx {
    pub fn wasi(&mut self) -> &mut wasmtime_wasi::WasiCtx {
        &mut self.wasi
    }

    pub fn session(&mut self) -> &mut Session {
        &mut self.session
    }

    pub fn take_guest_profiler(&mut self) -> Option<Box<GuestProfiler>> {
        self.guest_profiler.take()
    }

    pub fn limiter(&self) -> &Limiter {
        &self.limiter
    }

    pub fn close_downstream_response_sender(&mut self) {
        self.session.close_downstream_response_sender()
    }

    /// Initialize a new [`Store`][store], given an [`ExecuteCtx`][ctx].
    ///
    /// [ctx]: ../wiggle_abi/struct.ExecuteCtx.html
    /// [store]: https://docs.rs/wasmtime/latest/wasmtime/struct.Store.html
    pub(crate) fn create_store(
        ctx: &ExecuteCtx,
        session: Session,
        guest_profiler: Option<GuestProfiler>,
        extra_init: impl FnOnce(&mut WasiCtxBuilder),
    ) -> Result<Store<Self>, anyhow::Error> {
        let mut builder = make_wasi_ctx(ctx, &session);

        extra_init(&mut builder);

        let wasm_ctx = Self {
            table: wasmtime_wasi::ResourceTable::new(),
            wasi: builder.build(),
            session,
            guest_profiler: guest_profiler.map(Box::new),
            limiter: Limiter::new(100, 100),
        };
        let mut store = Store::new(ctx.engine(), wasm_ctx);
        store.set_epoch_deadline(1);
        store.epoch_deadline_callback(|mut store| {
            if let Some(mut prof) = store.data_mut().guest_profiler.take() {
                prof.sample(&store, std::time::Duration::ZERO);
                store.data_mut().guest_profiler = Some(prof);
            }
            Ok(UpdateDeadline::Yield(1))
        });
        store.limiter(|ctx| &mut ctx.limiter);
        Ok(store)
    }
}

impl wasmtime_wasi::WasiView for ComponentCtx {
    fn table(&mut self) -> &mut wasmtime_wasi::ResourceTable {
        &mut self.table
    }
    fn ctx(&mut self) -> &mut wasmtime_wasi::WasiCtx {
        &mut self.wasi
    }
}

pub struct WasmCtx {
    wasi: WasiP1Ctx,
    wasi_nn: WasiNnCtx,
    session: Session,
    guest_profiler: Option<Box<GuestProfiler>>,
    limiter: Limiter,
}

impl WasmCtx {
    pub fn wasi(&mut self) -> &mut WasiP1Ctx {
        &mut self.wasi
    }

    fn wasi_nn(&mut self) -> &mut WasiNnCtx {
        &mut self.wasi_nn
    }

    pub fn session(&mut self) -> &mut Session {
        &mut self.session
    }

    pub fn take_guest_profiler(&mut self) -> Option<Box<GuestProfiler>> {
        self.guest_profiler.take()
    }

    pub fn limiter(&self) -> &Limiter {
        &self.limiter
    }
}

impl WasmCtx {
    pub fn close_downstream_response_sender(&mut self) {
        self.session.close_downstream_response_sender()
    }
}

/// Initialize a new [`Store`][store], given an [`ExecuteCtx`][ctx].
///
/// [ctx]: ../wiggle_abi/struct.ExecuteCtx.html
/// [store]: https://docs.rs/wasmtime/latest/wasmtime/struct.Store.html
pub(crate) fn create_store(
    ctx: &ExecuteCtx,
    session: Session,
    guest_profiler: Option<GuestProfiler>,
    extra_init: impl FnOnce(&mut WasiCtxBuilder),
) -> Result<Store<WasmCtx>, anyhow::Error> {
    let mut builder = make_wasi_ctx(ctx, &session);

    extra_init(&mut builder);

    let wasi = builder.build_p1();
    let (backends, registry) = wasmtime_wasi_nn::preload(&[])?;
    let wasi_nn = WasiNnCtx::new(backends, registry);
    let wasm_ctx = WasmCtx {
        wasi,
        wasi_nn,
        session,
        guest_profiler: guest_profiler.map(Box::new),
        limiter: Limiter::default(),
    };
    let mut store = Store::new(ctx.engine(), wasm_ctx);
    store.set_epoch_deadline(1);
    store.epoch_deadline_callback(|mut store| {
        if let Some(mut prof) = store.data_mut().guest_profiler.take() {
            prof.sample(&store, std::time::Duration::ZERO);
            store.data_mut().guest_profiler = Some(prof);
        }
        Ok(UpdateDeadline::Yield(1))
    });
    store.limiter(|ctx| &mut ctx.limiter);
    Ok(store)
}

/// Constructs a `WasiCtxBuilder` for _each_ incoming request.
fn make_wasi_ctx(ctx: &ExecuteCtx, session: &Session) -> WasiCtxBuilder {
    let mut wasi_ctx = WasiCtxBuilder::new();

    // Viceroy provides the same `FASTLY_*` environment variables that the production
    // Compute platform provides:

    wasi_ctx
        // These variables are stubbed out for compatibility
        .env("FASTLY_CACHE_GENERATION", "0")
        .env("FASTLY_CUSTOMER_ID", "0000000000000000000000")
        .env("FASTLY_POP", "XXX")
        .env("FASTLY_REGION", "Somewhere")
        .env("FASTLY_SERVICE_ID", "0000000000000000000000")
        .env("FASTLY_SERVICE_VERSION", "0")
        // signal that we're in a local testing environment
        .env("FASTLY_HOSTNAME", "localhost")
        // request IDs start at 0 and increment, rather than being UUIDs, for ease of testing
        .env("FASTLY_TRACE_ID", &format!("{:032x}", session.req_id()));

    if ctx.log_stdout() {
        wasi_ctx.stdout(LogEndpoint::new(b"stdout", ctx.capture_logs()));
    } else {
        wasi_ctx.inherit_stdout();
    }

    if ctx.log_stderr() {
        wasi_ctx.stderr(LogEndpoint::new(b"stderr", ctx.capture_logs()));
    } else {
        wasi_ctx.inherit_stderr();
    }

    wasi_ctx
}

pub fn link_host_functions(
    linker: &mut Linker<WasmCtx>,
    experimental_modules: &HashSet<ExperimentalModule>,
) -> Result<(), Error> {
    experimental_modules
        .iter()
        .try_for_each(|experimental_module| match experimental_module {
            ExperimentalModule::WasiNn => {
                wasmtime_wasi_nn::witx::add_to_linker(linker, WasmCtx::wasi_nn)
            }
        })?;

    wasmtime_wasi::preview1::add_to_linker_async(linker, WasmCtx::wasi)?;
    wiggle_abi::fastly_abi::add_to_linker(linker, WasmCtx::session)?;
    wiggle_abi::fastly_cache::add_to_linker(linker, WasmCtx::session)?;
    wiggle_abi::fastly_config_store::add_to_linker(linker, WasmCtx::session)?;
    wiggle_abi::fastly_dictionary::add_to_linker(linker, WasmCtx::session)?;
    wiggle_abi::fastly_device_detection::add_to_linker(linker, WasmCtx::session)?;
    wiggle_abi::fastly_erl::add_to_linker(linker, WasmCtx::session)?;
    wiggle_abi::fastly_geo::add_to_linker(linker, WasmCtx::session)?;
    wiggle_abi::fastly_http_body::add_to_linker(linker, WasmCtx::session)?;
    wiggle_abi::fastly_http_req::add_to_linker(linker, WasmCtx::session)?;
    wiggle_abi::fastly_http_resp::add_to_linker(linker, WasmCtx::session)?;
    wiggle_abi::fastly_log::add_to_linker(linker, WasmCtx::session)?;
    wiggle_abi::fastly_object_store::add_to_linker(linker, WasmCtx::session)?;
    wiggle_abi::fastly_purge::add_to_linker(linker, WasmCtx::session)?;
    wiggle_abi::fastly_secret_store::add_to_linker(linker, WasmCtx::session)?;
    wiggle_abi::fastly_uap::add_to_linker(linker, WasmCtx::session)?;
    wiggle_abi::fastly_async_io::add_to_linker(linker, WasmCtx::session)?;
    wiggle_abi::fastly_backend::add_to_linker(linker, WasmCtx::session)?;
    link_legacy_aliases(linker)?;
    Ok(())
}

fn link_legacy_aliases(linker: &mut Linker<WasmCtx>) -> Result<(), Error> {
    linker.alias("fastly_abi", "init", "env", "xqd_init")?;

    let body = "fastly_http_body";
    linker.alias(body, "append", "env", "xqd_body_append")?;
    linker.alias(body, "new", "env", "xqd_body_new")?;
    linker.alias(body, "read", "env", "xqd_body_read")?;
    linker.alias(body, "write", "env", "xqd_body_write")?;
    linker.alias(body, "close", "env", "xqd_body_close")?;
    // `xqd_body_close_downstream` is deprecated since `fastly-sys:0.3.4`, and renamed to
    // `xqd_body_close`. We include it here under both names for compatibility's sake.
    linker.alias(body, "close", "env", "xqd_body_close_downstream")?;

    linker.alias("fastly_log", "endpoint_get", "env", "xqd_log_endpoint_get")?;
    linker.alias("fastly_log", "write", "env", "xqd_log_write")?;

    let req = "fastly_http_req";
    linker.alias(
        req,
        "body_downstream_get",
        "env",
        "xqd_req_body_downstream_get",
    )?;
    linker.alias(
        req,
        "cache_override_set",
        "env",
        "xqd_req_cache_override_set",
    )?;
    linker.alias(
        req,
        "downstream_client_ip_addr",
        "env",
        "xqd_req_downstream_client_ip_addr",
    )?;
    linker.alias(
        req,
        "downstream_client_request_id",
        "env",
        "xqd_req_downstream_client_request_id",
    )?;
    linker.alias(
        req,
        "downstream_tls_cipher_openssl_name",
        "env",
        "xqd_req_downstream_tls_cipher_openssl_name",
    )?;
    linker.alias(
        req,
        "downstream_tls_protocol",
        "env",
        "xqd_req_downstream_tls_protocol",
    )?;
    linker.alias(
        req,
        "downstream_tls_client_hello",
        "env",
        "xqd_req_downstream_tls_client_hello",
    )?;
    linker.alias(req, "new", "env", "xqd_req_new")?;

    linker.alias(req, "header_names_get", "env", "xqd_req_header_names_get")?;
    linker.alias(
        req,
        "original_header_names_get",
        "env",
        "xqd_req_original_header_names_get",
    )?;
    linker.alias(
        req,
        "original_header_count",
        "env",
        "xqd_req_original_header_count",
    )?;
    linker.alias(req, "header_value_get", "env", "xqd_req_header_value_get")?;
    linker.alias(req, "header_values_get", "env", "xqd_req_header_values_get")?;
    linker.alias(req, "header_values_set", "env", "xqd_req_header_values_set")?;
    linker.alias(req, "header_insert", "env", "xqd_req_header_insert")?;
    linker.alias(req, "header_append", "env", "xqd_req_header_append")?;
    linker.alias(req, "header_remove", "env", "xqd_req_header_remove")?;
    linker.alias(req, "method_get", "env", "xqd_req_method_get")?;
    linker.alias(req, "method_set", "env", "xqd_req_method_set")?;
    linker.alias(req, "uri_get", "env", "xqd_req_uri_get")?;
    linker.alias(req, "uri_set", "env", "xqd_req_uri_set")?;
    linker.alias(req, "version_get", "env", "xqd_req_version_get")?;
    linker.alias(req, "version_set", "env", "xqd_req_version_set")?;
    linker.alias(req, "send", "env", "xqd_req_send")?;
    linker.alias(req, "send_async", "env", "xqd_req_send_async")?;
    linker.alias(
        req,
        "send_async_streaming",
        "env",
        "xqd_req_send_async_streaming",
    )?;
    linker.alias(req, "pending_req_poll", "env", "xqd_pending_req_poll")?;
    linker.alias(req, "pending_req_wait", "env", "xqd_pending_req_wait")?;
    linker.alias(req, "pending_req_select", "env", "xqd_pending_req_select")?;

    let resp = "fastly_http_resp";
    linker.alias(resp, "new", "env", "xqd_resp_new")?;

    linker.alias(resp, "header_names_get", "env", "xqd_resp_header_names_get")?;
    linker.alias(resp, "header_value_get", "env", "xqd_resp_header_value_get")?;
    linker.alias(
        resp,
        "header_values_get",
        "env",
        "xqd_resp_header_values_get",
    )?;
    linker.alias(
        resp,
        "header_values_set",
        "env",
        "xqd_resp_header_values_set",
    )?;
    linker.alias(resp, "header_insert", "env", "xqd_resp_header_insert")?;
    linker.alias(resp, "header_append", "env", "xqd_resp_header_append")?;
    linker.alias(resp, "header_remove", "env", "xqd_resp_header_remove")?;
    linker.alias(resp, "version_get", "env", "xqd_resp_version_get")?;
    linker.alias(resp, "version_set", "env", "xqd_resp_version_set")?;
    linker.alias(resp, "status_get", "env", "xqd_resp_status_get")?;
    linker.alias(resp, "status_set", "env", "xqd_resp_status_set")?;
    Ok(())
}
