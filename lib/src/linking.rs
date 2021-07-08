//! Linking and name resolution.

use {
    crate::{execute::ExecuteCtx, logging::LogEndpoint, session::Session, wiggle_abi, Error},
    anyhow::Context,
    wasi_common::{pipe::WritePipe, WasiCtx},
    wasmtime::{Engine, Linker, Store},
    wasmtime_wasi::tokio::WasiCtxBuilder,
};

pub struct WasmCtx {
    wasi: WasiCtx,
    session: Session,
}

impl WasmCtx {
    fn wasi(&mut self) -> &mut WasiCtx {
        &mut self.wasi
    }
    fn session(&mut self) -> &mut Session {
        &mut self.session
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
) -> Result<Store<WasmCtx>, anyhow::Error> {
    let wasi = make_wasi_ctx(ctx, &session).context("creating Wasi context")?;
    let wasm_ctx = WasmCtx { wasi, session };
    let mut store = Store::new(ctx.engine(), wasm_ctx);
    store.out_of_fuel_async_yield(u32::MAX, 10000);
    Ok(store)
}

/// Create a `Store<WasmCtx>` which will only be used to check whether pre-initialization is
/// possible, and never used to execute code
pub(crate) fn dummy_store(engine: &Engine) -> Store<WasmCtx> {
    let wasi = WasiCtxBuilder::new().build();
    let session = Session::mock();
    Store::new(engine, WasmCtx { wasi, session })
}

/// Constructs a fresh `WasiCtx` for _each_ incoming request.
fn make_wasi_ctx(ctx: &ExecuteCtx, session: &Session) -> Result<WasiCtx, anyhow::Error> {
    let mut wasi_ctx = WasiCtxBuilder::new();

    // Viceroy provides a subset of the `FASTLY_*` environment variables that the production
    // Compute@Edge platform provides:

    wasi_ctx = wasi_ctx
        // signal that we're in a local testing environment
        .env("FASTLY_HOSTNAME", "localhost")?
        // request IDs start at 0 and increment, rather than being UUIDs, for ease of testing
        .env("FASTLY_TRACE_ID", &format!("{:032x}", session.req_id()))?;

    if ctx.log_stdout() {
        wasi_ctx = wasi_ctx.stdout(Box::new(WritePipe::new(LogEndpoint::new(b"stdout"))));
    } else {
        wasi_ctx = wasi_ctx.inherit_stdout();
    }

    if ctx.log_stderr() {
        wasi_ctx = wasi_ctx.stderr(Box::new(WritePipe::new(LogEndpoint::new(b"stderr"))));
    } else {
        wasi_ctx = wasi_ctx.inherit_stderr();
    }
    Ok(wasi_ctx.build())
}

pub fn link_host_functions(linker: &mut Linker<WasmCtx>) -> Result<(), Error> {
    wasmtime_wasi::add_to_linker(linker, WasmCtx::wasi)?;
    wiggle_abi::fastly_abi::add_to_linker(linker, WasmCtx::session)?;
    wiggle_abi::fastly_dictionary::add_to_linker(linker, WasmCtx::session)?;
    wiggle_abi::fastly_geo::add_to_linker(linker, WasmCtx::session)?;
    wiggle_abi::fastly_http_body::add_to_linker(linker, WasmCtx::session)?;
    wiggle_abi::fastly_http_req::add_to_linker(linker, WasmCtx::session)?;
    wiggle_abi::fastly_http_resp::add_to_linker(linker, WasmCtx::session)?;
    wiggle_abi::fastly_log::add_to_linker(linker, WasmCtx::session)?;
    wiggle_abi::fastly_uap::add_to_linker(linker, WasmCtx::session)?;
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
