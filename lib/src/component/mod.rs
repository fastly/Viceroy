use {crate::linking::ComponentCtx, wasmtime::component};

component::bindgen!({
    path: "wit",
    world: "fastly:api/compute",
    async: true,
    with: {
        "fastly:api/uap/user-agent": uap::UserAgent,
        "fastly:api/kv-store/lookup-result": kv_store::LookupResult,

        "wasi:clocks": wasmtime_wasi::bindings::clocks,
        "wasi:random": wasmtime_wasi::bindings::random,
        "wasi:io": wasmtime_wasi::bindings::io,
        "wasi:cli": wasmtime_wasi::bindings::cli,
    },

    trappable_error_type: {
        "fastly:api/types/error" => types::TrappableError,
    },

    trappable_imports: [
        "header-values-get",
        "[method]lookup-result.body",
        "[method]lookup-result.metadata",
        "[method]lookup-result.generation"
    ],
});

pub fn link_host_functions(linker: &mut component::Linker<ComponentCtx>) -> anyhow::Result<()> {
    fn wrap(ctx: &mut ComponentCtx) -> wasmtime_wasi::WasiImpl<&mut ComponentCtx> {
        wasmtime_wasi::WasiImpl(ctx)
    }

    wasmtime_wasi::bindings::clocks::wall_clock::add_to_linker_get_host(linker, wrap)?;
    wasmtime_wasi::bindings::clocks::monotonic_clock::add_to_linker_get_host(linker, wrap)?;
    wasmtime_wasi::bindings::random::random::add_to_linker_get_host(linker, wrap)?;
    wasmtime_wasi::bindings::filesystem::types::add_to_linker_get_host(linker, wrap)?;
    wasmtime_wasi::bindings::filesystem::preopens::add_to_linker_get_host(linker, wrap)?;
    wasmtime_wasi::bindings::io::error::add_to_linker_get_host(linker, wrap)?;
    wasmtime_wasi::bindings::io::streams::add_to_linker_get_host(linker, wrap)?;
    wasmtime_wasi::bindings::io::poll::add_to_linker_get_host(linker, wrap)?;
    wasmtime_wasi::bindings::cli::environment::add_to_linker_get_host(linker, wrap)?;
    wasmtime_wasi::bindings::cli::exit::add_to_linker_get_host(linker, wrap)?;
    wasmtime_wasi::bindings::cli::stdin::add_to_linker_get_host(linker, wrap)?;
    wasmtime_wasi::bindings::cli::stdout::add_to_linker_get_host(linker, wrap)?;
    wasmtime_wasi::bindings::cli::stderr::add_to_linker_get_host(linker, wrap)?;

    fastly::api::acl::add_to_linker(linker, |x| x)?;
    fastly::api::async_io::add_to_linker(linker, |x| x)?;
    fastly::api::backend::add_to_linker(linker, |x| x)?;
    fastly::api::cache::add_to_linker(linker, |x| x)?;
    fastly::api::compute_runtime::add_to_linker(linker, |x| x)?;
    fastly::api::config_store::add_to_linker(linker, |x| x)?;
    fastly::api::device_detection::add_to_linker(linker, |x| x)?;
    fastly::api::dictionary::add_to_linker(linker, |x| x)?;
    fastly::api::erl::add_to_linker(linker, |x| x)?;
    fastly::api::geo::add_to_linker(linker, |x| x)?;
    fastly::api::http_body::add_to_linker(linker, |x| x)?;
    fastly::api::http_downstream::add_to_linker(linker, |x| x)?;
    fastly::api::http_req::add_to_linker(linker, |x| x)?;
    fastly::api::http_resp::add_to_linker(linker, |x| x)?;
    fastly::api::http_types::add_to_linker(linker, |x| x)?;
    fastly::api::image_optimizer::add_to_linker(linker, |x| x)?;
    fastly::api::kv_store::add_to_linker(linker, |x| x)?;
    fastly::api::log::add_to_linker(linker, |x| x)?;
    fastly::api::object_store::add_to_linker(linker, |x| x)?;
    fastly::api::purge::add_to_linker(linker, |x| x)?;
    fastly::api::secret_store::add_to_linker(linker, |x| x)?;
    fastly::api::shielding::add_to_linker(linker, |x| x)?;
    fastly::api::types::add_to_linker(linker, |x| x)?;
    fastly::api::uap::add_to_linker(linker, |x| x)?;

    Ok(())
}

pub mod acl;
pub mod async_io;
pub mod backend;
pub mod cache;
pub mod compute_runtime;
pub mod config_store;
pub mod device_detection;
pub mod dictionary;
pub mod erl;
pub mod error;
pub mod geo;
pub mod headers;
pub mod http_body;
pub mod http_downstream;
pub mod http_req;
pub mod http_resp;
pub mod http_types;
pub mod image_optimizer;
pub mod kv_store;
pub mod log;
pub mod object_store;
pub mod purge;
pub mod secret_store;
pub mod shielding;
pub mod types;
pub mod uap;
