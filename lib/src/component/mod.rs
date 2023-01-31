use {crate::linking::ComponentCtx, wasmtime::component};

component::bindgen!({
    path: "wit",
    world: "xqd",
    tracing: true,
    async: true,
    trappable_error_type: {
        "fastly:compute-at-edge/types"::error: FastlyError
    },
});

pub fn link_host_functions(linker: &mut component::Linker<ComponentCtx>) -> anyhow::Result<()> {
    wasmtime_wasi::preview2::bindings::clocks::wall_clock::add_to_linker(linker, |x| x)?;
    wasmtime_wasi::preview2::bindings::clocks::monotonic_clock::add_to_linker(linker, |x| x)?;
    wasmtime_wasi::preview2::bindings::random::random::add_to_linker(linker, |x| x)?;
    wasmtime_wasi::preview2::bindings::filesystem::filesystem::add_to_linker(linker, |x| x)?;
    wasmtime_wasi::preview2::bindings::io::streams::add_to_linker(linker, |x| x)?;
    wasmtime_wasi::preview2::bindings::cli_base::environment::add_to_linker(linker, |x| x)?;
    wasmtime_wasi::preview2::bindings::cli_base::preopens::add_to_linker(linker, |x| x)?;
    wasmtime_wasi::preview2::bindings::cli_base::exit::add_to_linker(linker, |x| x)?;
    wasmtime_wasi::preview2::bindings::cli_base::stdin::add_to_linker(linker, |x| x)?;
    wasmtime_wasi::preview2::bindings::cli_base::stdout::add_to_linker(linker, |x| x)?;
    wasmtime_wasi::preview2::bindings::cli_base::stderr::add_to_linker(linker, |x| x)?;

    fastly::compute_at_edge::async_io::add_to_linker(linker, |x| x.session())?;
    fastly::compute_at_edge::backend::add_to_linker(linker, |x| x.session())?;
    fastly::compute_at_edge::cache::add_to_linker(linker, |x| x.session())?;
    fastly::compute_at_edge::dictionary::add_to_linker(linker, |x| x.session())?;
    fastly::compute_at_edge::geo::add_to_linker(linker, |x| x.session())?;
    fastly::compute_at_edge::http_body::add_to_linker(linker, |x| x.session())?;
    fastly::compute_at_edge::http_req::add_to_linker(linker, |x| x.session())?;
    fastly::compute_at_edge::http_resp::add_to_linker(linker, |x| x.session())?;
    fastly::compute_at_edge::http_types::add_to_linker(linker, |x| x.session())?;
    fastly::compute_at_edge::log::add_to_linker(linker, |x| x.session())?;
    fastly::compute_at_edge::object_store::add_to_linker(linker, |x| x.session())?;
    fastly::compute_at_edge::purge::add_to_linker(linker, |x| x.session())?;
    fastly::compute_at_edge::secret_store::add_to_linker(linker, |x| x.session())?;
    fastly::compute_at_edge::types::add_to_linker(linker, |x| x.session())?;
    fastly::compute_at_edge::uap::add_to_linker(linker, |x| x.session())?;

    Ok(())
}

pub mod async_io;
pub mod backend;
pub mod cache;
pub mod dictionary;
pub mod error;
pub mod geo;
pub mod http_body;
pub mod http_req;
pub mod http_resp;
pub mod http_types;
pub mod log;
pub mod object_store;
pub mod purge;
pub mod secret_store;
pub mod types;
pub mod uap;
