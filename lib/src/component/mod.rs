use crate::linking::ComponentCtx;
use wasmtime::component::{self, HasData};

component::bindgen!({
    path: "wit",
    world: "fastly:api/compute",
    async: true,
    tracing: true,
    with: {
        "fastly:api/uap/user-agent": uap::UserAgent,
        "fastly:api/kv-store/lookup-result": kv_store::LookupResult,

        // "wasi:clocks": p2bindings::clocks,
        // "wasi:random": p2bindings::random,
        // "wasi:io": p2bindings::io,
        // "wasi:cli": p2bindings::cli,
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

impl HasData for ComponentCtx {
    type Data<'a> = &'a mut ComponentCtx;
}

pub fn link_host_functions(linker: &mut component::Linker<ComponentCtx>) -> anyhow::Result<()> {
    macro_rules! add_to_linker {
        ($mod:path) => {{
            use $mod::{add_to_linker};
            add_to_linker::<_, ComponentCtx>(linker, |ctx| ctx)
        }}
    }

    // TODO: revisit this...
    wasmtime_wasi::p2::add_to_linker_async(linker)?;
    // p2bindings::clocks::wall_clock::add_to_linker::<_, ComponentCtx>(linker, g)?;
    // p2bindings::clocks::monotonic_clock::add_to_linker(linker, wrap)?;
    // p2bindings::random::random::add_to_linker(linker, wrap)?;
    // p2bindings::filesystem::types::add_to_linker(linker, wrap)?;
    // p2bindings::filesystem::preopens::add_to_linker(linker, wrap)?;
    // p2bindings::io::error::add_to_linker(linker, wrap)?;
    // p2bindings::io::streams::add_to_linker(linker, wrap)?;
    // p2bindings::io::poll::add_to_linker(linker, wrap)?;
    // p2bindings::cli::environment::add_to_linker(linker, wrap)?;
    // p2bindings::cli::exit::add_to_linker(linker, wrap)?;
    // p2bindings::cli::stdin::add_to_linker(linker, wrap)?;
    // p2bindings::cli::stdout::add_to_linker(linker, wrap)?;
    // p2bindings::cli::stderr::add_to_linker(linker, wrap)?;

    add_to_linker!(fastly::api::acl)?;
    add_to_linker!(fastly::api::async_io)?;
    add_to_linker!(fastly::api::backend)?;
    add_to_linker!(fastly::api::cache)?;
    add_to_linker!(fastly::api::compute_runtime)?;
    add_to_linker!(fastly::api::config_store)?;
    add_to_linker!(fastly::api::device_detection)?;
    add_to_linker!(fastly::api::dictionary)?;
    add_to_linker!(fastly::api::erl)?;
    add_to_linker!(fastly::api::geo)?;
    add_to_linker!(fastly::api::http_body)?;
    add_to_linker!(fastly::api::http_cache)?;
    add_to_linker!(fastly::api::http_req)?;
    add_to_linker!(fastly::api::http_resp)?;
    add_to_linker!(fastly::api::http_types)?;
    add_to_linker!(fastly::api::image_optimizer)?;
    add_to_linker!(fastly::api::kv_store)?;
    add_to_linker!(fastly::api::log)?;
    add_to_linker!(fastly::api::object_store)?;
    add_to_linker!(fastly::api::purge)?;
    add_to_linker!(fastly::api::secret_store)?;
    add_to_linker!(fastly::api::shielding)?;
    add_to_linker!(fastly::api::types)?;
    add_to_linker!(fastly::api::uap)?;

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
pub mod http_cache;
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
