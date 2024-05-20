use {crate::linking::ComponentCtx, wasmtime::component};

/// This error type is used to classify two errors that can arise in a host-side implementation of
/// the fastly api:
///
/// * Application errors that are recoverable, and returned to the guest, and
/// * Traps that are expected to cause the guest to tear down immediately.
///
/// So a return type of `Result<T, FastlyError>` is  morally equivalent to
/// `Result<Result<T, ApplicationError>, TrapError>`, but the former is much more pleasant to
/// program with.
///
/// We write explicit `From` impls for errors that we raise throughout the implementation of the
/// compute apis, so that we're able to make the choice between an application error and a trap.
pub enum FastlyError {
    /// An application error, that will be communicated back to the guest through the
    /// `fastly:api/types/error` type.
    FastlyError(anyhow::Error),

    /// An trap, which will cause wasmtime to immediately terminate the guest.
    Trap(anyhow::Error),
}

impl FastlyError {
    pub fn with_empty_detail<T>(
        self,
    ) -> wasmtime::Result<
        Result<
            T,
            (
                Option<fastly::api::http_req::SendErrorDetail>,
                fastly::api::types::Error,
            ),
        >,
    > {
        match self {
            Self::FastlyError(e) => match e.downcast() {
                Ok(e) => Ok(Err((None, e))),
                Err(e) => Err(e),
            },
            Self::Trap(e) => Err(e),
        }
    }
}

component::bindgen!({
    path: "wit",
    world: "fastly:api/compute",
    async: true,
    with: {
        "fastly:api/uap/user-agent": uap::UserAgent,

        "wasi:clocks": wasmtime_wasi::bindings::clocks,
        "wasi:random": wasmtime_wasi::bindings::random,
        "wasi:io": wasmtime_wasi::bindings::io,
        "wasi:cli": wasmtime_wasi::bindings::cli,
    },
    trappable_imports: true,
    trappable_error_type: {
        "fastly:api/types/error" => FastlyError
    },
});

pub fn link_host_functions(linker: &mut component::Linker<ComponentCtx>) -> anyhow::Result<()> {
    // A utility function to add the types needed for `add_to_linker_get_host`.
    fn project_wasi_view(
        t: &mut impl wasmtime_wasi::WasiView,
    ) -> &mut impl wasmtime_wasi::WasiView {
        t
    }

    wasmtime_wasi::bindings::clocks::wall_clock::add_to_linker_get_host(linker, project_wasi_view)?;
    wasmtime_wasi::bindings::clocks::monotonic_clock::add_to_linker_get_host(
        linker,
        project_wasi_view,
    )?;
    wasmtime_wasi::bindings::random::random::add_to_linker_get_host(linker, project_wasi_view)?;
    wasmtime_wasi::bindings::filesystem::types::add_to_linker_get_host(linker, project_wasi_view)?;
    wasmtime_wasi::bindings::filesystem::preopens::add_to_linker_get_host(
        linker,
        project_wasi_view,
    )?;
    wasmtime_wasi::bindings::io::error::add_to_linker_get_host(linker, project_wasi_view)?;
    wasmtime_wasi::bindings::io::streams::add_to_linker_get_host(linker, project_wasi_view)?;
    wasmtime_wasi::bindings::io::poll::add_to_linker_get_host(linker, project_wasi_view)?;
    wasmtime_wasi::bindings::cli::environment::add_to_linker_get_host(linker, project_wasi_view)?;
    wasmtime_wasi::bindings::cli::exit::add_to_linker_get_host(linker, project_wasi_view)?;
    wasmtime_wasi::bindings::cli::stdin::add_to_linker_get_host(linker, project_wasi_view)?;
    wasmtime_wasi::bindings::cli::stdout::add_to_linker_get_host(linker, project_wasi_view)?;
    wasmtime_wasi::bindings::cli::stderr::add_to_linker_get_host(linker, project_wasi_view)?;

    fastly::api::async_io::add_to_linker(linker, |x| x.session())?;
    fastly::api::backend::add_to_linker(linker, |x| x.session())?;
    fastly::api::cache::add_to_linker(linker, |x| x.session())?;
    fastly::api::dictionary::add_to_linker(linker, |x| x.session())?;
    fastly::api::geo::add_to_linker(linker, |x| x.session())?;
    fastly::api::http_body::add_to_linker(linker, |x| x.session())?;
    fastly::api::http_req::add_to_linker(linker, |x| x.session())?;
    fastly::api::http_resp::add_to_linker(linker, |x| x.session())?;
    fastly::api::http_types::add_to_linker(linker, |x| x.session())?;
    fastly::api::log::add_to_linker(linker, |x| x.session())?;
    fastly::api::kv_store::add_to_linker(linker, |x| x.session())?;
    fastly::api::purge::add_to_linker(linker, |x| x.session())?;
    fastly::api::secret_store::add_to_linker(linker, |x| x.session())?;
    fastly::api::types::add_to_linker(linker, |x| x.session())?;
    fastly::api::uap::add_to_linker(linker, |x| x.session())?;

    Ok(())
}

pub mod async_io;
pub mod backend;
pub mod cache;
pub mod dictionary;
pub mod error;
pub mod geo;
pub mod headers;
pub mod http_body;
pub mod http_req;
pub mod http_resp;
pub mod http_types;
pub mod kv_store;
pub mod log;
pub mod purge;
pub mod secret_store;
pub mod types;
pub mod uap;
