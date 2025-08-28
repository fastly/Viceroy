use {
    crate::linking::ComponentCtx,
    wasmtime::component::{self, HasSelf},
    wasmtime_wasi::p2::add_to_linker_async,
};

component::bindgen!({
    path: "wasm_abi/wit",
    world: "fastly:adapter/adapter-service-without-wasi",
    async: true,
    with: {
        "fastly:adapter/adapter-uap/user-agent": adapter::uap::UserAgent,
        "fastly:compute/kv-store/entry": compute::kv_store::Entry,
        "fastly:compute/http-req/dynamic-backend-options": compute::http_req::BackendBuilder,
    },

    trappable_imports: [
        "[constructor]dynamic-backend-options",
        "select",
        "await-lookup",
    ],
});

pub fn link_host_functions(linker: &mut component::Linker<ComponentCtx>) -> anyhow::Result<()> {
    // Add the Viceroy host implementations.
    AdapterServiceWithoutWasi::add_to_linker::<_, HasSelf<_>>(linker, |x| x)?;

    // Add the WASI host implementations.
    add_to_linker_async(linker)?;

    Ok(())
}

pub mod adapter;
pub mod compute;
pub mod handles;
