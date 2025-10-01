use {
    crate::linking::ComponentCtx,
    wasmtime::component::{self, HasSelf},
};

pub(crate) mod bindings {
    wasmtime::component::bindgen!({
        path: "wasm_abi/wit",
        world: "fastly:adapter/adapter-service",
        imports: {
            default: tracing,

            "fastly:compute/backend/[constructor]dynamic-backend-options": trappable,

            // The trap-test test depends on being able to induce an artificial
            // trap in `get-header-values`.
            "fastly:compute/http-resp/[method]response.get-header-values": trappable,

            "fastly:compute/http-body/append": async | tracing,
            "fastly:compute/kv-store/await-delete": async | tracing,
            "fastly:compute/cache/await-entry": async | tracing,
            "fastly:compute/kv-store/await-insert": async | tracing,
            "fastly:compute/kv-store/await-list": async | tracing,
            "fastly:compute/kv-store/await-lookup": async | tracing | trappable,
            "fastly:compute/http-downstream/await-next-request": async | tracing,
            "fastly:compute/http-req/await-request": async | tracing,
            "fastly:compute/cache/close-entry": async | tracing,
            "fastly:compute/cache/insert": async | tracing,
            "fastly:compute/cache/replace": async | tracing,
            "fastly:compute/cache/replace-get-age-ns": async | tracing,
            "fastly:compute/cache/replace-get-body": async | tracing,
            "fastly:compute/cache/replace-get-hits": async | tracing,
            "fastly:compute/cache/replace-get-length": async | tracing,
            "fastly:compute/cache/replace-get-max-age-ns": async | tracing,
            "fastly:compute/cache/replace-get-stale-while-revalidate-ns": async | tracing,
            "fastly:compute/cache/replace-get-state": async | tracing,
            "fastly:compute/cache/replace-get-user-metadata": async | tracing,
            "fastly:compute/cache/replace-insert": async | tracing,
            "fastly:compute/cache/[method]entry.get-age-ns": async | tracing,
            "fastly:compute/cache/[method]entry.get-body": async | tracing,
            "fastly:compute/cache/[method]entry.get-hits": async | tracing,
            "fastly:compute/cache/[method]entry.get-length": async | tracing,
            "fastly:compute/cache/[method]entry.get-max-age-ns": async | tracing,
            "fastly:compute/cache/[method]entry.get-stale-while-revalidate-ns": async | tracing,
            "fastly:compute/cache/[method]entry.get-state": async | tracing,
            "fastly:compute/cache/[method]entry.get-user-metadata": async | tracing,
            "fastly:compute/cache/[method]entry.transaction-cancel": async | tracing,
            "fastly:compute/cache/[method]entry.transaction-insert": async | tracing,
            "fastly:compute/cache/[method]entry.transaction-insert-and-stream-back": async | tracing,
            "fastly:compute/cache/[method]entry.transaction-update": async | tracing,
            "fastly:compute/kv-store/[method]store.delete": async | tracing,
            "fastly:compute/kv-store/[method]store.delete-async": async | tracing,
            "fastly:compute/kv-store/[method]store.insert": async | tracing,
            "fastly:compute/kv-store/[method]store.insert-async": async | tracing,
            "fastly:compute/kv-store/[method]store.list": async | tracing,
            "fastly:compute/kv-store/[method]store.list-async": async | tracing,
            "fastly:compute/kv-store/[method]store.lookup": async | tracing,
            "fastly:compute/kv-store/[method]store.lookup-async": async | tracing,
            "fastly:compute/http-downstream/next-request": async | tracing,
            "fastly:compute/http-body/read": async | tracing,
            "fastly:compute/backend/register-dynamic-backend": async | tracing,
            "fastly:compute/async-io/select": async | tracing | trappable,
            "fastly:compute/async-io/select-with-timeout": async | tracing,
            "fastly:compute/http-req/send": async | tracing,
            "fastly:compute/http-req/send-async": async | tracing,
            "fastly:compute/http-req/send-async-streaming": async | tracing,
            "fastly:compute/http-req/send-async-uncached": async | tracing,
            "fastly:compute/http-req/send-async-uncached-streaming": async | tracing,
            "fastly:compute/http-req/send-uncached": async | tracing,
            "fastly:compute/cache/[static]entry.lookup": async | tracing,
            "fastly:compute/cache/[static]entry.transaction-lookup": async | tracing,
            "fastly:compute/cache/[static]entry.transaction-lookup-async": async | tracing,
            "fastly:compute/http-body/write": async | tracing,
            "fastly:compute/http-body/write-front": async | tracing,

            // Match the `wasmtime-wasi` crate's bindings.
            "wasi:io/streams/[method]output-stream.write": tracing | trappable,
            "wasi:io/streams/[method]output-stream.blocking-write-and-flush": async | tracing | trappable,
            "wasi:io/streams/[method]output-stream.flush": tracing | trappable,
            "wasi:io/streams/[method]output-stream.blocking-flush": async | tracing | trappable,
            "wasi:io/streams/[method]output-stream.check-write": tracing | trappable,
            "wasi:io/streams/[method]output-stream.write-zeroes": tracing | trappable,
            "wasi:io/streams/[method]output-stream.blocking-write-zeroes-and-flush": async | tracing | trappable,
            "wasi:io/streams/[method]output-stream.splice": tracing | trappable,
            "wasi:io/streams/[method]output-stream.blocking-splice": async | tracing | trappable,
            "wasi:io/streams/[method]input-stream.read": tracing | trappable,
            "wasi:io/streams/[method]input-stream.blocking-read": async | tracing | trappable,
            "wasi:io/streams/[method]input-stream.skip": tracing | trappable,
            "wasi:io/streams/[method]input-stream.blocking-skip": async | tracing | trappable,
            "wasi:io/poll/poll": async | tracing,
            "wasi:io/poll/[method]pollable.block": async | tracing,
            "wasi:cli/exit/exit": tracing | trappable,
            "wasi:cli/exit/exit-with-code": tracing | trappable,
        },
        exports: {
            default: tracing,
            "fastly:compute/http-incoming/handle": async | tracing,
        },
        with: {
            // Match the `wasmtime-wasi` crate's bindings.
            "wasi:io/poll/pollable": wasmtime_wasi::p2::DynPollable,
            "wasi:io/streams/input-stream": wasmtime_wasi::p2::DynInputStream,
            "wasi:io/streams/output-stream": wasmtime_wasi::p2::DynOutputStream,
            "wasi:io/error/error": wasmtime_wasi_io::streams::Error,

            "fastly:adapter/adapter-uap/user-agent": super::adapter::uap::UserAgent,
            "fastly:compute/kv-store/entry": super::compute::kv_store::Entry,
            "fastly:compute/backend/dynamic-backend-options": super::compute::backend::BackendBuilder,
        },

        trappable_error_type: {
            // Match the wasmtime-wasi crate's bindings.
            "wasi:io/streams/stream-error" => wasmtime_wasi::p2::StreamError,
        },
    });
}

pub fn link_host_functions(linker: &mut component::Linker<ComponentCtx>) -> anyhow::Result<()> {
    let options = bindings::LinkOptions::default();

    // Add the Viceroy host implementations.
    bindings::AdapterService::add_to_linker::<_, HasSelf<_>>(linker, &options, |x| x)?;

    Ok(())
}

pub mod adapter;
pub mod compute;
pub mod handles;
pub mod wasi;
