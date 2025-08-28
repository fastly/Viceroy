# The Fastly Component Adapter

This crate builds a wasm module that adapts both the preview1 api and the fastly
compute host calls to the component model. It started as a fork of the
[wasi_snapshot_preview1] component adapter with the `proxy` feature manually
expanded out, with all of the fastly-specific functionality mostly being added
in the `src/fastly` tree. The exception to this is the `http-incoming` export defined
by the compute world of `compute.wit`, whose definition is in `src/lib.rs`
instead of being defined in `src/fastly`, as the `wit-bindgen::generate!` makes
assumptions about relative module paths that make it hard to define elsewhere.

## Adding New Host Calls

When adding new witx host calls, the adapter will need to be updated to know how
they should be adapted to WIT APIs. In most cases, this will involve
updating the `/wasm_abi/wit/deps/fastly/compute.wit` package to describe what the
component imports of the new host call should look like, implementing it in both
`/src/wiggle_abi` and `/src/component`, and then finally adding a
version of the host call to the adapter in `src/fastly`. The top-level `bindings`
module contains the bindings to the imported WIT API.

[wasi_snapshot_preview1]: https://github.com/bytecodealliance/wasmtime/tree/main/crates/wasi-preview1-component-adapter
