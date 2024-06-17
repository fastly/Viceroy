# The Fastly Component Adapter

This crate builds a wasm module that adapts both the preview1 api and the fastly
compute host calls to the component model. It started as a fork of the
[wasi_snapshot_preview1] component adapter with the `proxy` feature manually
expanded out, with all of the fastly-specific functionality mostly being added
in the `src/fastly` tree. The exception to this is the reactor export defined
by the compute world of `compute.wit`, whose definition is in `src/lib.rs`
instead of being defined in `src/fastly`, as the `wit-bindgen::generate!` makes
assumptions about relative module paths that make it hard to define elsewhere.

Changes to the adapter require running the top-level `make adapter` target, and
committing the resulting `lib/data/viceroy-component-adapter.wasm` wasm module.
This is a bit unfortunate, but as there's no way to hook the packaging step with
cargo, committing the binary is the easiest way to ensure that fresh checkouts
of this repository and packaged versions of the crates both build seamlessly.

## Adding New Host Calls

When adding new host calls, the adapter will need to be updated to know how they
should be adapted to the component model. In most cases, this will involve
updating the `/lib/wit/deps/fastly/compute.wit` package to describe what the
component imports of the new host call should look like, implementing it in both
`/lib/src/wiggle_abi` and `/lib/src/component`, and then finally adding a
version of the host call to the adapter in `src/fastly`. As the adapter builds
with the same `compute.wit` that `viceroy-lib` does, the imports will
automatically be available through the top-level `bindings` module.

[wasi_snapshot_preview1]: https://github.com/bytecodealliance/wasmtime/tree/main/crates/wasi-preview1-component-adapter
