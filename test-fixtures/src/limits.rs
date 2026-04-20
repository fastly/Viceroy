// MAX_HEADER_NAME_LEN is defined in src/wiggle_abi/headers.rs but cannot
// be imported due to compilation of this workspace to the wasi32-wasm target.
// In a more perfect world, the Hyper crate would export a constant for this
// value since it panics when attempting to parse header names longer than
// 32,768.
pub const MAX_HEADER_NAME_LEN: usize = (1 << 16) - 1;
