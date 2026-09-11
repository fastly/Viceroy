//! Cross-compiles guest wasm programs in `test-fixtures`.
//!
//! We use a build.rs script to compile fixtures based on the
//! config in ../../fixtures.toml. This also avoids infinite
//! recursion (a build.rs in test-fixtures would re-invoke itself).

/// Directory holding the compiled fixtures. Beneath this, fixtures
/// can be found at `<target triple>/<profile>/<fixture>.wasm`.
pub const FIXTURE_DIR: &str = env!("VICEROY_FIXTURE_DIR");
