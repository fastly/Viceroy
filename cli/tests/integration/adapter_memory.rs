//! Both Go runtimes lay out linear memory very differently from Rust's, and both used to
//! collide with the component adapter's own pages on startup: TinyGo in
//! [issue #491](https://github.com/fastly/Viceroy/issues/491) and "big" Go in
//! [issue #498](https://github.com/fastly/Viceroy/issues/498). The fix was to
//! shift the main module's memory accesses by 2 pages, so the first 2 pages are
//! reserved for the adapter: [#538](https://github.com/fastly/Viceroy/pull/538)
//!
//! The Go toolchains are not required to build Viceroy, so these tests skip themselves when
//! their fixture is absent. See `test-fixtures/README.md` for build steps.

use {
    crate::{
        common::{GoToolchain, TestResult},
        go_fixture,
    },
    hyper::{StatusCode, body},
};

/// A guest with an empty handler reproduces the adapter state clobber under both TinyGo and Go.
/// When either runtime starts up, they trample over the adapter state, corrupting the magic canary
/// constants. Then the first hostcall from `fsthttp.Serve` triggers the assertion in State::with.
async fn empty_handler_responds(toolchain: GoToolchain) -> TestResult {
    let resp = go_fixture!(toolchain, "empty-main.wasm")
        .adapt_component(true)
        .against_empty()
        .await?;

    assert_eq!(resp.status(), StatusCode::OK);
    let body = body::to_bytes(resp.into_body()).await?;
    assert!(body.is_empty(), "expected an empty body, got {body:?}");

    Ok(())
}

/// The component adapter takes some of the main module's memory and grows it to store
/// its State struct. However, tinygo isn't aware of this and stores its GC metadata
/// at the end of the heap, which collides.
#[tokio::test(flavor = "multi_thread")]
async fn tinygo_guest_with_empty_handler() -> TestResult {
    empty_handler_responds(GoToolchain::TinyGo).await
}

#[tokio::test(flavor = "multi_thread")]
async fn go_guest_with_empty_handler() -> TestResult {
    empty_handler_responds(GoToolchain::Go).await
}
