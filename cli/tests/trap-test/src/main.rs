use std::collections::HashSet;
use {
    hyper::{Body, Request, StatusCode},
    viceroy_lib::{ExecuteCtx, ProfilingStrategy},
};

/// A shorthand for the path to our test fixtures' build artifacts for Rust tests.
const RUST_FIXTURE_PATH: &str = "../../../test-fixtures/target/wasm32-wasip1/debug/";

/// A catch-all error, so we can easily use `?` in test cases.
pub type Error = Box<dyn std::error::Error + Send + Sync>;

/// Handy alias for the return type of async Tokio tests
pub type TestResult = Result<(), Error>;

async fn fatal_error_traps_impl(adapt_core_wasm: bool) -> TestResult {
    let module_path = format!("{RUST_FIXTURE_PATH}/response.wasm");
    let ctx = ExecuteCtx::new(
        module_path,
        ProfilingStrategy::None,
        HashSet::new(),
        None,
        viceroy_lib::config::UnknownImportBehavior::LinkError,
        adapt_core_wasm,
    )?;
    let req = Request::get("http://127.0.0.1:7676/").body(Body::from(""))?;
    let local = "127.0.0.1:80".parse().unwrap();
    let remote = "127.0.0.1:0".parse().unwrap();
    let resp = ctx
        .handle_request_with_runtime_error(req, local, remote)
        .await?;

    // The Guest was terminated and so should return a 500.
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

    // Examine the cause in the body and assert that it is the expected
    // Trap error supplied by the Guest.

    let body = resp.into_body().read_into_string().await?;

    assert_eq!(
        body,
        "Fatal error: [A fatal error occurred in the test-only implementation of header_values_get]"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn fatal_error_traps() -> TestResult {
    fatal_error_traps_impl(false).await
}

#[tokio::test(flavor = "multi_thread")]
async fn fatal_error_traps_component() -> TestResult {
    fatal_error_traps_impl(true).await
}
