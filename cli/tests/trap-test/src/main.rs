use std::collections::HashSet;
use {
    crate::common::{TestResult, RUST_FIXTURE_PATH},
    hyper::{Body, Request, StatusCode},
    viceroy_lib::{ExecuteCtx, ProfilingStrategy},
};

#[path = "../../integration/common.rs"]
mod common;

#[tokio::test(flavor = "multi_thread")]
async fn fatal_error_traps() -> TestResult {
    let module_path = format!("../../{}/response.wasm", RUST_FIXTURE_PATH);
    let ctx = ExecuteCtx::new(module_path, ProfilingStrategy::None, HashSet::new())?;
    let req = Request::get("http://127.0.0.1:7878/").body(Body::from(""))?;
    let resp = ctx
        .handle_request_with_runtime_error(req, "127.0.0.1".parse().unwrap())
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
