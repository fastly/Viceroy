//! Tests related to HTTP request and response bodies.

use {
    crate::common::{Test, TestResult},
    hyper::StatusCode,
};

#[tokio::test(flavor = "multi_thread")]
async fn check_hostcalls_implemented() -> TestResult {
    let resp = Test::using_fixture("edge-rate-limiting.wasm")
        .against_empty()
        .await?;
    assert_eq!(resp.status(), StatusCode::OK);
    Ok(())
}
