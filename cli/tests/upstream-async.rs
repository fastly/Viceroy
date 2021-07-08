mod common;

use {
    common::{Test, TestResult},
    hyper::{Response, StatusCode},
};

#[tokio::test(flavor = "multi_thread")]
async fn upstream_async_methods() -> TestResult {
    // Set up the test harness
    let test = Test::using_fixture("upstream-async.wasm")
        // Set up the backends, which just return responses with an identifying header
        .backend("backend1", "http://127.0.0.1:9000/")
        .host(9000, |_| {
            Response::builder()
                .header("Backend-1-Response", "")
                .status(StatusCode::OK)
                .body(vec![])
                .unwrap()
        })
        .backend("backend2", "http://127.0.0.1:9001/")
        .host(9001, |_| {
            Response::builder()
                .header("Backend-2-Response", "")
                .status(StatusCode::OK)
                .body(vec![])
                .unwrap()
        });

    // The meat of the test is on the guest side; we just check that we made it through successfully
    let resp = test.against_empty().await;
    assert_eq!(resp.status(), StatusCode::OK);
    Ok(())
}
