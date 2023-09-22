use crate::common::{Test, TestResult};
use hyper::{body::to_bytes, StatusCode};
/// Run a program that only sleeps. This exercises async functionality in wasi.
/// Check that an empty response is sent downstream by default.
///
/// `sleep.wasm` is a guest program which sleeps for 100 milliseconds,then returns.
#[tokio::test(flavor = "multi_thread")]
async fn empty_ok_response_by_default_after_sleep() -> TestResult {
    let resp = Test::using_fixture("sleep.wasm").against_empty().await?;

    assert_eq!(resp.status(), StatusCode::OK);
    assert!(to_bytes(resp.into_body())
        .await
        .expect("can read body")
        .to_vec()
        .is_empty());

    Ok(())
}
