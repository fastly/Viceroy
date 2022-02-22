use crate::common::{Test, TestResult};
use hyper::StatusCode;

#[tokio::test(flavor = "multi_thread")]
async fn direct_wasm_works() -> TestResult {
    let resp = Test::using_wat_fixture("return_ok.wat")
        .against_empty()
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    Ok(())
}
