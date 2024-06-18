use {
    crate::common::{Test, TestResult},
    hyper::StatusCode,
};

#[tokio::test(flavor = "multi_thread")]
async fn request_works() -> TestResult {
    let resp = Test::using_fixture("request.wasm").against_empty().await?;
    assert_eq!(resp.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn request_works_component() -> TestResult {
    let resp = Test::using_fixture("request.wasm")
        .adapt_component()
        .against_empty()
        .await?;
    assert_eq!(resp.status(), StatusCode::OK);
    Ok(())
}
