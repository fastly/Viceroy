use {
    crate::common::{Test, TestResult},
    hyper::{Request, StatusCode},
};

#[tokio::test(flavor = "multi_thread")]
async fn downstream_request_works() -> TestResult {
    let req = Request::get("/")
        .header("Accept", "text/html")
        .header("X-Custom-Test", "abcdef")
        .body("Hello, world!")?;
    let resp = Test::using_fixture("downstream-req.wasm")
        .against(req)
        .await?;

    assert_eq!(resp.status(), StatusCode::OK);
    Ok(())
}
