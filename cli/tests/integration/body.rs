//! Tests related to HTTP request and response bodies.

use {
    crate::common::{Test, TestResult},
    hyper::{body, StatusCode},
};

#[tokio::test(flavor = "multi_thread")]
async fn bodies_can_be_written_and_appended() -> TestResult {
    let resp = Test::using_fixture("write-body.wasm")
        .against_empty()
        .await?;

    let body = body::to_bytes(resp.into_body())
        .await
        .expect("can read body")
        .to_vec();
    let body = String::from_utf8(body)?;
    assert_eq!(&body, "Hello, Viceroy!");

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn bodies_can_be_written_and_read() -> TestResult {
    let resp = Test::using_fixture("write-and-read-body.wasm")
        .against_empty()
        .await?;
    assert_eq!(resp.status(), StatusCode::OK);
    Ok(())
}
