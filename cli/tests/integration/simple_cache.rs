use crate::common::{Test, TestResult};
use hyper::{body::to_bytes, StatusCode};

#[tokio::test(flavor = "multi_thread")]
async fn simple_cache_get_or_set_with() -> TestResult {
    let resp = Test::using_fixture("simple_cache.wasm")
        .against_empty()
        .await?;

    assert_eq!(resp.status(), StatusCode::OK);
    assert!(to_bytes(resp.into_body())
        .await
        .expect("can read body")
        .to_vec()
        .is_empty());

    Ok(())
}
