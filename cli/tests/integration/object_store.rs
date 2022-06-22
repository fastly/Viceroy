use crate::common::{Test, TestResult};
use hyper::{body::to_bytes, StatusCode};

#[tokio::test(flavor = "multi_thread")]
async fn object_store() -> TestResult {
    const FASTLY_TOML: &str = r#"
        name = "object-store-test"
        description = "object store test"
        authors = ["Jill Bryson <jbryson@fastly.com>", "Rose McDowall <rmcdowall@fastly.com>"]
        language = "rust"
        [local_server]
        object_store.empty_store = []
        object_store.store_one = [{key = "first", data = "This is some data"},{key = "second", path = "../test-fixtures/data/object-store.txt"}]
    "#;

    let resp = Test::using_fixture("object_store.wasm")
        .using_fastly_toml(FASTLY_TOML)?
        .against_empty()
        .await;

    assert_eq!(resp.status(), StatusCode::OK);
    assert!(to_bytes(resp.into_body())
        .await
        .expect("can read body")
        .to_vec()
        .is_empty());

    Ok(())
}
