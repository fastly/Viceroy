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

#[tokio::test(flavor = "multi_thread")]
async fn object_store_bad_configs() -> TestResult {
    const BAD_1_FASTLY_TOML: &str = r#"
        name = "object-store-test"
        description = "object store test"
        authors = ["Jill Bryson <jbryson@fastly.com>", "Rose McDowall <rmcdowall@fastly.com>"]
        language = "rust"
        [local_server]
        object_store.store_one = [{key = 3, data = "This is some data"}]
    "#;
    match Test::using_fixture("object_store.wasm").using_fastly_toml(BAD_1_FASTLY_TOML) {
      Err(e) => assert_eq!("invalid configuration for 'store_one': The `key` value for an object is not a string.", &e.to_string()),
      _ => panic!(),
    }

    const BAD_2_FASTLY_TOML: &str = r#"
        name = "object-store-test"
        description = "object store test"
        authors = ["Jill Bryson <jbryson@fastly.com>", "Rose McDowall <rmcdowall@fastly.com>"]
        language = "rust"
        [local_server]
        object_store.store_one = [{key = "first", data = 3}]
    "#;
    match Test::using_fixture("object_store.wasm").using_fastly_toml(BAD_2_FASTLY_TOML) {
      Err(e) => assert_eq!("invalid configuration for 'store_one': The `data` value for the object `first` is not a string.", &e.to_string()),
      _ => panic!(),
    }

    const BAD_3_FASTLY_TOML: &str = r#"
        name = "object-store-test"
        description = "object store test"
        authors = ["Jill Bryson <jbryson@fastly.com>", "Rose McDowall <rmcdowall@fastly.com>"]
        language = "rust"
        [local_server]
        object_store.store_one = [{key = "first", data = "This is some data", path = "../test-fixtures/data/object-store.txt"}]
    "#;
    match Test::using_fixture("object_store.wasm").using_fastly_toml(BAD_3_FASTLY_TOML) {
      Err(e) => assert_eq!("invalid configuration for 'store_one': The `path` and `data` keys for the object `first` are set. Only one can be used.", &e.to_string()),
      _ => panic!(),
    }

    const BAD_4_FASTLY_TOML: &str = r#"
        name = "object-store-test"
        description = "object store test"
        authors = ["Jill Bryson <jbryson@fastly.com>", "Rose McDowall <rmcdowall@fastly.com>"]
        language = "rust"
        [local_server]
        object_store.store_one = [{key = "first", path = 3}]
    "#;
    match Test::using_fixture("object_store.wasm").using_fastly_toml(BAD_4_FASTLY_TOML) {
      Err(e) => assert_eq!("invalid configuration for 'store_one': The `path` value for the object `first` is not a string.", &e.to_string()),
      _ => panic!(),
    }

    const BAD_5_FASTLY_TOML: &str = r#"
        name = "object-store-test"
        description = "object store test"
        authors = ["Jill Bryson <jbryson@fastly.com>", "Rose McDowall <rmcdowall@fastly.com>"]
        language = "rust"
        [local_server]
        object_store.store_one = [{key = "first", path = "../path/does/not/exist"}]
    "#;
    match Test::using_fixture("object_store.wasm").using_fastly_toml(BAD_5_FASTLY_TOML) {
      Err(e) => assert_eq!("invalid configuration for 'store_one': No such file or directory (os error 2)", &e.to_string()),
      _ => panic!(),
    }

    const BAD_6_FASTLY_TOML: &str = r#"
        name = "object-store-test"
        description = "object store test"
        authors = ["Jill Bryson <jbryson@fastly.com>", "Rose McDowall <rmcdowall@fastly.com>"]
        language = "rust"
        [local_server]
        object_store.store_one = [{key = "first"}]
    "#;
    match Test::using_fixture("object_store.wasm").using_fastly_toml(BAD_6_FASTLY_TOML) {
      Err(e) => assert_eq!("invalid configuration for 'store_one': The `path` or `data` key for the object `first` is not set. One must be used.", &e.to_string()),
      _ => panic!(),
    }

    const BAD_7_FASTLY_TOML: &str = r#"
        name = "object-store-test"
        description = "object store test"
        authors = ["Jill Bryson <jbryson@fastly.com>", "Rose McDowall <rmcdowall@fastly.com>"]
        language = "rust"
        [local_server]
        object_store.store_one = [{data = "This is some data"}]
    "#;
    match Test::using_fixture("object_store.wasm").using_fastly_toml(BAD_7_FASTLY_TOML) {
      Err(e) => assert_eq!("invalid configuration for 'store_one': The `key` key for an object is not set. It must be used.", &e.to_string()),
      _ => panic!(),
    }

    const BAD_8_FASTLY_TOML: &str = r#"
        name = "object-store-test"
        description = "object store test"
        authors = ["Jill Bryson <jbryson@fastly.com>", "Rose McDowall <rmcdowall@fastly.com>"]
        language = "rust"
        [local_server]
        object_store.store_one = "lol lmao"
    "#;
    match Test::using_fixture("object_store.wasm").using_fastly_toml(BAD_8_FASTLY_TOML) {
      Err(e) => assert_eq!("invalid configuration for 'store_one': There is no array of objects for the given store.", &e.to_string()),
      _ => panic!(),
    }

    const BAD_9_FASTLY_TOML: &str = r#"
        name = "object-store-test"
        description = "object store test"
        authors = ["Jill Bryson <jbryson@fastly.com>", "Rose McDowall <rmcdowall@fastly.com>"]
        language = "rust"
        [local_server]
        object_store.store_one = ["This is some data"]
    "#;
    match Test::using_fixture("object_store.wasm").using_fastly_toml(BAD_9_FASTLY_TOML) {
      Err(e) => assert_eq!("invalid configuration for 'store_one': There is an object in the given store that is not a table of keys.", &e.to_string()),
      _ => panic!(),
    }

    Ok(())
}
