use crate::{
    common::{Test, TestResult},
    viceroy_test,
};
use hyper::{body::to_bytes, StatusCode};

viceroy_test!(kv_store, |is_component| {
    const FASTLY_TOML: &str = r#"
        name = "kv-store-test"
        description = "kv store test"
        authors = ["Jill Bryson <jbryson@fastly.com>", "Rose McDowall <rmcdowall@fastly.com>"]
        language = "rust"
        [local_server]
        kv_stores.empty_store = []
        kv_stores.store_one = [{key = "first", data = "This is some data"},{key = "second", file = "../test-fixtures/data/kv-store.txt"},{key = "third", data = "third", metadata = "some metadata"}]
    "#;

    let resp = Test::using_fixture("kv_store.wasm")
        .adapt_component(is_component)
        .using_fastly_toml(FASTLY_TOML)?
        .against_empty()
        .await?;

    assert_eq!(resp.status(), StatusCode::OK);
    assert!(to_bytes(resp.into_body())
        .await
        .expect("can read body")
        .to_vec()
        .is_empty());

    Ok(())
});

viceroy_test!(object_stores_backward_compat, |is_component| {
    // Previously the "kv_stores" key was named "object_stores" and
    // the "file" key was named "path".  This test ensures that both
    // still work.
    const FASTLY_TOML: &str = r#"
        name = "object-store-test"
        description = "object store test"
        authors = ["Jill Bryson <jbryson@fastly.com>", "Rose McDowall <rmcdowall@fastly.com>"]
        language = "rust"
        [local_server]
        object_stores.empty_store = []
        object_stores.store_one = [{key = "first", data = "This is some data"},{key = "second", path = "../test-fixtures/data/kv-store.txt"},{key = "third", data = "third", metadata = "some metadata"}]
    "#;

    let resp = Test::using_fixture("kv_store.wasm")
        .adapt_component(is_component)
        .using_fastly_toml(FASTLY_TOML)?
        .against_empty()
        .await?;

    assert_eq!(resp.status(), StatusCode::OK);
    assert!(to_bytes(resp.into_body())
        .await
        .expect("can read body")
        .to_vec()
        .is_empty());

    Ok(())
});

viceroy_test!(kv_store_allows_fetching_of_key_from_file, |is_component| {
    // This test checks that we can provide a "format" and a "file"
    // with a JSON dictionary inside it for a KV Store
    // and have the KV Store populated with it.
    const FASTLY_TOML: &str = r#"
        name = "kv-store-test"
        description = "kv store test"
        authors = ["Gustav Wengel <gustav@climatiq.io>"]
        language = "rust"
        [local_server]
        kv_stores.empty_store = []
        kv_stores.store_one = { file = "../test-fixtures/data/json-kv_store.json", format = "json" }
    "#;

    let resp = Test::using_fixture("kv_store.wasm")
        .adapt_component(is_component)
        .using_fastly_toml(FASTLY_TOML)?
        .against_empty()
        .await?;

    assert_eq!(resp.status(), StatusCode::OK);
    assert!(to_bytes(resp.into_body())
        .await
        .expect("can read body")
        .to_vec()
        .is_empty());

    Ok(())
});

viceroy_test!(object_store_backward_compat, |is_component| {
    // Previously the "object_stores" key was named "object_store" and
    // the "file" key was named "path".  This test ensures that both
    // still work.
    const FASTLY_TOML: &str = r#"
        name = "object-store-test"
        description = "object store test"
        authors = ["Jill Bryson <jbryson@fastly.com>", "Rose McDowall <rmcdowall@fastly.com>"]
        language = "rust"
        [local_server]
        object_store.empty_store = []
        object_store.store_one = [{key = "first", data = "This is some data"},{key = "second", path = "../test-fixtures/data/kv-store.txt"},{key = "third", data = "third", metadata = "some metadata"}]
    "#;

    let resp = Test::using_fixture("kv_store.wasm")
        .adapt_component(is_component)
        .using_fastly_toml(FASTLY_TOML)?
        .against_empty()
        .await?;

    assert_eq!(resp.status(), StatusCode::OK);
    assert!(to_bytes(resp.into_body())
        .await
        .expect("can read body")
        .to_vec()
        .is_empty());

    Ok(())
});

viceroy_test!(kv_store_bad_configs, |is_component| {
    const BAD_1_FASTLY_TOML: &str = r#"
        name = "kv-store-test"
        description = "kv store test"
        authors = ["Jill Bryson <jbryson@fastly.com>", "Rose McDowall <rmcdowall@fastly.com>"]
        language = "rust"
        [local_server]
        kv_stores.store_one = [{key = 3, data = "This is some data"}]
    "#;
    match Test::using_fixture("kv_store.wasm")
        .adapt_component(is_component)
        .using_fastly_toml(BAD_1_FASTLY_TOML)
    {
        Err(e) => assert_eq!(
            "invalid configuration for 'store_one': The `key` value for an object is not a string.",
            &e.to_string()
        ),
        _ => panic!(),
    }

    const BAD_2_FASTLY_TOML: &str = r#"
        name = "kv-store-test"
        description = "kv store test"
        authors = ["Jill Bryson <jbryson@fastly.com>", "Rose McDowall <rmcdowall@fastly.com>"]
        language = "rust"
        [local_server]
        kv_stores.store_one = [{key = "first", data = 3}]
    "#;
    match Test::using_fixture("kv_store.wasm")
        .adapt_component(is_component)
        .using_fastly_toml(BAD_2_FASTLY_TOML) {
      Err(e) => assert_eq!("invalid configuration for 'store_one': The `data` value for the object `first` is not a string.", &e.to_string()),
      _ => panic!(),
    }

    const BAD_3_FASTLY_TOML: &str = r#"
        name = "kv-store-test"
        description = "kv store test"
        authors = ["Jill Bryson <jbryson@fastly.com>", "Rose McDowall <rmcdowall@fastly.com>"]
        language = "rust"
        [local_server]
        kv_stores.store_one = [{key = "first", data = "This is some data", file = "../test-fixtures/data/kv-store.txt"}]
    "#;
    match Test::using_fixture("kv_store.wasm").adapt_component(is_component).using_fastly_toml(BAD_3_FASTLY_TOML) {
      Err(e) => assert_eq!("invalid configuration for 'store_one': The `file` and `data` keys for the object `first` are set. Only one can be used.", &e.to_string()),
      _ => panic!(),
    }

    const BAD_4_FASTLY_TOML: &str = r#"
        name = "kv-store-test"
        description = "kv store test"
        authors = ["Jill Bryson <jbryson@fastly.com>", "Rose McDowall <rmcdowall@fastly.com>"]
        language = "rust"
        [local_server]
        kv_stores.store_one = [{key = "first", file = 3}]
    "#;
    match Test::using_fixture("kv_store.wasm").adapt_component(is_component).using_fastly_toml(BAD_4_FASTLY_TOML) {
      Err(e) => assert_eq!("invalid configuration for 'store_one': The `file` value for the object `first` is not a string.", &e.to_string()),
      _ => panic!(),
    }

    const BAD_5_FASTLY_TOML: &str = r#"
        name = "kv-store-test"
        description = "kv store test"
        authors = ["Jill Bryson <jbryson@fastly.com>", "Rose McDowall <rmcdowall@fastly.com>"]
        language = "rust"
        [local_server]
        kv_stores.store_one = [{key = "first", file = "../path/does/not/exist"}]
    "#;

    // For CI to pass we need to include the specific message for each platform
    // we test against
    #[cfg(target_os = "macos")]
    let invalid_path_message =
        "invalid configuration for 'store_one': No such file or directory (os error 2)";
    #[cfg(target_os = "linux")]
    let invalid_path_message =
        "invalid configuration for 'store_one': No such file or directory (os error 2)";
    #[cfg(target_os = "windows")]
    let invalid_path_message = "invalid configuration for 'store_one': The system cannot find the path specified. (os error 3)";

    match Test::using_fixture("kv_store.wasm")
        .adapt_component(is_component)
        .using_fastly_toml(BAD_5_FASTLY_TOML)
    {
        Err(e) => assert_eq!(invalid_path_message, &e.to_string()),
        _ => panic!(),
    }

    const BAD_6_FASTLY_TOML: &str = r#"
        name = "kv-store-test"
        description = "kv store test"
        authors = ["Jill Bryson <jbryson@fastly.com>", "Rose McDowall <rmcdowall@fastly.com>"]
        language = "rust"
        [local_server]
        kv_stores.store_one = [{key = "first"}]
    "#;
    match Test::using_fixture("kv_store.wasm").adapt_component(is_component).using_fastly_toml(BAD_6_FASTLY_TOML) {
      Err(e) => assert_eq!("invalid configuration for 'store_one': The `file` or `data` key for the object `first` is not set. One must be used.", &e.to_string()),
      _ => panic!(),
    }

    const BAD_7_FASTLY_TOML: &str = r#"
        name = "kv-store-test"
        description = "kv store test"
        authors = ["Jill Bryson <jbryson@fastly.com>", "Rose McDowall <rmcdowall@fastly.com>"]
        language = "rust"
        [local_server]
        kv_stores.store_one = [{data = "This is some data"}]
    "#;
    match Test::using_fixture("kv_store.wasm").adapt_component(is_component).using_fastly_toml(BAD_7_FASTLY_TOML) {
      Err(e) => assert_eq!("invalid configuration for 'store_one': The `key` key for an object is not set. It must be used.", &e.to_string()),
      _ => panic!(),
    }

    const BAD_8_FASTLY_TOML: &str = r#"
        name = "kv-store-test"
        description = "kv store test"
        authors = ["Jill Bryson <jbryson@fastly.com>", "Rose McDowall <rmcdowall@fastly.com>"]
        language = "rust"
        [local_server]
        kv_stores.store_one = "lol lmao"
    "#;
    match Test::using_fixture("kv_store.wasm").adapt_component(is_component).using_fastly_toml(BAD_8_FASTLY_TOML) {
      Err(e) => assert_eq!("invalid configuration for 'store_one': There is no array of objects for the given store.", &e.to_string()),
      _ => panic!(),
    }

    const BAD_9_FASTLY_TOML: &str = r#"
        name = "kv-store-test"
        description = "kv store test"
        authors = ["Jill Bryson <jbryson@fastly.com>", "Rose McDowall <rmcdowall@fastly.com>"]
        language = "rust"
        [local_server]
        kv_stores.store_one = ["This is some data"]
    "#;
    match Test::using_fixture("kv_store.wasm").adapt_component(is_component).using_fastly_toml(BAD_9_FASTLY_TOML) {
      Err(e) => assert_eq!("invalid configuration for 'store_one': There is an object in the given store that is not a table of keys.", &e.to_string()),
      _ => panic!(),
    }

    const BAD_10_FASTLY_TOML: &str = r#"
        name = "kv-store-test"
        description = "kv store test"
        authors = ["Gustav Wengel <gustav@climatiq.io>"]
        language = "rust"
        [local_server]
        kv_stores.empty_store = []
        kv_stores.store_one = { file = "../test-fixtures/data/json-kv_store.json" }
    "#;
    match Test::using_fixture("kv_store.wasm").using_fastly_toml(BAD_10_FASTLY_TOML) {
        Err(e) => assert_eq!("invalid configuration for 'store_one': When using a top-level 'file' to load data, both 'file' and 'format' must be set.", &e.to_string()),
        _ => panic!(),
    }

    const BAD_11_FASTLY_TOML: &str = r#"
        name = "kv-store-test"
        description = "kv store test"
        authors = ["Gustav Wengel <gustav@climatiq.io>"]
        language = "rust"
        [local_server]
        kv_stores.empty_store = []
        kv_stores.store_one = { format = "json" }
    "#;
    match Test::using_fixture("kv_store.wasm").using_fastly_toml(BAD_11_FASTLY_TOML) {
        Err(e) => assert_eq!("invalid configuration for 'store_one': When using a top-level 'file' to load data, both 'file' and 'format' must be set.", &e.to_string()),
        _ => panic!(),
    }

    const BAD_12_FASTLY_TOML: &str = r#"
        name = "kv-store-test"
        description = "kv store test"
        authors = ["Gustav Wengel <gustav@climatiq.io>"]
        language = "rust"
        [local_server]
        kv_stores.empty_store = []
        kv_stores.store_one = { file = "../test-fixtures/data/json-kv_store.json", format = "INVALID" }
    "#;
    match Test::using_fixture("kv_store.wasm").using_fastly_toml(BAD_12_FASTLY_TOML) {
        Err(e) => assert_eq!("invalid configuration for 'store_one': 'INVALID' is not a valid format for the config store. Supported format(s) are: 'json'.", &e.to_string()),
        _ => panic!(),
    }

    const BAD_13_FASTLY_TOML: &str = r#"
        name = "kv-store-test"
        description = "kv store test"
        authors = ["Gustav Wengel <gustav@climatiq.io>"]
        language = "rust"
        [local_server]
        kv_stores.empty_store = []
        kv_stores.store_one = { file = "../test-fixtures/data/ABSOLUTELY_NOT_A_REAL_PATH", format = "json" }
    "#;
    match Test::using_fixture("kv_store.wasm").using_fastly_toml(BAD_13_FASTLY_TOML) {
        Err(e) => {
            // We can't assert on the whole error message here as the next part of the string is platform-specific
            // where it says that it cannot find the file.
            assert!(e
                .to_string()
                .contains("invalid configuration for 'store_one'"));
        }
        _ => panic!(),
    }

    // Not a valid JSON file
    const BAD_14_FASTLY_TOML: &str = r#"
        name = "kv-store-test"
        description = "kv store test"
        authors = ["Gustav Wengel <gustav@climatiq.io>"]
        language = "rust"
        [local_server]
        kv_stores.empty_store = []
        kv_stores.store_one = { file = "../test-fixtures/data/kv-store.txt", format = "json" }
    "#;
    match Test::using_fixture("kv_store.wasm").using_fastly_toml(BAD_14_FASTLY_TOML) {
        Err(e) => assert_eq!("invalid configuration for 'store_one': The file is of the wrong format. The file is expected to contain a single JSON Object.", &e.to_string()),
        _ => panic!(),
    }

    const BAD_15_FASTLY_TOML: &str = r#"
        name = "kv-store-test"
        description = "kv store test"
        authors = ["Jill Bryson <jbryson@fastly.com>", "Rose McDowall <rmcdowall@fastly.com>"]
        language = "rust"
        [local_server]
        kv_stores.store_one = [{key = "first", data = "This is some data", metadata = 5}]
    "#;
    match Test::using_fixture("kv_store.wasm")
        .adapt_component(is_component)
        .using_fastly_toml(BAD_15_FASTLY_TOML)
    {
        Err(e) => assert_eq!(
            "invalid configuration for 'store_one': The `metadata` value for the object `first` is not a string.",
            &e.to_string()
        ),
        _ => panic!(),
    }

    // Invalid format JSON - entry must have data or file (or path)
    const BAD_16_FASTLY_TOML: &str = r#"
        name = "kv-store-test"
        description = "kv store test"
        authors = ["Gustav Wengel <gustav@climatiq.io>"]
        language = "rust"
        [local_server]
        kv_stores.empty_store = []
        kv_stores.store_one = { file = "../test-fixtures/data/json-kv_store-invalid_1.json", format = "json" }
    "#;
    match Test::using_fixture("kv_store.wasm").using_fastly_toml(BAD_16_FASTLY_TOML) {
        Err(e) => assert_eq!("invalid configuration for 'store_one': Item value under key named 'first' is of the wrong format. One of 'data' or 'file' must be present.", &e.to_string()),
        _ => panic!(),
    }

    // Invalid format JSON - entry cannot have both data and file
    const BAD_17_FASTLY_TOML: &str = r#"
        name = "kv-store-test"
        description = "kv store test"
        authors = ["Gustav Wengel <gustav@climatiq.io>"]
        language = "rust"
        [local_server]
        kv_stores.empty_store = []
        kv_stores.store_one = { file = "../test-fixtures/data/json-kv_store-invalid_2.json", format = "json" }
    "#;
    match Test::using_fixture("kv_store.wasm").using_fastly_toml(BAD_17_FASTLY_TOML) {
        Err(e) => assert_eq!("invalid configuration for 'store_one': Item value under key named 'first' is of the wrong format. 'data' and 'file' are mutually exclusive.", &e.to_string()),
        _ => panic!(),
    }

    Ok(())
});

viceroy_test!(kv_store_bad_key_values, |is_component| {
    const BAD_1_FASTLY_TOML: &str = r#"
        name = "kv-store-test"
        description = "kv store test"
        authors = ["Jill Bryson <jbryson@fastly.com>", "Rose McDowall <rmcdowall@fastly.com>"]
        language = "rust"
        [local_server]
        kv_stores.store_one = [{key = "", data = "This is some data"}]
    "#;
    match Test::using_fixture("kv_store.wasm").adapt_component(is_component).using_fastly_toml(BAD_1_FASTLY_TOML) {
        Err(e) => assert_eq!("invalid configuration for 'store_one': Invalid `key` value used: Keys for objects cannot be empty.", &e.to_string()),
        _ => panic!(),
    }

    const BAD_2_FASTLY_TOML: &str = r#"
        name = "kv-store-test"
        description = "kv store test"
        authors = ["Jill Bryson <jbryson@fastly.com>", "Rose McDowall <rmcdowall@fastly.com>"]
        language = "rust"
        [local_server]
        kv_stores.store_one = [{key = "LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOoooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooong,looooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooong,keeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeEEEEEEEEEEEEEEEEEEEEEEEEEEEEEeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeey", data = "This is some data"}]
    "#;
    match Test::using_fixture("kv_store.wasm").adapt_component(is_component).using_fastly_toml(BAD_2_FASTLY_TOML) {
        Err(e) => assert_eq!(
            "invalid configuration for 'store_one': Invalid `key` value used: Keys for objects cannot be over 1024 bytes in size.",
            &e.to_string()
        ),
        _ => panic!(),
    }

    const BAD_3_FASTLY_TOML: &str = r#"
        name = "kv-store-test"
        description = "kv store test"
        authors = ["Jill Bryson <jbryson@fastly.com>", "Rose McDowall <rmcdowall@fastly.com>"]
        language = "rust"
        [local_server]
        kv_stores.store_one = [{key = ".well-known/acme-challenge/wheeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", data = "This is some data"}]
    "#;
    match Test::using_fixture("kv_store.wasm").adapt_component(is_component).using_fastly_toml(BAD_3_FASTLY_TOML) {
        Err(e) => assert_eq!(
            "invalid configuration for 'store_one': Invalid `key` value used: Keys for objects cannot start with `.well-known/acme-challenge`.",
            &e.to_string()
        ),
        _ => panic!(),
    }

    const BAD_4_FASTLY_TOML: &str = r#"
        name = "kv-store-test"
        description = "kv store test"
        authors = ["Jill Bryson <jbryson@fastly.com>", "Rose McDowall <rmcdowall@fastly.com>"]
        language = "rust"
        [local_server]
        kv_stores.store_one = [{key = ".", data = "This is some data"}]
    "#;
    match Test::using_fixture("kv_store.wasm").adapt_component(is_component).using_fastly_toml(BAD_4_FASTLY_TOML) {
        Err(e) => assert_eq!("invalid configuration for 'store_one': Invalid `key` value used: Keys for objects cannot be named `.`.", &e.to_string()),
        _ => panic!(),
    }

    const BAD_5_FASTLY_TOML: &str = r#"
        name = "kv-store-test"
        description = "kv store test"
        authors = ["Jill Bryson <jbryson@fastly.com>", "Rose McDowall <rmcdowall@fastly.com>"]
        language = "rust"
        [local_server]
        kv_stores.store_one = [{key = "..", data = "This is some data"}]
    "#;
    match Test::using_fixture("kv_store.wasm").adapt_component(is_component).using_fastly_toml(BAD_5_FASTLY_TOML) {
        Err(e) => assert_eq!("invalid configuration for 'store_one': Invalid `key` value used: Keys for objects cannot be named `..`.", &e.to_string()),
        _ => panic!(),
    }

    const BAD_6_FASTLY_TOML: &str = r#"
        name = "kv-store-test"
        description = "kv store test"
        authors = ["Jill Bryson <jbryson@fastly.com>", "Rose McDowall <rmcdowall@fastly.com>"]
        language = "rust"
        [local_server]
        kv_stores.store_one = [{key = "carriage\rreturn", data = "This is some data"}]
    "#;
    match Test::using_fixture("kv_store.wasm").adapt_component(is_component).using_fastly_toml(BAD_6_FASTLY_TOML) {
        Err(e) => assert_eq!("invalid configuration for 'store_one': Invalid `key` value used: Keys for objects cannot contain a `\r`.", &e.to_string()),
        _ => panic!(),
    }

    const BAD_7_FASTLY_TOML: &str = r#"
        name = "kv-store-test"
        description = "kv store test"
        authors = ["Jill Bryson <jbryson@fastly.com>", "Rose McDowall <rmcdowall@fastly.com>"]
        language = "rust"
        [local_server]
        kv_stores.store_one = [{key = "newlines\nin\nthis\neconomy?", data = "This is some data"}]
    "#;
    match Test::using_fixture("kv_store.wasm").adapt_component(is_component).using_fastly_toml(BAD_7_FASTLY_TOML) {
        Err(e) => assert_eq!("invalid configuration for 'store_one': Invalid `key` value used: Keys for objects cannot contain a `\n`.", &e.to_string()),
        _ => panic!(),
    }

    const BAD_8_FASTLY_TOML: &str = r#"
        name = "kv-store-test"
        description = "kv store test"
        authors = ["Jill Bryson <jbryson@fastly.com>", "Rose McDowall <rmcdowall@fastly.com>"]
        language = "rust"
        [local_server]
        kv_stores.store_one = [{key = "howdy#", data = "This is some data"}]
    "#;
    match Test::using_fixture("kv_store.wasm").adapt_component(is_component).using_fastly_toml(BAD_8_FASTLY_TOML) {
        Err(e) => assert_eq!("invalid configuration for 'store_one': Invalid `key` value used: Keys for objects cannot contain a `#`.", &e.to_string()),
        _ => panic!(),
    }

    const BAD_9_FASTLY_TOML: &str = r#"
        name = "kv-store-test"
        description = "kv store test"
        authors = ["Jill Bryson <jbryson@fastly.com>", "Rose McDowall <rmcdowall@fastly.com>"]
        language = "rust"
        [local_server]
        kv_stores.store_one = [{key = "hello;", data = "This is some data"}]
    "#;
    match Test::using_fixture("kv_store.wasm").adapt_component(is_component).using_fastly_toml(BAD_9_FASTLY_TOML) {
        Err(e) => assert_eq!("invalid configuration for 'store_one': Invalid `key` value used: Keys for objects cannot contain a `;`.", &e.to_string()),
        _ => panic!(),
    }

    const BAD_10_FASTLY_TOML: &str = r#"
        name = "kv-store-test"
        description = "kv store test"
        authors = ["Jill Bryson <jbryson@fastly.com>", "Rose McDowall <rmcdowall@fastly.com>"]
        language = "rust"
        [local_server]
        kv_stores.store_one = [{key = "yoohoo?", data = "This is some data"}]
    "#;
    match Test::using_fixture("kv_store.wasm").adapt_component(is_component).using_fastly_toml(BAD_10_FASTLY_TOML) {
        Err(e) => assert_eq!("invalid configuration for 'store_one': Invalid `key` value used: Keys for objects cannot contain a `?`.", &e.to_string()),
        _ => panic!(),
    }

    const BAD_11_FASTLY_TOML: &str = r#"
        name = "kv-store-test"
        description = "kv store test"
        authors = ["Jill Bryson <jbryson@fastly.com>", "Rose McDowall <rmcdowall@fastly.com>"]
        language = "rust"
        [local_server]
        kv_stores.store_one = [{key = "hey^", data = "This is some data"}]
    "#;
    match Test::using_fixture("kv_store.wasm").adapt_component(is_component).using_fastly_toml(BAD_11_FASTLY_TOML) {
        Err(e) => assert_eq!("invalid configuration for 'store_one': Invalid `key` value used: Keys for objects cannot contain a `^`.", &e.to_string()),
        _ => panic!(),
    }

    const BAD_12_FASTLY_TOML: &str = r#"
        name = "kv-store-test"
        description = "kv store test"
        authors = ["Jill Bryson <jbryson@fastly.com>", "Rose McDowall <rmcdowall@fastly.com>"]
        language = "rust"
        [local_server]
        kv_stores.store_one = [{key = "ello ello|", data = "This is some data"}]
    "#;
    match Test::using_fixture("kv_store.wasm").adapt_component(is_component).using_fastly_toml(BAD_12_FASTLY_TOML) {
        Err(e) => assert_eq!("invalid configuration for 'store_one': Invalid `key` value used: Keys for objects cannot contain a `|`.", &e.to_string()),
        _ => panic!(),
    }

    const BAD_13_FASTLY_TOML: &str = r#"
        name = "kv-store-test"
        description = "kv store test"
        authors = ["Jill Bryson <jbryson@fastly.com>", "Rose McDowall <rmcdowall@fastly.com>"]
        language = "rust"
        [local_server]
        kv_stores.store_one = [{key = " ", data = "This is some data"}]
    "#;
    match Test::using_fixture("kv_store.wasm").adapt_component(is_component).using_fastly_toml(BAD_13_FASTLY_TOML) {
        Err(e) => assert_eq!("invalid configuration for 'store_one': Invalid `key` value used: Keys for objects cannot contain a `\\u{20}`.", &e.to_string()),
        _ => panic!(),
    }

    Ok(())
});
