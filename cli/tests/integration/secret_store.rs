use crate::{
    common::{Test, TestResult},
    viceroy_test,
};
use hyper::{body::to_bytes, StatusCode};
use viceroy_lib::config::FastlyConfig;
use viceroy_lib::error::{FastlyConfigError, SecretStoreConfigError};

viceroy_test!(secret_store_works, |is_component| {
    const FASTLY_TOML: &str = r#"
        name = "secret-store"
        description = "secret store test"
        authors = ["Jill Bryson <jbryson@fastly.com>", "Rose McDowall <rmcdowall@fastly.com>"]
        language = "rust"
        [local_server]
        secret_stores.store_one = [{key = "first", data = "This is some data"},{key = "second", file = "../test-fixtures/data/kv-store.txt"}]
    "#;

    let resp = Test::using_fixture("secret-store.wasm")
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

fn bad_config_test(toml_fragment: &str) -> Result<FastlyConfig, FastlyConfigError> {
    let toml = format!(
        r#"
        name = "secret-store"
        description = "secret store test"
        authors = ["Jill Bryson <jbryson@fastly.com>", "Rose McDowall <rmcdowall@fastly.com>"]
        language = "rust"
        [local_server]
        {}
    "#,
        toml_fragment
    );

    println!("TOML: {}", toml);
    toml.parse::<FastlyConfig>()
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_config_store_not_array() -> TestResult {
    const TOML_FRAGMENT: &str = "secret_stores.store_one = 1";
    match bad_config_test(TOML_FRAGMENT) {
        Err(FastlyConfigError::InvalidSecretStoreDefinition {
            err: SecretStoreConfigError::NotAnArray,
            ..
        }) => (),
        Err(_) => panic!("Expected a FastlyConfigError::InvalidSecretStoreDefinition with SecretStoreConfigError::NotAnArray"),
        _ => panic!("Expected an error"),
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_config_store_not_table() -> TestResult {
    const TOML_FRAGMENT: &str = "secret_stores.store_one = [1]";
    match bad_config_test(TOML_FRAGMENT) {
        Err(FastlyConfigError::InvalidSecretStoreDefinition {
            err: SecretStoreConfigError::NotATable,
            ..
        }) => (),
        Err(_) => panic!("Expected a FastlyConfigError::InvalidSecretStoreDefinition with SecretStoreConfigError::NotATable"),
        _ => panic!("Expected an error"),
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_config_no_key() -> TestResult {
    const TOML_FRAGMENT: &str = r#"secret_stores.store_one = [{data = "This is some data"}]"#;
    match bad_config_test(TOML_FRAGMENT) {
        Err(FastlyConfigError::InvalidSecretStoreDefinition {
            err: SecretStoreConfigError::NoKey,
            ..
        }) => (),
        Err(_) => panic!("Expected a FastlyConfigError::InvalidSecretStoreDefinition with SecretStoreConfigError::NoKey"),
        _ => panic!("Expected an error"),
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_config_key_not_string() -> TestResult {
    const TOML_FRAGMENT: &str =
        r#"secret_stores.store_one = [{key = 1, data = "This is some data"}]"#;
    match bad_config_test(TOML_FRAGMENT) {
        Err(FastlyConfigError::InvalidSecretStoreDefinition {
            err: SecretStoreConfigError::KeyNotAString,
            ..
        }) => (),
        Err(_) => panic!("Expected a FastlyConfigError::InvalidSecretStoreDefinition with SecretStoreConfigError::KeyNotAString"),
        _ => panic!("Expected an error"),
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_config_no_data_or_file() -> TestResult {
    const TOML_FRAGMENT: &str = r#"secret_stores.store_one = [{key = "first"}]"#;
    match bad_config_test(TOML_FRAGMENT) {
        Err(FastlyConfigError::InvalidSecretStoreDefinition {
            err: SecretStoreConfigError::NoFileOrData(_),
            ..
        }) => (),
        Err(_) => panic!("Expected a FastlyConfigError::InvalidSecretStoreDefinition with SecretStoreConfigError::NoFileOrData"),
        _ => panic!("Expected an error"),
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_config_both_data_and_file() -> TestResult {
    const TOML_FRAGMENT: &str = r#"secret_stores.store_one = [{key = "first", file = "file.txt", data = "This is some data"}]"#;
    match bad_config_test(TOML_FRAGMENT) {
        Err(FastlyConfigError::InvalidSecretStoreDefinition {
            err: SecretStoreConfigError::FileAndData(_),
            ..
        }) => (),
        Err(_) => panic!("Expected a FastlyConfigError::InvalidSecretStoreDefinition with SecretStoreConfigError::FileAndData"),
        _ => panic!("Expected an error"),
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_config_data_not_string() -> TestResult {
    const TOML_FRAGMENT: &str = r#"secret_stores.store_one = [{key = "first", data = 1}]"#;
    match bad_config_test(TOML_FRAGMENT) {
        Err(FastlyConfigError::InvalidSecretStoreDefinition {
            err: SecretStoreConfigError::DataNotAString(_),
            ..
        }) => (),
        Err(_) => panic!("Expected a FastlyConfigError::InvalidSecretStoreDefinition with SecretStoreConfigError::DataNotAString"),
        _ => panic!("Expected an error"),
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_config_file_not_string() -> TestResult {
    const TOML_FRAGMENT: &str = r#"secret_stores.store_one = [{key = "first", file = 1}]"#;
    match bad_config_test(TOML_FRAGMENT) {
        Err(FastlyConfigError::InvalidSecretStoreDefinition {
            err: SecretStoreConfigError::FileNotAString(_),
            ..
        }) => (),
        Err(_) => panic!("Expected a FastlyConfigError::InvalidSecretStoreDefinition with SecretStoreConfigError::FileNotAString"),
        _ => panic!("Expected an error"),
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_config_file_nonexistent() -> TestResult {
    const TOML_FRAGMENT: &str =
        r#"secret_stores.store_one = [{key = "first", file = "nonexistent.txt"}]"#;
    match bad_config_test(TOML_FRAGMENT) {
        Err(FastlyConfigError::InvalidSecretStoreDefinition {
            err: SecretStoreConfigError::IoError(_),
            ..
        }) => (),
        Err(_) => panic!("Expected a FastlyConfigError::InvalidSecretStoreDefinition with SecretStoreConfigError::IoError"),
        _ => panic!("Expected an error"),
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_config_invalid_store_name() -> TestResult {
    const TOML_FRAGMENT: &str =
        r#"secret_stores.store*one = [{key = "first", data = "This is some data"}]"#;
    match bad_config_test(TOML_FRAGMENT) {
        Err(FastlyConfigError::InvalidFastlyToml(_)) => (),
        Err(_) => panic!("Expected a FastlyConfigError::InvalidFastlyToml"),
        _ => panic!("Expected an error"),
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_config_invalid_secret_name() -> TestResult {
    const TOML_FRAGMENT: &str =
        r#"secret_stores.store_one = [{key = "first*", data = "This is some data"}]"#;
    match bad_config_test(TOML_FRAGMENT) {
        Err(FastlyConfigError::InvalidSecretStoreDefinition {
            err: SecretStoreConfigError::InvalidSecretName(_),
            ..
        }) => (),
        Err(_) => panic!("Expected a FastlyConfigError::InvalidSecretStoreDefinition with SecretStoreConfigError::InvalidSecretName"),
        _ => panic!("Expected an error"),
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_config_secret_name_too_long() -> TestResult {
    const TOML_FRAGMENT: &str = r#"secret_stores.store_one = [{key = "firstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirstfirst", data = "This is some data"}]"#;
    match bad_config_test(TOML_FRAGMENT) {
        Err(FastlyConfigError::InvalidSecretStoreDefinition {
            err: SecretStoreConfigError::InvalidSecretName(_),
            ..
        }) => (),
        Err(_) => panic!("Expected a FastlyConfigError::InvalidSecretStoreDefinition with SecretStoreConfigError::InvalidSecretName"),
        _ => panic!("Expected an error"),
    }
    Ok(())
}
