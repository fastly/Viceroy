use crate::{common::Test, common::TestResult, viceroy_test};
use hyper::{StatusCode, body::to_bytes};
use viceroy_lib::config::FastlyConfig;
use viceroy_lib::error::{AclConfigError, FastlyConfigError};

viceroy_test!(acl_works, |is_component| {
    const FASTLY_TOML: &str = r#"
        name = "acl"
        description = "acl test"
        authors = ["Test User <test_user@fastly.com>"]
        language = "rust"
        [local_server]
        acls.my-acl-1 = "../test-fixtures/data/my-acl-1.json"
        acls.my-acl-2 = {file = "../test-fixtures/data/my-acl-2.json"}
    "#;

    let resp = Test::using_fixture("acl.wasm")
        .adapt_component(is_component)
        .using_fastly_toml(FASTLY_TOML)?
        .log_stderr()
        .log_stdout()
        .against_empty()
        .await?;

    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        to_bytes(resp.into_body())
            .await
            .expect("can read body")
            .to_vec()
            .is_empty()
    );

    Ok(())
});

fn bad_config_test(local_server_fragment: &str) -> Result<FastlyConfig, FastlyConfigError> {
    let toml = format!(
        r#"
        name = "acl"
        description = "acl test"
        authors = ["Test User <test_user@fastly.com>"]
        language = "rust"
        [local_server]
        {}
    "#,
        local_server_fragment
    );

    toml.parse::<FastlyConfig>()
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_config_invalid_path() -> TestResult {
    const TOML_FRAGMENT: &str = "acls.bad = 1";
    match bad_config_test(TOML_FRAGMENT) {
        Err(FastlyConfigError::InvalidAclDefinition {
            err: AclConfigError::InvalidType,
            ..
        }) => (),
        Err(_) => panic!(
            "expected a FastlyConfigError::InvalidAclDefinition with AclConfigError::InvalidType"
        ),
        _ => panic!("Expected an error"),
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_config_missing_key() -> TestResult {
    const TOML_FRAGMENT: &str = "acls.bad = { \"other\" = true }";
    match bad_config_test(TOML_FRAGMENT) {
        Err(FastlyConfigError::InvalidAclDefinition {
            err: AclConfigError::MissingFile,
            ..
        }) => (),
        Err(_) => panic!(
            "expected a FastlyConfigError::InvalidAclDefinition with AclConfigError::MissingFile"
        ),
        _ => panic!("Expected an error"),
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_config_missing_file() -> TestResult {
    const TOML_FRAGMENT: &str = "acls.bad = \"/does/not/exist\"";
    match bad_config_test(TOML_FRAGMENT) {
        Err(FastlyConfigError::InvalidAclDefinition {
            err: AclConfigError::IoError(_),
            ..
        }) => (),
        Err(_) => panic!(
            "expected a FastlyConfigError::InvalidAclDefinition with AclConfigError::IoError"
        ),
        _ => panic!("Expected an error"),
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_config_invalid_json() -> TestResult {
    const TOML_FRAGMENT: &str = "acls.bad = \"../Cargo.toml\"";
    match bad_config_test(TOML_FRAGMENT) {
        Err(FastlyConfigError::InvalidAclDefinition {
            err: AclConfigError::JsonError(_),
            ..
        }) => (),
        Err(_) => panic!(
            "expected a FastlyConfigError::InvalidAclDefinition with AclConfigError::JsonError"
        ),
        _ => panic!("Expected an error"),
    }
    Ok(())
}
