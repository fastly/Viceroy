use crate::common::{Test, TestResult};

#[tokio::test]
async fn env_vars_are_set() -> TestResult {
    let resp = Test::using_fixture("env-vars.wasm").against_empty().await?;
    assert!(resp.status().is_success());
    Ok(())
}
