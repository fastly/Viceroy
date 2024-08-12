use crate::{
    common::{Test, TestResult},
    viceroy_test,
};

viceroy_test!(env_vars_are_set, |is_component| {
    let resp = Test::using_fixture("env-vars.wasm")
        .adapt_component(is_component)
        .against_empty()
        .await?;
    assert!(resp.status().is_success());
    Ok(())
});
