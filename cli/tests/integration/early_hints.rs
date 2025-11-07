// A test to ensure that early hints (103 responses) don't cause errors in Viceroy.

use crate::{
    common::{Test, TestResult},
    viceroy_test,
};

viceroy_test!(early_hints, |is_component| {
    let resp = Test::using_fixture("env-vars.wasm")
        .adapt_component(is_component)
        .against_empty()
        .await?;
    assert!(resp.status().is_success());
    Ok(())
});
