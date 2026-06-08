// A test to ensure that invalid status codes (1xx other than 103 Early Hunts) return errors in Viceroy.

use crate::{
    common::{Test, TestResult},
    viceroy_test,
};

use hyper::StatusCode;

viceroy_test!(invalid_status_code, |is_component| {
    let resp = Test::using_fixture("invalid-status-code.wasm")
        .adapt_component(is_component)
        .against_empty()
        .await?;
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    Ok(())
});
