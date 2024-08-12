//! Tests related to HTTP request and response bodies.

use {
    crate::{
        common::{Test, TestResult},
        viceroy_test,
    },
    hyper::StatusCode,
};

viceroy_test!(check_hostcalls_implemented, |is_component| {
    let resp = Test::using_fixture("edge-rate-limiting.wasm")
        .adapt_component(is_component)
        .against_empty()
        .await?;
    assert_eq!(resp.status(), StatusCode::OK);
    Ok(())
});
