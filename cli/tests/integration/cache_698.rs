//! Regression test for https://github.com/fastly/Viceroy/issues/698: a
//! `transaction_lookup` against a key that already has an open, unresolved
//! handle should return an error immediately (per XQD), not hang forever.
//!
//! `viceroy_test!` has no notion of a deadline, and today this guest does
//! hang, so we bound it with an explicit timeout: a regression fails fast
//! with a clear message instead of stalling the whole suite/CI job.

use crate::common::{Test, TestResult};
use hyper::StatusCode;
use std::time::Duration;

async fn run(is_component: bool) -> TestResult {
    let test = Test::using_fixture("cache_698.wasm").adapt_component(is_component);

    let resp = tokio::time::timeout(Duration::from_secs(2), test.against_empty())
        .await
        .expect("guest hung: transaction_lookup did not return for a key with an open handle (issue #698)")?;
    assert_eq!(resp.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[should_panic(expected = "guest hung: transaction_lookup")]
async fn core_wasm() {
    // should_panic doesn't work with a non-unit return type, so we can't return TestResult here
    run(false).await.expect("received Err")
}

#[tokio::test(flavor = "multi_thread")]
#[should_panic(expected = "guest hung: transaction_lookup")]
async fn component() {
    run(true).await.expect("received Err")
}
