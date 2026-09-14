//! Regression tests for the cache-handle ownership family, starting with
//! https://github.com/fastly/Viceroy/issues/696: which resource owns a cache `AsyncItem`, and
//! what is allowed to free it.
//!
//! One scenario per request path, all served by `cache-step-pollable.wasm`.

use hyper::{Request, StatusCode};

use crate::common::{Error, Test, TestResult};

async fn run_scenario(path: &str) -> Result<String, Error> {
    // fixture is always a component - no need to adapt
    let resp = Test::using_p2_fixture("cache-step-pollable.wasm")
        .against(Request::get(path).body("")?)
        .await?;
    assert_eq!(resp.status(), StatusCode::OK);
    Ok(resp.into_body().read_into_string().await?)
}

/// `cache.entry.step`'s pollable borrows the entry, so dropping it must leave the entry usable.
#[tokio::test(flavor = "multi_thread")]
async fn test_step_pollable_drop_keeps_entry() -> TestResult {
    let out = run_scenario("/step-pollable-drop").await?;
    assert!(
        out.starts_with("get-state succeeded"),
        "entry.step pollable drop freed the entry: {out}"
    );
    Ok(())
}

/// `cache.pending-entry` *is* an `async-io.pollable` and has no second owner, so dropping it
/// must cancel the pending transaction and hand the go-get obligation to a collapsed waiter.
#[tokio::test(flavor = "multi_thread")]
async fn test_pending_entry_drop_cancels_transaction() -> TestResult {
    let out = run_scenario("/pending-entry-drop").await?;
    assert_eq!(
        out, "pending-entry drop cancelled",
        "pending-entry drop did not cancel the transaction"
    );
    Ok(())
}

/// Dropping a `cache.entry` resource without `cache.close-entry` must release the go-get
/// obligation, matching Compute@Edge, whose `HostEntry::drop` frees the entry as a backstop.
/// Without it the entry and it's obligation survive until sandbox teardown, meaning
/// collapsed waiter for the same key never wakes.
#[tokio::test(flavor = "multi_thread")]
async fn test_entry_drop_releases_obligation() -> TestResult {
    let out = run_scenario("/entry-drop").await?;
    assert_eq!(
        out, "entry drop released the obligation",
        "abandoned entry kept the obligation"
    );
    Ok(())
}
