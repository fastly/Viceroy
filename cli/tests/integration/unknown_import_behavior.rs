use hyper::{Request, Response, StatusCode};
use viceroy_lib::config::UnknownImportBehavior;

use crate::common::{Test, TestResult};

/// A test using the default behavior, where the unknown import will fail to link.
#[tokio::test(flavor = "multi_thread")]
async fn default_behavior_link_failure() -> TestResult {
    let res = Test::using_fixture("unknown-import.wasm")
        .against_empty()
        .await;

    let err = res.expect_err("should be a link failure");
    assert!(err
        .to_string()
        .contains("unknown import: `unknown_module::unknown_function` has not been defined"));

    Ok(())
}

/// A test using the trap behavior, where calling the unknown import will cause a runtime trap.
#[tokio::test(flavor = "multi_thread")]
async fn trap_behavior_function_called() -> TestResult {
    let resp = Test::using_fixture("unknown-import.wasm")
        .using_unknown_import_behavior(UnknownImportBehavior::Trap)
        .against(Request::get("/").header("call-it", "yes").body("").unwrap())
        .await?;

    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body_bytes = hyper::body::to_bytes(resp.into_body()).await?;
    let body = std::str::from_utf8(&body_bytes)?;
    // The backtrace contains things like stack addresses and gensyms, so we just look for a couple
    // key parts that should be relatively stable across invocations and wasmtime
    // versions. Fundamentally though, we're still making assertions based on pretty-printed errors,
    // so beware of trivial breakages.
    assert!(body.contains("error while executing at wasm backtrace"));
    assert!(body.contains("unknown_import::main::"));

    Ok(())
}

/// A test using the trap behavior, where not calling the function means execution proceeds normally.
#[tokio::test(flavor = "multi_thread")]
async fn trap_behavior_function_not_called() -> TestResult {
    let resp = Test::using_fixture("unknown-import.wasm")
        .backend("TheOrigin", "/", None, |_req| {
            Response::builder()
                .status(StatusCode::OK)
                .body(vec![])
                .unwrap()
        })
        .await
        .using_unknown_import_behavior(UnknownImportBehavior::Trap)
        .against_empty()
        .await?;

    assert_eq!(resp.status(), StatusCode::OK);

    Ok(())
}

/// A test using the zero-or-null value behavior, where calling the function returns an expected
/// zero value and execution proceeds normally.
#[tokio::test(flavor = "multi_thread")]
async fn zero_or_null_behavior_function_called() -> TestResult {
    let resp = Test::using_fixture("unknown-import.wasm")
        .backend("TheOrigin", "/", None, |_req| {
            Response::builder()
                .status(StatusCode::OK)
                .body(vec![])
                .unwrap()
        })
        .await
        .using_unknown_import_behavior(UnknownImportBehavior::ZeroOrNull)
        .against(Request::get("/").header("call-it", "yes").body("").unwrap())
        .await?;

    assert_eq!(resp.status(), StatusCode::OK);

    Ok(())
}
