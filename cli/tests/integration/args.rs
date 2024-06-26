use crate::common::{Test, TestResult};
use hyper::{body::to_bytes, StatusCode};

/// Run a program that tests its args. This checks that we're populating the argument list with the
/// singleton "compute-app" value.
/// Check that an empty response is sent downstream by default.
///
/// `args.wasm` is a guest program checks its cli args.
#[tokio::test(flavor = "multi_thread")]
async fn empty_ok_response_by_default_after_args() -> TestResult {
    let resp = Test::using_fixture("args.wasm").against_empty().await?;

    assert_eq!(resp.status(), StatusCode::OK);
    assert!(to_bytes(resp.into_body())
        .await
        .expect("can read body")
        .to_vec()
        .is_empty());

    Ok(())
}

/// Run a program that tests its args. This checks that we're populating the argument list with the
/// singleton "compute-app" value.
/// Check that an empty response is sent downstream by default.
///
/// `args.wasm` is a guest program checks its cli args.
#[tokio::test(flavor = "multi_thread")]
async fn empty_ok_response_by_default_after_args_component() {
    let resp = Test::using_fixture("args.wasm")
        .adapt_component(true)
        .against_empty()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert!(to_bytes(resp.into_body())
        .await
        .expect("can read body")
        .to_vec()
        .is_empty());
}
