use {
    crate::{
        common::{Test, TestResult},
        viceroy_test,
    },
    hyper::{Request, StatusCode},
};

viceroy_test!(upstream_sync, |is_component| {
    // Set up the test harness:
    let test = Test::using_fixture("inspect.wasm").adapt_component(is_component);

    // And send a request to exercise the hostcall:
    let resp = test
        .against(Request::post("/").body("Hello, Viceroy!").unwrap())
        .await?;

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.into_body().read_into_string().await?,
        "inspect result: waf_response=200, tags=[], decision_ms=0ms, verdict=Allow"
    );

    Ok(())
});
