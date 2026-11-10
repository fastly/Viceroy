use {
    crate::{
        common::{Test, TestResult},
        viceroy_test,
    },
    hyper::{Response, StatusCode},
};

// Test that guests can stream a body into an upstream request.
viceroy_test!(upstream_streaming, |is_component| {
    // Set up the test harness
    let test = Test::using_fixture("upstream-streaming.wasm")
        .adapt_component(is_component)
        // The "origin" backend simply echos the request body
        .backend("origin", "/", None, |req| Response::new(req.into_body()))
        .await;

    // Test with an empty request
    let resp = test.against_empty().await?;
    assert_eq!(resp.status(), StatusCode::OK);

    // work with the body as a string, breaking it into lines
    let body_str = resp
        .into_body()
        .read_into_string()
        .await
        .expect("can read body");
    let mut i: u32 = 0;
    for line in body_str.lines() {
        assert_eq!(line, i.to_string());
        i += 1;
    }
    assert_eq!(i, 1000);

    Ok(())
});
