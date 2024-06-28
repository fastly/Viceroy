use {
    crate::{
        common::{Test, TestResult},
        viceroy_test,
    },
    hyper::{body::HttpBody, Response, StatusCode},
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
    let mut resp = test.against_empty().await?;
    assert_eq!(resp.status(), StatusCode::OK);

    // accumulate the entire body to a vector
    let mut body = Vec::new();
    while let Some(chunk) = resp.data().await {
        body.extend_from_slice(&chunk?);
    }

    // work with the body as a string, breaking it into lines
    let body_str = String::from_utf8(body).unwrap();
    let mut i: u32 = 0;
    for line in body_str.lines() {
        assert_eq!(line, i.to_string());
        i += 1;
    }
    assert_eq!(i, 1000);

    Ok(())
});
