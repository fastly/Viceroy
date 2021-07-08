mod common;

use {
    common::{Test, TestResult},
    hyper::{Request, Response, StatusCode},
};

#[tokio::test(flavor = "multi_thread")]
async fn upstream_sync() -> TestResult {
    ////////////////////////////////////////////////////////////////////////////////////
    // Setup
    ////////////////////////////////////////////////////////////////////////////////////

    // Set up the test harness
    let test = Test::using_fixture("upstream.wasm")
        .backend("origin", "http://127.0.0.1:9000/")
        // The "origin" backend simply echos the request body
        .host(9000, |req| {
            let body = req.into_body();
            Response::new(body)
        })
        // The "prefix-*" backends return the request URL as the response body
        .backend("prefix-hello", "http://127.0.0.1:9001/hello")
        .backend("prefix-hello-slash", "http://127.0.0.1:9001/hello/")
        .host(9001, |req| {
            let body = req.uri().to_string().into_bytes();
            Response::new(body)
        });

    ////////////////////////////////////////////////////////////////////////////////////
    // A simple round-trip echo test to "origin"
    ////////////////////////////////////////////////////////////////////////////////////

    let resp = test
        .against(
            Request::post("http://localhost/")
                .header("Viceroy-Backend", "origin")
                .body("Hello, Viceroy!")
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.into_body().read_into_string().await?,
        "Hello, Viceroy!"
    );

    ////////////////////////////////////////////////////////////////////////////////////
    // A variety of tests of prefixes and requested URLs, to check that the URL prefix is
    // stitched in properly
    ////////////////////////////////////////////////////////////////////////////////////

    let resp = test
        .against(
            Request::get("http://localhost/")
                .header("Viceroy-Backend", "prefix-hello")
                .body("")
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.into_body().read_into_string().await?, "/hello/");

    let resp = test
        .against(
            Request::get("http://localhost/")
                .header("Viceroy-Backend", "prefix-hello-slash")
                .body("")
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.into_body().read_into_string().await?, "/hello/");

    let resp = test
        .against(
            Request::get("http://localhost/greeting.html")
                .header("Viceroy-Backend", "prefix-hello")
                .body("")
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.into_body().read_into_string().await?,
        "/hello/greeting.html"
    );

    let resp = test
        .against(
            Request::get("http://localhost/greeting.html")
                .header("Viceroy-Backend", "prefix-hello-slash")
                .body("")
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.into_body().read_into_string().await?,
        "/hello/greeting.html"
    );

    ////////////////////////////////////////////////////////////////////////////////////
    // Test that non-existent backends produce an error
    ////////////////////////////////////////////////////////////////////////////////////

    let resp = test
        .against(
            Request::get("http://localhost/greeting.html")
                .header("Viceroy-Backend", "nonsense")
                .body("")
                .unwrap(),
        )
        .await;
    assert!(resp.status().is_server_error());

    Ok(())
}
