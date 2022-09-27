use {
    crate::common::{Test, TestResult},
    hyper::{
        header::{self, HeaderValue},
        Request, Response, StatusCode,
    },
};

#[tokio::test(flavor = "multi_thread")]
async fn upstream_sync() -> TestResult {
    ////////////////////////////////////////////////////////////////////////////////////
    // Setup
    ////////////////////////////////////////////////////////////////////////////////////

    // Set up the test harness
    let test = Test::using_fixture("upstream-dynamic.wasm")
        .backend("origin", "http://127.0.0.1:9000/", None)
        // The "origin" backend simply echos the request body
        .host(9000, |req| {
            let body = req.into_body();
            Response::new(body)
        });

    ////////////////////////////////////////////////////////////////////////////////////
    // A simple round-trip echo test to "origin", but with a dynamic backend
    ////////////////////////////////////////////////////////////////////////////////////

    let resp = test
        .against(
            Request::post("http://localhost/")
                .header("Dynamic-Backend", "127.0.0.1:9000")
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
    // Test that you can still use standard backends without a problem
    ////////////////////////////////////////////////////////////////////////////////////

    let resp = test
        .against(
            Request::post("http://localhost/")
                .header("Static-Backend", "origin")
                .body("Hello, Viceroy!")
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.into_body().read_into_string().await?,
        "Hello, Viceroy!"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn override_host_works() -> TestResult {
    // Set up the test harness
    let test = Test::using_fixture("upstream-dynamic.wasm")
        .backend(
            "override-host",
            "http://127.0.0.1:9000/",
            None, // Some("otherhost.com"),
        )
        .host(9000, |req| {
            assert_eq!(
                req.headers().get(header::HOST),
                Some(&HeaderValue::from_static("otherhost.com"))
            );
            Response::new(vec![])
        });

    let resp = test
        .via_hyper()
        .against(
            Request::get("http://localhost:7878/override")
                .header("Dynamic-Backend", "127.0.0.1:9000")
                .header("With-Override", "otherhost.com")
                .body("")
                .unwrap(),
        )
        .await;

    assert_eq!(resp.status(), StatusCode::OK);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn duplication_errors_right() -> TestResult {
    // Set up the test harness
    let test = Test::using_fixture("upstream-dynamic.wasm")
        .backend("static", "http://127.0.0.1:9000/", None)
        .host(9000, |_| Response::new(vec![]));

    let resp = test
        .against(
            Request::get("http://localhost:7878/override")
                .header("Dynamic-Backend", "127.0.0.1:9000")
                .header("Supplementary-Backend", "dynamic-backend")
                .body("")
                .unwrap(),
        )
        .await;

    assert_eq!(resp.status(), StatusCode::CONFLICT);

    let resp = test
        .against(
            Request::get("http://localhost:7878/override")
                .header("Dynamic-Backend", "127.0.0.1:9000")
                .header("Supplementary-Backend", "static")
                .body("")
                .unwrap(),
        )
        .await;

    assert_eq!(resp.status(), StatusCode::CONFLICT);

    Ok(())
}
