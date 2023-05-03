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
        // The "origin" backend simply echos the request body
        .backend("origin", "/", None, |req| {
            let body = req.into_body();
            Response::new(body)
        })
        .await;

    ////////////////////////////////////////////////////////////////////////////////////
    // A simple round-trip echo test to "origin", but with a dynamic backend
    ////////////////////////////////////////////////////////////////////////////////////

    // Make sure the backends are started so we can know where to direct the requests
    test.start_backend_servers().await;
    let backend_uri = test.uri_for_backend_server("origin").await;

    let resp = test
        .against(
            Request::post("/")
                .header("Dynamic-Backend", backend_uri.authority().unwrap().as_str())
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
            Request::post("/")
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
            "/",
            None, // Some("otherhost.com"),
            |req| {
                assert_eq!(
                    req.headers().get(header::HOST),
                    Some(&HeaderValue::from_static("otherhost.com"))
                );
                Response::new(vec![])
            },
        )
        .await;
    // Make sure the backends are started so we can know where to direct the request
    test.start_backend_servers().await;
    let backend_uri = test.uri_for_backend_server("override-host").await;

    let resp = test
        .via_hyper()
        .against(
            Request::get("/override")
                .header("Dynamic-Backend", backend_uri.authority().unwrap().as_str())
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
        .backend("static", "/", None, |_| Response::new(vec![]))
        .await;
    // Make sure the backends are started so we can know where to direct the request
    test.start_backend_servers().await;
    let backend_uri = test.uri_for_backend_server("static").await;
    let backend_authority = backend_uri.authority().unwrap().as_str();

    let resp = test
        .against(
            Request::get("/override")
                .header("Dynamic-Backend", backend_authority)
                .header("Supplementary-Backend", "dynamic-backend")
                .body("")
                .unwrap(),
        )
        .await;

    assert_eq!(resp.status(), StatusCode::CONFLICT);

    let resp = test
        .against(
            Request::get("/override")
                .header("Dynamic-Backend", backend_authority)
                .header("Supplementary-Backend", "static")
                .body("")
                .unwrap(),
        )
        .await;

    assert_eq!(resp.status(), StatusCode::CONFLICT);

    Ok(())
}
