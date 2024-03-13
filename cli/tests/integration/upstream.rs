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
    let test = Test::using_fixture("upstream.wasm")
        // The "origin" backend simply echos the request body
        .backend("origin", "/", None, |req| {
            let body = req.into_body();
            Response::new(body)
        })
        .await
        // The "prefix-*" backends return the request URL as the response body
        .backend("prefix-hello", "/hello", None, |req| {
            let body = req.uri().to_string().into_bytes();
            Response::new(body)
        })
        .await
        .backend("prefix-hello-slash", "/hello/", None, |req| {
            let body = req.uri().to_string().into_bytes();
            Response::new(body)
        })
        .await;

    ////////////////////////////////////////////////////////////////////////////////////
    // A simple round-trip echo test to "origin"
    ////////////////////////////////////////////////////////////////////////////////////

    let resp = test
        .against(
            Request::post("/")
                .header("Viceroy-Backend", "origin")
                .body("Hello, Viceroy!")
                .unwrap(),
        )
        .await?;
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
            Request::get("/")
                .header("Viceroy-Backend", "prefix-hello")
                .body("")
                .unwrap(),
        )
        .await?;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.into_body().read_into_string().await?, "/hello/");

    let resp = test
        .against(
            Request::get("/")
                .header("Viceroy-Backend", "prefix-hello-slash")
                .body("")
                .unwrap(),
        )
        .await?;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.into_body().read_into_string().await?, "/hello/");

    let resp = test
        .against(
            Request::get("/greeting.html")
                .header("Viceroy-Backend", "prefix-hello")
                .body("")
                .unwrap(),
        )
        .await?;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.into_body().read_into_string().await?,
        "/hello/greeting.html"
    );

    let resp = test
        .against(
            Request::get("/greeting.html")
                .header("Viceroy-Backend", "prefix-hello-slash")
                .body("")
                .unwrap(),
        )
        .await?;
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
            Request::get("/greeting.html")
                .header("Viceroy-Backend", "nonsense")
                .body("")
                .unwrap(),
        )
        .await?;
    assert!(resp.status().is_server_error());

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn override_host_works() -> TestResult {
    // Set up the test harness
    let test = Test::using_fixture("upstream.wasm")
        .backend("override-host", "/", Some("otherhost.com"), |req| {
            assert_eq!(
                req.headers().get(header::HOST),
                Some(&HeaderValue::from_static("otherhost.com"))
            );
            Response::new(vec![])
        })
        .await;

    let resp = test
        .via_hyper()
        .against(
            Request::get("/override")
                .header("Viceroy-Backend", "override-host")
                .body("")
                .unwrap(),
        )
        .await?;

    assert_eq!(resp.status(), StatusCode::OK);

    Ok(())
}

/// Test that we can transparently gunzip responses when required.
#[tokio::test(flavor = "multi_thread")]
async fn transparent_gunzip() -> TestResult {
    let resp = Test::using_fixture("gzipped-response.wasm")
        .backend("echo", "/", None, |mut req| {
            let mut response_builder = Response::builder();

            for (key, value) in req.headers_mut().drain() {
                if let Some(real_key) = key {
                    response_builder = response_builder.header(real_key, value);
                }
            }

            response_builder
                .status(StatusCode::OK)
                .body(req.into_body())
                .unwrap()
        })
        .await
        .against_empty()
        .await?;

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        "hello, world!\n",
        resp.into_body().read_into_string().await.unwrap()
    );

    Ok(())
}
