use {
    crate::{
        common::{Error, Test, TestResult},
        viceroy_test,
    },
    hyper::{Body as HyperBody, Request, Response, StatusCode, header::HeaderValue},
    std::time::Duration,
    viceroy_lib::body::Body,
};

viceroy_test!(upstream_sync, |is_component| {
    ////////////////////////////////////////////////////////////////////////////////////
    // Setup
    ////////////////////////////////////////////////////////////////////////////////////

    // Set up the test harness
    let test = Test::using_fixture("pending-req.wasm")
        .adapt_component(is_component)
        // The "origin" backend echos the request body along with several header:
        .backend("origin", "/", None, |req| {
            let mut resp = Response::new(req.into_body());
            let headers = resp.headers_mut();
            headers.insert("a", HeaderValue::from_static("original"));
            headers.insert("b", HeaderValue::from_static("keep"));
            headers.insert("c", HeaderValue::from_static("hidden"));
            resp
        })
        .await;
    test.start_backend_servers().await;

    ////////////////////////////////////////////////////////////////////////////////////
    // Do a round-trip to "origin" without any header manipulation.
    ////////////////////////////////////////////////////////////////////////////////////

    let resp = test
        .against(
            Request::post("/")
                .header("Backend-Name", "origin")
                .body("Hello, Viceroy!")
                .unwrap(),
        )
        .await?;
    let (parts, body) = resp.into_parts();
    assert_eq!(parts.status, StatusCode::OK);
    assert_eq!(
        parts.headers.get_all("a").iter().collect::<Vec<_>>(),
        vec!["original"]
    );
    assert_eq!(
        parts.headers.get_all("b").iter().collect::<Vec<_>>(),
        vec!["keep"]
    );
    assert_eq!(
        parts.headers.get_all("c").iter().collect::<Vec<_>>(),
        vec!["hidden"]
    );
    assert_eq!(body.read_into_string().await?, "Hello, Viceroy!");

    ////////////////////////////////////////////////////////////////////////////////////
    // Do a round-trip to "origin" with basic header manipulation.
    ////////////////////////////////////////////////////////////////////////////////////

    let resp = test
        .against(
            Request::post("/")
                .header("Backend-Name", "origin")
                .header("With-Header-Ops", "insert:a:update1,append:b:new1,remove:c")
                .body("Hello, Viceroy!")
                .unwrap(),
        )
        .await?;
    let (parts, body) = resp.into_parts();
    assert_eq!(parts.status, StatusCode::OK);
    assert_eq!(
        parts.headers.get_all("a").iter().collect::<Vec<_>>(),
        vec!["update1"]
    );
    assert_eq!(
        parts.headers.get_all("b").iter().collect::<Vec<_>>(),
        vec!["keep", "new1"]
    );
    assert_eq!(parts.headers.get_all("c").iter().next(), None);
    assert_eq!(body.read_into_string().await?, "Hello, Viceroy!");

    ////////////////////////////////////////////////////////////////////////////////////
    // Do a round-trip to "origin", and show that the error headers aren't applied.
    ////////////////////////////////////////////////////////////////////////////////////

    let resp = test
        .against(
            Request::post("/")
                .header("Backend-Name", "origin")
                .header("With-Header-Ops", "insert:a:update1,append:b:new1,remove:c")
                .header(
                    "With-Error-Header-Ops",
                    "insert:a:nonexistent,append:b:foo,remove:b",
                )
                .body("Hello, Viceroy!")
                .unwrap(),
        )
        .await?;
    let (parts, body) = resp.into_parts();
    assert_eq!(parts.status, StatusCode::OK);
    assert_eq!(
        parts.headers.get_all("a").iter().collect::<Vec<_>>(),
        vec!["update1"]
    );
    assert_eq!(
        parts.headers.get_all("b").iter().collect::<Vec<_>>(),
        vec!["keep", "new1"]
    );
    assert_eq!(parts.headers.get_all("c").iter().next(), None);
    assert_eq!(body.read_into_string().await?, "Hello, Viceroy!");

    Ok(())
});

/// Send a pending request to the given backend and hand it downstream, applying header
/// operations to the synthetic error response so we can see they still take effect.
async fn send_pending_expecting_error(test: &Test, backend: &str) -> Result<Response<Body>, Error> {
    test.against(
        Request::post("/")
            .header("Backend-Name", backend)
            .header("With-Header-Ops", "insert:a:any")
            .header("With-Error-Header-Ops", "insert:b:error")
            .body("Hello, Viceroy!")
            .unwrap(),
    )
    .await
}

/// Assert that a failed pending request produced the same synthetic response as Fastly Compute:
/// the status's reason phrase as a plain-text body, with the error header operations applied.
async fn assert_synthetic_error_response(resp: Response<Body>, status: StatusCode) -> TestResult {
    let (parts, body) = resp.into_parts();
    assert_eq!(parts.status, status);
    assert_eq!(parts.headers.get("content-type").unwrap(), "text/plain");
    assert_eq!(parts.headers.get("a").unwrap(), "any");
    assert_eq!(parts.headers.get("b").unwrap(), "error");
    assert_eq!(
        body.read_into_string().await?,
        status.canonical_reason().unwrap()
    );
    Ok(())
}

viceroy_test!(pending_req_backend_error, |is_component| {
    // The test server drops the connection without responding when its handler panics, which
    // Viceroy reports as a backend connection error. A bit of a hack but we don't have a way
    // to define a backend that doesn't respond yet.
    let test = Test::using_fixture("pending-req.wasm")
        .adapt_component(is_component)
        .async_backend("origin", "/", None, |_req| {
            Box::new(async { panic!("drop the connection without a response") })
        })
        .await;

    let resp = send_pending_expecting_error(&test, "origin").await?;
    assert_synthetic_error_response(resp, StatusCode::BAD_GATEWAY).await
});

viceroy_test!(pending_req_first_byte_timeout, |is_component| {
    let test = Test::using_fixture("pending-req.wasm")
        .adapt_component(is_component)
        .async_backend_with_timeouts(
            "origin",
            "/",
            None,
            Some(Duration::from_millis(100)),
            None,
            |_req| {
                Box::new(async {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    Response::new(HyperBody::empty())
                })
            },
        )
        .await;

    let resp = send_pending_expecting_error(&test, "origin").await?;
    assert_synthetic_error_response(resp, StatusCode::GATEWAY_TIMEOUT).await
});
