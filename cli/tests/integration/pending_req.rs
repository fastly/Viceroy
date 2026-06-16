use {
    crate::{
        common::{Test, TestResult},
        viceroy_test,
    },
    hyper::{Request, Response, StatusCode, header::HeaderValue},
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
