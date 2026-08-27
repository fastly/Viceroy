use {
    crate::{
        common::{Test, TestResult},
        viceroy_test,
    },
    hyper::{Request, Response, StatusCode},
};

viceroy_test!(backend_accessors_report_configuration, |is_component| {
    let test = Test::using_fixture("backend-introspection.wasm")
        .adapt_component(is_component)
        .backend("origin", "/", Some("otherhost.com"), |_| {
            Response::new(Vec::new())
        })
        .await;

    test.start_backend_servers().await;
    let backend_uri = test.uri_for_backend_server("origin").await;
    let authority = backend_uri.authority().expect("backend uri has authority");

    let resp = test
        .against(Request::get("/").body("").unwrap())
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK);

    let body = std::str::from_utf8(&hyper::body::to_bytes(resp.into_body()).await?)
        .expect("body is valid UTF-8")
        .to_owned();

    assert_eq!(
        body,
        format!(
            "host={}\nport={}\nis_ssl=false\noverride_host=otherhost.com\n",
            authority.host(),
            authority.port_u16().expect("backend uri has a port"),
        )
    );

    Ok(())
});
