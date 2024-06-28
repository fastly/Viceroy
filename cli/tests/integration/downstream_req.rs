use {
    crate::{
        common::{Test, TestResult},
        viceroy_test,
    },
    hyper::{Request, StatusCode},
};

viceroy_test!(downstream_request_works, |is_component| {
    let req = Request::get("/")
        .header("Accept", "text/html")
        .header("X-Custom-Test", "abcdef")
        .body("Hello, world!")?;
    let resp = Test::using_fixture("downstream-req.wasm")
        .adapt_component(is_component)
        .against(req)
        .await?;

    assert_eq!(resp.status(), StatusCode::OK);
    Ok(())
});
