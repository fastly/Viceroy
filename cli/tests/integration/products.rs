use {
    crate::{
        common::{Test, TestResult},
        viceroy_test,
    },
    hyper::{Request, StatusCode},
};

viceroy_test!(products_are_reported_disabled, |is_component| {
    let req = Request::get("/").body("Hello, world!")?;
    let resp = Test::using_fixture("products.wasm")
        .adapt_component(is_component)
        .against(req)
        .await?;

    assert_eq!(resp.status(), StatusCode::OK);
    Ok(())
});
