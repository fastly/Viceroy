use {
    crate::{
        common::{Test, TestResult},
        viceroy_test,
    },
    hyper::StatusCode,
};

viceroy_test!(request_works, |is_component| {
    let resp = Test::using_fixture("request.wasm")
        .adapt_component(is_component)
        .against_empty()
        .await?;
    assert_eq!(resp.status(), StatusCode::OK);
    Ok(())
});
