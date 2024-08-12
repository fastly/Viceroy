use crate::{
    common::{Test, TestResult},
    viceroy_test,
};
use hyper::body::to_bytes;
use hyper::{Request, StatusCode};

viceroy_test!(direct_wasm_works, |is_component| {
    let resp = Test::using_wat_fixture("return_ok.wat")
        .adapt_component(is_component)
        .against_empty()
        .await?;
    assert_eq!(resp.status(), StatusCode::OK);
    Ok(())
});

viceroy_test!(heap_limit_test_ok, |is_component| {
    let resp = Test::using_wat_fixture("combined_heap_limits.wat")
        .adapt_component(is_component)
        .against(
            Request::get("/")
                .header("guest-kb", "235")
                .header("header-kb", "1")
                .header("body-kb", "16")
                .body("")
                .unwrap(),
        )
        .await?;
    println!("response: {:?}", resp);
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers().len(), 16);
    assert!(resp.headers().contains_key("x-test-header-3"));
    assert_eq!(
        resp.headers().get("x-test-header-12").unwrap(),
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit viverra."
    );
    let body = resp.into_body();
    assert_eq!(to_bytes(body).await.unwrap().len(), 16 * 1024);
    Ok(())
});

viceroy_test!(heap_limit_test_bad, |is_component| {
    let resp = Test::using_wat_fixture("combined_heap_limits.wat")
        .adapt_component(is_component)
        .against(
            Request::get("/")
                .header("guest-kb", "150000")
                .body("")
                .unwrap(),
        )
        .await?;
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    Ok(())
});
