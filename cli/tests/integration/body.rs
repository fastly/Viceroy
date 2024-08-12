//! Tests related to HTTP request and response bodies.

use {
    crate::{
        common::{Test, TestResult},
        viceroy_test,
    },
    hyper::{body, StatusCode},
};

viceroy_test!(bodies_can_be_written_and_appended, |is_component| {
    let resp = Test::using_fixture("write-body.wasm")
        .adapt_component(is_component)
        .against_empty()
        .await?;

    let body = body::to_bytes(resp.into_body())
        .await
        .expect("can read body")
        .to_vec();
    let body = String::from_utf8(body)?;
    assert_eq!(&body, "Hello, Viceroy!");

    Ok(())
});

viceroy_test!(bodies_can_be_written_and_read, |is_component| {
    let resp = Test::using_fixture("write-and-read-body.wasm")
        .adapt_component(is_component)
        .against_empty()
        .await?;
    assert_eq!(resp.status(), StatusCode::OK);
    Ok(())
});
