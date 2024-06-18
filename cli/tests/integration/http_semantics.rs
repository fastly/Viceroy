//! Tests related to HTTP semantics (e.g. framing headers, status codes).

use {
    crate::common::{Test, TestResult},
    hyper::{header, Request, Response, StatusCode},
};

#[tokio::test(flavor = "multi_thread")]
async fn framing_headers_are_overridden() -> TestResult {
    // Set up the test harness
    let test = Test::using_fixture("bad-framing-headers.wasm")
        // The "TheOrigin" backend checks framing headers on the request and then echos its body.
        .backend("TheOrigin", "/", None, |req| {
            assert!(!req.headers().contains_key(header::TRANSFER_ENCODING));
            assert_eq!(
                req.headers().get(header::CONTENT_LENGTH),
                Some(&hyper::header::HeaderValue::from(9))
            );
            Response::new(Vec::from(&b"salutations"[..]))
        })
        .await;

    let resp = test
        .via_hyper()
        .against(Request::post("/").body("greetings").unwrap())
        .await?;

    assert_eq!(resp.status(), StatusCode::OK);

    assert!(!resp.headers().contains_key(header::TRANSFER_ENCODING));
    assert_eq!(
        resp.headers().get(header::CONTENT_LENGTH),
        Some(&hyper::header::HeaderValue::from(11))
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn content_length_is_computed_correctly() -> TestResult {
    // Set up the test harness
    let test = Test::using_fixture("content-length.wasm")
        // The "TheOrigin" backend supplies a fixed-size body.
        .backend("TheOrigin", "/", None, |_| {
            Response::new(Vec::from(&b"ABCDEFGHIJKLMNOPQRST"[..]))
        })
        .await;

    let resp = test.via_hyper().against_empty().await?;

    assert_eq!(resp.status(), StatusCode::OK);

    assert!(!resp.headers().contains_key(header::TRANSFER_ENCODING));
    assert_eq!(
        resp.headers().get(header::CONTENT_LENGTH),
        Some(&hyper::header::HeaderValue::from(28))
    );
    let resp_body = resp.into_body().read_into_string().await.unwrap();
    assert_eq!(resp_body, "ABCD12345xyzEFGHIJKLMNOPQRST");

    Ok(())
}
