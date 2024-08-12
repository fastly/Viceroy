//! Tests related to sending HTTP responses downstream.

use {
    crate::{
        common::{Test, TestResult},
        viceroy_test,
    },
    hyper::{
        body::{to_bytes, HttpBody},
        StatusCode,
    },
};

// Use the `teapot-status` fixture to check that responses can be sent downstream by the guest.
//
// `teapot-status.wasm` will create a [`418 I'm a teapot`][tea] response, per [RFC2324][rfc]. This
// status code is used to clearly indicate that a response came from the guest program.
//
// [rfc]: https://tools.ietf.org/html/rfc2324
// [tea]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/418
viceroy_test!(responses_can_be_sent_downstream, |is_component| {
    let resp = Test::using_fixture("teapot-status.wasm")
        .adapt_component(is_component)
        .against_empty()
        .await?;
    assert_eq!(resp.status(), StatusCode::IM_A_TEAPOT);
    Ok(())
});

// Run a program that does nothing, to check that an empty response is sent downstream by default.
//
// `noop.wasm` is an empty guest program. This exists to show that if no response is sent
// downstream by the guest, a [`200 OK`][ok] response will be sent.
//
// [ok]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/200
viceroy_test!(empty_ok_response_by_default, |is_component| {
    let resp = Test::using_fixture("noop.wasm")
        .adapt_component(is_component)
        .against_empty()
        .await?;

    assert_eq!(resp.status(), StatusCode::OK);
    assert!(to_bytes(resp.into_body())
        .await
        .expect("can read body")
        .to_vec()
        .is_empty());

    Ok(())
});

// Run a program that panics, to check that a [`500 Internal Server Error`][err] response is sent
// downstream.
//
// [err]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/500
viceroy_test!(five_hundred_when_guest_panics, |is_component| {
    let resp = Test::using_fixture("panic.wasm")
        .adapt_component(is_component)
        .against_empty()
        .await?;
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    Ok(())
});

// Test that gradually writing to a streaming body works.
viceroy_test!(responses_can_be_streamed_downstream, |is_component| {
    let mut resp = Test::using_fixture("streaming-response.wasm")
        .adapt_component(is_component)
        .via_hyper()
        .against_empty()
        .await?;

    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp
        .headers()
        .contains_key(hyper::header::TRANSFER_ENCODING));
    assert!(!resp.headers().contains_key(hyper::header::CONTENT_LENGTH));

    // accumulate the entire body to a vector
    let mut body = Vec::new();
    while let Some(chunk) = resp.data().await {
        body.extend_from_slice(&chunk.unwrap());
    }

    // work with the body as a string, breaking it into lines
    let body_str = String::from_utf8(body).unwrap();
    let mut i: u32 = 0;
    for line in body_str.lines() {
        assert_eq!(line, i.to_string());
        i += 1;
    }
    assert_eq!(i, 1000);

    Ok(())
});
