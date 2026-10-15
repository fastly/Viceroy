//! Tests that Core Cache bodies sent to the client are framed like production Compute:
//! with `Content-Length` when the length is known up front, and chunked otherwise.

use {
    crate::{
        common::{Error, Test, TestResult},
        viceroy_test,
    },
    hyper::{Request, Response, StatusCode, header},
    viceroy_lib::body::Body,
};

const LENGTH: usize = 5000;

fn contents() -> Vec<u8> {
    (0..LENGTH).map(|i| (i % 251) as u8).collect()
}

async fn get(is_component: bool, path: &str) -> Result<Response<Body>, Error> {
    let resp = Test::using_fixture("cache-framing.wasm")
        .adapt_component(is_component)
        .via_hyper()
        .against(Request::get(path).body("").unwrap())
        .await?;
    assert_eq!(resp.status(), StatusCode::OK);
    Ok(resp)
}

/// Check the response has `Content-Length: want.len()`, no `Transfer-Encoding`, and the body `want`.
async fn assert_content_length(resp: Response<Body>, want: &[u8]) -> TestResult {
    assert!(!resp.headers().contains_key(header::TRANSFER_ENCODING));
    assert_eq!(
        resp.headers().get(header::CONTENT_LENGTH),
        Some(&hyper::header::HeaderValue::from(want.len()))
    );
    let got = resp.into_body().read_into_vec().await?;
    assert_eq!(got, want);
    Ok(())
}

viceroy_test!(cache_body_full_has_content_length, |is_component| {
    let resp = get(is_component, "/full").await?;
    assert_content_length(resp, &contents()).await
});

viceroy_test!(
    cache_body_complete_unknown_length_has_content_length,
    |is_component| {
        let resp = get(is_component, "/full-unknown-length").await?;
        assert_content_length(resp, &contents()).await
    }
);

viceroy_test!(cache_body_range_has_content_length, |is_component| {
    let resp = get(is_component, "/range").await?;
    assert_content_length(resp, &contents()[100..200]).await
});

viceroy_test!(cache_body_open_range_has_content_length, |is_component| {
    let resp = get(is_component, "/open-range").await?;
    assert_content_length(resp, &contents()[4990..]).await
});

viceroy_test!(
    cache_body_streaming_known_length_has_content_length,
    |is_component| {
        let resp = get(is_component, "/streaming-known-length").await?;
        assert_content_length(resp, &contents()).await
    }
);

viceroy_test!(
    cache_body_streaming_unknown_length_is_chunked,
    |is_component| {
        let resp = get(is_component, "/streaming-unknown-length").await?;
        assert!(!resp.headers().contains_key(header::CONTENT_LENGTH));
        assert_eq!(
            resp.headers().get(header::TRANSFER_ENCODING),
            Some(&hyper::header::HeaderValue::from_static("chunked"))
        );
        let got = resp.into_body().read_into_vec().await?;
        assert_eq!(got, contents());
        Ok(())
    }
);

viceroy_test!(cache_body_truncated_is_incomplete, |is_component| {
    // Depending on how far the insert got before it was abandoned, the connection is cut off
    // either before the headers are sent or partway through the body. Either way, the client
    // must not see a complete response.
    let Ok(resp) = Test::using_fixture("cache-framing.wasm")
        .adapt_component(is_component)
        .via_hyper()
        .against(Request::get("/truncated").body("").unwrap())
        .await
    else {
        return Ok(());
    };
    assert_eq!(
        resp.headers().get(header::CONTENT_LENGTH),
        Some(&hyper::header::HeaderValue::from(LENGTH))
    );
    assert!(resp.into_body().read_into_vec().await.is_err());
    Ok(())
});

viceroy_test!(cache_body_appended_has_summed_length, |is_component| {
    let resp = get(is_component, "/append").await?;
    let mut want = b"prefix".to_vec();
    want.extend(contents());
    assert_content_length(resp, &want).await
});

viceroy_test!(cache_body_guest_known_length, |is_component| {
    let resp = get(is_component, "/guest-known-length").await?;
    assert_content_length(resp, &contents()).await
});
