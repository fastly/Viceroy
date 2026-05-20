use crate::common::{Test, TestResult};
use crate::viceroy_test;
use futures::stream::StreamExt;
use hyper::{Request, Response, StatusCode};
use std::time::Duration;
use viceroy_lib::Error;

fn generate_delaying_service(
    first_byte_delay: Duration,
    between_bytes_delay: Duration,
) -> impl Fn(Request<hyper::body::Body>) -> crate::common::AsyncResp {
    move |request| {
        Box::new(async move {
            let (mut write, read) = hyper::Body::channel();
            let mut incoming_body = request.into_body();

            tokio::spawn(async move {
                while let Some(Ok(bytes)) = incoming_body.next().await {
                    tokio::time::sleep(between_bytes_delay).await;
                    if write.send_data(bytes).await.is_err() {
                        break;
                    }
                }
            });

            tokio::time::sleep(first_byte_delay).await;
            Response::builder()
                .status(StatusCode::OK)
                .body(read)
                .unwrap()
        })
    }
}

// This test may seem unnecessary, as it doesn't actually exercise our timeouts.
// However, the infrastructure used for these tests is a little delicate, as is
// the implementation. So it's handy to have a test that just makes sure that
// setting timeouts will not break things, even if those timeouts never fired.
//
// (As an example, it is possible to shift the code that creates a timer into
// a place where it cannot properly sync with the tokio runtime, and so setting
// a timer causes the whole system to panic. Having this test would quickly help
// identify that it wasn't a problem running timeouts, it was a problem setting
// timeouts.)
viceroy_test!(can_set_http_timeouts, |is_component| {
    let resp = Test::using_fixture("upstream.wasm")
        .adapt_component(is_component)
        .async_backend_with_timeouts(
            "origin",
            "/",
            None,
            Some(Duration::from_secs(15)),
            Some(Duration::from_secs(15)),
            generate_delaying_service(Duration::from_millis(0), Duration::from_millis(0)),
        )
        .await
        .against(
            Request::post("/")
                .header("Viceroy-Backend", "origin")
                .body("foobar")
                .unwrap(),
        )
        .await;

    assert!(resp.is_ok());
    let body_str = resp.unwrap().into_body().read_into_string().await;
    assert_eq!(body_str.unwrap(), "foobar");

    Ok(())
});

viceroy_test!(first_byte_timeout_fires, |is_component| {
    let resp = Test::using_fixture("upstream.wasm")
        .adapt_component(is_component)
        .async_backend_with_timeouts(
            "origin",
            "/",
            None,
            Some(Duration::from_millis(200)),
            Some(Duration::from_secs(15)),
            generate_delaying_service(Duration::from_secs(1), Duration::from_millis(0)),
        )
        .await
        .against(
            Request::post("/")
                .header("Viceroy-Backend", "origin")
                .body("foobar")
                .unwrap(),
        )
        .await;

    assert!(resp.is_ok());
    assert_eq!(
        resp.as_ref().unwrap().status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    let body_str = resp.unwrap().into_body().read_into_string().await;
    assert_eq!(body_str.unwrap(), "");

    Ok(())
});

viceroy_test!(between_bytes_timeout_fires, |is_component| {
    let resp = Test::using_fixture("upstream.wasm")
        .adapt_component(is_component)
        .async_backend_with_timeouts(
            "origin",
            "/",
            None,
            Some(Duration::from_secs(15)),
            Some(Duration::from_millis(200)),
            generate_delaying_service(Duration::from_millis(0), Duration::from_secs(2)),
        )
        .await
        .against(
            Request::post("/")
                .header("Viceroy-Backend", "origin")
                .body("foobar")
                .unwrap(),
        )
        .await;

    assert!(resp.is_ok());
    // this next test may seem weird, but it's correct. recall that this is the
    // test for the between-bytes timeout. which only applies to the bytes after
    // the status and headers, so they don't know about the error coming. so this
    // status code should read OK, we just see the error later on.
    assert_eq!(resp.as_ref().unwrap().status(), StatusCode::OK);
    let body_str = resp.unwrap().into_body().read_into_string().await;
    assert!(matches!(body_str, Err(Error::BetweenBytesTimeout)));

    Ok(())
});
