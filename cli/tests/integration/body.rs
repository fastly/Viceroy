//! Tests related to HTTP request and response bodies.

use {
    crate::{
        common::{Test, TestResult},
        viceroy_test,
    },
    hyper::{body, HeaderMap, Response, StatusCode},
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

viceroy_test!(zero_length_raw_chunks_are_transparent, |is_component| {
    let resp = Test::using_fixture("expects-hello.wasm")
        .adapt_component(is_component)
        .async_backend(
            "ReturnsHello",
            "/",
            None,
            move |_req: hyper::Request<hyper::Body>| {
                Box::new(async move {
                    // We'll "trickle back" our response.
                    let (mut write, read) = hyper::Body::channel();
                    // Assume a Tokio runtime for writing the response...
                    tokio::spawn(async move {
                        for chunk in ["", "hello", "", " ", "", "world", ""] {
                            let Ok(_) = write.send_data(chunk.into()).await else {
                                return;
                            };
                            tokio::task::yield_now().await;
                        }
                        let _ = write.send_trailers(HeaderMap::default());
                    });
                    Response::builder()
                        .status(StatusCode::OK)
                        .body(read)
                        .unwrap()
                })
            },
        )
        .await
        .against_empty()
        .await?;
    assert_eq!(resp.status(), StatusCode::OK);
    Ok(())
});

viceroy_test!(gzip_breaks_are_ok, |is_component| {
    let resp = Test::using_fixture("expects-hello.wasm")
        .adapt_component(is_component)
        .async_backend(
            "ReturnsHello",
            "/",
            None,
            move |req: hyper::Request<hyper::Body>| {
                Box::new(async move {
                    let Some(encoding) = req.headers().get("accept-encoding") else {
                        return Response::builder()
                            .status(StatusCode::BAD_REQUEST)
                            .body(hyper::Body::empty())
                            .unwrap();
                    };
                    if !encoding.to_str().unwrap().to_lowercase().contains("gzip") {
                        return Response::builder()
                            .status(StatusCode::BAD_REQUEST)
                            .body(hyper::Body::empty())
                            .unwrap();
                    }
                    // Produced by: echo -n "hello world" | gzip >hello_world.gzip
                    const GZ_BODY: &[u8] = include_bytes!("hello_world.gzip");
                    // We'll "trickle back" our response.
                    let (mut write, read) = hyper::Body::channel();
                    // Assume a Tokio runtime for writing the response...
                    tokio::spawn(async move {
                        for &byte in GZ_BODY.iter() {
                            let Ok(_) =
                                write.send_data(body::Bytes::copy_from_slice(&[byte])).await
                            else {
                                return;
                            };
                            tokio::task::yield_now().await;
                        }
                        let _ = write.send_trailers(HeaderMap::default());
                    });
                    Response::builder()
                        .status(StatusCode::OK)
                        .header("content-encoding", "gzip")
                        .body(read)
                        .unwrap()
                })
            },
        )
        .await
        .against_empty()
        .await?;
    assert_eq!(resp.status(), StatusCode::OK);
    Ok(())
});
