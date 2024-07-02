use crate::{
    common::{Test, TestResult},
    viceroy_test,
};
use hyper::{body::HttpBody, Body, Request, Response, StatusCode};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tokio::sync::Barrier;

// On Windows, streaming body backpressure doesn't seem to work as expected, either
// due to the Hyper client or server too eagerly clearing the chunk buffer. This issue does
// not appear related to async I/O hostcalls; the behavior is seen within the streaming body
// implementation in general. For the time being, this test is unix-only.
//
// https://github.com/fastly/Viceroy/issues/207 tracks the broader issue.
#[cfg(target_family = "unix")]
viceroy_test!(async_io_methods, |is_component| {
    let request_count = Arc::new(AtomicUsize::new(0));
    let req_count_1 = request_count.clone();
    let req_count_2 = request_count.clone();
    let req_count_3 = request_count.clone();
    let req_count_4 = request_count.clone();

    let barrier = Arc::new(Barrier::new(3));
    let barrier_1 = barrier.clone();
    let barrier_2 = barrier.clone();
    let sync_barrier = Arc::new(Barrier::new(2));
    let sync_barrier_1 = sync_barrier.clone();

    // We set up 4 async backends below, configured to test different
    // combinations of async behavior from the guest.  The first three backends
    // are things we are actually testing, and the fourth ("Semaphore") is just
    // used as a synchronization mechanism. Each backend will receive 4 requests
    // total and will behave differently depending on which request # it is
    // processing.
    let test = Test::using_fixture("async_io.wasm")
        .adapt_component(is_component)
        .async_backend("Simple", "/", None, move |req: Request<Body>| {
            assert_eq!(req.headers()["Host"], "simple.org");
            let req_count_1 = req_count_1.clone();
            let barrier_1 = barrier_1.clone();
            Box::new(async move {
                match req_count_1.load(Ordering::Relaxed) {
                    1 => Response::builder()
                        .status(StatusCode::OK)
                        .body(Body::empty())
                        .unwrap(),
                    0 | 2 | 3 => {
                        barrier_1.wait().await;
                        Response::builder()
                            .status(StatusCode::OK)
                            .body(Body::empty())
                            .unwrap()
                    }
                    _ => unreachable!(),
                }
            })
        })
        .await
        .async_backend("ReadBody", "/", None, move |req: Request<Body>| {
            assert_eq!(req.headers()["Host"], "readbody.org");
            let req_count_2 = req_count_2.clone();
            Box::new(async move {
                match req_count_2.load(Ordering::Relaxed) {
                    2 => Response::builder()
                        .status(StatusCode::OK)
                        .body(Body::empty())
                        .unwrap(),
                    0 | 1 | 3 => Response::builder()
                        .header("Transfer-Encoding", "chunked")
                        .status(StatusCode::OK)
                        .body(Body::empty())
                        .unwrap(),
                    _ => unreachable!(),
                }
            })
        })
        .await
        .async_backend("WriteBody", "/", None, move |req: Request<Body>| {
            assert_eq!(req.headers()["Host"], "writebody.org");
            let req_count_3 = req_count_3.clone();
            let barrier_2 = barrier_2.clone();
            let sync_barrier = sync_barrier.clone();
            Box::new(async move {
                match req_count_3.load(Ordering::Relaxed) {
                    3 => {
                        // Read at least 4MB and one 8K chunk from the request
                        // to relieve back-pressure for the guest. These numbers
                        // come from the amount of data that the guest writes to
                        // the request body in test-fixtures/src/bin/async_io.rs
                        let mut bod = req.into_body();
                        let mut bytes_read = 0;
                        while bytes_read < (4 * 1024 * 1024) + (8 * 1024) {
                            if let Some(Ok(bytes)) = bod.data().await {
                                bytes_read += bytes.len();
                            }
                        }

                        // The guest will have another outstanding request to
                        // the Semaphore backend below. Awaiting on the barrier
                        // here will cause that request to return indicating to
                        // the guest that we have read from the request body
                        // and the write handle should be ready again.
                        sync_barrier.wait().await;
                        let _body = hyper::body::to_bytes(bod);
                        Response::builder()
                            .status(StatusCode::OK)
                            .body(Body::empty())
                            .unwrap()
                    }
                    0..=2 => {
                        barrier_2.wait().await;
                        Response::builder()
                            .status(StatusCode::OK)
                            .body(Body::empty())
                            .unwrap()
                    }
                    _ => unreachable!(),
                }
            })
        })
        .await
        .async_backend("Semaphore", "/", None, move |req: Request<Body>| {
            assert_eq!(req.headers()["Host"], "writebody.org");
            let req_count_4 = req_count_4.clone();
            let sync_barrier_1 = sync_barrier_1.clone();
            Box::new(async move {
                match req_count_4.load(Ordering::Relaxed) {
                    3 => {
                        sync_barrier_1.wait().await;
                        Response::builder()
                            .status(StatusCode::OK)
                            .body(Body::empty())
                            .unwrap()
                    }
                    0..=2 => Response::builder()
                        .status(StatusCode::OK)
                        .body(Body::empty())
                        .unwrap(),
                    _ => unreachable!(),
                }
            })
        })
        .await;

    // request_count is 0 here
    let resp = test.against_empty().await?;

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["Simple-Ready"], "false");
    assert_eq!(resp.headers()["Read-Ready"], "false");
    assert_eq!(resp.headers()["Write-Ready"], "false");
    assert_eq!(resp.headers()["Ready-Index"], "timeout");

    barrier.wait().await;

    request_count.store(1, Ordering::Relaxed);
    let resp = test.against_empty().await?;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["Simple-Ready"], "true");
    assert_eq!(resp.headers()["Read-Ready"], "false");
    assert_eq!(resp.headers()["Write-Ready"], "false");
    assert_eq!(resp.headers()["Ready-Index"], "0");
    let temp_barrier = barrier.clone();
    let _task = tokio::task::spawn(async move { temp_barrier.wait().await });
    barrier.wait().await;

    request_count.store(2, Ordering::Relaxed);
    let resp = test.against_empty().await?;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["Simple-Ready"], "false");
    assert_eq!(resp.headers()["Read-Ready"], "true");
    assert_eq!(resp.headers()["Write-Ready"], "false");
    assert_eq!(resp.headers()["Ready-Index"], "1");
    barrier.wait().await;

    request_count.store(3, Ordering::Relaxed);
    let resp = test.against_empty().await?;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["Simple-Ready"], "false");
    assert_eq!(resp.headers()["Read-Ready"], "false");
    assert_eq!(resp.headers()["Write-Ready"], "true");
    assert_eq!(resp.headers()["Ready-Index"], "2");
    let temp_barrier = barrier.clone();
    let _task = tokio::task::spawn(async move { temp_barrier.wait().await });
    barrier.wait().await;

    let resp = test
        .against(
            Request::get("/")
                .header("Empty-Select-Timeout", "0")
                .body(Body::empty())
                .unwrap(),
        )
        .await?;
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let resp = test
        .against(
            Request::get("/")
                .header("Empty-Select-Timeout", "1")
                .body(Body::empty())
                .unwrap(),
        )
        .await?;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["Ready-Index"], "timeout");

    Ok(())
});
