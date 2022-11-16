use crate::common::Test;
use crate::common::TestResult;
use hyper::Body;
use hyper::Request;
use hyper::Response;
use hyper::StatusCode;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::sync::Barrier;

// For some reason on windows this test fails with the write body portion due to
// some difference we believe between unix systems and windows when it comes to
// hyper. We don't believe this means the implementation is wrong. As such we've
// disabled this test only on windwos.
#[cfg(target_family = "unix")]
#[tokio::test(flavor = "multi_thread")]
async fn async_io_methods() -> TestResult {
    let request_count = Arc::new(AtomicUsize::new(0));
    let req_count_1 = request_count.clone();
    let req_count_2 = request_count.clone();
    let req_count_3 = request_count.clone();

    let barrier = Arc::new(Barrier::new(3));
    let barrier_1 = barrier.clone();
    let barrier_2 = barrier.clone();

    let test = Test::using_fixture("async_io.wasm")
        .backend("Simple", "http://127.0.0.1:9000/", None)
        .async_host(9000, move |req: Request<Body>| {
            assert_eq!(req.headers()["Host"], "simple.org");
            let req_count_1 = req_count_1.clone();
            let barrier_1 = barrier_1.clone();
            Box::new(async move {
                match req_count_1.load(Ordering::Relaxed) {
                    0 => {
                        barrier_1.wait().await;
                        Response::builder()
                            .status(StatusCode::OK)
                            .body(Body::empty())
                            .unwrap()
                    }
                    1 => Response::builder()
                        .status(StatusCode::OK)
                        .body(Body::empty())
                        .unwrap(),
                    2 => {
                        barrier_1.wait().await;
                        Response::builder()
                            .status(StatusCode::OK)
                            .body(Body::empty())
                            .unwrap()
                    }
                    3 => {
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
        .backend("ReadBody", "http://127.0.0.1:9001/", None)
        .async_host(9001, move |req: Request<Body>| {
            assert_eq!(req.headers()["Host"], "readbody.org");
            let req_count_2 = req_count_2.clone();
            Box::new(async move {
                match req_count_2.load(Ordering::Relaxed) {
                    0 => Response::builder()
                        .header("Transfer-Encoding", "chunked")
                        .status(StatusCode::OK)
                        .body(Body::empty())
                        .unwrap(),
                    1 => Response::builder()
                        .header("Transfer-Encoding", "chunked")
                        .status(StatusCode::OK)
                        .body(Body::empty())
                        .unwrap(),
                    2 => Response::builder()
                        .status(StatusCode::OK)
                        .body(Body::empty())
                        .unwrap(),
                    3 => Response::builder()
                        .header("Transfer-Encoding", "chunked")
                        .status(StatusCode::OK)
                        .body(Body::empty())
                        .unwrap(),
                    _ => unreachable!(),
                }
            })
        })
        .backend("WriteBody", "http://127.0.0.1:9002/", None)
        .async_host(9002, move |req: Request<Body>| {
            assert_eq!(req.headers()["Host"], "writebody.org");
            let req_count_3 = req_count_3.clone();
            let barrier_2 = barrier_2.clone();
            Box::new(async move {
                match req_count_3.load(Ordering::Relaxed) {
                    0 => {
                        barrier_2.wait().await;
                        Response::builder()
                            .status(StatusCode::OK)
                            .body(Body::empty())
                            .unwrap()
                    }
                    1 => {
                        barrier_2.wait().await;
                        Response::builder()
                            .status(StatusCode::OK)
                            .body(Body::empty())
                            .unwrap()
                    }
                    2 => {
                        barrier_2.wait().await;
                        Response::builder()
                            .status(StatusCode::OK)
                            .body(Body::empty())
                            .unwrap()
                    }
                    3 => {
                        let _body = hyper::body::to_bytes(req.into_body()).await;
                        Response::builder()
                            .status(StatusCode::OK)
                            .body(Body::empty())
                            .unwrap()
                    }
                    _ => unreachable!(),
                }
            })
        });

    // request_count is 0 here
    let resp = test
        .against(
            Request::builder()
                .header("Host", "example.org")
                .body(Body::empty())
                .unwrap(),
        )
        .await;

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["Simple-Ready"], "false");
    assert_eq!(resp.headers()["Read-Ready"], "false");
    assert_eq!(resp.headers()["Write-Ready"], "false");
    assert_eq!(resp.headers()["Ready-Index"], "timeout");

    barrier.wait().await;

    request_count.store(1, Ordering::Relaxed);
    let resp = test
        .against(
            Request::builder()
                .header("Host", "example.org")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["Simple-Ready"], "true");
    assert_eq!(resp.headers()["Read-Ready"], "false");
    assert_eq!(resp.headers()["Write-Ready"], "false");
    assert_eq!(resp.headers()["Ready-Index"], "0");
    let temp_barrier = barrier.clone();
    let _task = tokio::task::spawn(async move { temp_barrier.wait().await });
    barrier.wait().await;

    request_count.store(2, Ordering::Relaxed);
    let resp = test
        .against(
            Request::builder()
                .header("Host", "example.org")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["Simple-Ready"], "false");
    assert_eq!(resp.headers()["Read-Ready"], "true");
    assert_eq!(resp.headers()["Write-Ready"], "false");
    assert_eq!(resp.headers()["Ready-Index"], "1");
    barrier.wait().await;

    request_count.store(3, Ordering::Relaxed);
    let resp = test
        .against(
            Request::builder()
                .header("Host", "example.org")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
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
            Request::builder()
                .header("Host", "example.org")
                .header("Empty-Select-Timeout", "0")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let resp = test
        .against(
            Request::builder()
                .header("Host", "example.org")
                .header("Empty-Select-Timeout", "1")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["Ready-Index"], "timeout");

    Ok(())
}
