use std::sync::Arc;

use tokio::sync::Semaphore;

use {
    crate::{
        common::{Test, TestResult},
        viceroy_test,
    },
    hyper::{Response, StatusCode},
};

viceroy_test!(upstream_async_methods, |is_component| {
    // Set up two backends that share a semaphore that starts with zero permits. `backend1` must
    // take a semaphore permit and then "forget" it before returning its response. `backend2` adds a
    // permit to the semaphore and promptly returns. This relationship allows the test fixtures to
    // examine the behavior of the various pending request operators beyond just whether they
    // eventually return the expected response.
    let sema_backend1 = Arc::new(Semaphore::new(0));
    let sema_backend2 = sema_backend1.clone();
    let test = Test::using_fixture("upstream-async.wasm")
        .adapt_component(is_component)
        .async_backend("backend1", "/", None, move |_| {
            let sema_backend1 = sema_backend1.clone();
            Box::new(async move {
                sema_backend1.acquire().await.unwrap().forget();
                Response::builder()
                    .header("Backend-1-Response", "")
                    .status(StatusCode::OK)
                    .body(hyper::Body::empty())
                    .unwrap()
            })
        })
        .await
        .async_backend("backend2", "/", None, move |_| {
            let sema_backend2 = sema_backend2.clone();
            Box::new(async move {
                sema_backend2.add_permits(1);
                Response::builder()
                    .header("Backend-2-Response", "")
                    .status(StatusCode::OK)
                    .body(hyper::Body::empty())
                    .unwrap()
            })
        })
        .await;

    // The meat of the test is on the guest side; we just check that we made it through successfully
    let resp = test.against_empty().await?;
    assert_eq!(resp.status(), StatusCode::OK);
    Ok(())
});
