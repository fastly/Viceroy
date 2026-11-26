//! Tests for the readthrough (HTTP) cache API.

use {
    crate::common::{Test, TestResult},
    hyper::{Request, Response, StatusCode, header},
    std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

/// Build the test harness: the "TheOrigin" backend counts the requests it receives, and picks its
/// caching headers from the request path.
async fn http_cache_test(enable_http_cache: bool) -> Test {
    let requests = Arc::new(AtomicUsize::new(0));
    Test::using_fixture("http-cache.wasm")
        .configure_ctx(move |ctx| ctx.set_enable_http_cache(enable_http_cache))
        .backend("TheOrigin", "/", None, move |req| {
            let count = requests.fetch_add(1, Ordering::SeqCst);
            let path = req.uri().path();
            let mut resp = Response::builder().status(StatusCode::OK);
            resp = match path {
                "/vary" | "/vary-guest" => resp
                    .header(header::CACHE_CONTROL, "max-age=60")
                    .header(header::VARY, "x-variant"),
                "/metadata" => resp
                    .header(header::CACHE_CONTROL, "max-age=60")
                    .header("surrogate-control", "max-age=300")
                    .header(header::VARY, "x-variant"),
                "/status-500" => resp
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .header(header::CACHE_CONTROL, "max-age=60"),
                "/no-store" | "/no-store-override" => {
                    resp.header(header::CACHE_CONTROL, "no-store")
                }
                "/private" => resp.header(header::CACHE_CONTROL, "private, max-age=60"),
                "/max-age-0" => resp.header(header::CACHE_CONTROL, "max-age=0"),
                _ => resp.header(header::CACHE_CONTROL, "max-age=60"),
            };
            resp.body(format!("response #{count} for {path}").into_bytes())
                .unwrap()
        })
        .await
}

// The HTTP cache API is only implemented for core wasm modules (witx) so far; the component
// (WIT) interface still reports it as unsupported. So these tests do not use `viceroy_test!`.

#[tokio::test(flavor = "multi_thread")]
async fn http_cache_core_wasm() -> TestResult {
    let resp = http_cache_test(true)
        .await
        .against(Request::get("/").body("")?)
        .await?;
    assert_eq!(resp.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn http_cache_is_disabled_by_default_core_wasm() -> TestResult {
    let resp = http_cache_test(false)
        .await
        .against(Request::get("/disabled").body("")?)
        .await?;
    assert_eq!(resp.status(), StatusCode::OK);
    Ok(())
}
