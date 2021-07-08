use {
    crate::common::{TestResult, FIXTURE_PATH},
    http::header::WARNING,
    hyper::{Body, Request, StatusCode},
    viceroy_lib::ExecuteCtx,
};

#[path = "../../common.rs"]
mod common;

#[tokio::test(flavor = "multi_thread")]
async fn fatal_error_traps() -> TestResult {
    let module_path = format!("../../{}/response.wasm", FIXTURE_PATH);
    let ctx = ExecuteCtx::new(module_path)?;
    let req = Request::get("http://127.0.0.1:7878/").body(Body::from(""))?;
    let resp = ctx
        .handle_request(req, "127.0.0.1".parse().unwrap())
        .await?;

    // The Guest was terminated and so should return a 500.
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

    // Examine the WARNING message in the response headers and assert that it is the expected
    // Trap error supplied by the Guest.
    if let Some(warning) = resp.headers().get(WARNING) {
        assert_eq!(
            warning,
            "A fatal error occurred in the test-only implementation of header_values_get"
        );
    } else {
        panic!("The response did not contain the expected warning header");
    }

    Ok(())
}
