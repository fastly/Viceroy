//! Tests related to HTTP request and response bodies.

use crate::common::{Test, TestResult};
use crate::viceroy_test;
use hyper::{Request, StatusCode};

viceroy_test!(check_hostcalls_implemented, |is_component| {
    let test = Test::using_fixture("reusable-sessions.wasm")
        .adapt_component(is_component)
        .via_hyper();

    let reqs = (0..5)
        .into_iter()
        .map(|n| Request::post("/").body(n.to_string()).unwrap())
        .collect();

    let resps = test.against_many(reqs).await?;

    for (n, resp) in resps.into_iter().enumerate() {
        let exp = format!("Response #{}", n + 1);
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.into_body().read_into_string().await?, exp);
    }

    Ok(())
});

viceroy_test!(check_crash_causes_5xx, |is_component| {
    let test = Test::using_fixture("reusable-sessions.wasm")
        .adapt_component(is_component)
        .via_hyper();

    let reqs = (0..5)
        .into_iter()
        .map(|n| {
            let body = if n == 4 {
                "crash!".to_owned()
            } else {
                n.to_string()
            };
            Request::post("/").body(body).unwrap()
        })
        .collect();

    let mut resps = test.against_many(reqs).await?;
    let errs = resps.split_off(4);

    assert_eq!(resps.len(), 4);
    assert_eq!(errs.len(), 1);

    for (n, resp) in resps.into_iter().enumerate() {
        let exp = format!("Response #{}", n + 1);
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.into_body().read_into_string().await?, exp);
    }

    for resp in errs.into_iter() {
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = resp.into_body().read_into_string().await?;
        let needle = "error while executing at wasm backtrace";
        assert!(body.contains(needle), "missing expected string: {body:?}");
    }

    Ok(())
});
