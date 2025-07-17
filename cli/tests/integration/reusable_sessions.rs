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
