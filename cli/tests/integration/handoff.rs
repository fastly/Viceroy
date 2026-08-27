use {
    crate::{
        common::{Test, TestResult},
        viceroy_test,
    },
    hyper::{Request, StatusCode},
};

/// `FastlyStatus::UNSUPPORTED`, which is what a guest sees when a feature is not enabled for
/// the service.
const UNSUPPORTED: &str = "status=5";

/// `FastlyStatus::ERROR`, the generic error.
const ERROR: &str = "status=1";

/// Define the backend the fixture hands off to.
///
/// A backend has to exist even for the cases that are expected to fail: on the component path
/// the adapter resolves the backend name before invoking the hostcall, so an undefined backend
/// would fail with `FastlyStatus::NONE` before the feature check is ever reached.
async fn with_backend(test: Test) -> Test {
    test.backend("origin", "/", None, |_| {
        hyper::Response::builder()
            .status(StatusCode::IM_A_TEAPOT)
            .body(Vec::from("from the backend"))
            .unwrap()
    })
    .await
}

viceroy_test!(fanout_is_unsupported_when_not_enabled, |is_component| {
    // No `--local-pushpin-proxy-port` is configured, so Fanout is not enabled. The guest must
    // observe that itself, rather than Viceroy manufacturing a response after the fact.
    let resp = with_backend(Test::using_fixture("handoff.wasm").adapt_component(is_component))
        .await
        .against(Request::get("/fanout").body("")?)
        .await?;

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.into_body().read_into_string().await?, UNSUPPORTED);

    Ok(())
});

viceroy_test!(
    websocket_passthrough_is_unsupported_when_disabled,
    |is_component| {
        let resp = with_backend(
            Test::using_fixture("handoff.wasm")
                .adapt_component(is_component)
                .enable_local_websocket_passthrough(false),
        )
        .await
        .against(Request::get("/websocket").body("")?)
        .await?;

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.into_body().read_into_string().await?, UNSUPPORTED);

        Ok(())
    }
);

viceroy_test!(websocket_passthrough_proxies_when_enabled, |is_component| {
    // Enabled by default: the handoff should go through to the backend, and the backend's
    // response — not the guest's — is what reaches the client.
    let resp = with_backend(Test::using_fixture("handoff.wasm").adapt_component(is_component))
        .await
        .against(Request::get("/websocket").body("")?)
        .await?;

    assert_eq!(resp.status(), StatusCode::IM_A_TEAPOT);
    assert_eq!(
        resp.into_body().read_into_string().await?,
        "from the backend"
    );

    Ok(())
});

viceroy_test!(
    already_sent_response_takes_precedence_over_feature_check,
    |is_component| {
        // Matches the ordering in production: a handoff attempted after a response has already
        // been sent reports that, rather than reporting the feature as unsupported.
        let resp = with_backend(
            Test::using_fixture("handoff.wasm")
                .adapt_component(is_component)
                .enable_local_websocket_passthrough(false),
        )
        .await
        .against(
            Request::get("/websocket")
                .header("send-response-first", "yes")
                .body("")?,
        )
        .await?;

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.into_body().read_into_string().await?, ERROR);

        Ok(())
    }
);
