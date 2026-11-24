use {
    crate::{
        common::{Test, TestResult},
        viceroy_test,
    },
    hyper::{Request, Response, StatusCode, ext::ReasonPhrase},
};

viceroy_test!(response_works, |is_component| {
    let resp = Test::using_fixture("response.wasm")
        .adapt_component(is_component)
        .against_empty()
        .await?;
    assert_eq!(resp.status(), StatusCode::OK);
    Ok(())
});

viceroy_test!(test_reason_phrase_canonical, |is_component| {
    let resp = Test::using_fixture("reason-phrase.wasm")
        .adapt_component(is_component)
        .backend("TheOrigin", "/", None, |_| {
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(b"Not Found".to_vec())
                .unwrap()
        })
        .await
        .against_empty()
        .await?;
    assert_eq!(resp.status(), StatusCode::OK);
    Ok(())
});

viceroy_test!(test_reason_phrase_custom, |is_component| {
    let paths = ["/custom", "/empty", "/unknown", "/long"];
    let responses = Test::using_fixture("reason-phrase.wasm")
        .adapt_component(is_component)
        .backend("TheOrigin", "/", None, |req| {
            let (status, phrase) = match req.uri().path() {
                "/custom" => (200, b"Something\tdifferent ".to_vec()),
                "/empty" => (200, Vec::new()),
                "/unknown" => (599, b"Custom status".to_vec()),
                "/long" => (200, vec![b'x'; 1024]),
                path => panic!("unexpected path: {path}"),
            };
            Response::builder()
                .status(status)
                .extension(ReasonPhrase::try_from(phrase.clone()).unwrap())
                .body(phrase)
                .unwrap()
        })
        .await
        .against_many(
            paths
                .iter()
                .map(|path| Request::get(*path).body("").unwrap())
                .collect(),
        )
        .await?;
    assert_eq!(responses.len(), paths.len());
    for (path, resp) in paths.iter().zip(responses) {
        assert_eq!(resp.status(), StatusCode::OK, "{path}");
    }
    Ok(())
});
