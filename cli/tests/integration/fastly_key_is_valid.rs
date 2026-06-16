use {
    crate::{
        common::{Test, TestResult},
        viceroy_test,
    },
    hyper::{Request, StatusCode},
};

viceroy_test!(fastly_key_is_valid_with_valid_key, |is_component| {
    let resp = Test::using_fixture("fastly-key-is-valid.wasm")
        .adapt_component(is_component)
        .using_fastly_toml(
            r#"
            manifest_version = 3
            name = "fastly-key-is-valid-test"
            language = "rust"

            [local_server]
            fake_valid_fastly_keys = ["test-key-123", "another-key"]
        "#,
        )?
        .against(
            Request::get("/")
                .header("fastly-key", "test-key-123")
                .body("")?,
        )
        .await?;

    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().read_into_string().await?;
    assert!(
        body.contains("is_valid=true"),
        "expected valid key, got: {body}"
    );
    Ok(())
});

viceroy_test!(fastly_key_is_valid_with_invalid_key, |is_component| {
    let resp = Test::using_fixture("fastly-key-is-valid.wasm")
        .adapt_component(is_component)
        .using_fastly_toml(
            r#"
            manifest_version = 3
            name = "fastly-key-is-valid-test"
            language = "rust"

            [local_server]
            fake_valid_fastly_keys = ["test-key-123", "another-key"]
        "#,
        )?
        .against(
            Request::get("/")
                .header("fastly-key", "wrong-key")
                .body("")?,
        )
        .await?;

    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().read_into_string().await?;
    assert!(
        body.contains("is_valid=false"),
        "expected invalid key, got: {body}"
    );
    Ok(())
});

viceroy_test!(fastly_key_is_valid_with_no_header, |is_component| {
    let resp = Test::using_fixture("fastly-key-is-valid.wasm")
        .adapt_component(is_component)
        .using_fastly_toml(
            r#"
            manifest_version = 3
            name = "fastly-key-is-valid-test"
            language = "rust"

            [local_server]
            fake_valid_fastly_keys = ["test-key-123"]
        "#,
        )?
        .against(Request::get("/").body("")?)
        .await?;

    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().read_into_string().await?;
    assert!(
        body.contains("is_valid=false"),
        "expected invalid without header, got: {body}"
    );
    Ok(())
});

viceroy_test!(
    fastly_key_is_valid_with_no_keys_configured,
    |is_component| {
        let resp = Test::using_fixture("fastly-key-is-valid.wasm")
            .adapt_component(is_component)
            .against(Request::get("/").header("fastly-key", "any-key").body("")?)
            .await?;

        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().read_into_string().await?;
        assert!(
            body.contains("is_valid=false"),
            "expected invalid when no keys configured, got: {body}"
        );
        Ok(())
    }
);
