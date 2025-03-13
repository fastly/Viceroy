use crate::common::{Test, TestResult};
use crate::viceroy_test;
use hyper::{body, Request, StatusCode};

viceroy_test!(shielding_running_on, |is_component| {
    const FASTLY_TOML: &str = r#"
        name = "shielding_running_on"
        description = "test that running_on works"
        authors = ["Test user <test_user@fastly.com>"]
        language = "rust"
        [local_server.shielding_sites]
        "pdx-or-us" = "Local"
        "bfi-wa-us".unencrypted = "http://localhost"
        "bfi-wa-us".encrypted = "https://localhost"
    "#;
    let test = Test::using_fixture("shielding.wasm")
        .using_fastly_toml(FASTLY_TOML)?
        .adapt_component(is_component);

    let resp1 = test
        .against(
            Request::get("/is-shield")
                .header("shield", "waffle-cone")
                .body("")?,
        )
        .await?;
    assert_eq!(StatusCode::INTERNAL_SERVER_ERROR, resp1.status());

    let resp2 = test
        .against(
            Request::get("/is-shield")
                .header("shield", "pdx-or-us")
                .body("")?,
        )
        .await?;
    assert_eq!(StatusCode::OK, resp2.status());
    let body = body::to_bytes(resp2.into_body()).await.unwrap().to_vec();
    let string = String::from_utf8(body).unwrap();
    assert_eq!("true", &string);

    let resp3 = test
        .against(
            Request::get("/is-shield")
                .header("shield", "bfi-wa-us")
                .body("")?,
        )
        .await?;
    assert_eq!(StatusCode::OK, resp3.status());
    let body = body::to_bytes(resp3.into_body()).await.unwrap().to_vec();
    let string = String::from_utf8(body).unwrap();
    assert_eq!("false", &string);

    Ok(())
});
