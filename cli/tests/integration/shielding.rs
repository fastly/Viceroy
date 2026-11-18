use crate::common::{Test, TestBody, TestResult, spawn_server};
use crate::viceroy_test;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use std::net::SocketAddr;

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
    let body = resp2.into_body().read_into_vec().await.unwrap();
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
    let body = resp3.into_body().read_into_vec().await.unwrap();
    let string = String::from_utf8(body).unwrap();
    assert_eq!("false", &string);

    Ok(())
});

viceroy_test!(shield_backends, |is_component| {
    let blank_addr = SocketAddr::from(([127, 0, 0, 1], 0));

    let unenc_server = spawn_server(blank_addr, |_, _| {
        service_fn(|_| async {
            Ok::<_, std::io::Error>(Response::new(TestBody::full("unencrypted land")))
        })
    })?;
    let enc_server = spawn_server(blank_addr, |_, _| {
        service_fn(|_| async {
            Ok::<_, std::io::Error>(Response::new(TestBody::full("encrypted land")))
        })
    })?;

    let unenc_addr = unenc_server.bound_addr;
    let enc_addr = enc_server.bound_addr;

    let fastly_toml = format!(
        r#"
        name = "shielding_running_on"
        description = "test that running_on works"
        authors = ["Test user <test_user@fastly.com>"]
        language = "rust"
        [local_server.shielding_sites]
        "pdx-or-us" = "Local"
        "bfi-wa-us".unencrypted = "http://{}"
        "bfi-wa-us".encrypted = "http://{}"
    "#,
        unenc_addr, enc_addr
    );

    let test = Test::using_fixture("shielding.wasm")
        .using_fastly_toml(&fastly_toml)?
        .adapt_component(is_component);

    let resp1 = test
        .against(
            Request::get("/shield-to")
                .header("shield", "bfi-wa-us")
                .header("shield-type", "unencrypted")
                .body("")?,
        )
        .await?;
    assert_eq!(StatusCode::OK, resp1.status());
    let body = resp1.into_body().read_into_vec().await.unwrap();
    let string = String::from_utf8(body).unwrap();
    assert_eq!("unencrypted land", &string);

    let resp2 = test
        .against(
            Request::get("/shield-to")
                .header("shield", "bfi-wa-us")
                .header("shield-type", "encrypted")
                .body("")?,
        )
        .await?;
    assert_eq!(StatusCode::OK, resp2.status());
    let body = resp2.into_body().read_into_vec().await.unwrap();
    let string = String::from_utf8(body).unwrap();
    assert_eq!("encrypted land", &string);

    Ok(())
});
