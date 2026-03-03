use crate::common::{Test, TestResult};
use crate::viceroy_test;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server, StatusCode, body};
use std::convert::Infallible;
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

viceroy_test!(shield_backends, |is_component| {
    let blank_addr = SocketAddr::from(([127, 0, 0, 1], 0));

    let make_service_unenc = make_service_fn(|_conn| async {
        Ok::<_, Infallible>(service_fn(|_: Request<Body>| async {
            Ok::<Response<Body>, std::io::Error>(Response::new(Body::from("unencrypted land")))
        }))
    });

    let make_service_enc = make_service_fn(|_conn| async {
        Ok::<_, Infallible>(service_fn(|_: Request<Body>| async {
            Ok::<Response<Body>, std::io::Error>(Response::new(Body::from("encrypted land")))
        }))
    });

    let unenc_server = Server::bind(&blank_addr).serve(make_service_unenc);
    let enc_server = Server::bind(&blank_addr).serve(make_service_enc);

    let unenc_addr = unenc_server.local_addr();
    let enc_addr = enc_server.local_addr();

    let mut server_set = tokio::task::JoinSet::new();
    server_set.spawn(unenc_server);
    server_set.spawn(enc_server);

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
    let body = body::to_bytes(resp1.into_body()).await.unwrap().to_vec();
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
    let body = body::to_bytes(resp2.into_body()).await.unwrap().to_vec();
    let string = String::from_utf8(body).unwrap();
    assert_eq!("encrypted land", &string);

    Ok(())
});
