use crate::common::{Test, TestResult};
use hyper::{body::to_bytes, StatusCode};

#[tokio::test(flavor = "multi_thread")]
async fn json_geoip_lookup_works() -> TestResult {
    const FASTLY_TOML: &str = r#"
        name = "json-geoip-lookup"
        description = "json geoip lookup test"
        authors = ["Test User <test_user@fastly.com>"]
        language = "rust"
        [local_server]
        [local_server.geoip_mapping]
        file = "../test-fixtures/data/geoip-mapping.json"
        format = "json"
    "#;

    let resp = Test::using_fixture("geoip-lookup.wasm")
        .using_fastly_toml(FASTLY_TOML)?
        .against_empty()
        .await;

    assert_eq!(resp.status(), StatusCode::OK);
    assert!(to_bytes(resp.into_body())
        .await
        .expect("can read body")
        .to_vec()
        .is_empty());

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn inline_toml_geoip_lookup_works() -> TestResult {
    const FASTLY_TOML: &str = r#"
        name = "inline-toml-geoip-lookup"
        description = "inline toml geoip lookup test"
        authors = ["Test User <test_user@fastly.com>"]
        language = "rust"
        [local_server]
        [local_server.geoip_mapping]
        format = "inline-toml"
        [local_server.geoip_mapping.contents]
        [local_server.geoip_mapping.contents."127.0.0.1"]
        as_name = "Fastly Test"
        as_number = 12345
        area_code = 123
        city = "Test City"
        conn_speed = "broadband"
        conn_type = "wired"
        continent = "NA"
        country_code = "CA"
        country_code3 = "CAN"
        country_name = "Canada"
        latitude = 12.345
        longitude = 54.321
        metro_code = 0
        postal_code = "12345"
        proxy_description = "?"
        proxy_type = "?"
        region = "CA-BC"
        utc_offset = -700
    "#;

    let resp = Test::using_fixture("geoip-lookup.wasm")
        .using_fastly_toml(FASTLY_TOML)?
        .against_empty()
        .await;

    assert_eq!(resp.status(), StatusCode::OK);
    assert!(to_bytes(resp.into_body())
        .await
        .expect("can read body")
        .to_vec()
        .is_empty());

    Ok(())
}