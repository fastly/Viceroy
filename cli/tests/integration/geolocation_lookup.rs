use crate::{
    common::{Test, TestResult},
    viceroy_test,
};
use hyper::{body::to_bytes, StatusCode};

viceroy_test!(json_geolocation_lookup_works, |is_component| {
    const FASTLY_TOML: &str = r#"
        name = "json-geolocation-lookup"
        description = "json geolocation lookup test"
        authors = ["Test User <test_user@fastly.com>"]
        language = "rust"
        [local_server]
        [local_server.geolocation]
        use_default_loopback = false
        file = "../test-fixtures/data/geolocation-mapping.json"
        format = "json"
    "#;

    let resp = Test::using_fixture("geolocation-lookup.wasm")
        .adapt_component(is_component)
        .using_fastly_toml(FASTLY_TOML)?
        .against_empty()
        .await?;

    assert_eq!(resp.status(), StatusCode::OK);
    assert!(to_bytes(resp.into_body())
        .await
        .expect("can read body")
        .to_vec()
        .is_empty());

    Ok(())
});

viceroy_test!(inline_toml_geolocation_lookup_works, |is_component| {
    const FASTLY_TOML: &str = r#"
        name = "inline-toml-geolocation-lookup"
        description = "inline toml geolocation lookup test"
        authors = ["Test User <test_user@fastly.com>"]
        language = "rust"
        [local_server]
        [local_server.geolocation]
        use_default_loopback = false
        format = "inline-toml"
        [local_server.geolocation.addresses]
        [local_server.geolocation.addresses."127.0.0.1"]
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
        region = "BC"
        utc_offset = -700
        [local_server.geolocation.addresses."0000:0000:0000:0000:0000:0000:0000:0001"]
        as_name = "Fastly Test IPv6"
        as_number = 12345
        area_code = 123
        city = "Test City IPv6"
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
        region = "BC"
        utc_offset = -700
    "#;

    let resp = Test::using_fixture("geolocation-lookup.wasm")
        .adapt_component(is_component)
        .using_fastly_toml(FASTLY_TOML)?
        .against_empty()
        .await?;

    assert_eq!(resp.status(), StatusCode::OK);
    assert!(to_bytes(resp.into_body())
        .await
        .expect("can read body")
        .to_vec()
        .is_empty());

    Ok(())
});

viceroy_test!(
    default_configuration_geolocation_lookup_works,
    |is_component| {
        const FASTLY_TOML: &str = r#"
        name = "default-config-geolocation-lookup"
        description = "default config geolocation lookup test"
        authors = ["Test User <test_user@fastly.com>"]
        language = "rust"
    "#;

        let resp = Test::using_fixture("geolocation-lookup-default.wasm")
            .adapt_component(is_component)
            .using_fastly_toml(FASTLY_TOML)?
            .against_empty()
            .await?;

        assert_eq!(resp.status(), StatusCode::OK);
        assert!(to_bytes(resp.into_body())
            .await
            .expect("can read body")
            .to_vec()
            .is_empty());

        Ok(())
    }
);
