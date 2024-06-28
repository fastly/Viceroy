use crate::{
    common::{Test, TestResult},
    viceroy_test,
};
use hyper::{body::to_bytes, StatusCode};

viceroy_test!(json_device_detection_lookup_works, |is_component| {
    const FASTLY_TOML: &str = r#"
        name = "json-device-detection-lookup"
        description = "json device detection lookup test"
        authors = ["Test User <test_user@fastly.com>"]
        language = "rust"
        [local_server]
        [local_server.device_detection]
        file = "../test-fixtures/data/device-detection-mapping.json"
        format = "json"
    "#;

    let resp = Test::using_fixture("device-detection-lookup.wasm")
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

viceroy_test!(inline_toml_device_detection_lookup_works, |is_component| {
    const FASTLY_TOML: &str = r#"
        name = "inline-toml-device-detection-lookup"
        description = "inline toml device detection lookup test"
        authors = ["Test User <test_user@fastly.com>"]
        language = "rust"
        [local_server]
        [local_server.device_detection]
        format = "inline-toml"
        [local_server.device_detection.user_agents]
        [local_server.device_detection.user_agents."Mozilla/5.0 (X11; Linux x86_64; rv:10.0) Gecko/20100101 Firefox/10.0 [FBAN/FBIOS;FBAV/8.0.0.28.18;FBBV/1665515;FBDV/iPhone4,1;FBMD/iPhone;FBSN/iPhone OS;FBSV/7.0.4;FBSS/2; FBCR/Telekom.de;FBID/phone;FBLC/de_DE;FBOP/5]"]
        user_agent = {}
        os = {}
        device = {name = "iPhone", brand = "Apple", model = "iPhone4,1", hwtype = "Mobile Phone", is_ereader = false, is_gameconsole = false, is_mediaplayer = false, is_mobile = true, is_smarttv = false, is_tablet = false, is_tvplayer = false, is_desktop = false, is_touchscreen = true }
        [local_server.device_detection.user_agents."ghosts-app/1.0.2.1 (ASUSTeK COMPUTER INC.; X550CC; Windows 8 (X86); en)"]
        user_agent = {}
        os = {}
        device = {name = "Asus TeK", brand = "Asus", model = "TeK", is_desktop = false }
        "#;

    let resp = Test::using_fixture("device-detection-lookup.wasm")
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
