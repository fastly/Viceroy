use crate::{
    common::{Test, TestResult},
    viceroy_test,
};
use hyper::{body::to_bytes, StatusCode};

viceroy_test!(json_dictionary_lookup_works, |is_component| {
    const FASTLY_TOML: &str = r#"
        name = "json-dictionary-lookup"
        description = "json dictionary lookup test"
        authors = ["Jill Bryson <jbryson@fastly.com>", "Rose McDowall <rmcdowall@fastly.com>"]
        language = "rust"
        [local_server]
        [local_server.dictionaries]
        [local_server.dictionaries.animals]
        file = "../test-fixtures/data/json-dictionary.json"
        format = "json"
    "#;

    let resp = Test::using_fixture("dictionary-lookup.wasm")
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

viceroy_test!(inline_toml_dictionary_lookup_works, |is_component| {
    const FASTLY_TOML: &str = r#"
        name = "inline-toml-dictionary-lookup"
        description = "inline toml dictionary lookup test"
        authors = ["Jill Bryson <jbryson@fastly.com>", "Rose McDowall <rmcdowall@fastly.com>"]
        language = "rust"
        [local_server]
        [local_server.dictionaries]
        [local_server.dictionaries.animals]
        format = "inline-toml"
        [local_server.dictionaries.animals.contents]
        dog = "woof"
        cat = "meow"
    "#;

    let resp = Test::using_fixture("dictionary-lookup.wasm")
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

viceroy_test!(missing_dictionary_works, |is_component| {
    const FASTLY_TOML: &str = r#"
        name = "missing-dictionary-config"
        description = "missing dictionary test"
        language = "rust"
    "#;

    let resp = Test::using_fixture("dictionary-lookup.wasm")
        .adapt_component(is_component)
        .using_fastly_toml(FASTLY_TOML)?
        .against_empty()
        .await?;

    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

    Ok(())
});
