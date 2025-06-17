use crate::{
    common::{Test, TestResult},
    viceroy_test,
};

viceroy_test!(env_vars_are_set_from_env_section, |is_component| {
    const FASTLY_TOML: &str = r#"
            name = "config_store-dotenv"
            description = "config_store dotenv test"
            authors = ["Cameron Walters <cameron.walters@fastly.com>"]
            language = "rust"
            [env]
            LOG_LEVEL = "INFO"
            # FASTLY_OMITTED = "SORRY"      # keys starting with FASTLY return an error.
        "#;

    let resp = Test::using_fixture("env-vars.wasm")
        .adapt_component(is_component)
        .using_fastly_toml(FASTLY_TOML)?
        .against_empty()
        .await?;
    assert!(resp.status().is_success());
    Ok(())
});
