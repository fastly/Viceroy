use {
    crate::{
        common::{Test, TestResult},
        viceroy_test,
    },
    hyper::StatusCode,
};

viceroy_test!(cache, |is_component| {
    if !std::env::var("ENABLE_EXPERIMENTAL_CACHE_API").is_ok_and(|v| v == "1") {
        eprintln!("WARNING: Skipping cache tests.");
        eprintln!(
            "Set ENABLE_EXPERIMENTAL_CACHE_API=1 to enable experimental cache API and run tests."
        );
        return Ok(());
    }

    let resp = Test::using_fixture("cache.wasm")
        .adapt_component(is_component)
        .against_empty()
        .await?;
    assert_eq!(resp.status(), StatusCode::OK);
    Ok(())
});
