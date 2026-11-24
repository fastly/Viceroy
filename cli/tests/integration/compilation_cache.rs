//! Tests for caching compiled guests with `ExecuteCtxBuilder::set_compilation_cache`.

use {
    crate::{
        common::{Test, TestResult},
        viceroy_test,
    },
    hyper::StatusCode,
};

/// A fresh cache in its own directory, so the counts below aren't affected by other tests.
fn fresh_cache() -> Result<(tempfile::TempDir, wasmtime::Cache), crate::common::Error> {
    let dir = tempfile::tempdir()?;
    let mut config = wasmtime::CacheConfig::new();
    config.with_directory(dir.path());
    Ok((dir, wasmtime::Cache::new(config)?))
}

// Starting a guest that was compiled before with the same cache loads it from the cache, and
// the loaded guest serves requests.
viceroy_test!(cached_guest_is_reused, |is_component| {
    let (_dir, cache) = fresh_cache()?;
    let test = || {
        Test::using_fixture("write-body.wasm")
            .adapt_component(is_component)
            .configure_ctx(|ctx| ctx.set_compilation_cache(Some(cache.clone())))
    };

    test().start().await?;
    let misses = cache.cache_misses();
    assert!(misses > 0, "the first start compiles the guest");
    assert_eq!(cache.cache_hits(), 0);

    let resp = test().against_empty().await?;
    assert_eq!(
        cache.cache_misses(),
        misses,
        "the second start doesn't compile"
    );
    assert!(
        cache.cache_hits() > 0,
        "the second start loads from the cache"
    );

    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().read_into_vec().await?;
    assert_eq!(String::from_utf8(body)?, "Hello, Viceroy!");
    Ok(())
});

// Guests compiled with different settings don't share cache entries, so changing a setting
// can't load a guest compiled without it.
viceroy_test!(settings_changes_miss_the_cache, |is_component| {
    let (_dir, cache) = fresh_cache()?;
    let test = |debug_info| {
        Test::using_fixture("write-body.wasm")
            .adapt_component(is_component)
            .configure_ctx(|ctx| {
                ctx.set_compilation_cache(Some(cache.clone()));
                ctx.set_debug_info(debug_info);
            })
    };

    test(false).start().await?;
    let misses = cache.cache_misses();
    assert!(misses > 0, "the first start compiles the guest");

    test(true).start().await?;
    assert!(
        cache.cache_misses() > misses,
        "changing debug info compiles the guest again"
    );
    assert_eq!(cache.cache_hits(), 0);
    Ok(())
});
