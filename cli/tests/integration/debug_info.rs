//! Tests for running guests compiled with native debug info.

use {
    crate::{
        common::{Test, TestResult},
        viceroy_test,
    },
    hyper::{StatusCode, body},
};

// `write-and-read-body.wasm` is the fixture whose DWARF originally blocked enabling `debug_info`
// (see https://github.com/fastly/Viceroy/issues/52), so it is the one to exercise here. The
// fixtures are built as debug artifacts, so they carry the DWARF that wasmtime has to translate.
viceroy_test!(guests_run_with_debug_info_enabled, |is_component| {
    let resp = Test::using_fixture("write-and-read-body.wasm")
        .debug_info(true)
        .adapt_component(is_component)
        .against_empty()
        .await?;
    assert_eq!(resp.status(), StatusCode::OK);
    Ok(())
});

viceroy_test!(bodies_are_unaffected_by_debug_info, |is_component| {
    let resp = Test::using_fixture("write-body.wasm")
        .debug_info(true)
        .adapt_component(is_component)
        .against_empty()
        .await?;

    let body = body::to_bytes(resp.into_body())
        .await
        .expect("can read body")
        .to_vec();
    assert_eq!(String::from_utf8(body)?, "Hello, Viceroy!");

    Ok(())
});
