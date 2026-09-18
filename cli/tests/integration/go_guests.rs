//! Tests for guests built with the Go toolchains.
//!
//! Both Go runtimes lay out linear memory very differently from Rust's, and both used to
//! collide with the component adapter's own pages on startup: TinyGo in
//! [issue #491](https://github.com/fastly/Viceroy/issues/491) and "big" Go in
//! [issue #498](https://github.com/fastly/Viceroy/issues/498). The fix (shifting the
//! adapter's pages out of the guest's way, in
//! [#538](https://github.com/fastly/Viceroy/pull/538)) is only exercised on the component
//! path, but each test runs against core wasm too so we notice if the two diverge.
//!
//! The Go toolchains are not required to build Viceroy, so these tests skip themselves when
//! their fixture is absent. See `test-fixtures/README.md` for how to build them.

use {
    crate::{
        common::{GoToolchain, TestResult},
        go_fixture, viceroy_test,
    },
    hyper::{Request, StatusCode, body},
};

// A TinyGo guest that registers a handler and does nothing else is the smallest program
// that reproduced #491: the runtime's startup alone was enough to trample the adapter.
viceroy_test!(tinygo_guest_with_empty_handler, |is_component| {
    let resp = go_fixture!(GoToolchain::TinyGo, "empty-main.wasm")
        .adapt_component(is_component)
        .against_empty()
        .await?;

    assert_eq!(resp.status(), StatusCode::OK);
    let body = body::to_bytes(resp.into_body()).await?;
    assert!(body.is_empty(), "expected an empty body, got {body:?}");

    Ok(())
});

// The baseline for #498: a "big" Go guest that only writes a response proves the Fastly ABI
// round-trips at all before the heavier scenarios below lean on it.
viceroy_test!(go_guest_responds, |is_component| {
    let resp = go_fixture!(GoToolchain::Go, "sdk-guest.wasm")
        .adapt_component(is_component)
        .against_empty()
        .await?;

    assert_eq!(resp.status(), StatusCode::OK);
    let body = body::to_bytes(resp.into_body()).await?;
    assert_eq!(String::from_utf8(body.to_vec())?, "Hello, Viceroy!\n");

    Ok(())
});

// Allocating past the initial heap forces Go's collector to run and linear memory to grow,
// which is what originally walked over the adapter's state. The checksum is how we tell a
// surviving heap from a corrupted one.
viceroy_test!(go_guest_survives_garbage_collection, |is_component| {
    let resp = go_fixture!(GoToolchain::Go, "sdk-guest.wasm")
        .adapt_component(is_component)
        .against(Request::get("/gc").body("")?)
        .await?;

    assert_eq!(resp.status(), StatusCode::OK);
    let body = body::to_bytes(resp.into_body()).await?;

    // The fixture fills 512 chunks of 16 KiB with `byte(i + j)`. Each chunk spans every byte
    // value exactly 16384 / 256 = 64 times regardless of which chunk it is, so the total is
    // a closed form. Keep in step with the fixture's loop bounds.
    const BYTE_VALUE_SUM: u64 = 255 * 256 / 2;
    const EXPECTED: u64 = 512 * 64 * BYTE_VALUE_SUM;
    assert_eq!(
        String::from_utf8(body.to_vec())?,
        format!("checksum {EXPECTED}\n")
    );

    Ok(())
});

// `crypto/rand` goes through WASI's `random_get`, the call that used to trap once the guest
// runtime had moved in on top of the adapter.
viceroy_test!(go_guest_reads_random_bytes, |is_component| {
    let resp = go_fixture!(GoToolchain::Go, "sdk-guest.wasm")
        .adapt_component(is_component)
        .against(Request::get("/random").body("")?)
        .await?;

    assert_eq!(resp.status(), StatusCode::OK);
    let body = body::to_bytes(resp.into_body()).await?;
    let hex = String::from_utf8(body.to_vec())?;
    let hex = hex.trim_end();

    // 32 bytes, hex encoded by the guest.
    assert_eq!(hex.len(), 64, "unexpected response: {hex:?}");
    assert!(
        hex.chars().all(|c| c.is_ascii_hexdigit()),
        "not hex: {hex:?}"
    );
    // A zero-filled buffer would still be valid hex, but it would mean `random_get` silently
    // did nothing rather than filling the guest's buffer.
    assert!(
        hex.chars().any(|c| c != '0'),
        "random bytes were all zero: {hex:?}"
    );

    Ok(())
});

// Echoing the request body moves bytes through buffers the guest owns, in both directions,
// which is the part of the ABI most likely to notice memory the adapter and the guest
// disagree about.
viceroy_test!(go_guest_echoes_request_body, |is_component| {
    const BODY: &str = "a body that has to survive the round trip through guest memory";

    let resp = go_fixture!(GoToolchain::Go, "sdk-guest.wasm")
        .adapt_component(is_component)
        .against(Request::post("/echo").body(BODY)?)
        .await?;

    assert_eq!(resp.status(), StatusCode::OK);
    let body = body::to_bytes(resp.into_body()).await?;
    assert_eq!(String::from_utf8(body.to_vec())?, BODY);

    Ok(())
});
