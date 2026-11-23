//! Tests for guest profiling functionality.

use {
    crate::{
        common::{Test, TestResult},
        viceroy_test,
    },
    hyper::StatusCode,
    std::{path::PathBuf, time::Duration},
    test_fixtures_artifacts::FIXTURE_DIR,
    viceroy_lib::ProfilingConfig,
};

viceroy_test!(guest_profiling_works, |is_component| {
    // Create a temporary directory for the profile output
    let temp_dir = tempfile::tempdir()?;
    let profile_dir = temp_dir.path().join("profiles");
    std::fs::create_dir(&profile_dir)?;

    let resp = Test::using_fixture("noop.wasm")
        .adapt_component(is_component)
        .configure_ctx(|ctx| {
            ctx.set_profiling(ProfilingConfig::Guest {
                path: profile_dir.clone(),
                sample_period: Duration::from_micros(50),
            });
        })
        .against_empty()
        .await?;

    // Verify the request succeeded
    assert_eq!(resp.status(), StatusCode::OK);

    // Verify that a profile file was created in the directory
    let profile_files: Vec<_> = std::fs::read_dir(&profile_dir)?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("json"))
        .collect();

    assert!(
        !profile_files.is_empty(),
        "At least one profile JSON file should be created in {:?}",
        profile_dir
    );

    // Verify the first profile file has content and is valid JSON
    let first_profile = &profile_files[0];
    let metadata = std::fs::metadata(first_profile.path())?;
    assert!(metadata.len() > 0, "Profile file should not be empty");

    let profile_content = std::fs::read_to_string(first_profile.path())?;
    let _: serde_json::Value = serde_json::from_str(&profile_content)?;

    Ok(())
});

/// For core modules, profiles give code addresses as offsets into the Wasm binary.
#[tokio::test(flavor = "multi_thread")]
async fn guest_profile_uses_wasm_offsets() -> TestResult {
    let temp_dir = tempfile::tempdir()?;
    let profile_dir = temp_dir.path().join("profiles");
    std::fs::create_dir(&profile_dir)?;

    // This fixture makes hostcalls, and the profiler samples at every hostcall.
    let fixture = "teapot-status.wasm";
    let resp = Test::using_fixture(fixture)
        .configure_ctx(|ctx| {
            ctx.set_profiling(ProfilingConfig::Guest {
                path: profile_dir.clone(),
                sample_period: Duration::from_micros(50),
            });
        })
        .against_empty()
        .await?;
    assert_eq!(resp.status(), StatusCode::IM_A_TEAPOT);

    let wasm = std::fs::read(
        PathBuf::from(FIXTURE_DIR)
            .join("rust")
            .join("wasm32-wasip1")
            .join("debug")
            .join(fixture),
    )?;
    let mut bodies = Vec::new();
    for payload in wasmparser::Parser::new(0).parse_all(&wasm) {
        if let wasmparser::Payload::CodeSectionEntry(body) = payload? {
            bodies.push(body.range());
        }
    }

    let profile_path = std::fs::read_dir(&profile_dir)?
        .next()
        .expect("a profile was written")?
        .path();
    let profile: serde_json::Value = serde_json::from_slice(&std::fs::read(profile_path)?)?;
    let numbers = |pointer: &str| -> Vec<u64> {
        profile
            .pointer(pointer)
            .and_then(serde_json::Value::as_array)
            .unwrap_or_else(|| panic!("profile has {pointer}"))
            .iter()
            .filter_map(serde_json::Value::as_u64)
            .collect()
    };

    let symbols = numbers("/threads/0/nativeSymbols/address");
    assert!(!symbols.is_empty(), "profile has samples");
    for address in symbols {
        assert!(
            bodies.iter().any(|b| b.start == address),
            "symbol address {address:#x} is not the start of a function body"
        );
    }
    for address in numbers("/threads/0/frameTable/address") {
        assert!(
            bodies.iter().any(|b| b.contains(&address)),
            "frame address {address:#x} is not inside a function body"
        );
    }
    Ok(())
}
