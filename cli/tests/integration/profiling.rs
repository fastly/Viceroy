//! Tests for guest profiling functionality.

use {
    crate::{
        common::{Test, TestResult},
        viceroy_test,
    },
    hyper::StatusCode,
    std::{
        path::{Path, PathBuf},
        time::Duration,
    },
    test_fixtures_artifacts::FIXTURE_DIR,
    viceroy_lib::ProfilingConfig,
};

/// Waits for a profile to be written to `dir`, returning its path.
///
/// Profiles are written after the response is sent, so they may not exist
/// yet when the test gets the response.
async fn wait_for_profile(dir: &Path) -> Result<PathBuf, std::io::Error> {
    for _ in 0..100 {
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                return Ok(path);
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("no profile was written to {}", dir.display());
}

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

    // Verify the profile file has content and is valid JSON
    let profile_path = wait_for_profile(&profile_dir).await?;
    let metadata = std::fs::metadata(&profile_path)?;
    assert!(metadata.len() > 0, "Profile file should not be empty");

    let profile_content = std::fs::read_to_string(&profile_path)?;
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

    let profile_path = wait_for_profile(&profile_dir).await?;
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

    let frames = numbers("/threads/0/frameTable/address");
    assert!(!frames.is_empty(), "profile has sampled frames");
    let symbols = numbers("/threads/0/nativeSymbols/address");
    assert!(!symbols.is_empty(), "profile has native symbols");
    for address in symbols {
        assert!(
            bodies.iter().any(|b| b.start == address),
            "symbol address {address:#x} is not the start of a function body"
        );
    }
    for address in frames {
        assert!(
            bodies.iter().any(|b| b.contains(&address)),
            "frame address {address:#x} is not inside a function body"
        );
    }
    Ok(())
}
