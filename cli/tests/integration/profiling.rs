//! Tests for guest profiling functionality.

use {
    crate::{
        common::{Test, TestResult},
        viceroy_test,
    },
    hyper::StatusCode,
    std::time::Duration,
    viceroy_lib::GuestProfileConfig,
};

viceroy_test!(guest_profiling_works, |is_component| {
    // Create a temporary directory for the profile output
    let temp_dir = tempfile::tempdir()?;
    let profile_dir = temp_dir.path().join("profiles");
    std::fs::create_dir(&profile_dir)?;

    let resp = Test::using_fixture("noop.wasm")
        .adapt_component(is_component)
        .with_guest_profiling(GuestProfileConfig {
            path: profile_dir.clone(),
            sample_period: Duration::from_micros(50),
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
