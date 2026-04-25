use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    // Only rebuild if the adapter source changes
    println!("cargo:rerun-if-changed=wasm_abi/adapter");

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let adapter_dir = manifest_dir.join("wasm_abi/adapter");
    let data_dir = manifest_dir.join("wasm_abi/data");

    // Ensure the data directory exists
    std::fs::create_dir_all(&data_dir).expect("Failed to create wasm_abi/data directory");

    // Get the cargo command to use (allows for override like in Makefile)
    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());

    // Build the component adapter for adapting the host-call abi to the
    // component model. This version uses `--no-default-features` to disable
    // the default "exports" feature, to build the imports-only "library"
    // version of the adapter.
    build_adapter(
        &cargo,
        &adapter_dir,
        &data_dir,
        "release-library",
        &["--no-default-features"],
        "viceroy-component-adapter.library.wasm",
    );

    // Build the non-shift "library" version of the adapter.
    build_adapter(
        &cargo,
        &adapter_dir,
        &data_dir,
        "release-library-noshift",
        &["--no-default-features", "--features", "noshift"],
        "viceroy-component-adapter.library.noshift.wasm",
    );

    // Build the component adapter for adapting the host-call abi to the
    // component model. This is the normal version that includes the exports.
    build_adapter(
        &cargo,
        &adapter_dir,
        &data_dir,
        "release",
        &[],
        "viceroy-component-adapter.wasm",
    );

    // Build the non-shift normal version of the adapter.
    build_adapter(
        &cargo,
        &adapter_dir,
        &data_dir,
        "release-noshift",
        &["--features", "noshift"],
        "viceroy-component-adapter.noshift.wasm",
    );
}

fn build_adapter(
    cargo: &str,
    adapter_dir: &Path,
    data_dir: &Path,
    profile: &str,
    extra_args: &[&str],
    output_name: &str,
) {
    eprintln!("Building adapter variant: {}", output_name);

    let mut cmd = Command::new(cargo);
    cmd.current_dir(adapter_dir)
        .arg("build")
        .arg("--package")
        .arg("viceroy-component-adapter")
        .arg("--target")
        .arg("wasm32-unknown-unknown")
        .arg("--profile")
        .arg(profile);

    // Add any extra arguments (like --no-default-features or --features)
    for arg in extra_args {
        cmd.arg(arg);
    }

    let status = cmd
        .status()
        .unwrap_or_else(|e| panic!("Failed to execute cargo build for {}: {}", output_name, e));

    if !status.success() {
        panic!("Failed to build adapter variant: {}", output_name);
    }

    // Copy the built wasm file to the data directory
    let source = adapter_dir
        .join("target/wasm32-unknown-unknown")
        .join(profile)
        .join("viceroy_component_adapter.wasm");

    let dest = data_dir.join(output_name);

    std::fs::copy(&source, &dest).unwrap_or_else(|e| {
        panic!(
            "Failed to copy {} to {}: {}",
            source.display(),
            dest.display(),
            e
        )
    });

    eprintln!("Successfully built and copied {}", output_name);
}
