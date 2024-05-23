use std::{path::PathBuf, process::Command};

fn main() {
    build_adapter()
}

fn build_adapter() {
    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").unwrap());

    // ensure that we rebuild the artifacts if the adapter is changed
    println!("cargo:rerun-if-changed=../adapter/src");
    println!("cargo:rerun-if-changed=../../lib/wit");

    let mut cmd = Command::new("cargo");

    cmd.arg("build")
        .arg("--release")
        .arg("--package=viceroy-component-adapter")
        .arg("--target=wasm32-unknown-unknown")
        .env("CARGO_TARGET_DIR", &out_dir)
        .env_remove("CARGO_ENCODED_RUSTFLAGS");

    eprintln!("running: {cmd:?}");
    let status = cmd.status().unwrap();
    assert!(status.success());

    let adapter = out_dir.join(format!("wasi_snapshot_preview1.wasm"));

    std::fs::copy(
        out_dir
            .join("wasm32-unknown-unknown")
            .join("release")
            .join("wasi_snapshot_preview1.wasm"),
        &adapter,
    )
    .unwrap();

    let mut generated_code = String::new();

    generated_code +=
        &format!("pub const ADAPTER_BYTES: &'static [u8] = include_bytes!({adapter:?});\n");

    std::fs::write(out_dir.join("gen.rs"), generated_code).unwrap();
}
