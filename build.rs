//! Supplies the component adapter binaries that `src/adapt.rs` embeds.
//!
//! The adapter lives in `wasm_abi/adapter` as its own cargo workspace, built
//! for `wasm32-unknown-unknown` in four variants. Rather than commit those
//! binaries — which differ between platforms and go stale whenever someone
//! forgets to rebuild them — this script produces them, and `src/adapt.rs`
//! reads them out of `OUT_DIR`.
//!
//! There are two ways that happens:
//!
//! * In a checkout, the adapter sources are present, so every variant is
//!   rebuilt from them. Editing the adapter, or any of the WITs it binds
//!   against, rebuilds the embedded wasm on the next `cargo build`.
//!
//! * In a published crate they are not: `wasm_abi/adapter` is deliberately
//!   left out of the `include` list in `Cargo.toml`. The prebuilt binaries
//!   shipped in `wasm_abi/data` are used instead, so that building
//!   `viceroy-lib` from crates.io needs neither a wasm target nor network
//!   access. (docs.rs, in particular, builds offline.)
//!
//! Release packaging is what populates `wasm_abi/data`: setting
//! `VICEROY_STAGE_ADAPTER` installs the freshly built binaries there as well,
//! so that `cargo package` can pick them up. See the `package-adapter` target
//! in the Makefile.

use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Where `cargo package` looks for the prebuilt adapter binaries, relative to
/// the manifest directory. The `include` list in `Cargo.toml` and the entry in
/// `.gitignore` name the same directory; neither can read a constant.
const PACKAGED_DATA_DIR: &str = "wasm_abi/data";

/// Set this to any non-empty value to have the freshly built adapter binaries
/// installed into [`PACKAGED_DATA_DIR`] as well as `OUT_DIR`, for release
/// packaging. It is a flag rather than a destination because there is only one
/// directory the packaged crate ever reads them back from.
const STAGE_ENV: &str = "VICEROY_STAGE_ADAPTER";

/// One build of the adapter: the cargo profile to build it under, the feature
/// flags that go with that profile, and the name `src/adapt.rs` expects to
/// find the result under.
struct Variant {
    profile: &'static str,
    features: &'static [&'static str],
    output: &'static str,
}

const VARIANTS: &[Variant] = &[
    // The normal adapter, which includes the exports.
    Variant {
        profile: "release",
        features: &[],
        output: "viceroy-component-adapter.wasm",
    },
    // The non-shift version of the normal adapter, which doesn't shift the
    // memory address and so relies on `cabi_realloc` or `memory.grow` to
    // maintain WASI state.
    Variant {
        profile: "release-noshift",
        features: &["--features", "noshift"],
        output: "viceroy-component-adapter.noshift.wasm",
    },
    // `--no-default-features` disables the default "exports" feature, giving
    // the imports-only "library" adapter used by components that don't
    // provide their own `http_incoming` export.
    Variant {
        profile: "release-library",
        features: &["--no-default-features"],
        output: "viceroy-component-adapter.library.wasm",
    },
    // The non-shift version of the "library" adapter.
    Variant {
        profile: "release-library-noshift",
        features: &["--no-default-features", "--features", "noshift"],
        output: "viceroy-component-adapter.library.noshift.wasm",
    },
];

fn main() -> Result<(), Box<dyn Error>> {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let out_dir = PathBuf::from(std::env::var("OUT_DIR")?);
    let adapter_dir = manifest_dir.join("wasm_abi/adapter");

    println!("cargo::rerun-if-env-changed={STAGE_ENV}");

    if adapter_dir.join("Cargo.toml").is_file() {
        // Changing the adapter's manifest or lockfile changes what gets built,
        // but neither shows up in the dep-info that `build_variant` reads.
        for manifest in ["Cargo.toml", "Cargo.lock"] {
            println!(
                "cargo::rerun-if-changed={}",
                adapter_dir.join(manifest).display()
            );
        }

        let package_dir = std::env::var_os(STAGE_ENV)
            .filter(|value| !value.is_empty())
            .map(|_| manifest_dir.join(PACKAGED_DATA_DIR));
        if let Some(package_dir) = &package_dir {
            std::fs::create_dir_all(package_dir)
                .map_err(|e| format!("creating {}: {e}", package_dir.display()))?;
        }

        for variant in VARIANTS {
            let built = build_variant(&adapter_dir, variant)?;
            install(&built, &out_dir.join(variant.output))?;
            if let Some(package_dir) = &package_dir {
                install(&built, &package_dir.join(variant.output))?;
            }
        }
    } else {
        let data_dir = manifest_dir.join(PACKAGED_DATA_DIR);
        for variant in VARIANTS {
            let prebuilt = data_dir.join(variant.output);
            println!("cargo::rerun-if-changed={}", prebuilt.display());
            if !prebuilt.is_file() {
                return Err(format!(
                    "{} is missing, and there is no adapter source at {} to build it from. \
                     A published crate is supposed to ship this file; if this is a checkout, \
                     the adapter sources have gone missing.",
                    prebuilt.display(),
                    adapter_dir.display(),
                )
                .into());
            }
            install(&prebuilt, &out_dir.join(variant.output))?;
        }
    }

    Ok(())
}

/// Build one variant of the adapter, returning the path of the wasm it
/// produced.
fn build_variant(adapter_dir: &Path, variant: &Variant) -> Result<PathBuf, Box<dyn Error>> {
    // Each variant uses a distinct profile, so a single target directory holds
    // all four without them invalidating each other. Keeping it inside the
    // adapter's own workspace means the four builds are shared across every
    // profile of the outer build instead of being repeated per `OUT_DIR`.
    let target_dir = adapter_dir.join("target");

    // `CARGO` is the cargo running this build script, so the adapter is built
    // with the same toolchain as everything else, whether or not cargo is on
    // `PATH`.
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());

    let status = Command::new(cargo)
        .current_dir(adapter_dir)
        .arg("build")
        .arg("--locked")
        .arg("--package=viceroy-component-adapter")
        .arg("--target=wasm32-unknown-unknown")
        .arg(format!("--profile={}", variant.profile))
        .args(variant.features)
        .env("CARGO_TARGET_DIR", &target_dir)
        // The adapter is a separate workspace with its own lockfile and its
        // own notion of how it must be compiled; don't let the outer build's
        // flags or target selection leak into it.
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_BUILD_RUSTFLAGS")
        .env_remove("CARGO_BUILD_TARGET")
        // `cargo clippy` asks for its driver through these. The adapter is a
        // build input here, not something the outer lint run is checking, so
        // linting it — against the outer command's lint levels, no less —
        // would only turn unrelated lints into build failures.
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .env_remove("CLIPPY_ARGS")
        // Cargo reads this build script's stdout for `cargo::` directives, and
        // a child inherits it. Cargo's own progress output goes to stderr, so
        // nothing is lost by making sure the nested build cannot write there.
        .stdout(Stdio::null())
        .status()
        .map_err(|e| format!("running cargo to build {}: {e}", variant.output))?;

    if !status.success() {
        return Err(format!(
            "building {} failed ({status}). If the failure mentions a missing target, \
             install it with `rustup target add wasm32-unknown-unknown`.",
            variant.output
        )
        .into());
    }

    let built = target_dir
        .join("wasm32-unknown-unknown")
        .join(variant.profile)
        .join("viceroy_component_adapter.wasm");

    rerun_if_sources_changed(&built)?;

    Ok(built)
}

/// Copy `from` to `to`, leaving `to` untouched if it already has the wanted
/// contents so that unchanged output doesn't look like a change to anything
/// watching timestamps.
fn install(from: &Path, to: &Path) -> Result<(), Box<dyn Error>> {
    if let (Ok(current), Ok(wanted)) = (std::fs::read(to), std::fs::read(from))
        && current == wanted
    {
        return Ok(());
    }

    std::fs::copy(from, to)
        .map_err(|e| format!("copying {} to {}: {e}", from.display(), to.display()))?;

    Ok(())
}

/// Emit `rerun-if-changed` for every file rustc recorded as an input of the
/// adapter. That covers the adapter's own sources, its path dependencies, and
/// the WIT files it generates bindings from.
///
/// See <https://doc.rust-lang.org/cargo/reference/build-cache.html#dep-info-files>.
fn rerun_if_sources_changed(artifact: &Path) -> Result<(), Box<dyn Error>> {
    let dep_info = artifact.with_extension("d");
    let contents = std::fs::read_to_string(&dep_info)
        .map_err(|e| format!("reading {}: {e}", dep_info.display()))?;

    for line in contents.lines() {
        // Each line is `<target>: <input> <input> ...`, with spaces in a path
        // escaped as `\ `.
        let Some((_target, inputs)) = line.split_once(": ") else {
            continue;
        };

        let mut parts = inputs.split_whitespace();
        while let Some(part) = parts.next() {
            let mut input = part.to_string();
            while let Some(escaped) = input.strip_suffix('\\') {
                let Some(rest) = parts.next() else {
                    break;
                };
                input = format!("{escaped} {rest}");
            }
            println!("cargo::rerun-if-changed={input}");
        }
    }

    Ok(())
}
