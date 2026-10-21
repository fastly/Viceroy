use std::{collections::BTreeSet, env, fs, path::PathBuf};

use crate::build_support::{
    cfg::{BuildFilters, FixtureCfg, FixtureCfgEntry, LangDefaults, Language, Target},
    state::BuildState,
};
use anyhow::{Context, Result, anyhow};

mod build_support;

fn main() -> Result<()> {
    let manifest_dir = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR")
            .ok_or_else(|| anyhow!("CARGO_MANIFEST_DIR is not set"))?,
    );
    let fixtures_dir = fs::canonicalize(manifest_dir.parent().unwrap())
        .context("failed to resolve test-fixtures dir")?;
    let fixtures_manifest = fixtures_dir.join("Cargo.toml");
    let fixtures_cfg = fixtures_dir.join("fixtures.toml");
    let out_dir =
        PathBuf::from(env::var_os("OUT_DIR").ok_or_else(|| anyhow!("OUT_DIR is not set"))?);

    // For now we only support Rust since we haven't set up the Go toolchain in CI
    // or for devs. This will change later when we have a good way to ensure it's always
    // available (nix dev shell?).
    let def_langs = BTreeSet::from_iter([Language::Rust]);

    // constructed here so that fixtures in BuildState can hold
    // references, since a self-referential struct can't be expressed
    // easily in Rust.
    let cfg = FixtureCfg::from_file(&fixtures_cfg)?;
    let defaults = LangDefaults {
        rust: FixtureCfgEntry::new([Language::Rust], [Target::Wasm32Wasip1]).with_env([
            // Flags meant for the host build of this crate would otherwise be
            // applied to the wasm builds. TODO: need to inherit deny flags?
            ("RUSTFLAGS", None),
            ("CARGO_ENCODED_RUSTFLAGS", None),
            // `cargo clippy` runs an ordinary build with this pointed at
            // clippy-driver, and the nested cargo we spawn here inherits it.
            // The fixtures are workspace members, so they'd be linted as if
            // they were host code and clippy's deny-by-default lints would
            // fail the build. An empty value means "no wrapper" and, unlike
            // removing the variable, also overrides a `build.rustc-workspace-wrapper`
            // set in cargo config. `RUSTC_WRAPPER` is deliberately left alone
            // so build caches like sccache still apply to fixture builds.
            ("RUSTC_WORKSPACE_WRAPPER", Some(String::new())),
        ]),
        go: FixtureCfgEntry::new([Language::Go, Language::TinyGo], [Target::Wasm32Wasip1]),
    };

    let mut state = BuildState::new(
        &cfg,
        &defaults,
        BuildFilters::from_env("FIXTURE_LANGS", def_langs)?,
        fixtures_manifest,
        out_dir,
    );

    state.discover_fixtures()?;
    state.build_fixtures()?;
    state.emit_deps();
    println!("cargo:rerun-if-env-changed=FIXTURE_LANGS");
    // this may be overly wide - changes to files which aren't build inputs (e.g. markdown)
    // could be captured by this if under the src dir.
    // Maybe instead we have each build driver capture the files that participated?
    // We already do so by reading the .d files for rust, and go can list the source files
    // with a separate command (though it would be nice to just emit a .d somehow)
    println!(
        "cargo::rerun-if-changed={}",
        fixtures_dir.join("src").display()
    );
    // need to rebuild if any of the source files for our build script changed
    println!(
        "cargo:rerun-if-changed={}",
        manifest_dir.join("build_support").display()
    );

    Ok(())
}
