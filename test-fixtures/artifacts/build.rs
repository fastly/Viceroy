use anyhow::{Context, Result, anyhow};
use cargo_metadata::{MetadataCommand, TargetKind};
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs, io,
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureCfgEntry {
    #[serde(default)]
    targets: Vec<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureCfgDefaults {
    #[serde(default = "default_targets")]
    targets: Vec<String>,
}

fn default_targets() -> Vec<String> {
    vec!["wasm32-wasip1".to_string()]
}

impl Default for FixtureCfgDefaults {
    fn default() -> Self {
        Self {
            targets: default_targets(),
        }
    }
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureCfg {
    #[serde(default)]
    defaults: FixtureCfgDefaults,
    #[serde(default)]
    fixtures: BTreeMap<String, FixtureCfgEntry>,
}

impl FixtureCfg {
    fn from_file(file: impl AsRef<Path>) -> Result<Self> {
        let mut cfg: FixtureCfg = match fs::read_to_string(file) {
            Ok(data) => toml::from_str(&data).context("failed to parse cfg")?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => Default::default(),
            Err(e) => return Err(e.into()),
        };
        if cfg.defaults.targets.is_empty() {
            cfg.defaults.targets = default_targets();
        }
        Ok(cfg)
    }

    fn targets_for<'a>(&'a self, fixture: &'a str, filter: &'a Option<String>) -> &'a [String] {
        let targets = match self.fixtures.get(fixture) {
            Some(entry) if !entry.targets.is_empty() => &entry.targets,
            _ => &self.defaults.targets,
        };

        if let Some(f) = filter {
            if targets.contains(f) {
                filter.as_slice()
            } else {
                &[]
            }
        } else {
            targets
        }
    }
}

fn main() -> Result<()> {
    let manifest_dir = env::var_os("CARGO_MANIFEST_DIR")
        .ok_or_else(|| anyhow!("CARGO_MANIFEST_DIR is not set"))?;
    let fixtures_dir = fs::canonicalize(PathBuf::from(manifest_dir).parent().unwrap())
        .context("faled to resolve test-fixtures dir")?;
    let fixtures_manifest = fixtures_dir.join("Cargo.toml");
    let fixtures_cfg = fixtures_dir.join("fixtures.toml");
    let out_dir =
        PathBuf::from(env::var_os("OUT_DIR").ok_or_else(|| anyhow!("OUT_DIR is not set"))?);

    println!(
        "cargo::rerun-if-changed={}",
        fixtures_dir.join("src").display()
    );
    println!("cargo::rerun-if-changed={}", fixtures_cfg.display());
    println!("cargo::rerun-if-changed={}", fixtures_manifest.display());
    println!("cargo::rustc-env=VICEROY_FIXTURE_DIR={}", out_dir.display());

    let cfg = FixtureCfg::from_file(&fixtures_cfg)?;
    build_fixtures(&cfg, &fixtures_manifest, &out_dir)
}

fn build_fixtures(cfg: &FixtureCfg, manifest: &Path, out_dir: &Path) -> Result<()> {
    let meta = MetadataCommand::new()
        .manifest_path(manifest)
        .no_deps()
        .exec()
        .map_err(io::Error::other)?;

    let fixtures = meta
        .packages
        .iter()
        .find(|p| p.name == "test-fixtures")
        .ok_or_else(|| io::Error::other("test-fixtures package not found"))?
        .targets
        .iter()
        .filter(|t| t.kind.contains(&TargetKind::Bin))
        .map(|t| t.name.as_str())
        .collect::<BTreeSet<_>>();

    // A key in fixtures.toml which isn't present as a binary is an error.
    for name in cfg.fixtures.keys() {
        if !fixtures.contains(name.as_str()) {
            return Err(anyhow!("fixtures.toml configures unknown fixture `{name}`"));
        }
    }

    // assumes the host build isn't wasm
    // otherwise we can't tell if --target wasn't given
    let target_filter = env::var("TARGET").ok().filter(|t| t.starts_with("wasm"));

    // Group by target, since each `cargo build` accepts only one --target.
    let mut by_target = BTreeMap::<&str, Vec<&str>>::new();
    for fixture in &fixtures {
        let targets = cfg.targets_for(fixture, &target_filter);
        for target in targets {
            by_target.entry(target).or_default().push(fixture);
        }
        if targets.is_empty() {
            println!(
                "cargo:warning=Skipping build for fixture {:?} due to incompatible target {:?}",
                fixture,
                target_filter.as_ref().unwrap()
            )
        }
    }

    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    for (target, fixtures) in by_target {
        let mut cmd = Command::new(&cargo);
        cmd.arg("build")
            .arg("--manifest-path")
            .arg(manifest)
            .arg(format!("--target={target}"))
            .args(fixtures.iter().map(|f| format!("--bin={f}")))
            .env("CARGO_TARGET_DIR", out_dir)
            // Flags meant for the host build of this crate would otherwise be
            // applied to the wasm builds. TODO: need to inherit deny flags?
            .env_remove("CARGO_ENCODED_RUSTFLAGS")
            .env_remove("RUSTFLAGS")
            // Since `test-fixtures` joined the root workspace it inherits the
            // root `[profile.dev] opt-level = 1` override, which changed guest
            // codegen enough to expose a bug in the preview1-adapted component
            // path (a `uri_get` retry with a correctly-sized buffer fails).
            // TODO: fix that bug and drop this override. Pinning fixture
            // builds back to opt-level 0 in the meantime restores their old,
            // known-good codegen.
            .env("CARGO_PROFILE_DEV_OPT_LEVEL", "0");

        eprintln!("running: {cmd:?}");
        let status = cmd.status()?;
        if !status.success() {
            return Err(anyhow!("building fixtures for {target} failed: {status}"));
        }

        // now parse the .d format to tell cargo to rebuild when deps change
        for fix in fixtures {
            rebuild_on_deps_of(&out_dir, &target, &fix)?;
        }
    }

    Ok(())
}

/// Prints cargo directives to rebuild based on the deps file for a built artifact
/// https://doc.rust-lang.org/nightly/cargo/reference/build-cache.html#dep-info-files
fn rebuild_on_deps_of(out_dir: &Path, target: &str, fixture: &str) -> Result<()> {
    let deps = out_dir
        .join(target)
        .join("debug")
        .join(format!("{fixture}.d"));
    let data = fs::read_to_string(&deps)
        .with_context(|| format!("failed to read deps: {}", deps.display()))?;

    for line in data.lines() {
        let line = match line.split_once(": ") {
            None => {
                continue;
            }
            Some((_, suffix)) => suffix,
        };

        // now split on whitespace except where whitespace is escaped with '\'
        for file in split_on_unescaped_whitespace(line) {
            println!("cargo:rerun-if-changed={file}")
        }
    }

    Ok(())
}

fn split_on_unescaped_whitespace(line: &str) -> impl Iterator<Item = String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut chars = line.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '\\' if chars.peek().is_some_and(|next| next.is_whitespace()) => {
                current.push(chars.next().unwrap());
            }
            c if c.is_whitespace() => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            c => current.push(c),
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }

    tokens.into_iter()
}
