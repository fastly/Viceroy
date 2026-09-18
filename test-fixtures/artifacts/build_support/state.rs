use anyhow::{Context, Result, anyhow, bail};
use cargo_metadata::{MetadataCommand, TargetKind};
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs, io,
    path::{Path, PathBuf},
    process::Command,
};

use crate::build_support::cfg::{
    BuildFilters, FixtureCfg, FixtureCfgEntry, LangDefaults, Language, Target,
};

type EnvMap = Vec<(String, Option<String>)>;

#[derive(Debug, Clone)]
pub struct FixtureCfgEntryRef<'a> {
    name: String,
    src: String,
    // properties from the config
    targets: &'a BTreeSet<Target>,
    languages: &'a BTreeSet<Language>,
    env: EnvMap,
}

type Fixtures<'a> = BTreeMap<String, FixtureCfgEntryRef<'a>>;

/// The build parameters shared by every fixture in a group. Toolchains like
/// cargo and go build many binaries in one invocation, so fixtures which agree
/// on these can be built together.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct BuildGroup {
    target: Target,
    env: EnvMap,
}

pub struct BuildState<'a> {
    cfg: &'a FixtureCfg,
    defaults: &'a LangDefaults,
    filters: BuildFilters,
    manifest: PathBuf,
    out_dir: PathBuf,
    // fixtures that we discover through discover_fixtures
    fixtures: Fixtures<'a>,
    // dependencies to trigger rebuilds
    deps: BTreeSet<PathBuf>,
}

impl<'a> BuildState<'a> {
    pub fn new<'b>(
        cfg: &'b FixtureCfg,
        defaults: &'b LangDefaults,
        filters: BuildFilters,
        manifest: PathBuf,
        out_dir: PathBuf,
    ) -> BuildState<'b> {
        let deps = BTreeSet::from_iter([manifest.clone(), cfg.src().to_path_buf()]);

        BuildState {
            cfg,
            defaults,
            filters,
            manifest,
            out_dir,
            fixtures: BTreeMap::new(),
            deps,
        }
    }

    pub fn emit_deps(&self) {
        println!(
            "cargo::rustc-env=VICEROY_FIXTURE_DIR={}",
            self.out_dir.display()
        );

        for dep in &self.deps {
            println!("cargo:rerun-if-changed={}", dep.display());
        }
    }

    fn insert_fixtures(
        &mut self,
        fixtures: impl IntoIterator<Item = FixtureCfgEntryRef<'a>>,
    ) -> Result<()> {
        for fixture in fixtures {
            if let Some(existing) = self.fixtures.insert(fixture.name.clone(), fixture) {
                bail!(
                    "duplicate fixture found: {} and {}",
                    &existing.src,
                    &self.fixtures.get(&existing.name).unwrap().src
                )
            }
        }

        Ok(())
    }

    fn discover_rust_fixtures(&mut self) -> Result<()> {
        if !self.filters.languages().contains(&Language::Rust) {
            return Ok(());
        }

        let meta = MetadataCommand::new()
            .manifest_path(&self.manifest)
            .no_deps()
            .exec()
            .context("failed to run cargo metadata")?;

        let rust_fixtures = meta
            .packages
            .into_iter()
            .find(|p| p.name == "test-fixtures")
            .ok_or_else(|| io::Error::other("test-fixtures package not found"))?
            .targets
            .into_iter()
            .filter(|t| t.kind.contains(&TargetKind::Bin))
            .map(|t| {
                BuildState::get_fixture(
                    self.cfg,
                    t.name,
                    t.src_path.into_string(),
                    &self.defaults.rust,
                )
            });

        self.insert_fixtures(rust_fixtures)
    }

    fn go_cmd(&self, bin: &str) -> Command {
        let mut cmd = Command::new(bin);
        cmd.current_dir(self.manifest.parent().unwrap().join("src").join("go"));
        cmd
    }

    fn discover_go_fixtures(&mut self) -> Result<()> {
        if !self.filters.languages().contains(&Language::Go)
            && !self.filters.languages().contains(&Language::TinyGo)
        {
            return Ok(());
        }

        let go_fixtures = self
            .go_cmd("go")
            .arg("list")
            .arg("-f")
            // import path can't contain a space so its a fine separator
            .arg("{{if eq .Name \"main\"}}{{.ImportPath}} {{.Dir}}{{end}}")
            .arg("./...")
            .output()
            .context("failed to run `go list`")?;

        if !go_fixtures.status.success() {
            return Err(anyhow!(
                "`go list` failed with exit code {}: {}",
                go_fixtures.status,
                String::from_utf8_lossy(&go_fixtures.stderr)
            ));
        }

        let go_fixtures = String::from_utf8(go_fixtures.stdout)
            .context("failed to parse `go list` output as UTF-8")?;

        let go_fixtures = go_fixtures
            .lines()
            .filter_map(|line| {
                let (path, dir) = line.split_once(' ')?;
                let name = PathBuf::from(path)
                    .file_stem()
                    .ok_or_else(|| anyhow!("invalid import path: {}", path))
                    .map(|s| s.to_string_lossy().to_string());
                let fix = name.map(|name| {
                    BuildState::get_fixture(self.cfg, name, dir.to_string(), &self.defaults.go)
                });
                Some(fix)
            })
            .collect::<Result<Vec<_>>>()?;

        self.insert_fixtures(go_fixtures)
    }

    pub fn discover_fixtures(&mut self) -> Result<()> {
        self.discover_rust_fixtures()?;
        self.discover_go_fixtures()?;

        // this always errors if lang filter is set and config defines a conflicting fixture
        // since discovery is skipped for unselected languages
        // // A key in fixtures.toml which isn't present as source code is an error
        // for name in self.cfg.fixtures().keys() {
        //     if !self.fixtures.contains_key(name) {
        //         return Err(anyhow!("fixtures.toml configures unknown fixture `{name}`"));
        //     }
        // }

        Ok(())
    }

    pub fn build_fixtures(&mut self) -> Result<()> {
        self.build_rust_fixtures()?;
        self.build_tinygo_fixtures()?;
        self.build_go_fixtures()?;

        // always print the out directory so users can find the built artifacts
        println!("cargo:warning=fixtures built to {}", self.out_dir.display());

        Ok(())
    }

    fn build_go_fixtures(&mut self) -> Result<()> {
        if !self.filters.languages().contains(&Language::Go) {
            eprintln!("cargo:warning=skipping go fixture build since it is not in the filter");
            return Ok(());
        }

        let by_group = BuildState::group_fixtures(&self.fixtures, &self.filters, Language::Go);
        eprintln!("building {} go fixture groups", by_group.len());

        let out_dir = self.out_dir.join("go");

        for (group, fixtures) in by_group {
            let target = group.target;

            let target_dir = out_dir.join(target.to_string());
            fs::create_dir_all(&target_dir).context("failed to create out dir")?;

            let mut cmd = self.go_cmd("go");
            BuildState::set_env(&mut cmd, &group.env);

            cmd.arg("build")
                .arg("-o")
                .arg(&target_dir)
                .args(fixtures.iter().map(|f| &f.src));

            match target {
                Target::Wasm32Wasip1 => {
                    cmd.env("GOOS", "wasip1");
                    cmd.env("GOARCH", "wasm");
                }
                _ => {
                    return Err(anyhow!("unsupported go target: {target}"));
                }
            }

            eprintln!("running: {cmd:?}");
            let status = cmd.status()?;
            if !status.success() {
                return Err(anyhow!("building fixtures for {target} failed: {status}"));
            }

            // go doesn't add an extension to the output files, so for parity with tinygo
            // and rust we rename them to .wasm
            for fix in fixtures {
                let src = target_dir.join(&fix.name);
                let dst = target_dir.join(format!("{}.wasm", fix.name));
                fs::rename(&src, &dst).with_context(|| {
                    format!(
                        "failed to rename go fixture {} to {}",
                        src.display(),
                        dst.display()
                    )
                })?;
            }
        }

        Ok(())
    }

    fn build_tinygo_fixtures(&mut self) -> Result<()> {
        if !self.filters.languages().contains(&Language::TinyGo) {
            eprintln!("cargo:warning=skipping tinygo fixture build since it is not in the filter");
            return Ok(());
        }

        let by_group = BuildState::group_fixtures(&self.fixtures, &self.filters, Language::TinyGo);
        eprintln!("building {} tinygo fixture groups", by_group.len());

        let out_dir = self.out_dir.join("tinygo");

        for (group, fixtures) in by_group {
            let target = group.target;

            let target_dir = out_dir.join(target.to_string());
            fs::create_dir_all(&target_dir).context("failed to create out dir")?;

            // tinygo build doesn't support multiple packages
            // unlike cargo and go. We must iterate over the fixtures and build them one at a time.
            // TODO: parallelize?

            for fix in fixtures {
                let mut cmd = self.go_cmd("tinygo");
                BuildState::set_env(&mut cmd, &group.env);

                cmd.arg("build")
                    .arg("-o")
                    .arg(target_dir.join(format!("{}.wasm", fix.name)));

                match target {
                    Target::Wasm32Wasip1 => {
                        cmd.arg("-target=wasip1");
                    }
                    _ => {
                        return Err(anyhow!("unsupported tinygo target: {target}"));
                    }
                }

                cmd.arg(&fix.src);

                eprintln!("running: {cmd:?}");
                let out = cmd.output().context("failed to run tinygo build")?;
                if !out.status.success() {
                    println!(
                        "tinygo build failed with exit code {}: {}",
                        out.status,
                        String::from_utf8_lossy(&out.stderr)
                    );
                    return Err(anyhow!(
                        "building fixtures for {target} failed: {}",
                        out.status
                    ));
                }
            }
        }

        Ok(())
    }

    fn build_rust_fixtures(&mut self) -> Result<()> {
        if !self.filters.languages().contains(&Language::Rust) {
            eprintln!("cargo:warning=skipping rust fixture build since it is not in the filter");
            return Ok(());
        }

        let by_group = BuildState::group_fixtures(&self.fixtures, &self.filters, Language::Rust);

        let out_dir = self.out_dir.join("rust");

        let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        for (group, fixtures) in by_group {
            let target = group.target;

            let mut cmd = Command::new(&cargo);
            cmd.arg("build")
                .arg("--manifest-path")
                .arg(&self.manifest)
                .arg(format!("--target={target}"))
                .args(fixtures.iter().map(|f| format!("--bin={}", f.name)));

            BuildState::set_env(&mut cmd, &group.env);

            // we don't allow overriding the target dir through config so set it last
            cmd.env("CARGO_TARGET_DIR", &out_dir);

            eprintln!("running: {cmd:?}");
            let status = cmd.status()?;
            if !status.success() {
                return Err(anyhow!("building fixtures for {target} failed: {status}"));
            }

            // now parse the .d format to tell cargo to rebuild when deps change
            for fix in fixtures {
                let dep_file = out_dir
                    .join(target.to_string())
                    .join("debug")
                    .join(format!("{}.d", fix.name));
                self.rebuild_on_deps_of(&dep_file)?;
            }
        }

        Ok(())
    }

    fn set_env(cmd: &mut Command, env: &EnvMap) {
        for (k, v) in env.iter() {
            match v {
                Some(v) => cmd.env(k, v),
                None => cmd.env_remove(k),
            };
        }
    }

    /// Filters to fixtures with the given language and the target filter, then
    /// groups the survivors by the build parameters they share, so each group
    /// can be built with a single invocation of the toolchain.
    fn group_fixtures(
        fixtures: &Fixtures<'a>,
        filters: &BuildFilters,
        lang: Language,
    ) -> BTreeMap<BuildGroup, Vec<FixtureCfgEntryRef<'a>>> {
        let mut by_group = BTreeMap::<BuildGroup, Vec<FixtureCfgEntryRef<'a>>>::new();
        let mut skipped = BTreeMap::<Target, usize>::new();

        for fixture in fixtures.values() {
            if !fixture.languages.contains(&lang) {
                continue;
            }

            for target in fixture.targets {
                if let Some(filter) = filters.target()
                    && target != filter
                {
                    *skipped.entry(*target).or_default() += 1;
                    continue;
                }

                let group = BuildGroup {
                    target: *target,
                    env: fixture.env.clone(),
                };
                by_group.entry(group).or_default().push(fixture.clone());
            }
        }

        // only ever populated when a filter is set
        // we don't emit a warning for fixtures skipped by language
        // since we don't discover them in the first place if the
        // lang filter doesn't match
        if let Some(filter) = filters.target() {
            for (target, count) in skipped {
                println!(
                    "cargo:warning=skipping build of {count} fixtures for target {target} which doesn't match filter {filter}"
                );
            }
        }

        by_group
    }

    /// Prints cargo directives to rebuild based on the deps file for a built artifact
    /// https://doc.rust-lang.org/nightly/cargo/reference/build-cache.html#dep-info-files
    fn rebuild_on_deps_of(&mut self, dep_file: &Path) -> Result<()> {
        let data = fs::read_to_string(dep_file)
            .with_context(|| format!("failed to read deps: {}", dep_file.display()))?;

        for line in data.lines() {
            let line = match line.split_once(": ") {
                None => {
                    continue;
                }
                Some((_, suffix)) => suffix,
            };

            // now split on whitespace except where whitespace is escaped with '\'
            for file in split_on_unescaped_whitespace(line) {
                self.deps.insert(PathBuf::from(&file));
            }
        }

        Ok(())
    }

    // must be a free function and not a method on BuildState otherwise it would
    // borrow BuildState and hold it when we later borrow mutably to insert the
    // fixtures, despite us only using cfg & defaults which have their own lifetimes.
    fn get_fixture(
        cfg: &'a FixtureCfg,
        name: String,
        src: String,
        defaults: &'a FixtureCfgEntry,
    ) -> FixtureCfgEntryRef<'a> {
        let entry = cfg.fixtures().get(&name);

        match entry {
            Some(entry) => FixtureCfgEntryRef {
                name,
                src,
                targets: def_if_empty(entry.targets(), defaults.targets()),
                languages: def_if_empty(entry.languages(), defaults.languages()),
                env: env_map_with_defaults(entry.env(), defaults.env()),
            },
            None => FixtureCfgEntryRef {
                name,
                src,
                targets: defaults.targets(),
                languages: defaults.languages(),
                env: defaults
                    .env()
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect(),
            },
        }
    }
}

fn env_map_with_defaults(
    env: &BTreeMap<String, Option<String>>,
    defaults: &BTreeMap<String, Option<String>>,
) -> EnvMap {
    let mut merged = Vec::new();

    for (k, v) in defaults {
        if !env.contains_key(k) {
            merged.push((k.clone(), v.clone()));
        }
    }

    for (k, v) in env {
        merged.push((k.clone(), v.clone()));
    }

    merged
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

fn def_if_empty<'a, T>(set: &'a BTreeSet<T>, def: &'a BTreeSet<T>) -> &'a BTreeSet<T>
where
    T: Clone + Ord,
{
    if set.is_empty() { def } else { set }
}
