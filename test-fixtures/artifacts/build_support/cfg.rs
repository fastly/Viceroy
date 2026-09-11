use std::{
    collections::{BTreeMap, BTreeSet},
    env, fmt, fs, io,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use strum::{EnumString, VariantArray};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, EnumString, VariantArray, serde::Deserialize,
)]
#[strum(serialize_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum Language {
    Go,
    TinyGo,
    Rust,
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    EnumString,
    VariantArray,
    strum::Display,
    serde::Deserialize,
)]
pub enum Target {
    #[serde(rename = "wasm32-wasip1")]
    #[strum(serialize = "wasm32-wasip1")]
    Wasm32Wasip1,
    #[serde(rename = "wasm32-wasip2")]
    #[strum(serialize = "wasm32-wasip2")]
    Wasm32Wasip2,
}

#[derive(Debug, Clone)]
pub struct BuildFilters {
    target: Option<Target>,
    languages: BTreeSet<Language>,
}

impl BuildFilters {
    pub fn from_env(lang_env: &str, def_langs: BTreeSet<Language>) -> Result<Self> {
        let host = env::var("HOST").ok().context("HOST is not set")?;
        let ret = Self {
            target: env::var("TARGET")
                .ok()
                // TARGET defaults to the host target which isn't wasm
                // if we just parse blindly then we'd always fail
                // Perhaps we should just compare to
                .filter(|t| *t != host)
                .map(|t| t.parse())
                .transpose()
                .context("invalid TARGET")?,
            languages: env::var(lang_env)
                .ok()
                .map(|s| {
                    s.split(',')
                        .map(|s| s.trim().to_lowercase().parse())
                        .collect::<Result<_, _>>()
                })
                .transpose()
                .context("invalid FIXTURE_LANGS")?
                .unwrap_or(def_langs),
        };
        Ok(ret)
    }

    pub fn languages(&self) -> &BTreeSet<Language> {
        &self.languages
    }

    pub fn target(&self) -> &Option<Target> {
        &self.target
    }
}

#[derive(Debug, Clone)]
pub struct LangDefaults {
    pub rust: FixtureCfgEntry,
    pub go: FixtureCfgEntry,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(default)]
pub struct FixtureCfgEntry {
    targets: BTreeSet<Target>,
    languages: BTreeSet<Language>,
    #[serde(deserialize_with = "deserialize_env")]
    env: BTreeMap<String, Option<String>>,
}

/// A value in an `env` table: the string to set the variable to, or `false` to
/// remove it from the environment.
struct EnvValue(Option<String>);

impl<'de> serde::Deserialize<'de> for EnvValue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct EnvValueVisitor;

        impl serde::de::Visitor<'_> for EnvValueVisitor {
            type Value = EnvValue;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a string, or `false` to unset the variable")
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(EnvValue(Some(value.to_string())))
            }

            fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Self::Value, E> {
                if value {
                    return Err(E::custom(
                        "`true` is not an environment value; use a string, or `false` to unset",
                    ));
                }

                Ok(EnvValue(None))
            }
        }

        // TOML is self-describing, so let the document decide which arm applies
        deserializer.deserialize_any(EnvValueVisitor)
    }
}

/// Unsetting a variable is spelled `false` rather than null, because TOML has
/// no null literal and serde reads `Option` as "the field may be absent" --
/// which a map entry can't express, since an absent entry is just a missing
/// key. The `Option` is kept as the in-memory representation so that a `None`
/// still means "remove this from the environment".
fn deserialize_env<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, Option<String>>, D::Error> {
    let env = <BTreeMap<String, EnvValue> as serde::Deserialize>::deserialize(deserializer)?;

    Ok(env.into_iter().map(|(key, value)| (key, value.0)).collect())
}

impl FixtureCfgEntry {
    pub fn new(
        languages: impl IntoIterator<Item = Language>,
        targets: impl IntoIterator<Item = Target>,
    ) -> Self {
        Self {
            targets: targets.into_iter().collect(),
            languages: languages.into_iter().collect(),
            env: Default::default(),
        }
    }

    pub fn with_env(
        self,
        env: impl IntoIterator<Item = (impl Into<String>, Option<String>)>,
    ) -> Self {
        Self {
            env: BTreeMap::from_iter(env.into_iter().map(|(k, v)| (k.into(), v))),
            ..self
        }
    }

    pub fn targets(&self) -> &BTreeSet<Target> {
        &self.targets
    }

    pub fn languages(&self) -> &BTreeSet<Language> {
        &self.languages
    }

    pub fn env(&self) -> &BTreeMap<String, Option<String>> {
        &self.env
    }
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(default)]
pub struct FixtureCfg {
    /// The source path for this fixture config
    #[serde(skip)]
    src: PathBuf,
    fixtures: BTreeMap<String, FixtureCfgEntry>,
}

impl FixtureCfg {
    pub fn from_file(file: impl AsRef<Path>) -> Result<Self> {
        let file = file.as_ref();
        let mut cfg: FixtureCfg = match fs::read_to_string(file) {
            Ok(data) => toml::from_str(&data).context("failed to parse cfg")?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => Default::default(),
            Err(e) => return Err(e.into()),
        };
        cfg.src = file.to_path_buf();

        Ok(cfg)
    }

    pub fn fixtures(&self) -> &BTreeMap<String, FixtureCfgEntry> {
        &self.fixtures
    }

    pub fn src(&self) -> &Path {
        &self.src
    }
}
