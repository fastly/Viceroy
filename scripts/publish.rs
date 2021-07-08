//! Helper script to publish the viceroy crates.
//!
//! * `./publish verify` - verify crates can be published to crates.io

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

/// A type alias for some kind of [`Error`][std::error::Error].
type Error = Box<dyn std::error::Error + Send + Sync + 'static>;

/// A temporary directory used to verify that crates can be published to crates.io.
//
// N.B. This should match the entry in the project root's `.gitignore`.
const VERIFY_TEMPDIR: &str = "verify-publishable";

/// The crates that we will publish.
//
// N.B. This list must be topologically sorted by dependencies.
const CRATES_TO_PUBLISH: &[&str] = &["viceroy-lib", "viceroy-cli"];

/// The crates that we will NOT publish.
//
// N.B. This list is empty for now, but may grow in the future.
const CRATES_NOT_TO_PUBLISH: &[&str] = &["validate-witx"];

/// A crate's metadata.
struct Crate {
    /// The path to the crate's `Cargo.toml` manifest.
    manifest: PathBuf,
    /// The name of the crate.
    name: String,
    /// The current version of the crate.
    version: String,
    /// Whether or not the crate should be published.
    publish: bool,
}

/// The entry point for this program.
fn main() -> Result<(), Error> {
    let crates = {
        let cwd = std::env::current_dir()?;
        let mut crates = Vec::new();
        find_crates(&cwd, &mut crates)?;
        let pos = CRATES_TO_PUBLISH
            .iter()
            .enumerate()
            .map(|(i, c)| (*c, i))
            .collect::<HashMap<_, _>>();
        crates.sort_by_key(|krate| pos.get(&krate.name[..]));
        crates
    };

    match &std::env::args().nth(1).expect("must have one argument")[..] {
        "verify" => {
            verify(&crates);
        }

        s => panic!("unknown command: {}", s),
    }

    Ok(())
}

/// Find all of the crates that exist in `path` and add their metadata to `dst`.
fn find_crates(dir: &Path, dst: &mut Vec<Crate>) -> Result<(), Error> {
    if dir.join("Cargo.toml").exists() {
        if let Some(krate) = read_crate(&dir.join("Cargo.toml")) {
            if !krate.publish || CRATES_TO_PUBLISH.iter().any(|c| krate.name == *c) {
                dst.push(krate);
            } else {
                panic!("failed to find {:?} in whitelist or blacklist", krate.name);
            }
        }
    }

    for entry in dir.read_dir().unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            find_crates(&entry.path(), dst)?;
        }
    }

    Ok(())
}

fn read_crate(manifest: &Path) -> Option<Crate> {
    let mut name = None;
    let mut version = None;
    let mut publish = true;
    for line in fs::read_to_string(manifest).unwrap().lines() {
        if name.is_none() && line.starts_with("name = \"") {
            name = Some(
                line.replace("name = \"", "")
                    .replace("\"", "")
                    .trim()
                    .to_string(),
            );
        }
        if version.is_none() && line.starts_with("version = \"") {
            version = Some(
                line.replace("version = \"", "")
                    .replace("\"", "")
                    .trim()
                    .to_string(),
            );
        }
        if line.starts_with("publish = false") {
            publish = false;
        }
    }
    let name = name?;
    let version = version.unwrap();
    if CRATES_NOT_TO_PUBLISH.contains(&&name[..]) {
        if publish {
            eprintln!("blocklist prevented {} from being published", name);
        }
        publish = false;
    }
    Some(Crate {
        manifest: manifest.to_path_buf(),
        name,
        version,
        publish,
    })
}

/// Verify the current tree is publish-able to crates.io.
///
/// The intention here is that we'll run `cargo package` on everything which verifies the build
/// as-if it were published to crates.io. This requires using an incrementally-built directory
/// registry generated from `cargo vendor` because the versions referenced from `Cargo.toml` may
/// not exist on crates.io.
fn verify(crates: &[Crate]) {
    drop(fs::remove_dir_all(".cargo"));
    drop(fs::remove_dir_all(VERIFY_TEMPDIR));
    let vendor = Command::new("cargo")
        .arg("vendor")
        .arg(VERIFY_TEMPDIR)
        .stderr(Stdio::inherit())
        .output()
        .unwrap();
    assert!(vendor.status.success());

    fs::create_dir_all(".cargo").unwrap();
    fs::write(".cargo/config.toml", vendor.stdout).unwrap();

    for krate in crates {
        if !krate.publish {
            continue;
        }
        verify_and_vendor(&krate);
    }

    fn verify_and_vendor(krate: &Crate) {
        let status = Command::new("cargo")
            .arg("package")
            .arg("--manifest-path")
            .arg(&krate.manifest)
            .env("CARGO_TARGET_DIR", "./target")
            .status()
            .unwrap();
        assert!(status.success(), "failed to verify {:?}", &krate.manifest);
        let tar = Command::new("tar")
            .arg("xf")
            .arg(format!(
                "../target/package/{}-{}.crate",
                krate.name, krate.version
            ))
            .current_dir(format!("./{}", VERIFY_TEMPDIR))
            .status()
            .unwrap();
        assert!(tar.success());
        fs::write(
            format!(
                "./{}/{}-{}/.cargo-checksum.json",
                VERIFY_TEMPDIR, krate.name, krate.version
            ),
            "{\"files\":{}}",
        )
        .unwrap();
    }
}
