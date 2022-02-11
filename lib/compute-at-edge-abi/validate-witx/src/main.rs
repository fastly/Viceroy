//! `witx` validator.
//!
//! This program uses the [`witx`][witx-crate] crate to load the `.witx` specifying the
//! Compute@Edge interface. It will panic if the file fails to parse or validate.
//!
//! This program can be invoked by running the following command from the root of the
//! `compute-at-edge-abi` repository:
//!
//! ```sh
//! ; cargo run --manifest-path=validate-witx/Cargo.toml ./fastly.witx
//! ```
//!
//! [witx-crate]: https://crates.io/crates/witx

use {
    anyhow::{anyhow, Context},
    std::env,
};

fn main() -> anyhow::Result<()> {
    let args = env::args().skip(1).collect::<Vec<String>>();

    let witx = if args.len() != 1 {
        return Err(anyhow!(
            "ERROR: please provide the path to the `fastly.witx` file."
        ));
    } else {
        args.into_iter().next().unwrap()
    };

    witx::load(&[witx]).context("failed to parse and validate witx")?;

    Ok(())
}
