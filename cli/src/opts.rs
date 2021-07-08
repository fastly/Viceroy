//! Command line arguments.

use {
    std::{
        net::SocketAddr,
        path::{Path, PathBuf},
    },
    structopt::StructOpt,
    viceroy_lib::Error,
};

// Command-line arguments for the Viceroy CLI.
//
// This struct is used to derive a command-line argument parser. See the
// [structopt](https://docs.rs/structopt/latest/structopt) documentation for more information.
//
// Note that the doc comment below is used as descriptive text in the `--help` output.
/// Viceroy is a local testing daemon for Compute@Edge.
#[derive(Debug, StructOpt)]
#[structopt(name = "viceroy", author)]
pub struct Opts {
    /// The IP address that the service should be bound to.
    #[structopt(long = "addr", default_value = "127.0.0.1:7878")]
    socket_addr: SocketAddr,
    /// The path to the service's Wasm binary.
    #[structopt(
        parse(
            try_from_str = check_binary_extension
        )
    )]
    input: PathBuf,
    /// The path to a TOML file containing `local_server` configuration.
    #[structopt(short = "C")]
    config_path: Option<PathBuf>,
    /// Whether to treat stdout as a logging endpoint
    // NB: struct_opt won't let us use `default_value` here, but the default is `false`
    #[structopt(long = "log-stdout")]
    log_stdout: bool,
    /// Whether to treat stderr as a logging endpoint
    // NB: struct_opt won't let us use `default_value` here, but the default is `false`
    #[structopt(long = "log-stderr")]
    log_stderr: bool,
    /// Verbosity of logs for Viceroy. `-v` sets the log level to DEBUG and
    /// `-vv` to TRACE. This option will not take effect if you set RUST_LOG
    /// to a value before starting Viceroy
    #[structopt(short = "v", parse(from_occurrences))]
    verbosity: usize,
}

impl Opts {
    /// The address that the service should be bound to.
    pub fn addr(&self) -> SocketAddr {
        self.socket_addr
    }

    /// The path to the service's Wasm binary.
    pub fn input(&self) -> &Path {
        self.input.as_ref()
    }

    /// The path to a `local_server` configuration file.
    pub fn config_path(&self) -> Option<&Path> {
        self.config_path.as_deref()
    }

    /// Whether to treat stdout as a logging entpoint
    pub fn log_stdout(&self) -> bool {
        self.log_stdout
    }

    /// Whether to treat stderr as a logging entpoint
    pub fn log_stderr(&self) -> bool {
        self.log_stderr
    }

    /// Verbosity of logs for Viceroy. `-v` sets the log level to DEBUG and
    /// `-vv` to TRACE. This option will not take effect if you set RUST_LOG
    /// to a value before starting Viceroy
    pub fn verbosity(&self) -> usize {
        self.verbosity
    }
}

/// A parsing function used by [`Opts`][opts] to check that the input is a Wasm binary.
///
/// [opts]: struct.Opts.html
fn check_binary_extension(s: &str) -> Result<PathBuf, Error> {
    let path = PathBuf::from(s);
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("wasm") => Ok(path),
        _ => Err(Error::FileExtension),
    }
}

/// A collection of unit tests for our CLI argument parsing.
///
/// Note: When using [`StructOpt::from_iter_safe`][from] to test how command line arguments are
/// parsed, note that the first argument will be parsed as the binary name. `dummy-program-name` is
/// used to highlight that this argument is ignored.
///
/// [from]: https://docs.rs/structopt/0.3.15/structopt/trait.StructOpt.html#method.from_iter_safe
#[cfg(test)]
mod opts_tests {
    use {
        super::Opts,
        std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
        structopt::{
            clap::{Error, ErrorKind},
            StructOpt,
        },
    };

    /// A small type alias for test results, with a boxed error type.
    type TestResult = Result<(), anyhow::Error>;

    /// Test that the default address works as expected.
    #[test]
    fn default_addr_works() -> TestResult {
        let empty_args: &[&str] = &["dummy-program-name", "path/to/a/guest-program.wasm"];
        let opts = Opts::from_iter_safe(empty_args)?;
        let expected = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 7878);
        assert_eq!(opts.addr(), expected);
        Ok(())
    }

    /// Test that an `--addr` value with an invalid IPv4 address is rejected.
    #[test]
    fn invalid_addrs_are_rejected() -> TestResult {
        let args_with_bad_addr = &[
            "dummy-program-name",
            "--addr",
            "999.0.0.1:7878",
            "path/to/a/guest-program.wasm",
        ];
        match Opts::from_iter_safe(args_with_bad_addr) {
            Err(Error {
                kind: ErrorKind::ValueValidation,
                message,
                ..
            }) if message.contains("invalid IP address syntax") => Ok(()),
            res => panic!("unexpected result: {:?}", res),
        }
    }

    /// IPv6 addresses are supported. Test that they are accepted.
    #[test]
    fn ipv6_addrs_are_accepted() -> TestResult {
        let args_with_ipv6_addr = &[
            "dummy-program-name",
            "--addr",
            "[::1]:7878",
            "path/to/a/guest-program.wasm",
        ];
        let opts = Opts::from_iter_safe(args_with_ipv6_addr)?;
        let addr_v6 = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
        let expected = SocketAddr::new(addr_v6, 7878);
        assert_eq!(opts.addr(), expected);
        Ok(())
    }

    /// Test that a file with a non-wasm file extension will be rejected properly.
    #[test]
    fn invalid_extension_is_rejected() -> TestResult {
        let args_with_bad_ext = &["dummy-program-name", "path/to/a/invalid-binary.exe"];
        let expected_msg = format!("{}", viceroy_lib::Error::FileExtension);
        match Opts::from_iter_safe(args_with_bad_ext) {
            Err(Error {
                kind: ErrorKind::ValueValidation,
                message,
                ..
            }) if message.contains(&expected_msg) => Ok(()),
            res => panic!("unexpected result: {:?}", res),
        }
    }

    /// Test that a file with a wasm file extension will be accepted.
    #[test]
    fn valid_extension_is_accepted() -> TestResult {
        let args = &["dummy-program-name", "path/to/a/valid-binary.wasm"];
        match Opts::from_iter_safe(args) {
            Ok(_) => Ok(()),
            res => panic!("unexpected result: {:?}", res),
        }
    }
}
