//! Command line arguments.

use {
    clap::{Parser, ValueEnum},
    std::net::{IpAddr, Ipv4Addr},
    std::{
        collections::HashSet,
        net::SocketAddr,
        path::{Path, PathBuf},
    },
    viceroy_lib::{config::ExperimentalModule, Error, ProfilingStrategy},
};

// Command-line arguments for the Viceroy CLI.
//
// This struct is used to derive a command-line argument parser. See the
// [clap](https://docs.rs/clap/latest/clap/) documentation for more information.
//
// Note that the doc comment below is used as descriptive text in the `--help` output.
/// Viceroy is a local testing daemon for Compute@Edge.
#[derive(Parser, Debug)]
#[command(name = "viceroy", author, version, about)]
pub struct Opts {
    /// The IP address that the service should be bound to.
    #[arg(long = "addr")]
    socket_addr: Option<SocketAddr>,
    /// The path to the service's Wasm module.
    #[arg(value_parser = check_module)]
    input: PathBuf,
    /// The path to a TOML file containing `local_server` configuration.
    #[arg(short = 'C', long = "config")]
    config_path: Option<PathBuf>,
    /// Use Viceroy to run a module's _start function once, rather than in a
    /// web server loop
    #[arg(short = 'r', long = "run", default_value = "false")]
    run_mode: bool,
    /// Whether to treat stdout as a logging endpoint
    #[arg(long = "log-stdout", default_value = "false")]
    log_stdout: bool,
    /// Whether to treat stderr as a logging endpoint
    #[arg(long = "log-stderr", default_value = "false")]
    log_stderr: bool,
    /// Verbosity of logs for Viceroy. `-v` sets the log level to DEBUG and
    /// `-vv` to TRACE. This option will not take effect if you set RUST_LOG
    /// to a value before starting Viceroy
    #[arg(short = 'v', action = clap::ArgAction::Count)]
    verbosity: u8,
    // Whether to enable wasmtime's builtin profiler.
    #[arg(long = "profiler", value_parser = check_wasmtime_profiler_mode)]
    profiler: Option<ProfilingStrategy>,
    /// Set of experimental WASI modules to link against.
    #[arg(value_enum, long = "experimental_modules", required = false)]
    experimental_modules: Vec<ExperimentalModuleArg>,
    /// Don't log viceroy events to stdout or stderr
    #[arg(short = 'q', long = "quiet", default_value = "false")]
    quiet: bool,
    // Command line to start child process
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    run: Vec<String>,
}

impl Opts {
    /// The address that the service should be bound to.
    pub fn addr(&self) -> SocketAddr {
        self.socket_addr
            .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 7878))
    }

    /// The path to the service's Wasm binary.
    pub fn input(&self) -> &Path {
        self.input.as_ref()
    }

    /// The path to a `local_server` configuration file.
    pub fn config_path(&self) -> Option<&Path> {
        self.config_path.as_deref()
    }

    /// Whether to run Viceroy as a test runner
    pub fn run_mode(&self) -> bool {
        self.run_mode
    }

    /// Whether to treat stdout as a logging endpoint
    pub fn log_stdout(&self) -> bool {
        self.log_stdout
    }

    /// Whether to treat stderr as a logging endpoint
    pub fn log_stderr(&self) -> bool {
        self.log_stderr
    }

    /// Verbosity of logs for Viceroy. `-v` sets the log level to DEBUG and
    /// `-vv` to TRACE. This option will not take effect if you set RUST_LOG
    /// to a value before starting Viceroy
    pub fn verbosity(&self) -> u8 {
        self.verbosity
    }

    // Whether to enable wasmtime's builtin profiler.
    pub fn profiling_strategy(&self) -> ProfilingStrategy {
        self.profiler.unwrap_or(ProfilingStrategy::None)
    }

    pub fn run(&self) -> &[String] {
        self.run.as_ref()
    }
    pub fn quiet(&self) -> bool {
        self.quiet
    }

    // Set of experimental wasi modules to link against.
    pub fn wasi_modules(&self) -> HashSet<ExperimentalModule> {
        self.experimental_modules.iter().map(|x| x.into()).collect()
    }
}

/// Enum of available (experimental) wasi modules
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Hash)]
pub enum ExperimentalModuleArg {
    WasiNn,
}

impl From<ExperimentalModuleArg> for ExperimentalModule {
    fn from(arg: ExperimentalModuleArg) -> ExperimentalModule {
        match arg {
            ExperimentalModuleArg::WasiNn => ExperimentalModule::WasiNn,
        }
    }
}

impl From<&ExperimentalModuleArg> for ExperimentalModule {
    fn from(arg: &ExperimentalModuleArg) -> ExperimentalModule {
        match arg {
            ExperimentalModuleArg::WasiNn => ExperimentalModule::WasiNn,
        }
    }
}

impl From<ExperimentalModule> for ExperimentalModuleArg {
    fn from(module: ExperimentalModule) -> ExperimentalModuleArg {
        match module {
            ExperimentalModule::WasiNn => ExperimentalModuleArg::WasiNn,
        }
    }
}

impl From<&ExperimentalModule> for ExperimentalModuleArg {
    fn from(module: &ExperimentalModule) -> ExperimentalModuleArg {
        match module {
            ExperimentalModule::WasiNn => ExperimentalModuleArg::WasiNn,
        }
    }
}

/// A parsing function used by [`Opts`][opts] to check that the input is a valid Wasm module in
/// binary or text format.
///
/// [opts]: struct.Opts.html
fn check_module(s: &str) -> Result<PathBuf, Error> {
    let path = PathBuf::from(s);
    let contents = std::fs::read(&path)?;
    match wat::parse_bytes(&contents) {
        Ok(_) => Ok(path),
        _ => Err(Error::FileFormat),
    }
}

/// A parsing function used by [`Opts`][opts] to check that the input is valid wasmtime's profiling strategy.
///
/// [opts]: struct.Opts.html
fn check_wasmtime_profiler_mode(s: &str) -> Result<ProfilingStrategy, Error> {
    match s {
        "jitdump" => Ok(ProfilingStrategy::JitDump),
        "vtune" => Ok(ProfilingStrategy::VTune),
        _ => Err(Error::ProfilingStrategy),
    }
}

/// A collection of unit tests for our CLI argument parsing.
///
/// Note: When using [`Clap::try_parse_from`][from] to test how command line arguments are
/// parsed, note that the first argument will be parsed as the binary name. `dummy-program-name` is
/// used to highlight that this argument is ignored.
///
/// [from]: https://docs.rs/clap/latest/clap/trait.Parser.html#method.try_parse_from
#[cfg(test)]
mod opts_tests {
    use {
        super::Opts,
        clap::{error::ErrorKind, Parser},
        std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
        std::path::PathBuf,
    };

    fn test_file(name: &str) -> String {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("wasm");
        path.push(name);
        assert!(path.exists(), "test file does not exist");
        path.into_os_string().into_string().unwrap()
    }

    /// A small type alias for test results, with a boxed error type.
    type TestResult = Result<(), anyhow::Error>;

    /// Test that the default address works as expected.
    #[test]
    fn default_addr_works() -> TestResult {
        let empty_args = &["dummy-program-name", &test_file("minimal.wat")];
        let opts = Opts::try_parse_from(empty_args)?;
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
            &test_file("minimal.wat"),
        ];
        match Opts::try_parse_from(args_with_bad_addr) {
            Err(err)
                if err.kind() == ErrorKind::ValueValidation
                    && (err.to_string().contains("invalid socket address syntax")
                        || err.to_string().contains("invalid IP address syntax")) =>
            {
                Ok(())
            }
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
            &test_file("minimal.wat"),
        ];
        let opts = Opts::try_parse_from(args_with_ipv6_addr)?;
        let addr_v6 = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
        let expected = SocketAddr::new(addr_v6, 7878);
        assert_eq!(opts.addr(), expected);
        Ok(())
    }

    /// Test that a nonexistent file is rejected properly.
    #[test]
    fn nonexistent_file_is_rejected() -> TestResult {
        let args_with_nonexistent_file = &["dummy-program-name", "path/to/a/nonexistent/file"];
        match Opts::try_parse_from(args_with_nonexistent_file) {
            Err(err)
                if err.kind() == ErrorKind::ValueValidation
                    && (err.to_string().contains("No such file or directory")
                        || err.to_string().contains("cannot find the path specified")) =>
            {
                Ok(())
            }
            res => panic!("unexpected result: {:?}", res),
        }
    }

    /// Test that an invalid file is rejected.
    #[test]
    fn invalid_file_is_rejected() -> TestResult {
        let args_with_invalid_file = &["dummy-program-name", &test_file("invalid.wat")];
        let expected_msg = format!("{}", viceroy_lib::Error::FileFormat);
        match Opts::try_parse_from(args_with_invalid_file) {
            Err(err)
                if err.kind() == ErrorKind::ValueValidation
                    && err.to_string().contains(&expected_msg) =>
            {
                Ok(())
            }
            res => panic!("unexpected result: {:?}", res),
        }
    }

    /// Test that a Wasm module in text format is accepted.
    #[test]
    fn text_format_is_accepted() -> TestResult {
        let args = &["dummy-program-name", &test_file("minimal.wat")];
        match Opts::try_parse_from(args) {
            Ok(_) => Ok(()),
            res => panic!("unexpected result: {:?}", res),
        }
    }

    /// Test that a Wasm module in binary format is accepted.
    #[test]
    fn binary_format_is_accepted() -> TestResult {
        let args = &["dummy-program-name", &test_file("minimal.wasm")];
        match Opts::try_parse_from(args) {
            Ok(_) => Ok(()),
            res => panic!("unexpected result: {:?}", res),
        }
    }

    /// Test that wasmtime's jitdump profiling strategy is accepted.
    #[test]
    fn wasmtime_profiling_strategy_jitdump_is_accepted() -> TestResult {
        let args = &[
            "dummy-program-name",
            "--profiler",
            "jitdump",
            &test_file("minimal.wat"),
        ];
        match Opts::try_parse_from(args) {
            Ok(_) => Ok(()),
            res => panic!("unexpected result: {:?}", res),
        }
    }

    /// Test that wasmtime's VTune profiling strategy is accepted.
    #[test]
    fn wasmtime_profiling_strategy_vtune_is_accepted() -> TestResult {
        let args = &[
            "dummy-program-name",
            "--profiler",
            "vtune",
            &test_file("minimal.wat"),
        ];
        match Opts::try_parse_from(args) {
            Ok(_) => Ok(()),
            res => panic!("unexpected result: {:?}", res),
        }
    }

    /// Test that an invalid wasmtime's profiling strategy rejected.
    #[test]
    fn invalid_wasmtime_profiling_strategy_is_rejected() -> TestResult {
        let args = &[
            "dummy-program-name",
            "--profiler",
            "invalid_profiling_strategy",
            &test_file("minimal.wat"),
        ];
        match Opts::try_parse_from(args) {
            Ok(_) => panic!("unexpected result"),
            Err(_) => Ok(()),
        }
    }
}
