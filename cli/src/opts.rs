//! Command line arguments.

use viceroy_lib::config::UnknownImportBehavior;

use {
    clap::{Args, Parser, Subcommand, ValueEnum},
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
/// Viceroy is a local testing daemon for Compute.
#[derive(Parser, Debug)]
#[command(name = "viceroy", author, version, about)]
#[command(propagate_version = true)]
#[command(args_conflicts_with_subcommands = true)]
pub struct Opts {
    #[command(subcommand)]
    pub command: Option<Commands>,

    #[command(flatten)]
    pub serve: ServeArgs,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    /// Run the wasm in a Viceroy server. This is the default if no subcommand
    /// is given.
    Serve(ServeArgs),

    /// Run the input wasm once and then exit.
    Run(RunArgs),

    /// Adapt core wasm to a component.
    Adapt(AdaptArgs),
}

#[derive(Debug, Args, Clone)]
pub struct ServeArgs {
    /// The IP address that the service should be bound to.
    #[arg(long = "addr")]
    socket_addr: Option<SocketAddr>,

    #[command(flatten)]
    shared: SharedArgs,
}

#[derive(Args, Debug, Clone)]
pub struct RunArgs {
    #[command(flatten)]
    shared: SharedArgs,

    /// Args to pass along to the binary being executed.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    wasm_args: Vec<String>,
}

#[derive(Args, Debug, Clone)]
pub struct SharedArgs {
    /// The path to the service's Wasm module.
    #[arg(value_parser = check_module, required=true)]
    input: Option<PathBuf>,
    /// The path to a TOML file containing `local_server` configuration.
    #[arg(short = 'C', long = "config")]
    config_path: Option<PathBuf>,
    /// Whether to treat stdout as a logging endpoint
    #[arg(long = "log-stdout", default_value = "false")]
    log_stdout: bool,
    /// Whether to treat stderr as a logging endpoint
    #[arg(long = "log-stderr", default_value = "false")]
    log_stderr: bool,
    /// Profiling strategy (valid options are: perfmap, jitdump, vtune, guest)
    ///
    /// The perfmap, jitdump, and vtune profiling strategies integrate Viceroy
    /// with external profilers such as `perf`.
    ///
    /// The guest profiling strategy enables in-process sampling. By default,
    /// when Viceroy is running as a server it will write the captured
    /// per-request profiles to the `guest-profiles` directory, and as a test
    /// runner it will write the captured profile to the `guest-profile.json`
    /// file. These profiles can be viewed at https://profiler.firefox.com/.
    ///
    /// The `guest` option can be additionally configured as:
    ///
    ///     --profile=guest[,path]
    ///
    /// where `path` is the directory or filename to write the profile(s) to.
    #[arg(long = "profile", value_name = "STRATEGY", value_parser = check_wasmtime_profiler_mode)]
    profile: Option<Profile>,
    /// Set of experimental WASI modules to link against.
    #[arg(value_enum, long = "experimental_modules", required = false)]
    experimental_modules: Vec<ExperimentalModuleArg>,
    /// Set the behavior for unknown imports.
    ///
    /// Note that if a program only works with a non-default setting for this flag, it is unlikely
    /// to be publishable to Fastly.
    #[arg(long = "unknown-import-behavior", value_enum, default_value_t = UnknownImportBehavior::LinkError)]
    unknown_import_behavior: UnknownImportBehavior,
    /// Verbosity of logs for Viceroy. `-v` sets the log level to INFO,
    /// `-vv` to DEBUG, and `-vvv` to TRACE. This option will not take
    /// effect if you set RUST_LOG to a value before starting Viceroy
    #[arg(short = 'v', action = clap::ArgAction::Count)]
    verbosity: u8,
    /// Whether or not to automatically adapt core-wasm modules to
    /// components before running them.
    #[arg(long = "adapt")]
    adapt: bool,
}

#[derive(Debug, Clone)]
enum Profile {
    Native(ProfilingStrategy),
    Guest { path: Option<String> },
}

impl ServeArgs {
    /// The address that the service should be bound to.
    pub fn addr(&self) -> SocketAddr {
        self.socket_addr
            .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 7676))
    }

    /// The path to write guest profiles to
    pub fn profile_guest(&self) -> Option<PathBuf> {
        if let Some(Profile::Guest { path }) = &self.shared.profile {
            Some(
                path.clone()
                    .unwrap_or_else(|| "guest-profiles".to_string())
                    .into(),
            )
        } else {
            None
        }
    }

    pub fn shared(&self) -> &SharedArgs {
        &self.shared
    }
}

impl RunArgs {
    /// The arguments to pass to the underlying binary when run_mode=true
    pub fn wasm_args(&self) -> &Vec<String> {
        &self.wasm_args
    }

    pub fn shared(&self) -> &SharedArgs {
        &self.shared
    }

    /// The path to write a guest profile to
    pub fn profile_guest(&self) -> Option<PathBuf> {
        if let Some(Profile::Guest { path }) = &self.shared.profile {
            Some(
                path.clone()
                    .unwrap_or_else(|| "guest-profile.json".to_string())
                    .into(),
            )
        } else {
            None
        }
    }
}

impl SharedArgs {
    /// The path to the service's Wasm binary.
    pub fn input(&self) -> PathBuf {
        self.input.as_ref().unwrap().clone()
    }

    /// The path to a `local_server` configuration file.
    pub fn config_path(&self) -> Option<&Path> {
        self.config_path.as_deref()
    }

    /// Whether to treat stdout as a logging endpoint
    pub fn log_stdout(&self) -> bool {
        self.log_stdout
    }

    /// Whether to treat stderr as a logging endpoint
    pub fn log_stderr(&self) -> bool {
        self.log_stderr
    }

    /// Whether to enable wasmtime's builtin profiler.
    pub fn profiling_strategy(&self) -> ProfilingStrategy {
        match self.profile {
            Some(Profile::Native(s)) => s,
            _ => ProfilingStrategy::None,
        }
    }

    /// Set of experimental wasi modules to link against.
    pub fn wasi_modules(&self) -> HashSet<ExperimentalModule> {
        self.experimental_modules.iter().map(|x| x.into()).collect()
    }

    /// Unknown import behavior
    pub fn unknown_import_behavior(&self) -> UnknownImportBehavior {
        self.unknown_import_behavior
    }

    /// Verbosity of logs for Viceroy. `-v` sets the log level to DEBUG and
    /// `-vv` to TRACE. This option will not take effect if you set RUST_LOG
    /// to a value before starting Viceroy
    pub fn verbosity(&self) -> u8 {
        self.verbosity
    }

    pub fn adapt(&self) -> bool {
        self.adapt
    }
}

#[derive(Args, Debug, Clone)]
pub struct AdaptArgs {
    /// The path to the Wasm module to adapt.
    #[arg(value_parser = check_module, required=true)]
    input: PathBuf,

    /// The output name
    #[arg(short = 'o', long = "output")]
    output: Option<PathBuf>,

    /// Verbosity of logs for Viceroy. `-v` sets the log level to INFO,
    /// `-vv` to DEBUG, and `-vvv` to TRACE. This option will not take
    /// effect if you set RUST_LOG to a value before starting Viceroy
    #[arg(short = 'v', action = clap::ArgAction::Count)]
    verbosity: u8,
}

impl AdaptArgs {
    pub(crate) fn input(&self) -> PathBuf {
        self.input.clone()
    }

    pub(crate) fn output(&self) -> PathBuf {
        if let Some(output) = self.output.as_ref() {
            return output.clone();
        }

        let mut output = PathBuf::from(self.input.file_name().expect("input filename"));
        output.set_extension("component.wasm");
        output
    }

    /// Verbosity of logs for Viceroy. `-v` sets the log level to DEBUG and
    /// `-vv` to TRACE. This option will not take effect if you set RUST_LOG
    /// to a value before starting Viceroy
    pub fn verbosity(&self) -> u8 {
        self.verbosity
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
fn check_wasmtime_profiler_mode(s: &str) -> Result<Profile, Error> {
    let parts = s.split(',').collect::<Vec<_>>();
    match &parts[..] {
        ["jitdump"] => Ok(Profile::Native(ProfilingStrategy::JitDump)),
        ["perfmap"] => Ok(Profile::Native(ProfilingStrategy::PerfMap)),
        ["vtune"] => Ok(Profile::Native(ProfilingStrategy::VTune)),
        ["guest"] => Ok(Profile::Guest { path: None }),
        ["guest", path] => Ok(Profile::Guest {
            path: Some(path.to_string()),
        }),
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
        super::{Commands, Opts},
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
        let cmd = opts.command.unwrap_or(Commands::Serve(opts.serve));
        let expected = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 7676);
        if let Commands::Serve(serve_args) = cmd {
            assert_eq!(serve_args.addr(), expected);
        }
        Ok(())
    }

    /// Test that an `--addr` value with an invalid IPv4 address is rejected.
    #[test]
    fn invalid_addrs_are_rejected() -> TestResult {
        let args_with_bad_addr = &[
            "dummy-program-name",
            "--addr",
            "999.0.0.1:7676",
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
            "[::1]:7676",
            &test_file("minimal.wat"),
        ];
        let opts = Opts::try_parse_from(args_with_ipv6_addr)?;
        let cmd = opts.command.unwrap_or(Commands::Serve(opts.serve));
        let addr_v6 = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
        let expected = SocketAddr::new(addr_v6, 7676);
        if let Commands::Serve(serve_args) = cmd {
            assert_eq!(serve_args.addr(), expected);
        }
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
            "--profile",
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
            "--profile",
            "vtune",
            &test_file("minimal.wat"),
        ];
        match Opts::try_parse_from(args) {
            Ok(_) => Ok(()),
            res => panic!("unexpected result: {:?}", res),
        }
    }

    /// Test that wasmtime's PerfMap profiling strategy is accepted.
    #[test]
    fn wasmtime_profiling_strategy_perfmap_is_accepted() -> TestResult {
        let args = &[
            "dummy-program-name",
            "--profile",
            "perfmap",
            &test_file("minimal.wat"),
        ];
        match Opts::try_parse_from(args) {
            Ok(_) => Ok(()),
            res => panic!("unexpected result: {:?}", res),
        }
    }

    /// Test that wasmtime's guest profiling strategy without path is accepted.
    #[test]
    fn wasmtime_profiling_strategy_guest_without_path_is_accepted() -> TestResult {
        let args = &[
            "dummy-program-name",
            "--profile",
            "guest",
            &test_file("minimal.wat"),
        ];
        match Opts::try_parse_from(args) {
            Ok(_) => Ok(()),
            res => panic!("unexpected result: {:?}", res),
        }
    }

    /// Test that wasmtime's guest profiling strategy with path is accepted.
    #[test]
    fn wasmtime_profiling_strategy_guest_with_path_is_accepted() -> TestResult {
        let args = &[
            "dummy-program-name",
            "--profile",
            "guest,/some/path",
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
            "--profile",
            "invalid_profiling_strategy",
            &test_file("minimal.wat"),
        ];
        match Opts::try_parse_from(args) {
            Ok(_) => panic!("unexpected result"),
            Err(_) => Ok(()),
        }
    }

    /// Test that trailing arguments are collected successfully
    #[test]
    fn trailing_args_are_collected_in_run_mode() -> TestResult {
        let args = &[
            "dummy-program-name",
            "run",
            &test_file("minimal.wat"),
            "--",
            "--trailing-arg",
            "--trailing-arg-2",
        ];
        let opts = Opts::try_parse_from(args)?;
        let cmd = opts.command.unwrap_or(Commands::Serve(opts.serve));
        if let Commands::Run(run_args) = cmd {
            assert_eq!(
                run_args.wasm_args(),
                &["--trailing-arg", "--trailing-arg-2"]
            );
        }
        Ok(())
    }

    /// Input is still accepted after double-dash. This is how the input will be
    /// passed by cargo nextest if using Viceroy in run-mode to run tests
    #[test]
    fn input_accepted_after_double_dash() -> TestResult {
        let args = &[
            "dummy-program-name",
            "run",
            "--",
            &test_file("minimal.wat"),
            "--trailing-arg",
            "--trailing-arg-2",
        ];
        let opts = match Opts::try_parse_from(args) {
            Ok(opts) => opts,
            res => panic!("unexpected result: {:?}", res),
        };
        let cmd = opts.command.unwrap_or(Commands::Serve(opts.serve));
        if let Commands::Run(run_args) = cmd {
            assert_eq!(
                run_args.shared.input().to_str().unwrap(),
                &test_file("minimal.wat")
            );
            assert_eq!(
                run_args.wasm_args(),
                &["--trailing-arg", "--trailing-arg-2"]
            );
        }
        Ok(())
    }
}
