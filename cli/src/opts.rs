//! Command line arguments.

use std::time::Duration;

use viceroy_lib::{GuestProfileConfig, config::UnknownImportBehavior};

use {
    clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum, error::ErrorKind},
    std::net::{IpAddr, Ipv4Addr},
    std::{
        collections::HashSet,
        net::SocketAddr,
        path::{Path, PathBuf},
    },
    viceroy_lib::{Error, ProfilingStrategy, config::ExperimentalModule},
    wasmtime::WasmFeatures,
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
#[command(subcommand_negates_reqs = true)]
#[command(
    override_usage = "viceroy [OPTIONS] <INPUT>\n       viceroy [OPTIONS] serve [ARGS]\n       viceroy [SHARED OPTIONS] run [ARGS]\n       viceroy [-v...] adapt [ARGS]",
    after_help = "SHARED OPTIONS are all root options except --addr."
)]
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
    /// The IP address that the service should be bound to (serve mode only).
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
    ///     --profile=guest[,path[,sample]]
    ///
    /// where `path` is the directory or filename to write the profile(s) to and
    /// `sample` is the duration between profiler samples (default 50μs). Time
    /// units supported are "s" (seconds), "ms" (milliseconds"), "us"/"μs"
    /// (microseconds), and "ns" (nanoseconds).
    #[arg(long = "profile", value_name = "STRATEGY", value_parser = check_wasmtime_profiler_mode)]
    profile: Option<Profile>,
    /// Port running local Pushpin proxy. If not provided, Pushpin functionality
    /// is disabled.
    #[arg(long = "local-pushpin-proxy-port")]
    local_pushpin_proxy_port: Option<u16>,
    /// Set of experimental WASI modules to link against.
    #[arg(value_enum, long = "experimental_modules", required = false)]
    experimental_modules: Vec<ExperimentalModuleArg>,
    /// Set the behavior for unknown imports (default: link-error).
    ///
    /// Note that if a program only works with a non-default setting for this flag, it is unlikely
    /// to be publishable to Fastly.
    #[arg(long = "unknown-import-behavior", value_enum)]
    unknown_import_behavior: Option<UnknownImportBehavior>,
    /// Verbosity of logs for Viceroy. `-v` sets the log level to INFO,
    /// `-vv` to DEBUG, and `-vvv` to TRACE. This option will not take
    /// effect if you set RUST_LOG to a value before starting Viceroy
    #[arg(short = 'v', action = clap::ArgAction::Count)]
    verbosity: u8,
    /// Whether or not to automatically adapt core-wasm modules to
    /// components before running them.
    #[arg(long = "adapt")]
    adapt: bool,
    /// Enable the Wasm Exception Handling feature.
    #[arg(long)]
    wasm_exceptions: bool,
    /// Enable the Wasm GC feature.
    #[arg(long)]
    wasm_gc: bool,
    /// Enable component-model GC integration.
    #[arg(long)]
    wasm_cm_gc: bool,
}

#[derive(Debug, Clone)]
enum Profile {
    Native(ProfilingStrategy),
    Guest {
        path: Option<String>,
        sample_period: Option<Duration>,
    },
}

impl Opts {
    pub(crate) fn into_command(self) -> Result<Commands, clap::Error> {
        let Self {
            command,
            serve: prefix,
        } = self;

        match command {
            None => Ok(Commands::Serve(prefix)),
            Some(Commands::Serve(mut serve_args)) => {
                if prefix.shared.input.is_some() {
                    return Err(Self::argument_conflict(
                        "the input argument cannot be used before an explicit subcommand",
                    ));
                }
                serve_args
                    .inherit(prefix)
                    .map_err(Self::duplicate_argument)?;
                Ok(Commands::Serve(serve_args))
            }
            Some(Commands::Run(mut run_args)) => {
                if prefix.shared.input.is_some() {
                    return Err(Self::argument_conflict(
                        "the input argument cannot be used before an explicit subcommand",
                    ));
                }
                if prefix.socket_addr.is_some() {
                    return Err(Self::argument_conflict(
                        "the argument '--addr' cannot be used with 'run'",
                    ));
                }
                run_args
                    .shared
                    .inherit(prefix.shared)
                    .map_err(Self::duplicate_argument)?;
                Ok(Commands::Run(run_args))
            }
            Some(Commands::Adapt(mut adapt_args)) => {
                if prefix.socket_addr.is_some() || prefix.shared.has_non_verbosity_arguments() {
                    return Err(Self::argument_conflict(
                        "serve and run arguments cannot be used with 'adapt'",
                    ));
                }
                adapt_args.verbosity = adapt_args.verbosity.saturating_add(prefix.shared.verbosity);
                Ok(Commands::Adapt(adapt_args))
            }
        }
    }

    fn duplicate_argument(argument: &'static str) -> clap::Error {
        Self::argument_conflict(format!(
            "the argument '{argument}' cannot be used multiple times"
        ))
    }

    fn argument_conflict(message: impl std::fmt::Display) -> clap::Error {
        <Self as CommandFactory>::command().error(ErrorKind::ArgumentConflict, message)
    }
}

impl ServeArgs {
    /// The address that the service should be bound to.
    pub fn addr(&self) -> SocketAddr {
        self.socket_addr
            .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 7676))
    }

    pub fn shared(&self) -> &SharedArgs {
        &self.shared
    }

    fn inherit(&mut self, prefix: Self) -> Result<(), &'static str> {
        inherit_option(&mut self.socket_addr, prefix.socket_addr, "--addr")?;
        self.shared.inherit(prefix.shared)
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

    /// Port running local Pushpin proxy.
    pub fn local_pushpin_proxy_port(&self) -> Option<u16> {
        self.local_pushpin_proxy_port
    }

    /// Configuration for guest profiling if enabled
    pub fn guest_profile_config(&self) -> Option<GuestProfileConfig> {
        if let Some(Profile::Guest {
            path,
            sample_period,
        }) = &self.profile
        {
            Some(GuestProfileConfig {
                path: PathBuf::from(
                    path.as_ref()
                        .map(|p| p.as_str())
                        .unwrap_or("guest-profiles"),
                ),
                sample_period: sample_period.unwrap_or_else(|| Duration::from_micros(50)),
            })
        } else {
            None
        }
    }

    /// Set of experimental wasi modules to link against.
    pub fn wasi_modules(&self) -> HashSet<ExperimentalModule> {
        self.experimental_modules.iter().map(|x| x.into()).collect()
    }

    /// Unknown import behavior
    pub fn unknown_import_behavior(&self) -> UnknownImportBehavior {
        self.unknown_import_behavior.unwrap_or_default()
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

    pub fn wasm_features(&self) -> WasmFeatures {
        let mut wasm_features = WasmFeatures::default();
        if self.wasm_exceptions {
            wasm_features.insert(WasmFeatures::EXCEPTIONS);
        }
        if self.wasm_gc {
            wasm_features.insert(WasmFeatures::GC);
        }
        if self.wasm_cm_gc {
            wasm_features.insert(WasmFeatures::CM_GC);
        }
        wasm_features
    }

    fn inherit(&mut self, mut prefix: Self) -> Result<(), &'static str> {
        debug_assert!(prefix.input.is_none());

        inherit_option(&mut self.config_path, prefix.config_path, "--config")?;
        inherit_flag(&mut self.log_stdout, prefix.log_stdout, "--log-stdout")?;
        inherit_flag(&mut self.log_stderr, prefix.log_stderr, "--log-stderr")?;
        inherit_option(&mut self.profile, prefix.profile, "--profile")?;
        inherit_option(
            &mut self.local_pushpin_proxy_port,
            prefix.local_pushpin_proxy_port,
            "--local-pushpin-proxy-port",
        )?;

        prefix
            .experimental_modules
            .append(&mut self.experimental_modules);
        self.experimental_modules = prefix.experimental_modules;

        inherit_option(
            &mut self.unknown_import_behavior,
            prefix.unknown_import_behavior,
            "--unknown-import-behavior",
        )?;
        self.verbosity = prefix.verbosity.saturating_add(self.verbosity);
        inherit_flag(&mut self.adapt, prefix.adapt, "--adapt")?;
        inherit_flag(
            &mut self.wasm_exceptions,
            prefix.wasm_exceptions,
            "--wasm-exceptions",
        )?;
        inherit_flag(&mut self.wasm_gc, prefix.wasm_gc, "--wasm-gc")?;
        inherit_flag(&mut self.wasm_cm_gc, prefix.wasm_cm_gc, "--wasm-cm-gc")?;
        Ok(())
    }

    fn has_non_verbosity_arguments(&self) -> bool {
        self.input.is_some()
            || self.config_path.is_some()
            || self.log_stdout
            || self.log_stderr
            || self.profile.is_some()
            || self.local_pushpin_proxy_port.is_some()
            || !self.experimental_modules.is_empty()
            || self.unknown_import_behavior.is_some()
            || self.adapt
            || self.wasm_exceptions
            || self.wasm_gc
            || self.wasm_cm_gc
    }
}

fn inherit_option<T>(
    target: &mut Option<T>,
    prefix: Option<T>,
    argument: &'static str,
) -> Result<(), &'static str> {
    if target.is_some() && prefix.is_some() {
        return Err(argument);
    }
    if target.is_none() {
        *target = prefix;
    }
    Ok(())
}

fn inherit_flag(
    target: &mut bool,
    prefix: bool,
    argument: &'static str,
) -> Result<(), &'static str> {
    if *target && prefix {
        return Err(argument);
    }
    *target |= prefix;
    Ok(())
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

/// Parse a string as a duration
///
/// This implementation is mostly borrowed from the wasmtime cli
fn parse_profile_sample_duration(s: &str) -> Result<Duration, Error> {
    // assume an integer without a unit specified is a number of seconds ...
    if let Ok(val) = s.parse() {
        return Ok(Duration::from_secs(val));
    }

    if let Some(num) = s.strip_suffix("s")
        && let Ok(val) = num.parse()
    {
        return Ok(Duration::from_secs(val));
    }
    if let Some(num) = s.strip_suffix("ms")
        && let Ok(val) = num.parse()
    {
        return Ok(Duration::from_millis(val));
    }
    if let Some(num) = s.strip_suffix("us").or(s.strip_suffix("μs"))
        && let Ok(val) = num.parse()
    {
        return Ok(Duration::from_micros(val));
    }
    if let Some(num) = s.strip_suffix("ns")
        && let Ok(val) = num.parse()
    {
        return Ok(Duration::from_nanos(val));
    }

    Err(Error::ProfilingStrategy)
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
        ["guest"] => Ok(Profile::Guest {
            path: None,
            sample_period: None,
        }),
        ["guest", path] => Ok(Profile::Guest {
            path: Some(path.to_string()),
            sample_period: None,
        }),
        ["guest", path, sample_period] => Ok(Profile::Guest {
            path: path.to_string().into(),
            sample_period: Some(parse_profile_sample_duration(sample_period)?),
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
        super::{AdaptArgs, Commands, Opts, RunArgs, ServeArgs},
        clap::{CommandFactory, Parser, error::ErrorKind},
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

    fn parse_command(args: &[&str]) -> Result<Commands, clap::Error> {
        Opts::try_parse_from(args)?.into_command()
    }

    fn expect_run(args: &[&str]) -> RunArgs {
        match parse_command(args).expect("command should parse") {
            Commands::Run(run_args) => run_args,
            command => panic!("expected run command, got {command:?}"),
        }
    }

    fn expect_serve(args: &[&str]) -> ServeArgs {
        match parse_command(args).expect("command should parse") {
            Commands::Serve(serve_args) => serve_args,
            command => panic!("expected serve command, got {command:?}"),
        }
    }

    fn expect_adapt(args: &[&str]) -> AdaptArgs {
        match parse_command(args).expect("command should parse") {
            Commands::Adapt(adapt_args) => adapt_args,
            command => panic!("expected adapt command, got {command:?}"),
        }
    }

    #[test]
    fn shared_options_before_run_are_applied() {
        let input = test_file("minimal.wat");
        let run_args = expect_run(&["dummy-program-name", "--log-stdout", "-vv", "run", &input]);
        assert!(run_args.shared().log_stdout());
        assert_eq!(run_args.shared().verbosity(), 2);
    }

    #[test]
    fn shared_options_can_surround_run() {
        let input = test_file("minimal.wat");
        let run_args = expect_run(&[
            "dummy-program-name",
            "--config",
            "before.toml",
            "run",
            "--log-stderr",
            &input,
        ]);
        assert_eq!(
            run_args.shared().config_path(),
            Some(std::path::Path::new("before.toml"))
        );
        assert!(run_args.shared().log_stderr());
    }

    #[test]
    fn shared_options_before_explicit_serve_are_applied() {
        let input = test_file("minimal.wat");
        let expected_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7677);
        let serve_args = expect_serve(&[
            "dummy-program-name",
            "--log-stdout",
            "--addr",
            "127.0.0.1:7677",
            "serve",
            &input,
        ]);
        assert!(serve_args.shared().log_stdout());
        assert_eq!(serve_args.addr(), expected_addr);
    }

    #[test]
    fn prefix_options_do_not_capture_run_trailing_args() {
        let input = test_file("minimal.wat");
        let run_args = expect_run(&[
            "dummy-program-name",
            "--log-stdout",
            "run",
            "--",
            &input,
            "--log-stderr",
            "-v",
        ]);
        assert!(run_args.shared().log_stdout());
        assert!(!run_args.shared().log_stderr());
        assert_eq!(run_args.shared().verbosity(), 0);
        assert_eq!(run_args.wasm_args(), &["--log-stderr", "-v"]);
    }

    #[test]
    fn default_serve_options_still_work() {
        let input = test_file("minimal.wat");
        let serve_args = expect_serve(&[
            "dummy-program-name",
            "-v",
            "--config",
            "default-serve.toml",
            &input,
        ]);
        assert_eq!(serve_args.shared().verbosity(), 1);
        assert_eq!(
            serve_args.shared().config_path(),
            Some(std::path::Path::new("default-serve.toml"))
        );
    }

    #[test]
    fn verbosity_counts_across_run_boundary() {
        let input = test_file("minimal.wat");
        let run_args = expect_run(&["dummy-program-name", "-v", "run", "-vv", &input]);
        assert_eq!(run_args.shared().verbosity(), 3);
    }

    #[test]
    fn append_options_accumulate_across_run_boundary() {
        let input = test_file("minimal.wat");
        let run_args = expect_run(&[
            "dummy-program-name",
            "--experimental_modules",
            "wasi-nn",
            "run",
            "--experimental_modules",
            "wasi-nn",
            &input,
        ]);
        assert_eq!(run_args.shared.experimental_modules.len(), 2);
    }

    #[test]
    fn prefix_verbosity_is_applied_to_adapt() {
        let input = test_file("minimal.wat");
        let adapt_args = expect_adapt(&["dummy-program-name", "-v", "adapt", "-vv", &input]);
        assert_eq!(adapt_args.verbosity(), 3);
    }

    #[test]
    fn option_values_matching_subcommands_are_not_reinterpreted() {
        let input = test_file("minimal.wat");
        let serve_args = expect_serve(&["dummy-program-name", "--config", "run", "serve", &input]);
        assert_eq!(
            serve_args.shared().config_path(),
            Some(std::path::Path::new("run"))
        );
    }

    #[test]
    fn root_usage_distinguishes_adapt_from_serve_and_run() {
        let help = Opts::command().render_long_help().to_string();
        assert!(help.contains("viceroy [OPTIONS] <INPUT>"));
        assert!(help.contains("viceroy [OPTIONS] serve [ARGS]"));
        assert!(help.contains("viceroy [SHARED OPTIONS] run [ARGS]"));
        assert!(help.contains("viceroy [-v...] adapt"));
        assert!(help.contains("SHARED OPTIONS are all root options except --addr."));
        assert!(help.contains("serve mode only"));
        assert!(!help.contains("viceroy [OPTIONS] {serve|run}"));
        assert!(!help.contains("viceroy [OPTIONS] <COMMAND>"));
        assert!(!help.contains("viceroy [OPTIONS] [INPUT] <COMMAND>"));
    }

    #[test]
    fn unknown_import_behavior_default_is_preserved_and_documented() {
        let input = test_file("minimal.wat");
        let serve_args = expect_serve(&["dummy-program-name", &input]);
        assert_eq!(
            serve_args.shared().unknown_import_behavior(),
            viceroy_lib::config::UnknownImportBehavior::LinkError
        );

        let help = Opts::command().render_help().to_string();
        assert!(help.contains("Set the behavior for unknown imports (default: link-error)"));
    }

    #[test]
    fn unknown_flag_starts_run_trailing_args() {
        let input = test_file("minimal.wat");
        let run_args = expect_run(&[
            "dummy-program-name",
            "--log-stdout",
            "run",
            &input,
            "-x",
            "--config",
            "guest.toml",
        ]);
        assert!(run_args.shared().log_stdout());
        assert_eq!(run_args.shared().config_path(), None);
        assert_eq!(run_args.wasm_args(), &["-x", "--config", "guest.toml"]);
    }

    #[test]
    fn duplicate_options_across_subcommand_are_rejected() {
        let input = test_file("minimal.wat");
        let cases = [
            vec![
                "dummy-program-name",
                "--config",
                "before.toml",
                "run",
                "--config",
                "after.toml",
                &input,
            ],
            vec![
                "dummy-program-name",
                "--log-stdout",
                "run",
                "--log-stdout",
                &input,
            ],
            vec![
                "dummy-program-name",
                "--unknown-import-behavior",
                "link-error",
                "run",
                "--unknown-import-behavior",
                "trap",
                &input,
            ],
            vec![
                "dummy-program-name",
                "--addr",
                "127.0.0.1:7677",
                "serve",
                "--addr",
                "127.0.0.1:7678",
                &input,
            ],
        ];

        for args in cases {
            let error = parse_command(&args).expect_err("duplicate option should fail");
            assert_eq!(error.kind(), ErrorKind::ArgumentConflict);
        }
    }

    #[test]
    fn options_invalid_for_selected_subcommand_are_rejected() {
        let input = test_file("minimal.wat");
        let cases = [
            vec![
                "dummy-program-name",
                "--addr",
                "127.0.0.1:7677",
                "run",
                &input,
            ],
            vec![
                "dummy-program-name",
                "--config",
                "before.toml",
                "adapt",
                &input,
            ],
            vec!["dummy-program-name", &input, "run", &input],
        ];

        for args in cases {
            let error = parse_command(&args).expect_err("invalid option placement should fail");
            assert_eq!(error.kind(), ErrorKind::ArgumentConflict);
        }
    }

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

    #[test]
    fn wasmtime_profiling_strategy_guest_with_path_and_period_is_accepted() -> TestResult {
        let args = &[
            "dummy-program-name",
            "--profile",
            "guest,/some/path,250ns",
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
