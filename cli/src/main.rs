//! Fastly's local testing daemon for Compute.

// When building the project in release mode:
//   (1): Promote warnings into errors.
//   (2): Deny broken documentation links.
//   (3): Deny invalid codeblock attributes in documentation.
//   (4): Promote warnings in examples into errors, except for unused variables.
#![cfg_attr(not(debug_assertions), deny(warnings))]
#![cfg_attr(not(debug_assertions), deny(clippy::all))]
#![cfg_attr(not(debug_assertions), deny(broken_intra_doc_links))]
#![cfg_attr(not(debug_assertions), deny(invalid_codeblock_attributes))]
#![cfg_attr(not(debug_assertions), doc(test(attr(deny(warnings)))))]
#![cfg_attr(not(debug_assertions), doc(test(attr(allow(dead_code)))))]
#![cfg_attr(not(debug_assertions), doc(test(attr(allow(unused_variables)))))]

mod execute_ctx;
mod opts;
mod subcommands;

use {
    crate::execute_ctx::*,
    crate::opts::*,
    clap::Parser,
    std::env,
    std::process::ExitCode,
    tracing::{Level, event},
    tracing_subscriber::{FmtSubscriber, filter::EnvFilter},
};

#[tokio::main]
async fn main() -> ExitCode {
    // Parse the command-line options, exiting if there are any errors
    let opts = Opts::parse();
    let cmd = opts.command.unwrap_or(Commands::Serve(opts.serve));
    match cmd {
        Commands::Run(run_args) => subcommands::run::exec(run_args).await,
        Commands::Serve(serve_args) => subcommands::serve::exec(serve_args).await,
        Commands::Adapt(adapt_args) => subcommands::adapt::exec(adapt_args),
    }
}

/// Default to whatever a user provides, but if not set logging to work for
/// viceroy and viceroy-lib so that they can have output in the terminal
fn tracing_log_filter(env_filter: Option<&str>, verbosity: u8) -> &str {
    // technically a `viceroy` directive subsumes `viceroy_lib` because
    // tracing_subscriber does a naive string prefix match...
    // Explains why the prior `viceroy-lib` default still seemed to work despite
    // being invalid (syntax needs to match rust module not crate name).
    env_filter.unwrap_or(match verbosity {
        0 => "viceroy=error,viceroy_lib=error",
        1 => "viceroy=info,viceroy_lib=info",
        2 => "viceroy=debug,viceroy_lib=debug",
        _ => "viceroy=trace,viceroy_lib=trace",
    })
}

fn install_tracing_subscriber(verbosity: u8) {
    // Build a subscriber, using the default `RUST_LOG` environment variable for our filter.
    let filter_env = env::var(EnvFilter::DEFAULT_ENV).ok();
    let filter_str = tracing_log_filter(filter_env.as_deref(), verbosity);

    let builder = FmtSubscriber::builder()
        .with_writer(StdWriter::new())
        .with_env_filter(filter_str)
        .with_target(false);

    match env::var("RUST_LOG_PRETTY") {
        // If the `RUST_LOG_PRETTY` environment variable is set to "true", we should emit logs in a
        // pretty, human-readable output format.
        Ok(s) if s == "true" => builder
            .pretty()
            // Show levels, because ANSI escape sequences are normally used to indicate this.
            .with_level(true)
            .init(),
        // Otherwise, we should install the subscriber without any further additions.
        _ => builder.with_ansi(false).init(),
    }
    event!(
        Level::DEBUG,
        filter = %filter_str,
        "log filter configured"
    );
}

#[cfg(test)]
mod tests {
    use tracing::Level;
    use tracing_subscriber::FmtSubscriber;

    use crate::tracing_log_filter;

    fn test_log_filter(env_filter: Option<&str>, verbosity: u8, tests: impl FnOnce() -> ()) {
        let sub = FmtSubscriber::builder()
            .with_env_filter(tracing_log_filter(env_filter, verbosity))
            .finish();
        tracing::subscriber::with_default(sub, tests)
    }

    // unfortunately tracing doesn't provide a good way to use a runtime level
    // in tracing::enabled! This checks if a certain level is enabled through dispatch
    macro_rules! level_enabled {
        ($target:literal, $level:expr) => {
            match $level {
                Level::ERROR => tracing::enabled!(target: $target, Level::ERROR),
                Level::WARN => tracing::enabled!(target: $target, Level::WARN),
                Level::INFO => tracing::enabled!(target: $target, Level::INFO),
                Level::DEBUG => tracing::enabled!(target: $target, Level::DEBUG),
                Level::TRACE => tracing::enabled!(target: $target, Level::TRACE),
            }
        };
    }

    // the value of these log filter tests is debatable
    // we're really just testing a simple match and unwrap_or
    // but it does demonstrate the unintuitive directive
    // prefix match behavior

    #[test]
    fn log_filter_defaults() {
        let cases = [
            // verbosity, level
            (0, Level::ERROR),
            (1, Level::INFO),
            (2, Level::DEBUG),
            // this duplication is on purpose, >=3 sets trace. We skip warn
            (3, Level::TRACE),
            (4, Level::TRACE),
        ];

        for (verbosity, level) in cases {
            test_log_filter(None, verbosity, || {
                assert!(level_enabled!("viceroy", level));
                assert!(level_enabled!("viceroy_lib", level));
            });
        }
    }

    #[test]
    fn log_filter_uses_env() {
        // we choose warn because it's not one of the cases mapped from verbosity
        // so we can be sure that the var was read
        test_log_filter(Some("viceroy=warn"), 0, || {
            assert!(tracing::enabled!(target: "viceroy", Level::WARN));
            // viceroy_lib is set because tracing_subscriber does a naive string prefix match...
            // I think this is to handle submodules, but it also results in collisions like this
            // Currently fine, but would be a problem if we ever add another crate with a 'viceroy' prefix
            // that we don't want to include in the default directives
            assert!(tracing::enabled!(target: "viceroy_lib", Level::WARN));
        });
    }
}
