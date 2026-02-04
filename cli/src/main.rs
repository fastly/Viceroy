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
    tracing::{event, Level},
    tracing_subscriber::{filter::EnvFilter, FmtSubscriber},
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

fn install_tracing_subscriber(verbosity: u8) {
    // Default to whatever a user provides, but if not set logging to work for
    // viceroy and viceroy-lib so that they can have output in the terminal
    if env::var("RUST_LOG").ok().is_none() {
        match verbosity {
            0 => env::set_var("RUST_LOG", "viceroy=error,viceroy-lib=error"),
            1 => env::set_var("RUST_LOG", "viceroy=info,viceroy-lib=info"),
            2 => env::set_var("RUST_LOG", "viceroy=debug,viceroy-lib=debug"),
            _ => env::set_var("RUST_LOG", "viceroy=trace,viceroy-lib=trace"),
        }
    }

    // Build a subscriber, using the default `RUST_LOG` environment variable for our filter.
    let builder = FmtSubscriber::builder()
        .with_writer(StdWriter::new())
        .with_env_filter(EnvFilter::from_default_env())
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
        "RUST_LOG set to '{}'",
        env::var("RUST_LOG").unwrap_or_else(|_| String::from("<Could not get env>"))
    );
}
