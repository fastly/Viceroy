//! Fastly's local testing daemon for Compute@Edge.

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

use std::process::ExitCode;

mod opts;

use {
    crate::opts::Opts,
    clap::Parser,
    hyper::{client::Client, Body, Request},
    std::{
        env,
        io::{self, Stderr, Stdout},
        time::Duration,
    },
    tokio::time::timeout,
    tracing::{event, Level, Metadata},
    tracing_subscriber::{filter::EnvFilter, fmt::writer::MakeWriter, FmtSubscriber},
    viceroy_lib::{config::FastlyConfig, BackendConnector, Error, ExecuteCtx, ViceroyService},
};

/// Starts up a Viceroy server.
///
/// Create a new server, bind it to an address, and serve responses until an error occurs.
pub async fn serve(opts: Opts) -> Result<(), Error> {
    // Load the wasm module into an execution context
    let ctx = create_execution_context(&opts).await?;

    let addr = opts.addr();
    ViceroyService::new(ctx).serve(addr).await?;

    unreachable!()
}

#[tokio::main]
pub async fn main() -> ExitCode {
    // Parse the command-line options, exiting if there are any errors
    let opts = Opts::parse();
    install_tracing_subscriber(&opts);
    if opts.run_mode() {
        match run_wasm_main(opts).await {
            Ok(_) => ExitCode::SUCCESS,
            Err(_) => ExitCode::FAILURE,
        }
    } else {
        match {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    Ok(())
                }
                res = serve(opts) => {
                    if let Err(ref e) = res {
                        event!(Level::ERROR, "{}", e);
                    }
                    res
                }
            }
        } {
            Ok(_) => ExitCode::SUCCESS,
            Err(_) => ExitCode::FAILURE,
        }
    }
}

/// Execute a Wasm program in the Viceroy environment.
pub async fn run_wasm_main(opts: Opts) -> Result<(), anyhow::Error> {
    // Load the wasm module into an execution context
    let ctx = create_execution_context(&opts).await?;
    let program_name = match opts.input().file_stem() {
        Some(stem) => stem.to_string_lossy(),
        None => panic!("program cannot be a directory"),
    };
    ctx.run_main(&program_name, opts.wasm_args()).await
}

fn install_tracing_subscriber(opts: &Opts) {
    // Default to whatever a user provides, but if not set logging to work for
    // viceroy and viceroy-lib so that they can have output in the terminal
    if env::var("RUST_LOG").ok().is_none() {
        match opts.verbosity() {
            0 => env::set_var("RUST_LOG", "viceroy=info,viceroy-lib=info"),
            1 => {
                env::set_var("RUST_LOG", "viceroy=debug,viceroy-lib=debug");
            }
            _ => {
                env::set_var("RUST_LOG", "viceroy=trace,viceroy-lib=trace");
            }
        }
    }
    // If the quiet flag is passed in, don't log anything (this should maybe
    // just be a verbosity setting)
    if opts.quiet() {
        env::set_var("RUST_LOG", "viceroy=off,viceroy-lib=off");
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

pub enum Stdio {
    Stdout(Stdout),
    Stderr(Stderr),
}

impl io::Write for Stdio {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Stdout(out) => out.write(buf),
            Self::Stderr(err) => err.write(buf),
        }
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        match self {
            Self::Stdout(out) => out.write_all(buf),
            Self::Stderr(err) => err.write_all(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Stdout(out) => out.flush(),
            Self::Stderr(err) => err.flush(),
        }
    }
}

pub struct StdWriter;

impl StdWriter {
    fn new() -> Self {
        Self {}
    }
}

impl<'a> MakeWriter<'a> for StdWriter {
    type Writer = Stdio;

    // We need to implement a default behavior so we'll use stdout
    fn make_writer(&self) -> Self::Writer {
        Stdio::Stdout(io::stdout())
    }

    // This is where we can set where we want to send data actually based off
    // the log level. In this case we want errors to go to stderr as if we used
    // eprintln and to stdout for everything else.
    fn make_writer_for(&self, meta: &Metadata<'_>) -> Self::Writer {
        if meta.level() == &Level::ERROR {
            Stdio::Stderr(io::stderr())
        } else {
            Stdio::Stdout(io::stdout())
        }
    }
}

async fn create_execution_context(opts: &Opts) -> Result<ExecuteCtx, anyhow::Error> {
    let mut ctx = ExecuteCtx::new(opts.input(), opts.profiling_strategy(), opts.wasi_modules())?
        .with_log_stderr(opts.log_stderr())
        .with_log_stdout(opts.log_stdout());

    if let Some(config_path) = opts.config_path() {
        let config = FastlyConfig::from_file(config_path)?;
        let backends = config.backends();
        let geolocation = config.geolocation();
        let dictionaries = config.dictionaries();
        let object_store = config.object_store();
        let secret_stores = config.secret_stores();
        let backend_names = itertools::join(backends.keys(), ", ");

        ctx = ctx
            .with_backends(backends.clone())
            .with_geolocation(geolocation.clone())
            .with_dictionaries(dictionaries.clone())
            .with_object_store(object_store.clone())
            .with_secret_stores(secret_stores.clone())
            .with_config_path(config_path.into());

        if backend_names.is_empty() {
            event!(
                Level::WARN,
                "no backend definitions found in {}",
                config_path.display()
            );
        }
        if !opts.run_mode() {
            for (name, backend) in backends.iter() {
                let client = Client::builder().build(BackendConnector::new(
                    backend.clone(),
                    ctx.tls_config().clone(),
                ));
                let req = Request::get(&backend.uri).body(Body::empty()).unwrap();

                event!(Level::INFO, "checking if backend '{}' is up", name);
                match timeout(Duration::from_secs(5), client.request(req)).await {
                    // In the case that we don't time out but we have an error, we
                    // check that it's specifically a connection error as this is
                    // the only one that happens if the server is not up.
                    //
                    // We can't combine this with the case above due to needing the
                    // inner error to check if it's a connection error. The type
                    // checker complains about it.
                    Ok(Err(ref e)) if e.is_connect() => event!(
                        Level::WARN,
                        "backend '{}' on '{}' is not up right now",
                        name,
                        backend.uri
                    ),
                    // In the case we timeout we assume the backend is not up as 5
                    // seconds to do a simple get should be enough for a healthy
                    // service
                    Err(_) => event!(
                        Level::WARN,
                        "backend '{}' on '{}' is not up right now",
                        name,
                        backend.uri
                    ),
                    Ok(_) => event!(Level::INFO, "backend '{}' is up", name),
                }
            }
        }
    } else {
        event!(
            Level::WARN,
            "no configuration provided, invoke with `-C <TOML_FILE>` to provide a configuration"
        );
    }
    Ok(ctx)
}
