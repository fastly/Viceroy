use crate::opts::SharedArgs;
use hyper::{Body, Request, client::Client};
use std::io::{self, Stderr, Stdout};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;
use tracing::{Level, Metadata, event};
use tracing_subscriber::fmt::writer::MakeWriter;
use viceroy_lib::{BackendConnector, ExecuteCtx, GuestProfileConfig, config::FastlyConfig};

pub(crate) enum Stdio {
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

pub(crate) struct StdWriter;

impl StdWriter {
    pub(crate) fn new() -> Self {
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

pub(crate) async fn create_execution_context(
    args: &SharedArgs,
    check_backends: bool,
    guest_profile_config: Option<GuestProfileConfig>,
) -> Result<Arc<ExecuteCtx>, anyhow::Error> {
    let input = args.input();
    let ctx = ExecuteCtx::build(
        input,
        args.profiling_strategy(),
        args.wasi_modules(),
        guest_profile_config,
        args.unknown_import_behavior(),
        args.adapt(),
    )?
    .with_log_stderr(args.log_stderr())
    .with_log_stdout(args.log_stdout())
    .with_local_pushpin_proxy_port(args.local_pushpin_proxy_port());

    let Some(config_path) = args.config_path() else {
        event!(
            Level::WARN,
            "no configuration provided, invoke with `-C <TOML_FILE>` to provide a configuration"
        );

        return Ok(ctx.finish()?);
    };

    let config = FastlyConfig::from_file(config_path)?;
    let acls = config.acls();
    let backends = config.backends();
    let device_detection = config.device_detection();
    let geolocation = config.geolocation();
    let dictionaries = config.dictionaries();
    let object_stores = config.object_stores();
    let secret_stores = config.secret_stores();
    let shielding_sites = config.shielding_sites();
    let backend_names = itertools::join(backends.keys(), ", ");

    let ctx = ctx
        .with_acls(acls.clone())
        .with_backends(backends.clone())
        .with_device_detection(device_detection.clone())
        .with_geolocation(geolocation.clone())
        .with_dictionaries(dictionaries.clone())
        .with_object_stores(object_stores.clone())
        .with_secret_stores(secret_stores.clone())
        .with_shielding_sites(shielding_sites.clone())
        .with_config_path(config_path.into())
        .finish()?;

    if backend_names.is_empty() {
        event!(
            Level::WARN,
            "no backend definitions found in {}",
            config_path.display()
        );
    }

    if check_backends {
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

    Ok(ctx)
}
