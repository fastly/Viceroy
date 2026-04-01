use crate::opts::ServeArgs;
use crate::{create_execution_context, install_tracing_subscriber};
use std::process::ExitCode;
use tracing::{Level, event};
use viceroy_lib::{Error, ProfilingConfig, ViceroyService};

pub(crate) async fn exec(serve_args: ServeArgs) -> ExitCode {
    install_tracing_subscriber(serve_args.shared().verbosity());
    match {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                Ok(())
            }
            res = serve(serve_args) => {
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

/// Starts up a Viceroy server.
///
/// Create a new server, bind it to an address, and serve responses until an error occurs.
async fn serve(serve_args: ServeArgs) -> Result<(), Error> {
    // Load the wasm module into an execution context
    let ctx = create_execution_context(serve_args.shared(), true).await?;

    // Create profile directory if guest profiling is enabled
    if let ProfilingConfig::Guest { path, .. } = serve_args.shared().profiling_config() {
        std::fs::create_dir_all(path)?;
    }

    let addr = serve_args.addr();
    ViceroyService::new(ctx).serve(addr).await?;

    unreachable!()
}
