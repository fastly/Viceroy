use crate::opts::{ServeArgs, TlsMode};
use crate::{create_execution_context, install_tracing_subscriber};
use std::process::ExitCode;
use tracing::{Level, event};
use viceroy_lib::{Error, ProfilingConfig, ViceroyService, downstream_tls::DownstreamTlsConfig};

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
    let service = ViceroyService::new(ctx);
    match load_tls_config(&serve_args.tls_mode())? {
        Some(tls) => service.serve_tls(addr, tls).await?,
        None => service.serve(addr).await?,
    }

    unreachable!()
}

/// Build the downstream TLS configuration requested on the command line, if any.
fn load_tls_config(mode: &TlsMode) -> Result<Option<DownstreamTlsConfig>, Error> {
    match mode {
        TlsMode::Disabled => Ok(None),
        TlsMode::Files { cert, key } => Ok(Some(DownstreamTlsConfig::from_pem_files(cert, key)?)),
        TlsMode::SelfSigned { sans, out } => {
            let tls = DownstreamTlsConfig::self_signed(sans)?;
            let pem = tls.certificate_pem().unwrap_or_default();
            if let Some(out) = out {
                std::fs::write(out, pem)?;
                event!(
                    Level::INFO,
                    "Wrote self-signed certificate for {} to {}",
                    sans.join(", "),
                    out.display()
                );
            }
            // Always show the certificate, so it can be trusted even without `-v`.
            eprintln!(
                "Generated a self-signed certificate for {}. Clients will not trust it unless \
                 you add it to their trust store:\n{}",
                sans.join(", "),
                pem.trim_end()
            );
            Ok(Some(tls))
        }
    }
}
