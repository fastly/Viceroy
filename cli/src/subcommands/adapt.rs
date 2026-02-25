use crate::install_tracing_subscriber;
use crate::opts::AdaptArgs;
use std::process::ExitCode;
use tracing::{Level, event};

pub(crate) fn exec(adapt_args: AdaptArgs) -> ExitCode {
    install_tracing_subscriber(adapt_args.verbosity());
    let input = adapt_args.input();
    let output = adapt_args.output();
    let bytes = match std::fs::read(&input) {
        Ok(bytes) => bytes,
        Err(_) => {
            event!(
                Level::ERROR,
                "Failed to read module from: {}",
                input.display()
            );
            return ExitCode::FAILURE;
        }
    };

    if viceroy_lib::adapt::is_component(&bytes) {
        event!(
            Level::ERROR,
            "File is already a component: {}",
            input.display()
        );
        return ExitCode::FAILURE;
    }

    let is_wat = input.extension().map(|str| str == "wat").unwrap_or(false);

    let module = if is_wat {
        let text = match String::from_utf8(bytes) {
            Ok(module) => module,
            Err(e) => {
                event!(Level::ERROR, "Failed to parse wat: {e:?}");
                return ExitCode::FAILURE;
            }
        };

        match viceroy_lib::adapt::adapt_wat(&text) {
            Ok(module) => module,
            Err(e) => {
                event!(Level::ERROR, "Failed to adapt wat: {e:?}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        match viceroy_lib::adapt::adapt_bytes(&bytes) {
            Ok(module) => module,
            Err(e) => {
                event!(Level::ERROR, "Failed to adapt module: {e:?}");
                return ExitCode::FAILURE;
            }
        }
    };

    event!(Level::INFO, "Writing component to: {}", output.display());
    match std::fs::write(output, module) {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            event!(Level::ERROR, "Failed to write component: {e:?}");
            return ExitCode::FAILURE;
        }
    }
}
