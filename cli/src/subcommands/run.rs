use crate::execute_ctx::create_execution_context;
use crate::install_tracing_subscriber;
use crate::opts::RunArgs;
use std::process::ExitCode;
use tracing::{event, Level};
use wasmtime_wasi::I32Exit;

pub(crate) async fn exec(run_args: RunArgs) -> ExitCode {
    install_tracing_subscriber(run_args.shared().verbosity());
    match run_wasm_main(run_args).await {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            // Suppress stack trace if the error is due to a
            // normal call to proc_exit, leading to a process
            // exit.
            if !e.is::<I32Exit>() {
                event!(Level::ERROR, "{}", e);
            }
            get_exit_code(e)
        }
    }
}

/// Execute a Wasm program in the Viceroy environment.
async fn run_wasm_main(run_args: RunArgs) -> Result<(), anyhow::Error> {
    // Load the wasm module into an execution context
    let ctx = create_execution_context(
        run_args.shared(),
        false,
        run_args.shared().guest_profile_config(),
    )
    .await?;
    let input = run_args.shared().input();
    let program_name = match input.file_stem() {
        Some(stem) => stem.to_string_lossy(),
        None => panic!("program cannot be a directory"),
    };
    ctx.run_main(&program_name, run_args.wasm_args()).await
}

// This function is based on similar exit code logic in the wasmtime cli:
// https://github.com/bytecodealliance/wasmtime/blob/cc768f/src/commands/run.rs#L214-L246
fn get_exit_code(e: anyhow::Error) -> ExitCode {
    // If we exited with a specific WASI exit code, forward that to
    // the process
    if let Some(exit) = e.downcast_ref::<I32Exit>() {
        // On Windows, exit status 3 indicates an abort (see below),
        // so return 1 indicating a non-zero status to avoid ambiguity.
        if cfg!(windows) && exit.0 >= 3 {
            return ExitCode::FAILURE;
        }
        return ExitCode::from(exit.0 as u8);
    }

    // If the program exited because of a trap, return an error code
    // to the outside environment indicating a more severe problem
    // than a simple failure.
    if e.is::<wasmtime::Trap>() {
        if cfg!(unix) {
            // On Unix, return the error code of an abort.
            return ExitCode::from(128u8 + libc::SIGABRT as u8);
        } else if cfg!(windows) {
            // On Windows, return 3.
            // https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/abort?view=vs-2019
            return ExitCode::from(3u8);
        }
    }
    // Otherwise just return 1
    ExitCode::FAILURE
}
