use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use walrus::Module;

/// A simple tool to remap memory 0 to 1 in a Wasm module.
// Adapter has an imported memory 0, which is user's main memory.
// We add a local memory 1, and redirect all memory access to memory 1.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Input Wasm file
    input: PathBuf,
    /// Output Wasm file
    #[clap(short, long)]
    output: PathBuf,
    /// Use multi-memory for adapter. If false, shift the main module memory
    #[clap(short, long)]
    use_multi_memory: bool,
    /// Is the wasm module an adapter
    #[clap(short, long)]
    adapter: bool,
}

mod multi_mem;
mod shift;

fn main() -> Result<()> {
    let args = Args::parse();
    let wasm_bytes = std::fs::read(&args.input)?;
    let mut module = Module::from_buffer(&wasm_bytes)?;
    if args.use_multi_memory {
        multi_mem::use_multi_memory(&mut module)?
    } else {
        if args.adapter {
            shift::shift_adapter_module(&mut module)?
        } else {
            shift::shift_main_module(&mut module)?
        }
    }
    let modified_wasm_bytes = module.emit_wasm();
    std::fs::write(&args.output, modified_wasm_bytes)?;
    Ok(())
}
