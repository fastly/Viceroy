use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use walrus::ir::{dfs_pre_order_mut, VisitorMut};
use walrus::{MemoryId, Module};

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
}

/// A visitor to replace memory 0 with memory 1.
struct MemoryRemapper(MemoryId);
impl VisitorMut for MemoryRemapper {
    fn visit_memory_id_mut(&mut self, mem: &mut MemoryId) {
        *mem = self.0;
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    let wasm_bytes = std::fs::read(&args.input)?;
    let mut module = Module::from_buffer(&wasm_bytes)?;
    let adapter_memory = module.memories.add_local(false, false, 20, None, None);
    module.exports.add("adapter_memory", adapter_memory);

    let stack_pointer = module.globals.iter().find_map(|g| {
        let name = g.name.clone()?;
        if name == "__stack_pointer" { Some(g.id()) } else { None }
    }).unwrap();
    module.globals.get_mut(stack_pointer).name = Some("adapter_stack_pointer".to_string());

    let mut visitor = MemoryRemapper(adapter_memory);
    for (_, func) in module.funcs.iter_local_mut() {
        dfs_pre_order_mut(&mut visitor, func, func.entry_block());
    }
    let modified_wasm_bytes = module.emit_wasm();
    std::fs::write(&args.output, modified_wasm_bytes)?;
    Ok(())
}
