use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use walrus::ir::*;
use walrus::*;

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

const OFFSET_PAGES: i32 = 2;
const OFFSET: i32 = OFFSET_PAGES * 64 * 1024;
fn shift_func(gen: &mut ModuleLocals, func: &mut LocalFunction) {
    use ir::*;
    let start = func.entry_block();
    let mut locals = vec![];
    let mut stack = vec![start];
    while let Some(seq_id) = stack.pop() {
        let seq = func.block_mut(seq_id);
        let mut instrs = Vec::with_capacity(seq.len());
        for (instr, loc) in seq.instrs.iter() {
            let instr = instr.clone();
            let loc = loc.clone();
            match instr {
                Instr::Block(Block { seq }) | Instr::Loop(Loop { seq }) => {
                    stack.push(seq);
                    instrs.push((instr, loc));
                }
                Instr::IfElse(IfElse { consequent, alternative }) => {
                    stack.push(consequent);
                    stack.push(alternative);
                    instrs.push((instr, loc));
                }
                Instr::MemorySize(_) | Instr::MemoryGrow(_) => {
                    instrs.push((instr, loc));
                    instrs.push((Instr::Const(Const { value: Value::I32(OFFSET_PAGES) }), Default::default()));
                    instrs.push((Instr::Binop(Binop { op: BinaryOp::I32Sub }), Default::default()));
                }
                Instr::MemoryInit(_) => {
                    let local1 = get_local(gen, &mut locals, 0);
                    let local2 = get_local(gen, &mut locals, 1);
                    instrs.push((Instr::LocalSet(LocalSet { local: local1 }), Default::default()));
                    instrs.push((Instr::LocalSet(LocalSet { local: local2 }), Default::default()));
                    instrs.push((Instr::Const(Const { value: Value::I32(OFFSET) }), Default::default()));
                    instrs.push((Instr::Binop(Binop { op: BinaryOp::I32Add }), Default::default()));
                    instrs.push((Instr::LocalGet(LocalGet { local: local2 }), Default::default()));
                    instrs.push((Instr::LocalGet(LocalGet { local: local1 }), Default::default()));
                    instrs.push((instr, loc));
                }
                Instr::Load(Load { memory, kind, arg: MemArg { align, offset }}) => {
                    let offset = offset.checked_add(OFFSET as u32).unwrap();
                    let instr = Instr::Load(Load { memory, kind, arg: MemArg { align, offset }});
                    instrs.push((instr, loc));
                }
                Instr::Store(Store { memory, kind, arg: MemArg { align, offset }}) => {
                    let offset = offset.checked_add(OFFSET as u32).unwrap();
                    let instr = Instr::Store(Store { memory, kind, arg: MemArg { align, offset }});
                    instrs.push((instr, loc));
                }
                _ => instrs.push((instr, loc)),
            }
        }
        seq.instrs = instrs;
    }
}
fn get_local(gen: &mut ModuleLocals, locals: &mut Vec<LocalId>, idx: usize) -> LocalId {
    if idx < locals.len() {
        locals[idx]
    } else {
        for _ in locals.len()..=idx {
            locals.push(gen.add(ValType::I32));
        }
        locals[idx]
    }
}
fn shift_main_module(module: &mut Module) -> Result<()> {
    // enlarge memory
    if module.memories.is_empty() {
        module.memories.add_local(false, false, OFFSET_PAGES as u64, None, None);
    } else {
        assert!(module.memories.len() == 1);
        let mem = module.memories.iter_mut().next().unwrap();
        mem.initial += OFFSET_PAGES as u64;
        mem.maximum = mem.maximum.map(|m| m.checked_add(OFFSET_PAGES as u64).unwrap());
    }
    // shift data
    let data_ids: Vec<_> = module.data.iter().map(|d| d.id()).collect();
    for id in data_ids {
        let data = module.data.get_mut(id);
        match data.kind {
            DataKind::Active { offset: ConstExpr::Value(Value::I32(offset)), memory } => {
                let offset = offset.checked_add(OFFSET).unwrap();
                data.kind = DataKind::Active { memory, offset: ConstExpr::Value(Value::I32(offset)) };
            },
            DataKind::Active { .. } => unreachable!(),
            DataKind::Passive { .. } => {},
        }
    }
    // shift memory access
    for (_, func) in module.funcs.iter_local_mut() {
        shift_func(&mut module.locals, func);
    }
    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();
    let wasm_bytes = std::fs::read(&args.input)?;
    let mut module = Module::from_buffer(&wasm_bytes)?;
    if args.use_multi_memory {
        multi_mem::use_multi_memory(&mut module)?
    } else {
        if args.adapter {
            //shift_adapter_module(args)
        } else {
            shift_main_module(&mut module)?
        }
    }
    let modified_wasm_bytes = module.emit_wasm();
    std::fs::write(&args.output, modified_wasm_bytes)?;
    Ok(())
}