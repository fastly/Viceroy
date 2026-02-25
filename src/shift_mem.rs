/// This module takes the user wasm module (main module) and pushes the memory address
/// by 2 pages. Concretely, we perform the following binary rewriting:
///   1) Increase the initial memory size by 2 pages
///   2) For active data section, move the offset address by 2 pages
///   3) Instrument all the memory access instructions to add a 2 page offset.
///      This includes `memory.grow`, `memory.size`, `memory.init`, `memory.fill`,
///      `memory.copy`, `memory.load` and `memory.store`.
///   4) When calling imported functions, the argument is passed unchanged.
///      This means that the address passed to the imported function is the original address
///      before the offset. Therefore, the receiver, i.e., adapter, needs to add the offset
///      before accessing the passed in addresses. This is done in the adapter code.
///      The comment at the top of `wasm_abi/adapter/src` details how this is accomplished.
use walrus::ir::*;
use walrus::*;

const OFFSET_PAGES: i32 = 2;
// This const should always equal to the OFFSET defined in wasm_abi/adapter/src/lib.rs
const OFFSET: i32 = OFFSET_PAGES * 64 * 1024;
fn shift_func(r#gen: &mut ModuleLocals, func: &mut LocalFunction) {
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
                Instr::IfElse(IfElse {
                    consequent,
                    alternative,
                }) => {
                    stack.push(consequent);
                    stack.push(alternative);
                    instrs.push((instr, loc));
                }
                Instr::MemorySize(_) | Instr::MemoryGrow(_) => {
                    instrs.push((instr, loc));
                    instrs.push((
                        Instr::Const(Const {
                            value: Value::I32(OFFSET_PAGES),
                        }),
                        Default::default(),
                    ));
                    instrs.push((
                        Instr::Binop(Binop {
                            op: BinaryOp::I32Sub,
                        }),
                        Default::default(),
                    ));
                }
                Instr::MemoryInit(_) | Instr::MemoryFill(_) => {
                    let local1 = get_local(r#gen, &mut locals, 0);
                    let local2 = get_local(r#gen, &mut locals, 1);
                    instrs.push((
                        Instr::LocalSet(LocalSet { local: local1 }),
                        Default::default(),
                    ));
                    instrs.push((
                        Instr::LocalSet(LocalSet { local: local2 }),
                        Default::default(),
                    ));
                    instrs.push((
                        Instr::Const(Const {
                            value: Value::I32(OFFSET),
                        }),
                        Default::default(),
                    ));
                    instrs.push((
                        Instr::Binop(Binop {
                            op: BinaryOp::I32Add,
                        }),
                        Default::default(),
                    ));
                    instrs.push((
                        Instr::LocalGet(LocalGet { local: local2 }),
                        Default::default(),
                    ));
                    instrs.push((
                        Instr::LocalGet(LocalGet { local: local1 }),
                        Default::default(),
                    ));
                    instrs.push((instr, loc));
                }
                Instr::MemoryCopy(_) => {
                    let local1 = get_local(r#gen, &mut locals, 0);
                    let local2 = get_local(r#gen, &mut locals, 1);
                    instrs.push((
                        Instr::LocalSet(LocalSet { local: local1 }),
                        Default::default(),
                    ));
                    instrs.push((
                        Instr::LocalSet(LocalSet { local: local2 }),
                        Default::default(),
                    ));
                    instrs.push((
                        Instr::Const(Const {
                            value: Value::I32(OFFSET),
                        }),
                        Default::default(),
                    ));
                    instrs.push((
                        Instr::Binop(Binop {
                            op: BinaryOp::I32Add,
                        }),
                        Default::default(),
                    ));
                    instrs.push((
                        Instr::LocalGet(LocalGet { local: local2 }),
                        Default::default(),
                    ));
                    instrs.push((
                        Instr::Const(Const {
                            value: Value::I32(OFFSET),
                        }),
                        Default::default(),
                    ));
                    instrs.push((
                        Instr::Binop(Binop {
                            op: BinaryOp::I32Add,
                        }),
                        Default::default(),
                    ));
                    instrs.push((
                        Instr::LocalGet(LocalGet { local: local1 }),
                        Default::default(),
                    ));
                    instrs.push((instr, loc));
                }
                Instr::Load(Load {
                    memory,
                    kind,
                    arg: MemArg { align, offset },
                }) => {
                    let offset = offset.checked_add(OFFSET as u32).unwrap();
                    let instr = Instr::Load(Load {
                        memory,
                        kind,
                        arg: MemArg { align, offset },
                    });
                    instrs.push((instr, loc));
                }
                Instr::Store(Store {
                    memory,
                    kind,
                    arg: MemArg { align, offset },
                }) => {
                    let offset = offset.checked_add(OFFSET as u32).unwrap();
                    let instr = Instr::Store(Store {
                        memory,
                        kind,
                        arg: MemArg { align, offset },
                    });
                    instrs.push((instr, loc));
                }
                Instr::AtomicFence(_)
                | Instr::AtomicNotify(_)
                | Instr::AtomicWait(_)
                | Instr::AtomicRmw(_)
                | Instr::Cmpxchg(_) => todo!(),
                Instr::LoadSimd(_) => todo!(),
                _ => instrs.push((instr, loc)),
            }
        }
        seq.instrs = instrs;
    }
}
fn get_local(r#gen: &mut ModuleLocals, locals: &mut Vec<LocalId>, idx: usize) -> LocalId {
    if idx < locals.len() {
        locals[idx]
    } else {
        for _ in locals.len()..=idx {
            locals.push(r#gen.add(ValType::I32));
        }
        locals[idx]
    }
}

pub fn shift_main_module(bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut module = Module::from_buffer(bytes)?;
    // enlarge memory
    if module.memories.is_empty() {
        module
            .memories
            .add_local(false, false, OFFSET_PAGES as u64, None, None);
    } else {
        assert!(module.memories.len() == 1);
        let mem = module.memories.iter_mut().next().unwrap();
        mem.initial += OFFSET_PAGES as u64;
        mem.maximum = mem
            .maximum
            .map(|m| m.checked_add(OFFSET_PAGES as u64).unwrap());
    }
    // shift data
    let data_ids: Vec<_> = module.data.iter().map(|d| d.id()).collect();
    for id in data_ids {
        let data = module.data.get_mut(id);
        match data.kind {
            DataKind::Active {
                memory,
                offset: ConstExpr::Value(Value::I32(offset)),
            } => {
                let offset = offset.checked_add(OFFSET).unwrap();
                data.kind = DataKind::Active {
                    memory,
                    offset: ConstExpr::Value(Value::I32(offset)),
                };
            }
            DataKind::Active { .. } => unreachable!(),
            DataKind::Passive { .. } => {}
        }
    }
    // shift memory access
    for (_, func) in module.funcs.iter_local_mut() {
        shift_func(&mut module.locals, func);
    }
    Ok(module.emit_wasm())
}
