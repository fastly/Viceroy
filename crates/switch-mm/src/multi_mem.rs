use walrus::ir::*;
use walrus::*;

/// A visitor to replace memory 0 with memory 1.
struct MemoryRemapper {
    adapter_memory_id: MemoryId,
    is_adapter_region: bool,
    is_last_instr_magic: bool,
}
impl VisitorMut for MemoryRemapper {
    fn visit_instr_mut(&mut self, instr: &mut Instr, _: &mut ir::InstrLocId) {
        match instr {
            Instr::Drop(_) => {
                if self.is_last_instr_magic {
                    self.is_adapter_region = !self.is_adapter_region;
                }
                self.is_last_instr_magic = false;
            }
            Instr::Const(ir::Const {
                value: ir::Value::I32(n),
            }) if *n == 123456789 => self.is_last_instr_magic = true,
            _ => self.is_last_instr_magic = false,
        }
    }
    fn visit_memory_id_mut(&mut self, mem: &mut MemoryId) {
        if self.is_adapter_region {
            *mem = self.adapter_memory_id;
        }
    }
}

pub fn use_multi_memory(module: &mut Module) -> Result<()> {
    let adapter_memory_id = module.memories.add_local(false, false, 20, None, None);
    let stack_pointer = module
        .globals
        .iter()
        .find_map(|g| {
            let name = g.name.clone()?;
            if name == "__stack_pointer" {
                Some(g.id())
            } else {
                None
            }
        })
        .unwrap();
    module.globals.get_mut(stack_pointer).name = Some("adapter_stack_pointer".to_string());

    let mut visitor = MemoryRemapper {
        adapter_memory_id,
        is_adapter_region: true,
        is_last_instr_magic: false,
    };
    for (_, func) in module.funcs.iter_local_mut() {
        dfs_pre_order_mut(&mut visitor, func, func.entry_block());
    }
    Ok(())
}
