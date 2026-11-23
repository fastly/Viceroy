//! Rewriting guest profiles to use offsets into the Wasm binary.
//!
//! Wasmtime's guest profiler records each frame as an offset into the native
//! code it compiled for the module. Those offsets are only meaningful to a
//! tool that can reproduce exactly the same compilation, which needs the same
//! Wasmtime version and engine configuration as Viceroy. We rewrite them to
//! offsets into the Wasm binary instead, which tools can resolve with the
//! module's own DWARF debug info. This also stops profiles from revealing the
//! size of the generated native code.

use std::ops::Range;

use wasmtime::Module;

/// Maps native code offsets of a compiled core module to offsets in its Wasm
/// binary.
pub(crate) struct WasmOffsets {
    /// `(.text offset, Wasm binary offset)` pairs in order of `.text` offset,
    /// as returned by [`Module::address_map`].
    addrs: Vec<(usize, Option<u32>)>,
    /// Defined functions, sorted by native start.
    funcs: Vec<FuncRange>,
}

#[derive(Debug, Clone, PartialEq)]
struct FuncRange {
    native: Range<usize>,
    wasm: Range<u32>,
}

impl WasmOffsets {
    /// Builds the map for `module`, compiled from the Wasm binary `wasm`.
    ///
    /// Returns `None` if the module has no address map or its functions do not
    /// line up with the code section of `wasm`.
    pub(crate) fn new(module: &Module, wasm: &[u8]) -> Option<Self> {
        let addrs = module.address_map()?.collect();
        let bodies = function_bodies(wasm).ok()?;
        let functions = module.functions();
        if functions.len() != bodies.len() {
            return None;
        }
        // `Module::functions` yields defined functions in index order, which is
        // the order of their bodies in the code section.
        let mut funcs = functions
            .zip(bodies)
            .map(|(f, body)| {
                Some(FuncRange {
                    native: f.offset..f.offset + f.len,
                    wasm: u32::try_from(body.start).ok()?..u32::try_from(body.end).ok()?,
                })
            })
            .collect::<Option<Vec<_>>>()?;
        funcs.sort_by_key(|f| f.native.start);
        Some(Self::from_parts(addrs, funcs))
    }

    fn from_parts(addrs: Vec<(usize, Option<u32>)>, funcs: Vec<FuncRange>) -> Self {
        Self { addrs, funcs }
    }

    fn func_at(&self, native: usize) -> Option<&FuncRange> {
        let i = self
            .funcs
            .partition_point(|f| f.native.start <= native)
            .checked_sub(1)?;
        let f = &self.funcs[i];
        f.native.contains(&native).then_some(f)
    }

    /// Returns the Wasm binary offset for a native code offset. Code without a
    /// Wasm location of its own, like a function prologue, maps to the start
    /// of the function body.
    fn wasm_offset(&self, native: usize) -> Option<u32> {
        let func = self.func_at(native)?;
        let i = self.addrs.partition_point(|(n, _)| *n <= native);
        match i.checked_sub(1).map(|i| self.addrs[i]) {
            Some((n, Some(wasm))) if n >= func.native.start && func.wasm.contains(&wasm) => {
                Some(wasm)
            }
            _ => Some(func.wasm.start),
        }
    }

    /// Rewrites the frame addresses and native symbols of a processed Firefox
    /// profile, as written by `GuestProfiler::finish`, to Wasm binary offsets.
    ///
    /// A frame's new address is the offset of the Wasm instruction it was
    /// sampled at (a call, or the point where the epoch check happened). A
    /// native symbol's new address and size are the range of the function's
    /// body in the code section, after the body size.
    pub(crate) fn rewrite_profile(&self, profile: &mut serde_json::Value) {
        let Some(threads) = profile
            .get_mut("threads")
            .and_then(serde_json::Value::as_array_mut)
        else {
            return;
        };
        for thread in threads {
            if let Some(addresses) = thread
                .pointer_mut("/frameTable/address")
                .and_then(serde_json::Value::as_array_mut)
            {
                for address in addresses {
                    if let Some(wasm) = address
                        .as_u64()
                        .and_then(|a| usize::try_from(a).ok())
                        .and_then(|a| self.wasm_offset(a))
                    {
                        *address = wasm.into();
                    }
                }
            }

            let Some(symbols) = thread
                .get_mut("nativeSymbols")
                .and_then(serde_json::Value::as_object_mut)
            else {
                continue;
            };
            let funcs: Vec<Option<FuncRange>> = symbols
                .get("address")
                .and_then(serde_json::Value::as_array)
                .map(|addresses| {
                    addresses
                        .iter()
                        .map(|a| {
                            let a = usize::try_from(a.as_u64()?).ok()?;
                            self.func_at(a).filter(|f| f.native.start == a).cloned()
                        })
                        .collect()
                })
                .unwrap_or_default();
            if let Some(addresses) = symbols
                .get_mut("address")
                .and_then(serde_json::Value::as_array_mut)
            {
                for (address, func) in addresses.iter_mut().zip(&funcs) {
                    if let Some(func) = func {
                        *address = func.wasm.start.into();
                    }
                }
            }
            if let Some(sizes) = symbols
                .get_mut("functionSize")
                .and_then(serde_json::Value::as_array_mut)
            {
                for (size, func) in sizes.iter_mut().zip(&funcs) {
                    if let Some(func) = func {
                        *size = (func.wasm.end - func.wasm.start).into();
                    }
                }
            }
        }
    }
}

/// Returns the byte ranges of the function bodies in the code section of a
/// core Wasm module, in order.
fn function_bodies(wasm: &[u8]) -> wasmparser::Result<Vec<Range<u64>>> {
    let mut bodies = Vec::new();
    for payload in wasmparser::Parser::new(0).parse_all(wasm) {
        if let wasmparser::Payload::CodeSectionEntry(body) = payload? {
            bodies.push(body.range());
        }
    }
    Ok(bodies)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn offsets() -> WasmOffsets {
        WasmOffsets::from_parts(
            vec![
                (0x100, None),
                (0x108, Some(0x51)),
                (0x110, Some(0x55)),
                (0x200, None),
                (0x204, Some(0x81)),
            ],
            vec![
                FuncRange {
                    native: 0x100..0x180,
                    wasm: 0x50..0x60,
                },
                FuncRange {
                    native: 0x200..0x240,
                    wasm: 0x80..0x90,
                },
            ],
        )
    }

    #[test]
    fn wasm_offset() {
        let o = offsets();
        assert_eq!(o.wasm_offset(0x100), Some(0x50)); // prologue
        assert_eq!(o.wasm_offset(0x10b), Some(0x51));
        assert_eq!(o.wasm_offset(0x17f), Some(0x55));
        assert_eq!(o.wasm_offset(0x180), None); // between functions
        assert_eq!(o.wasm_offset(0x202), Some(0x80));
        assert_eq!(o.wasm_offset(0x23f), Some(0x81));
        assert_eq!(o.wasm_offset(0x10), None);
    }

    #[test]
    fn rewrite_profile() {
        let o = offsets();
        let mut profile = json!({
            "threads": [{
                "frameTable": { "address": [0x10b, 0x203, -1, 0x500] },
                "nativeSymbols": {
                    "address": [0x100, 0x200, 0x300],
                    "functionSize": [0x80, 0x40, 0x10],
                },
            }],
        });
        o.rewrite_profile(&mut profile);
        assert_eq!(
            profile,
            json!({
                "threads": [{
                    "frameTable": { "address": [0x51, 0x80, -1, 0x500] },
                    "nativeSymbols": {
                        "address": [0x50, 0x80, 0x300],
                        "functionSize": [0x10, 0x10, 0x10],
                    },
                }],
            })
        );
    }

    #[test]
    fn function_bodies_in_order() {
        let wasm = wat::parse_str(
            r#"(module
                (import "env" "f" (func))
                (func (result i32) i32.const 1)
                (func (result i32) i32.const 2 i32.const 3 i32.add))"#,
        )
        .unwrap();
        let bodies = function_bodies(&wasm).unwrap();
        assert_eq!(bodies.len(), 2);
        assert!(bodies[0].end <= bodies[1].start);
        // Each body starts with its local declaration count.
        assert_eq!(wasm[bodies[0].start as usize], 0);
    }

    #[test]
    fn new_matches_module() {
        let wasm = wat::parse_str(
            r#"(module
                (func $a (result i32) i32.const 1)
                (func $b (param i32) (result i32)
                    (loop $l (br_if $l (local.get 0)))
                    local.get 0))"#,
        )
        .unwrap();
        let mut config = wasmtime::Config::new();
        config.epoch_interruption(true);
        let engine = wasmtime::Engine::new(&config).unwrap();
        let module = Module::new(&engine, &wasm).unwrap();
        let o = WasmOffsets::new(&module, &wasm).unwrap();
        assert_eq!(o.funcs.len(), 2);
        let bodies = function_bodies(&wasm).unwrap();
        for f in &o.funcs {
            assert!(bodies.iter().any(|b| b.start == u64::from(f.wasm.start)));
            for native in f.native.clone() {
                let w = o.wasm_offset(native).unwrap();
                assert!(f.wasm.contains(&w), "{native:#x} -> {w:#x} outside {f:?}");
            }
        }
    }
}
