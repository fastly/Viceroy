use anyhow::Context;

/// The full adapter.
const ADAPTER_BYTES: &[u8] = include_bytes!("../wasm_abi/data/viceroy-component-adapter.wasm");
const ADAPTER_NOSHIFT_BYTES: &[u8] =
    include_bytes!("../wasm_abi/data/viceroy-component-adapter.noshift.wasm");

/// A version of the adapter that doesn't provide the `http_incoming` export.
///
/// This is used by "library" components meant to be linked to a main component
/// that does provide the `http_incoming` export.
const LIBRARY_ADAPTER_BYTES: &[u8] =
    include_bytes!("../wasm_abi/data/viceroy-component-adapter.library.wasm");
const LIBRARY_ADAPTER_NOSHIFT_BYTES: &[u8] =
    include_bytes!("../wasm_abi/data/viceroy-component-adapter.library.noshift.wasm");

/// Check if the bytes represent a core wasm module, or a component.
pub fn is_component(bytes: &[u8]) -> bool {
    wasmparser::Parser::is_component(bytes)
}

/// Given bytes that represent a core wasm module in the wat format, adapt it to a component using
/// the viceroy adapter.
pub fn adapt_wat(wat: &str) -> anyhow::Result<Vec<u8>> {
    let bytes = wat::parse_str(wat)?;
    adapt_bytes(&bytes)
}

/// Given bytes that represent a core wasm module, adapt it to a component using the viceroy
/// adapter.
///
/// The adapter has two flavors: the default *shifted* one, which moves the user
/// module's memory up by 2 pages so the adapter can park scratch state in the
/// first 2 pages without needing `cabi_realloc`; and the *noshift* one, which
/// allocates state via the user module's `cabi_realloc` and leaves memory
/// untouched. The shifted form is faster (state lives at a fixed offset, no
/// indirection) but only safe when nothing crosses the canonical-ABI boundary
/// directly: wasmtime's lift/lower has no knowledge of the 2-page shift, so
/// any pointer that travels through it lands at the wrong physical address.
///
/// We must therefore use the noshift adapter whenever the module participates
/// in cross-component composition through a wit-bindgen-generated interface,
/// on **either** side of the boundary:
///
/// * A wit-bindgen *import* call lowers args to raw (unshifted) pointers and
///   hands them to wasmtime, which then reads from the wrong place in shifted
///   memory. (Original symptom; partial fix in #582.)
/// * A wit-bindgen *export* receives args after wasmtime called the user's
///   `cabi_realloc` to allocate a destination buffer; in shifted mode that
///   `cabi_realloc` returns a shifted-view pointer, but wasmtime treats it
///   as a real pointer and copies source data to the wrong physical address.
///   The user-side function then reads from "its" pointer in shifted view,
///   which is OFFSET bytes off from where wasmtime wrote. (See ExecuteD#6130.)
pub fn adapt_bytes(bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
    // Determine if we have a main module or a library module.
    let library = !has_export(bytes, "_start");
    let needs_no_shift_adapter = has_wit_bindgen_imports(bytes) || has_wit_bindgen_exports(bytes);

    let bytes = if needs_no_shift_adapter {
        bytes.to_vec()
    } else {
        crate::shift_mem::shift_main_module(bytes)?
    };
    let module = mangle_imports(&bytes)?;

    let adapter_bytes = match (library, needs_no_shift_adapter) {
        (true, true) => LIBRARY_ADAPTER_NOSHIFT_BYTES,
        (true, false) => LIBRARY_ADAPTER_BYTES,
        (false, true) => ADAPTER_NOSHIFT_BYTES,
        (false, false) => ADAPTER_BYTES,
    };

    let component = wit_component::ComponentEncoder::default()
        .module(module.as_slice())?
        // NOTE: the adapter uses the module name `wasi_snapshot_preview1` as it was originally a
        // fork of the wasi_snapshot_preview1 adapter. The wasm has a different name to make the
        // codebase make more sense, but plumbing that name all the way through the adapter would
        // require adjusting all preview1 functions to have a mangled name, like
        // "wasi_snapshot_preview1#args_get".
        .adapter("wasi_snapshot_preview1", adapter_bytes)?
        .validate(true)
        .encode()?;

    // Add "viceroy" to the producers section.
    let mut producers = wasm_metadata::Producers::empty();
    let mut flags = Vec::with_capacity(2);
    if library {
        flags.push("library");
    }
    if needs_no_shift_adapter {
        flags.push("noshift");
    }
    producers.add(
        "processed-by",
        "viceroy adapt",
        &format!("{} ({})", env!("CARGO_PKG_VERSION"), flags.join(", ")),
    );
    let component = producers
        .add_to_wasm(&component)
        .context("failed to add viceroy producer metadata to wasm")?;

    Ok(component)
}

/// We need to ensure that the imports of the core wasm module are all remapped to the single
/// adapter `wasi_snapshot_preview1`, as that allows us to reuse common infrastructure in the
/// adapter's implementation. To accomplish this, we change imports to all come from the
/// `wasi_snapshot_preview1` module, and mangle the function name to
/// `original_module#original_name`.
fn mangle_imports(bytes: &[u8]) -> anyhow::Result<wasm_encoder::Module> {
    let mut module = wasm_encoder::Module::new();

    for payload in wasmparser::Parser::new(0).parse_all(bytes) {
        let payload = payload?;
        match payload {
            wasmparser::Payload::Version {
                encoding: wasmparser::Encoding::Component,
                ..
            } => {
                anyhow::bail!("Mangling only supports core-wasm modules, not components");
            }

            wasmparser::Payload::ImportSection(section) => {
                let mut imports = wasm_encoder::ImportSection::new();

                for import in section {
                    let import = import?;
                    let entity = wasm_encoder::EntityType::try_from(import.ty).map_err(|_| {
                        anyhow::anyhow!(
                            "Failed to translate type for import {}:{}",
                            import.module,
                            import.name
                        )
                    })?;

                    if is_fastly_module(import.module) {
                        // In order to build a single module that can serve as
                        // the adapter for the many "fastly_*" modules we have,
                        // as well as the "env" module we have, as well as for
                        // the "wasi_snapshot_preview1" module, we mangle
                        // "fastly_*" and "env" names and put them into the
                        // "wasi_snapshot_preview1" module.
                        let module = "wasi_snapshot_preview1";
                        let name = format!("{}#{}", import.module, import.name);
                        imports.import(module, &name, entity);
                    } else {
                        // It's not a "fastly_" module, so it may be
                        // "wasi_snapshot_preview1" which we should leave as-is,
                        // or a wit-bindgen-generated import which doesn't need
                        // adapting.
                        imports.import(import.module, import.name, entity);
                    }
                }

                module.section(&imports);
            }

            payload => {
                if let Some((id, range)) = payload.as_section() {
                    module.section(&wasm_encoder::RawSection {
                        id,
                        data: &bytes[range],
                    });
                }
            }
        }
    }

    Ok(module)
}

/// Test whether `bytes` holds a wasm binary with an export named `wanted`.
fn has_export(bytes: &[u8], wanted: &str) -> bool {
    for payload in wasmparser::Parser::new(0).parse_all(bytes) {
        let Ok(payload) = payload else {
            return false;
        };
        if let wasmparser::Payload::ExportSection(section) = payload {
            for export in section {
                let Ok(export) = export else {
                    return false;
                };
                if export.name == wanted {
                    return true;
                }
            }
        }
    }

    false
}
fn is_fastly_module(module: &str) -> bool {
    module.starts_with("fastly_") || module == "env" || module == "fastly" || module == "xqd"
}
/// True if the module imports any function from a non-WASI, non-Fastly module
/// (i.e. a wit-bindgen-generated cross-component import). Such a module cannot
/// use the shifted adapter because wit-bindgen's lowering passes raw pointers
/// to wasmtime that the canonical-ABI runtime would then interpret as real
/// physical addresses.
fn has_wit_bindgen_imports(bytes: &[u8]) -> bool {
    for payload in wasmparser::Parser::new(0).parse_all(bytes) {
        let Ok(payload) = payload else {
            return false;
        };
        if let wasmparser::Payload::ImportSection(section) = payload {
            for import in section {
                let Ok(import) = import else {
                    return false;
                };
                if !is_fastly_module(import.module) && import.module != "wasi_snapshot_preview1" {
                    return true;
                }
            }
        }
    }

    false
}

/// True if the module exports any function whose name is in the canonical-ABI
/// mangled form `<package>:<interface>@<version>#<func>`, i.e. a wit-bindgen
/// export consumed via cross-component composition. Such a module cannot use
/// the shifted adapter because its `cabi_realloc` would return shifted-view
/// pointers that wasmtime would then write source data to in the wrong
/// physical location.
///
/// Detection is by structural pattern: any export name containing both `:` and
/// `#`. The standard wasip1 exports a Rust Compute service emits (`_start`,
/// `__main_void`, `memory`, `cabi_realloc`, `cabi_realloc_wit_bindgen_*`)
/// contain neither, so the check has no false positives in practice.
fn has_wit_bindgen_exports(bytes: &[u8]) -> bool {
    for payload in wasmparser::Parser::new(0).parse_all(bytes) {
        let Ok(payload) = payload else {
            return false;
        };
        if let wasmparser::Payload::ExportSection(section) = payload {
            for export in section {
                let Ok(export) = export else {
                    return false;
                };
                if export.name.contains(':') && export.name.contains('#') {
                    return true;
                }
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal pure-WASIp1 Compute-style module: standard wasi import,
    /// `_start`, `memory`, plain `cabi_realloc`. No wit-bindgen on either
    /// side. Should keep the shifted adapter (no perf regression).
    fn pure_wasip1() -> Vec<u8> {
        wat::parse_str(
            r#"
            (module
              (import "wasi_snapshot_preview1" "fd_write"
                (func (param i32 i32 i32 i32) (result i32)))
              (func (export "_start"))
              (memory (export "memory") 1)
              (func (export "cabi_realloc")
                (param i32 i32 i32 i32) (result i32) (i32.const 0))
              (func (export "cabi_realloc_wit_bindgen_0_57_1")
                (param i32 i32 i32 i32) (result i32) (i32.const 0))
            )
            "#,
        )
        .unwrap()
    }

    /// A consumer module: imports a wit-bindgen interface, exports nothing
    /// component-shaped. Triggered the existing #582 fallback.
    fn wit_bindgen_consumer() -> Vec<u8> {
        wat::parse_str(
            r#"
            (module
              (import "wasi_snapshot_preview1" "fd_write"
                (func (param i32 i32 i32 i32) (result i32)))
              (import "fastly:component-template/inspector@0.1.0" "inspect"
                (func (param i32 i32) (result i32)))
              (func (export "_start"))
              (memory (export "memory") 1)
              (func (export "cabi_realloc")
                (param i32 i32 i32 i32) (result i32) (i32.const 0))
            )
            "#,
        )
        .unwrap()
    }

    /// A library module: only WASI/standard imports, but exports a
    /// wit-bindgen interface for another component to plug into. This is the
    /// case the new `has_wit_bindgen_exports` check must catch; without it
    /// the module gets the shifted adapter and silently corrupts data on the
    /// canonical-ABI boundary (ExecuteD#6130).
    fn wit_bindgen_library() -> Vec<u8> {
        wat::parse_str(
            r#"
            (module
              (import "wasi_snapshot_preview1" "fd_write"
                (func (param i32 i32 i32 i32) (result i32)))
              (memory (export "memory") 1)
              (func (export "fastly:component-template/inspector@0.1.0#inspect")
                (result i32) (i32.const 0))
              (func (export "cabi_post_fastly:component-template/inspector@0.1.0#inspect")
                (param i32))
              (func (export "cabi_realloc")
                (param i32 i32 i32 i32) (result i32) (i32.const 0))
            )
            "#,
        )
        .unwrap()
    }

    #[test]
    fn pure_wasip1_keeps_shifted_adapter() {
        let bytes = pure_wasip1();
        assert!(!has_wit_bindgen_imports(&bytes));
        assert!(!has_wit_bindgen_exports(&bytes));
    }

    #[test]
    fn wit_bindgen_consumer_uses_noshift_adapter() {
        let bytes = wit_bindgen_consumer();
        assert!(has_wit_bindgen_imports(&bytes));
        assert!(!has_wit_bindgen_exports(&bytes));
    }

    #[test]
    fn wit_bindgen_library_uses_noshift_adapter() {
        let bytes = wit_bindgen_library();
        assert!(!has_wit_bindgen_imports(&bytes));
        assert!(has_wit_bindgen_exports(&bytes));
    }

    /// End-to-end check that the heuristic actually flips the adapter
    /// selection in `adapt_bytes`. The producer-metadata custom section
    /// records which flavor was used, so we look for the flag string
    /// `viceroy adapt` writes.
    fn adapter_flags(adapted: &[u8]) -> String {
        // wasm-metadata embeds producer info as a UTF-8 substring; a
        // simple search is sufficient and avoids pulling in another
        // parser dependency.
        let needle = b"viceroy adapt";
        let pos = adapted
            .windows(needle.len())
            .position(|w| w == needle)
            .expect("producer metadata missing");
        let tail = &adapted[pos..];
        let end = tail
            .iter()
            .position(|&b| b == 0 || b == b'"')
            .unwrap_or(tail.len().min(64));
        String::from_utf8_lossy(&tail[..end]).to_string()
    }

    #[test]
    fn adapt_bytes_marks_pure_wasip1_as_unflagged() {
        let adapted = adapt_bytes(&pure_wasip1()).unwrap();
        let flags = adapter_flags(&adapted);
        assert!(!flags.contains("noshift"), "got {flags:?}");
        assert!(!flags.contains("library"), "got {flags:?}");
    }

    // Note: there is no end-to-end adapt_bytes test for the
    // wit-bindgen *consumer* fixture because adapt_bytes resolves the
    // imported WIT interface during component encoding, and the
    // standalone WAT fixture has no companion component to resolve
    // against. The heuristic test above (`wit_bindgen_consumer_uses_
    // noshift_adapter`) covers the relevant detection logic, and the
    // library wiring test below confirms the metadata flags reach the
    // output for at least one wit-bindgen case.

    #[test]
    fn adapt_bytes_marks_wit_bindgen_library_as_library_noshift() {
        let adapted = adapt_bytes(&wit_bindgen_library()).unwrap();
        let flags = adapter_flags(&adapted);
        assert!(flags.contains("library"), "got {flags:?}");
        assert!(flags.contains("noshift"), "got {flags:?}");
    }
}
