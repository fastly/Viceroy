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
pub fn adapt_bytes(bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
    // Determine if we have a main module or a library module.
    let library = !has_export(bytes, "_start");

    let bytes = crate::shift_mem::shift_main_module(bytes)?;
    let (module, needs_no_shift_adapter) = mangle_imports(&bytes)?;

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

    Ok(component)
}

/// We need to ensure that the imports of the core wasm module are all remapped to the single
/// adapter `wasi_snapshot_preview1`, as that allows us to reuse common infrastructure in the
/// adapter's implementation. To accomplish this, we change imports to all come from the
/// `wasi_snapshot_preview1` module, and mangle the function name to
/// `original_module#original_name`.
fn mangle_imports(bytes: &[u8]) -> anyhow::Result<(wasm_encoder::Module, bool)> {
    let mut module = wasm_encoder::Module::new();
    let mut needs_no_shift_adapter = false;

    for payload in wasmparser::Parser::new(0).parse_all(&bytes) {
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
                    } else if import.module == "wasi_snapshot_preview1" {
                        // Leave wasi_snapshot_preview1 imports as-is.
                        imports.import(import.module, import.name, entity);
                    } else {
                        // It's a wit-bindgen-generated import which doesn't need
                        // adapting.
                        needs_no_shift_adapter = true;
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

    Ok((module, needs_no_shift_adapter))
}

/// Test whether `bytes` holds a wasm binary with an export named `wanted`.
fn has_export(bytes: &[u8], wanted: &str) -> bool {
    for payload in wasmparser::Parser::new(0).parse_all(&bytes) {
        let Ok(payload) = payload else {
            return false;
        };
        match payload {
            wasmparser::Payload::ExportSection(section) => {
                for export in section {
                    let Ok(export) = export else {
                        return false;
                    };
                    if export.name == wanted {
                        return true;
                    }
                }
            }
            _ => {}
        }
    }

    false
}

fn is_fastly_module(module: &str) -> bool {
    module.starts_with("fastly_") || module == "env" || module == "fastly" || module == "xqd"
}
