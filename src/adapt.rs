use anyhow::Context;

// These are built by `build.rs`, which either compiles them from
// `wasm_abi/adapter` or, in a published crate, takes the prebuilt binaries from
// `wasm_abi/data`.

/// The full adapter.
const ADAPTER_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/viceroy-component-adapter.wasm"));
const ADAPTER_NOSHIFT_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/viceroy-component-adapter.noshift.wasm"
));

/// A version of the adapter that doesn't provide the `http_incoming` export.
///
/// This is used by "library" components meant to be linked to a main component
/// that does provide the `http_incoming` export.
const LIBRARY_ADAPTER_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/viceroy-component-adapter.library.wasm"
));
const LIBRARY_ADAPTER_NOSHIFT_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/viceroy-component-adapter.library.noshift.wasm"
));

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
    // Determine if we have a main module or a library module. Modules built for
    // `wasm32-wasip2` with `--skip-wit-component` export their entry point as
    // `wasi:cli/run@0.2.x#run` instead of `_start`.
    let has_start = has_export(bytes, "_start");
    let run_func = if has_start {
        None
    } else {
        find_wasi_cli_run_export(bytes)
    };
    let library = !has_start && run_func.is_none();

    // Wit-bindgen imports and exports need the noshift adapter.
    let needs_no_shift_adapter = has_wit_bindgen_imports(bytes) || has_wit_bindgen_exports(bytes);

    let bytes = if needs_no_shift_adapter {
        bytes.to_vec()
    } else {
        crate::shift_mem::shift_main_module(bytes)?
    };
    let module = mangle_imports(&bytes, run_func)?;

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
///
/// If `run_func` is given, it is the index of a `wasi:cli/run` export of type
/// `() -> i32`, and a `_start: () -> ()` export is synthesized that calls it,
/// since that's the entry point the adapter imports from the main module.
fn mangle_imports(bytes: &[u8], run_func: Option<u32>) -> anyhow::Result<wasm_encoder::Module> {
    use wasm_encoder::reencode::{Reencode, RoundtripReencoder};

    let mut module = wasm_encoder::Module::new();

    let mut imported_funcs = 0;
    let mut start_type = None;
    let mut start_func = None;
    let mut code = None;

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
                    for import in import {
                        let import = import?;
                        let import = import.1;
                        if matches!(
                            import.ty,
                            wasmparser::TypeRef::Func(_) | wasmparser::TypeRef::FuncExact(_)
                        ) {
                            imported_funcs += 1;
                        }
                        let entity =
                            wasm_encoder::EntityType::try_from(import.ty).map_err(|_| {
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
                }

                module.section(&imports);
            }

            // Everything below is only needed to synthesize `_start`.
            wasmparser::Payload::TypeSection(section) if run_func.is_some() => {
                let mut num_types = 0;
                for rec_group in section.clone() {
                    num_types += rec_group?.types().len() as u32;
                }
                let mut types = wasm_encoder::TypeSection::new();
                RoundtripReencoder.parse_type_section(&mut types, section)?;
                types.ty().function([], []);
                start_type = Some(num_types);
                module.section(&types);
            }

            wasmparser::Payload::FunctionSection(section) if run_func.is_some() => {
                let start_type =
                    start_type.ok_or_else(|| anyhow::anyhow!("missing type section"))?;
                start_func = Some(imported_funcs + section.count());
                let mut funcs = wasm_encoder::FunctionSection::new();
                RoundtripReencoder.parse_function_section(&mut funcs, section)?;
                funcs.function(start_type);
                module.section(&funcs);
            }

            wasmparser::Payload::ExportSection(section) if run_func.is_some() => {
                let start_func =
                    start_func.ok_or_else(|| anyhow::anyhow!("missing function section"))?;
                let mut exports = wasm_encoder::ExportSection::new();
                RoundtripReencoder.parse_export_section(&mut exports, section)?;
                exports.export("_start", wasm_encoder::ExportKind::Func, start_func);
                module.section(&exports);
            }

            wasmparser::Payload::CodeSectionStart { count, .. } if run_func.is_some() => {
                code = Some((count, wasm_encoder::CodeSection::new()));
            }

            wasmparser::Payload::CodeSectionEntry(body) if run_func.is_some() => {
                let (remaining, section) = code
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("code entry outside of code section"))?;
                section.raw(body.as_bytes());
                *remaining -= 1;
                if *remaining == 0 {
                    // Call the `wasi:cli/run` function, trapping if it
                    // returns an error, as a nonzero exit code would.
                    let mut start = wasm_encoder::Function::new([]);
                    start
                        .instructions()
                        .call(run_func.unwrap())
                        .if_(wasm_encoder::BlockType::Empty)
                        .unreachable()
                        .end()
                        .end();
                    section.function(&start);
                    module.section(section);
                }
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

/// Find the function index of a `wasi:cli/run@0.2.x#run` export, which is how
/// `wasm32-wasip2` modules linked with `--skip-wit-component` export their
/// entry point.
fn find_wasi_cli_run_export(bytes: &[u8]) -> Option<u32> {
    for payload in wasmparser::Parser::new(0).parse_all(bytes) {
        let Ok(payload) = payload else {
            return None;
        };
        if let wasmparser::Payload::ExportSection(section) = payload {
            for export in section {
                let Ok(export) = export else {
                    return None;
                };
                if export.kind == wasmparser::ExternalKind::Func
                    && export.name.starts_with("wasi:cli/run@0.2.")
                    && export.name.ends_with("#run")
                {
                    return Some(export.index);
                }
            }
        }
    }

    None
}

fn is_fastly_module(module: &str) -> bool {
    module.starts_with("fastly_") || module == "env" || module == "fastly" || module == "xqd"
}

// Treat non-WASI, non-Fastly imports as wit-bindgen imports.
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
                for import in import {
                    let Ok(import) = import else {
                        return false;
                    };
                    let import = import.1;
                    if !is_fastly_module(import.module) && import.module != "wasi_snapshot_preview1"
                    {
                        return true;
                    }
                }
            }
        }
    }

    false
}

// Best-effort check for wit-bindgen export names, such as
// `<package>:<interface>@<version>#<func>`. The Fastly SDK does not emit this
// shape for plain wasip1 services.
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

    #[test]
    fn adapt_bytes_marks_wit_bindgen_library_fixture_as_library_noshift() {
        // Fixture generated from fastly/edge-storage's
        // components/template/inspector-component crate and stripped with
        // `wasm-tools strip --all`.
        let adapted = adapt_bytes(include_bytes!(
            "../tests/fixtures/template_inspector_component.wasm"
        ))
        .unwrap();

        // Checking which adapter is used from the custom section.
        assert!(contains_bytes(&adapted, b"viceroy adapt"));
        assert!(contains_bytes(&adapted, b"(library, noshift)"));
    }

    fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }
}
